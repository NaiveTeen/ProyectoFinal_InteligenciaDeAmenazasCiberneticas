#!/usr/bin/env python3
"""Monitor de Indicadores de Compromiso (IoCs) + contencion automatica simulada."""
import argparse
import hashlib
import json
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

SUSPICIOUS_EXT = (".locked", ".encrypted", ".crypt", ".enc", ".ransom")
OFF_HOURS = (7, 20)  # fuera de 07:00-20:00 es sospechoso


def parse(ts):
    return datetime.fromisoformat(ts)


def analyze(events):
    """Reglas de deteccion sobre eventos del help desk. Devuelve lista de alertas."""
    events = sorted(events, key=lambda e: e["ts"])
    alerts = []

    def add(key, sev, rule, msg, ev, user=None):
        alerts.append({"key": key, "severity": sev, "rule": rule, "message": msg,
                       "user": user, "event_ts": ev["ts"]})

    known_ips = defaultdict(set)
    fails = defaultdict(list)
    denied = defaultdict(int)
    for i, e in enumerate(events):
        ev, t = e["event"], parse(e["ts"])
        if ev == "login_success":
            known_ips[e["user"]].add(e["ip"])
        elif ev == "login_failed":
            fails[e["ip"]] = [x for x in fails[e["ip"]] if t - x < timedelta(minutes=5)] + [t]
            if len(fails[e["ip"]]) == 5:
                add(f"R2-{e['ip']}-{e['ts']}", "HIGH", "R2_BRUTE_FORCE",
                    f"5 logins fallidos en 5 min desde {e['ip']}", e)
        elif ev == "reset_requested":
            h = t.astimezone().hour
            if h < OFF_HOURS[0] or h >= OFF_HOURS[1]:
                add(f"R3-{e['ts']}", "MEDIUM", "R3_OFF_HOURS",
                    f"Solicitud de reset fuera de horario para {e['employee']}", e, e["employee"])
        elif ev == "reset_denied":
            denied[e["employee"]] += 1
            if denied[e["employee"]] == 3:
                add(f"R4-{e['employee']}", "HIGH", "R4_REPEATED_DENIALS",
                    f"3 resets denegados para {e['employee']} (posible vishing)", e, e["employee"])
        elif ev == "reset_success":
            u = e["employee"]
            if not e.get("verified", False):
                add(f"R6-{e['ts']}", "HIGH", "R6_UNVERIFIED_RESET",
                    f"Reset de MFA de {u} SIN verificacion fuera de banda", e, u)
            for later in events[i + 1:]:
                if parse(later["ts"]) - t > timedelta(minutes=30):
                    break
                if later["event"] == "login_success" and later["user"] == u \
                        and later["ip"] not in known_ips[u]:
                    add(f"R1-{u}-{later['ts']}", "CRITICAL", "R1_RESET_THEN_NEW_IP",
                        f"Reset de MFA de {u} seguido de login desde IP nueva {later['ip']}",
                        later, u)
    return alerts


def file_hash(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_canary(canary_dir, baseline_path):
    """Archivos 'canario': si se renombran/cifran/modifican, es senal de ransomware."""
    canary_dir, baseline_path = Path(canary_dir), Path(baseline_path)
    if not baseline_path.exists():
        canary_dir.mkdir(parents=True, exist_ok=True)
        for n in range(1, 6):
            (canary_dir / f"documento_{n}.txt").write_text(f"contenido ficticio {n}\n")
        base = {p.name: file_hash(p) for p in canary_dir.iterdir()}
        baseline_path.write_text(json.dumps(base))
        return []
    base = json.loads(baseline_path.read_text())
    now = {p.name: p for p in canary_dir.iterdir()}
    bad = [n for n in now if n.endswith(SUSPICIOUS_EXT)]
    missing = [n for n in base if n not in now]
    changed = [n for n in base if n in now and file_hash(now[n]) != base[n]]
    if bad or missing or changed:
        n = len(bad) + len(missing) + len(changed)
        return [{"key": "CANARY", "severity": "CRITICAL", "rule": "R5_RANSOMWARE_CANARY",
                 "message": f"{n} cambios en archivos canario (extensiones sospechosas/cifrado)",
                 "user": None, "event_ts": None}]
    return []


def respond(alert, log_dir):
    """Contencion automatica simulada."""
    if alert["severity"] != "CRITICAL":
        return
    if alert["user"]:
        p = log_dir / "blocked_accounts.json"
        b = json.loads(p.read_text()) if p.exists() else {}
        b[alert["user"]] = datetime.now().isoformat()
        p.write_text(json.dumps(b))
        print(f"   -> CONTENCION: cuenta {alert['user']} bloqueada")
    else:
        (log_dir / "ISOLATE.flag").write_text(datetime.now().isoformat())
        print("   -> CONTENCION: host/contenedor aislado de la red (simulado); notificar al CISO")


def run(log_dir, canary_dir, once, interval):
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    out = log_dir / "alerts.jsonl"
    seen = set()
    if out.exists():
        seen = {json.loads(l)["key"] for l in out.read_text().splitlines() if l.strip()}
    print("[monitor] vigilando", log_dir, "| canary:", canary_dir, flush=True)
    while True:
        lp = log_dir / "helpdesk.log"
        events = [json.loads(l) for l in lp.read_text().splitlines() if l.strip()] if lp.exists() else []
        alerts = analyze(events) + check_canary(canary_dir, log_dir / "canary_baseline.json")
        for a in alerts:
            if a["key"] in seen:
                continue
            seen.add(a["key"])
            a["detected_at"] = datetime.now().astimezone().isoformat()
            if a["event_ts"]:
                a["detection_seconds"] = round(
                    (datetime.fromisoformat(a["detected_at"]) - parse(a["event_ts"])).total_seconds(), 1)
            print(f"[ALERTA {a['severity']}] {a['rule']}: {a['message']}", flush=True)
            with open(out, "a", encoding="utf-8") as f:
                f.write(json.dumps(a) + "\n")
            respond(a, log_dir)
        if once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="logs")
    ap.add_argument("--canary-dir", default="canary")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=float, default=2)
    a = ap.parse_args()
    run(a.log_dir, a.canary_dir, a.once, a.interval)
