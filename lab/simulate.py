#!/usr/bin/env python3
"""Simulador de escenarios contra TU PROPIO laboratorio (empleados ficticios)."""
import argparse
import json
from pathlib import Path

import requests

ATTACKER_IP = "198.51.100.77"  # IP de documentacion (RFC 5737), ficticia


def legit(url, logs):
    creds = json.loads((Path(logs) / "lab_credentials.json").read_text())
    r = requests.post(f"{url}/login", json={"user": "E1001", "password": creds["E1001"]},
                      headers={"X-Simulated-IP": "10.0.0.11"}, timeout=5)
    print("Login legitimo de E1001:", r.status_code)


def vishing(url):
    h = {"X-Simulated-IP": ATTACKER_IP}
    print("[atacante] Llamada al help desk fingiendo ser Luis Prado (E1002)...")
    r = requests.post(f"{url}/helpdesk/reset_mfa", headers=h, timeout=5,
                      json={"employee_id": "E1002", "caller_name": "Luis Prado"})
    if r.status_code == 200:
        temp = r.json()["temp_password"]
        l = requests.post(f"{url}/login", headers=h, timeout=5,
                          json={"user": "E1002", "password": temp})
        print(f"[atacante] Reset concedido sin verificar. Login: {l.status_code} -> CUENTA COMPROMETIDA")
        return
    print(f"[atacante] Help desk exige verificacion ({r.status_code}). Adivinando codigos...")
    for guess in ("000000", "123456", "111111"):
        r = requests.post(f"{url}/helpdesk/reset_mfa", headers=h, timeout=5,
                          json={"employee_id": "E1002", "caller_name": "Luis Prado",
                                "otp": guess, "manager_code": guess})
        print(f"[atacante] intento {guess}: {r.status_code}")
    print("[atacante] Ataque BLOQUEADO por la verificacion fuera de banda")


def ransomware(canary):
    files = sorted(Path(canary).glob("documento_*.txt"))
    for p in files:
        p.rename(p.with_suffix(".txt.locked"))
    print(f"[ransomware simulado] {len(files)} archivos renombrados a .locked en {canary}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["legit", "vishing", "ransomware"])
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--logs", default="logs")
    ap.add_argument("--canary", default="canary")
    a = ap.parse_args()
    {"legit": lambda: legit(a.url, a.logs), "vishing": lambda: vishing(a.url),
     "ransomware": lambda: ransomware(a.canary)}[a.scenario]()
