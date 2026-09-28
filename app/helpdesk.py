"""Portal de help desk simulado de MGM (LABORATORIO, todos los datos son ficticios).

MGM_MODE=insecure -> reset de MFA con solo "decir" quien eres (el fallo explotado por vishing).
MGM_MODE=secure   -> exige codigos enviados fuera de banda (telefono registrado + jefe directo).
"""
import json
import os
import secrets
import time
from datetime import datetime, timezone
from hmac import compare_digest
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

EMPLOYEES = {
    "E1001": {"name": "Ana Torres", "role": "Finanzas", "usual_ip": "10.0.0.11"},
    "E1002": {"name": "Luis Prado", "role": "Operaciones", "usual_ip": "10.0.0.12"},
    "E1003": {"name": "Carla Mena", "role": "Gerente TI", "usual_ip": "10.0.0.13"},
}
MAX_DENIED = 3
PENDING_TTL = 600  # segundos


def create_app(mode=None, log_dir=None):
    app = Flask(__name__)
    app.config["MODE"] = mode or os.environ.get("MGM_MODE", "insecure")
    log_dir = Path(log_dir or os.environ.get("MGM_LOG_DIR", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    app.config["LOG_DIR"] = log_dir

    # Credenciales del laboratorio: se generan al arrancar, nunca viven en el codigo.
    passwords = {eid: secrets.token_urlsafe(12) for eid in EMPLOYEES}
    hashes = {eid: generate_password_hash(p) for eid, p in passwords.items()}
    (log_dir / "lab_credentials.json").write_text(json.dumps(passwords))
    pending, denied = {}, {}

    def log(event, **kw):
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kw}
        with open(log_dir / "helpdesk.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def src_ip():
        return request.headers.get("X-Simulated-IP") or request.remote_addr

    def blocked():
        p = log_dir / "blocked_accounts.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def grant(eid, ip, verified):
        temp = secrets.token_urlsafe(9)
        hashes[eid] = generate_password_hash(temp)
        log("reset_success", employee=eid, ip=ip, verified=verified)
        return jsonify(status="reset_ok", temp_password=temp), 200

    @app.get("/health")
    def health():
        return jsonify(status="ok", mode=app.config["MODE"])

    @app.post("/helpdesk/reset_mfa")
    def reset_mfa():
        d = request.get_json(silent=True) or {}
        eid, ip = d.get("employee_id"), src_ip()
        log("reset_requested", employee=eid, caller_claim=d.get("caller_name", ""), ip=ip)
        if eid not in EMPLOYEES:
            log("reset_denied", employee=eid, ip=ip, reason="unknown_employee")
            return jsonify(status="denied"), 404

        if app.config["MODE"] == "insecure":
            return grant(eid, ip, verified=False)

        if denied.get(eid, 0) >= MAX_DENIED:
            log("reset_denied", employee=eid, ip=ip, reason="rate_limited")
            return jsonify(status="rate_limited"), 429

        p = pending.get(eid)
        if not p or p["exp"] < time.time():
            pending[eid] = {
                "otp": f"{secrets.randbelow(10**6):06d}",
                "mgr": f"{secrets.randbelow(10**6):06d}",
                "exp": time.time() + PENDING_TTL,
            }
            # Simula el SMS al telefono REGISTRADO y la aprobacion del jefe (canal fuera de banda).
            with open(log_dir / "out_of_band.log", "a", encoding="utf-8") as f:
                f.write(json.dumps({"employee": eid, "otp": pending[eid]["otp"],
                                    "manager_code": pending[eid]["mgr"]}) + "\n")
            log("reset_pending", employee=eid, ip=ip)
            return jsonify(status="verification_required"), 202

        ok = compare_digest(str(d.get("otp", "")), p["otp"]) and \
            compare_digest(str(d.get("manager_code", "")), p["mgr"])
        if not ok:
            denied[eid] = denied.get(eid, 0) + 1
            log("reset_denied", employee=eid, ip=ip, reason="bad_codes")
            return jsonify(status="denied"), 403
        pending.pop(eid, None)
        return grant(eid, ip, verified=True)

    @app.post("/login")
    def login():
        d = request.get_json(silent=True) or {}
        user, ip = d.get("user"), src_ip()
        if user in blocked():
            log("login_blocked", user=user, ip=ip)
            return jsonify(status="account_blocked"), 423
        ok = user in hashes and check_password_hash(hashes[user], d.get("password", ""))
        log("login_success" if ok else "login_failed", user=user, ip=ip)
        return (jsonify(status="ok"), 200) if ok else (jsonify(status="invalid"), 401)

    return app


def wsgi():
    return create_app()


if __name__ == "__main__":
    create_app().run(port=5000)
