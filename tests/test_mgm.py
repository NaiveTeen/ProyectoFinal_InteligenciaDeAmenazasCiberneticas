import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "monitor"))

from app.helpdesk import create_app  # noqa: E402
import monitor  # noqa: E402


def client(tmp_path, mode):
    return create_app(mode, tmp_path).test_client()


def test_insecure_mode_allows_vishing(tmp_path):
    c = client(tmp_path, "insecure")
    r = c.post("/helpdesk/reset_mfa", json={"employee_id": "E1002", "caller_name": "Luis"})
    assert r.status_code == 200 and "temp_password" in r.json


def test_secure_mode_blocks_vishing(tmp_path):
    c = client(tmp_path, "secure")
    assert c.post("/helpdesk/reset_mfa", json={"employee_id": "E1002"}).status_code == 202
    for _ in range(3):
        r = c.post("/helpdesk/reset_mfa", json={"employee_id": "E1002", "otp": "0", "manager_code": "0"})
        assert r.status_code == 403
    assert c.post("/helpdesk/reset_mfa", json={"employee_id": "E1002"}).status_code == 429


def test_secure_mode_allows_legit_flow(tmp_path):
    c = client(tmp_path, "secure")
    c.post("/helpdesk/reset_mfa", json={"employee_id": "E1001"})
    codes = json.loads((tmp_path / "out_of_band.log").read_text().splitlines()[-1])
    r = c.post("/helpdesk/reset_mfa", json={"employee_id": "E1001", "otp": codes["otp"],
                                            "manager_code": codes["manager_code"]})
    assert r.status_code == 200


def test_monitor_detects_reset_then_new_ip():
    ev = [
        {"ts": "2026-09-27T15:00:00+00:00", "event": "login_success", "user": "E1002", "ip": "10.0.0.12"},
        {"ts": "2026-09-27T15:05:00+00:00", "event": "reset_success", "employee": "E1002",
         "ip": "1.2.3.4", "verified": False},
        {"ts": "2026-09-27T15:06:00+00:00", "event": "login_success", "user": "E1002", "ip": "1.2.3.4"},
    ]
    rules = {a["rule"] for a in monitor.analyze(ev)}
    assert {"R1_RESET_THEN_NEW_IP", "R6_UNVERIFIED_RESET"} <= rules


def test_monitor_detects_canary(tmp_path):
    base, canary = tmp_path / "b.json", tmp_path / "canary"
    assert monitor.check_canary(canary, base) == []
    next(canary.iterdir()).rename(canary / "x.locked")
    assert monitor.check_canary(canary, base)[0]["rule"] == "R5_RANSOMWARE_CANARY"
