"""The relay's POST /check for the Android app, and the app-to-bot review loop. Synthetic data only."""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bharosa.appcheck import check_for_app, detect_kind
from bharosa.chatbot.core import ChatBot, ChatStore, Incoming
from bharosa.relay.app import create_app
from bharosa.service import FamilyService, ServiceError
from bharosa.store import Store

ROOT = Path(__file__).resolve().parents[1]
RISKY = "upi://pay?pa=rewards.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback"
SAFE = "upi://pay?pa=sharma.dairy@okaxis&pn=Sharma%20Dairy&am=60"
SCAM_SMS = "Dear customer your SBI KYC expires today. Update now at http://sbi-kyc-update.xyz/login or account blocked"


@pytest.fixture
def relay(clock):
    svc = FamilyService(Store(":memory:"), clock=clock)
    client = TestClient(create_app(svc), base_url="http://relay.test")
    p = client.post("/families", json={"parent_name": "Amma", "language": "hi"}).json()
    g = client.post("/join", json={"pair_code": p["pair_code"], "guardian_name": "Rohan"}).json()
    return {"client": client, "svc": svc, "p": p, "g": g,
            "ph": {"Authorization": "Bearer " + p["token"]}, "gh": {"Authorization": "Bearer " + g["token"]}}


def test_detect_kind():
    assert detect_kind("  " + SAFE) == "qr"
    assert detect_kind("https://example.com/x") == "url"
    assert detect_kind("www.example.com") == "url"
    assert detect_kind(SCAM_SMS) == "msg"


def test_unpaired_check_returns_verdict_without_storing(relay):
    c, svc = relay["client"], relay["svc"]
    before = svc.store.one("SELECT COUNT(*) AS n FROM cases")["n"]
    r = c.post("/check", json={"content": SCAM_SMS}).json()
    assert r["risk_level"] in ("medium", "high")
    assert r["state"] == "unpaired" and r["action"] == "warn"
    assert r["reasons"] and all(x["text"] for x in r["reasons"])
    assert r["message"]
    assert svc.store.one("SELECT COUNT(*) AS n FROM cases")["n"] == before
    safe = c.post("/check", json={"content": SAFE, "kind": "qr"}).json()
    assert safe["action"] == "proceed" and safe["is_payment"] is True


def test_parent_risky_qr_is_held_and_raw_link_is_not_stored(relay):
    c, svc = relay["client"], relay["svc"]
    r = c.post("/check", json={"content": RISKY, "kind": "qr", "lang": "hi"}, headers=relay["ph"]).json()
    assert (r["risk_level"], r["state"], r["action"]) == ("high", "held", "hold")
    assert r["is_payment"] is True
    assert r["guardians_notified"] == 1
    assert r["approval"]["status"] == "pending"
    assert r["payee_masked"] == "re***@okhdfcbank"
    # Hindi text comes from the i18n pack; rule ids stay the same.
    assert any(x["rule_id"] == "QR-RECEIVE-MONEY" for x in r["reasons"])
    row = svc.store.one("SELECT * FROM cases WHERE id = ?", (r["case_id"],))
    assert row["raw_content"] is None
    assert "rewards.demo@" not in row["masked_content"]
    held = c.get("/cases", params={"state": "held"}, headers=relay["gh"]).json()
    assert [h["id"] for h in held] == [r["case_id"]]


def test_safe_qr_is_allowed_and_handoff_works(relay):
    c = relay["client"]
    r = c.post("/check", json={"content": SAFE, "kind": "qr"}, headers=relay["ph"]).json()
    assert (r["risk_level"], r["state"], r["action"]) == ("low", "allowed", "proceed")
    h = c.post(f"/cases/{r['case_id']}/handoff", headers=relay["ph"])
    assert h.status_code == 200


def test_held_case_cannot_hand_off_until_approved(relay):
    c = relay["client"]
    r = c.post("/check", json={"content": RISKY, "kind": "qr"}, headers=relay["ph"]).json()
    assert c.post(f"/cases/{r['case_id']}/handoff", headers=relay["ph"]).status_code == 409
    c.post(f"/cases/{r['case_id']}/decision", json={"decision": "approve", "note": "called her"},
           headers=relay["gh"])
    assert c.get(f"/cases/{r['case_id']}/status", headers=relay["ph"]).json()["state"] == "approved"
    case = c.get(f"/cases/{r['case_id']}", headers=relay["ph"]).json()
    assert case["input_sha256"] == r["input_sha256"]  # the app checks this before handing off
    assert c.post(f"/cases/{r['case_id']}/handoff", headers=relay["ph"]).status_code == 200


def test_emergency_stop_makes_checks_stop(relay):
    c = relay["client"]
    c.post("/stop", json={"reason": "pressure call"}, headers=relay["gh"])
    r = c.post("/check", json={"content": RISKY, "kind": "qr"}, headers=relay["ph"]).json()
    assert (r["state"], r["action"]) == ("stopped", "stop")
    s = c.post("/check", json={"content": SAFE, "kind": "qr"}, headers=relay["ph"]).json()
    assert s["action"] == "stop"


def test_scanned_qr_that_is_a_plain_url_is_checked_as_a_url(relay):
    r = relay["client"].post("/check", json={"content": "http://sbi-kyc-update.xyz/login", "kind": "qr"}).json()
    assert r["input_type"] == "url" and r["is_payment"] is False


def test_guardian_check_is_not_queued(relay):
    r = relay["client"].post("/check", json={"content": RISKY}, headers=relay["gh"]).json()
    assert r["state"] == "unpaired" and r["action"] == "warn"


def test_bad_requests(relay):
    c = relay["client"]
    assert c.post("/check", json={"content": ""}).status_code == 422
    assert c.post("/check", json={"content": "x", "kind": "nope"}).status_code == 422
    assert c.post("/check", json={"content": "x"}, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.post("/check", json={"content": "x"}, headers={"Authorization": "Basic abc"}).status_code == 401
    too_big = "upi://pay?pa=a@okaxis&tn=" + "x" * 3000
    assert c.post("/check", json={"content": too_big, "kind": "qr"}).status_code == 400


def test_anonymous_checks_are_rate_limited(relay, monkeypatch):
    import bharosa.relay.app as relay_app

    monkeypatch.setattr(relay_app, "ANON_CHECKS_PER_HOUR", 2)
    c = TestClient(create_app(relay["svc"]))
    codes = [c.post("/check", json={"content": "hello"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_queue_failure_still_returns_verdict(relay, monkeypatch):
    svc = relay["svc"]

    def boom(*a, **k):
        raise ServiceError("rate limited for the test")

    monkeypatch.setattr(svc, "submit_case", boom)
    r = check_for_app(svc, relay["p"]["token"], RISKY, "qr")
    assert r["state"] == "not_queued" and r["action"] == "warn" and r["queue_error"]


class _Transport:
    platform = "telegram"

    def __init__(self):
        self.sent = []

    def send(self, chat_id, message):
        self.sent.append((chat_id, message))


def test_app_case_reaches_the_bot_and_bot_decision_reaches_the_app(relay, clock, tmp_path):
    """Parent on the Android app, guardian on Telegram, both on the same family queue."""
    c, svc = relay["client"], relay["svc"]
    tg = _Transport()
    bot = ChatBot(svc, ChatStore(tmp_path / "bot.db"), {"telegram": tg}, clock=clock)
    code = c.post("/pair-codes", headers=relay["ph"]).json()["pair_code"]
    bot.handle(Incoming("telegram", "77", "Meera", text=f"/join {code} Meera"))

    r = c.post("/check", json={"content": RISKY, "kind": "qr"}, headers=relay["ph"]).json()
    assert r["action"] == "hold" and r["guardians_notified"] == 2
    bot.tick()
    review = [m for chat, m in tg.sent if chat == "77" and m.buttons]
    assert review and review[-1].buttons[0].data == f"approve:{r['case_id']}"

    bot.handle(Incoming("telegram", "77", "Meera", action=f"block:{r['case_id']}"))
    assert c.get(f"/cases/{r['case_id']}/status", headers=relay["ph"]).json()["state"] == "blocked"


def test_android_fixtures_match_the_relay():
    """android/app/src/test/resources must have the same shape as today's relay responses."""
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from make_android_fixtures import OUT, build
    finally:
        sys.path.pop(0)
    for name, fresh in build().items():
        saved = json.loads((OUT / name).read_text(encoding="utf-8"))
        assert set(saved) == set(fresh), f"{name} is stale; run scripts/make_android_fixtures.py"
        for key in ("risk_level", "action", "state", "is_payment", "input_sha256"):
            if key in fresh:
                assert saved[key] == fresh[key], f"{name}: {key} changed; run scripts/make_android_fixtures.py"
