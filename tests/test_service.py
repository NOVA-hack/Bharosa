import json

import pytest

from bharosa.pipeline import DirectRunner, check_message, check_qr
from bharosa.service import (APPROVAL_TTL_SECONDS, AuthError, Conflict, Forbidden, NotFound, RateLimited,
                             ServiceError)

SCAM_QR = "upi://pay?pa=rewards.desk.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback"
SHOP_QR = "upi://pay?pa=sharmagrocery.demo@okaxis&pn=Sharma%20Grocery&am=240"


def submit(service, token, payload, ctx=None):
    r = check_qr(payload, DirectRunner(), ctx)
    case = service.submit_case(token, r.case_payload())
    return r, case


def test_pairing_and_roles(service, family):
    info = service.family_info(family["parent"])
    assert [g["display_name"] for g in info["guardians"]] == ["Rohan"]
    assert service.whoami(family["guardian"])["role"] == "guardian"
    with pytest.raises(AuthError):
        service.join_family(family["pair"]["pair_code"], "Again")  # one-time code
    with pytest.raises(AuthError):
        service.whoami("not-a-token")


def test_pair_code_expires(service, clock):
    p = service.create_family("Amma")
    clock.advance(11 * 60)
    with pytest.raises(AuthError):
        service.join_family(p["pair_code"], "Rohan")


def test_low_risk_case_is_allowed_and_payee_becomes_known(service, family):
    r, case = submit(service, family["parent"], SHOP_QR)
    assert case["state"] == "allowed"
    service.record_handoff(family["parent"], r.case_id)
    ctx = service.check_context(family["parent"])
    assert r.payee_hash in ctx["known_payees"]
    r2 = check_qr(SHOP_QR, DirectRunner(), ctx)
    assert r2.verdict.reasons == []


def test_risky_case_held_then_blocked_feeds_report_list(service, family, clock):
    r, case = submit(service, family["parent"], SCAM_QR)
    assert case["state"] == "checked"
    a = service.request_approval(family["parent"], r.case_id)
    assert a["status"] == "pending" and a["guardians_notified"] == 1
    assert a["expires_at"] == pytest.approx(clock() + APPROVAL_TTL_SECONDS)
    held = service.list_cases(family["guardian"], ["held"])
    assert [c["id"] for c in held] == [r.case_id]
    with pytest.raises(Forbidden):
        service.decide(family["parent"], r.case_id, "approve")  # parent cannot approve own case
    with pytest.raises(Conflict):
        service.record_handoff(family["parent"], r.case_id)  # no handoff while held
    clock.advance(42)
    c = service.decide(family["guardian"], r.case_id, "block", "fake reward")
    assert c["state"] == "blocked"
    ctx = service.check_context(family["parent"])
    assert r.payee_hash in ctx["reported_payees"]
    again = check_qr(SCAM_QR, DirectRunner(), ctx)
    assert "QR-REPORTED-PAYEE" in {x.rule_id for x in again.verdict.reasons}
    assert service.stats(family["guardian"])["median_review_seconds"] == pytest.approx(42)


def test_approved_case_can_hand_off(service, family):
    r, _ = submit(service, family["parent"], SCAM_QR)
    service.request_approval(family["parent"], r.case_id)
    service.decide(family["guardian"], r.case_id, "approve")
    assert service.record_handoff(family["parent"], r.case_id)["handoff"] == "mock"
    with pytest.raises(Conflict):
        service.decide(family["guardian"], r.case_id, "block")  # already decided


def test_approval_expires(service, family, clock):
    r, _ = submit(service, family["parent"], SCAM_QR)
    service.request_approval(family["parent"], r.case_id)
    clock.advance(APPROVAL_TTL_SECONDS + 1)
    assert service.case_status(family["parent"], r.case_id)["state"] == "expired"
    with pytest.raises(Conflict):
        service.decide(family["guardian"], r.case_id, "approve")


def test_other_family_cannot_see_or_decide(service, family):
    r, _ = submit(service, family["parent"], SCAM_QR)
    service.request_approval(family["parent"], r.case_id)
    other_parent = service.create_family("Other")
    other_guardian = service.join_family(other_parent["pair_code"], "Stranger")
    with pytest.raises(NotFound):
        service.get_case(other_guardian["token"], r.case_id)
    with pytest.raises(NotFound):
        service.decide(other_guardian["token"], r.case_id, "approve")
    assert service.list_cases(other_guardian["token"]) == []


def test_emergency_stop_locks_and_builds_redacted_packet(service, family, clock):
    r1, _ = submit(service, family["parent"], SCAM_QR)
    service.request_approval(family["parent"], r1.case_id)
    msg = check_message("This is CBI. You are under digital arrest. Do not tell anyone. Transfer Rs 50000 "
                        "now to safe.account.demo@ybl. Call 9999900001", DirectRunner())
    service.submit_case(family["parent"], msg.case_payload())
    clock.advance(600)
    res = service.emergency_stop(family["guardian"], "CBI call")
    assert set(res["locked_cases"]) == {r1.case_id, msg.case_id}
    assert service.family_info(family["parent"])["locked"] is True
    packet = res["packet"]
    blob = json.dumps(packet, ensure_ascii=False)
    assert "9999900001" not in blob and "safe.account.demo" not in blob
    assert packet["report_to"]["helpline"] == "1930"
    assert packet["golden_hour"]["minutes_since_incident"] == 10
    assert packet["golden_hour"]["within_golden_hour"] is True
    assert "digital arrest" in packet["ncrp_form"]["complaint_category"]
    # While locked: new cases are stopped, nothing can be approved or handed off.
    r3, case3 = submit(service, family["parent"], SHOP_QR)
    assert case3["state"] == "stopped"
    with pytest.raises(Conflict):
        service.record_handoff(family["parent"], r3.case_id)
    with pytest.raises(Forbidden):
        service.unlock(family["parent"])
    service.unlock(family["guardian"])
    assert service.family_info(family["parent"])["locked"] is False
    assert service.get_packet(family["parent"], r1.case_id)["sha256"] == res["sha256"]


def test_refuses_unmasked_pii_and_raw_content_hidden_from_guardian(service, family):
    r = check_qr(SHOP_QR, DirectRunner())
    bad = r.case_payload()
    bad["masked_content"] = "call 9999900001"
    with pytest.raises(ServiceError):
        service.submit_case(family["parent"], bad)
    case = service.submit_case(family["parent"], r.case_payload(keep_raw=True))
    assert case["raw_content"] == SHOP_QR
    assert "raw_content" not in service.get_case(family["guardian"], r.case_id)


def test_rate_limit(service, family):
    for _ in range(30):
        submit(service, family["parent"], SHOP_QR)
    with pytest.raises(RateLimited):
        submit(service, family["parent"], SHOP_QR)


def test_code_word(service, family):
    with pytest.raises(Conflict):
        service.verify_code_word(family["parent"], "mango")
    with pytest.raises(Forbidden):
        service.set_code_word(family["parent"], "mango")
    service.set_code_word(family["guardian"], "Mango")
    assert service.verify_code_word(family["parent"], " mango ") is True
    assert service.verify_code_word(family["parent"], "apple") is False
    row = service.store.one("SELECT code_word_hash FROM families")
    assert "mango" not in row["code_word_hash"]


def test_trusted_payees_and_review_amount(service, family):
    from bharosa.checks import hash_vpa

    service.add_trusted_payee(family["parent"], hash_vpa("rent.demo@oksbi"), "re***@oksbi", "Rent")
    assert service.list_trusted_payees(family["guardian"])[0]["label"] == "Rent"
    service.set_review_amount(family["guardian"], 20000)
    assert service.check_context(family["parent"])["review_amount"] == 20000
    assert service.remove_trusted_payee(family["parent"], hash_vpa("rent.demo@oksbi")) is True


def test_audit_log_is_append_only(service, family):
    import sqlite3

    assert any(a["action"] == "guardian_joined" for a in service.audit(family["parent"]))
    with pytest.raises(sqlite3.DatabaseError):
        service.store.execute("DELETE FROM audit_log")
    with pytest.raises(sqlite3.DatabaseError):
        service.store.execute("UPDATE audit_log SET action = 'x'")


def test_retention_purge(service, family, clock):
    r_old, _ = submit(service, family["parent"], SHOP_QR)  # allowed (decided)
    r_held, _ = submit(service, family["parent"], SCAM_QR)
    service.request_approval(family["parent"], r_held.case_id, ttl_seconds=10 * 86400)
    service.emergency_stop(family["parent"], "x")  # creates a packet (30-day expiry); held case -> stopped
    clock.advance(8 * 86400)
    res = service.purge_expired(7)
    assert res["cases_deleted"] == 2 and res["packets_deleted"] == 0
    clock.advance(30 * 86400)
    assert service.purge_expired(7)["packets_deleted"] == 1
    assert service.audit(family["parent"])  # audit log untouched
