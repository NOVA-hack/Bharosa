"""The relay HTTP API, driven through RelayBackend exactly as the CLI uses it."""

import pytest
from fastapi.testclient import TestClient

from bharosa.backend import RelayBackend
from bharosa.pipeline import DirectRunner, check_message, check_qr
from bharosa.relay.app import create_app
from bharosa.service import AuthError, Conflict, FamilyService, NotFound, ServiceError
from bharosa.store import Store


@pytest.fixture
def relay(clock):
    app = create_app(FamilyService(Store(":memory:"), clock=clock))
    client = TestClient(app, base_url="http://relay.test")
    return RelayBackend("http://relay.test", client=client), client


def test_health(relay):
    _, client = relay
    assert client.get("/health").json()["ok"] is True


def test_full_loop_over_http(relay):
    backend, client = relay
    p = backend.create_family("Amma", "hi")
    g = backend.join_family(p["pair_code"], "Rohan", "en", code_word="mango")
    r = check_qr("upi://pay?pa=rewards.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback",
                 DirectRunner(), backend.check_context(p["token"]))
    payload = r.case_payload(keep_raw=True)
    case = backend.submit_case(p["token"], payload)
    assert case["raw_content"] is None  # raw content never reaches the relay
    a = backend.request_approval(p["token"], r.case_id)
    assert a["status"] == "pending"
    held = backend.list_cases(g["token"], ["held"])
    assert [c["id"] for c in held] == [r.case_id]
    backend.decide(g["token"], r.case_id, "block", "fake")
    assert backend.case_status(p["token"], r.case_id)["state"] == "blocked"
    assert r.payee_hash in backend.check_context(p["token"])["reported_payees"]
    assert backend.verify_code_word(p["token"], "MANGO") is True
    events = backend.events_since(g["token"], 0)
    assert "case_blocked" in [e["action"] for e in events]
    assert backend.stats(g["token"])["decisions"] == 1


def test_auth_required_and_errors_map_to_exceptions(relay):
    backend, client = relay
    assert client.get("/cases").status_code == 401
    with pytest.raises(AuthError):
        backend.whoami("wrong")
    p = backend.create_family("Amma")
    with pytest.raises(NotFound):
        backend.get_case(p["token"], "case_doesnotexist")
    with pytest.raises(AuthError):
        backend.join_family("0000-000000", "x")


def test_relay_rejects_unmasked_pii(relay):
    backend, _ = relay
    p = backend.create_family("Amma")
    r = check_message("hello", DirectRunner())
    bad = r.case_payload()
    bad["masked_content"] = "my number is 9999900001"
    with pytest.raises(ServiceError):
        backend.submit_case(p["token"], bad)


def test_stop_and_unlock_over_http(relay):
    backend, _ = relay
    p = backend.create_family("Amma")
    g = backend.join_family(p["pair_code"], "Rohan")
    r = check_message("CBI here. You are under digital arrest. Do not tell anyone. Transfer money now.",
                      DirectRunner())
    backend.submit_case(p["token"], r.case_payload())
    backend.request_approval(p["token"], r.case_id)
    res = backend.emergency_stop(g["token"], "call")
    assert res["locked_cases"] == [r.case_id]
    with pytest.raises(Conflict):
        backend.decide(g["token"], r.case_id, "approve")
    assert backend.get_packet(p["token"])["packet"]["report_to"]["helpline"] == "1930"
    backend.unlock(g["token"])
    assert backend.family_info(p["token"])["locked"] is False
