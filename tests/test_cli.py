"""End-to-end CLI flows in local mode: two profiles (parent and guardian) sharing one SQLite file."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bharosa.cli import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def run(args, profile=None, monkeypatch=None):
    env = {"BHAROSA_DIRECT": "1", "COLUMNS": "120"}
    if profile:
        env["BHAROSA_PROFILE"] = profile
    res = runner.invoke(app, args, env=env, catch_exceptions=False)
    return res


def j(res):
    return json.loads(res.stdout)


@pytest.fixture
def paired():
    p = j(run(["pair", "--name", "Amma", "--lang", "hi", "--json"], "amma"))
    g = run(["pair", "--join", p["pair_code"], "--name", "Rohan", "--phone", "+91 90000 00000",
             "--code-word", "mango"], "rohan")
    assert g.exit_code == 0, g.stdout
    return p


def test_version_and_help():
    assert "ruleset" in run(["version"]).stdout
    assert "check" in run(["--help"]).stdout


def test_unpaired_check_still_gives_a_verdict():
    res = run(["check", "url", "http://sbi-kyc-update.xyz/login", "--json"])
    d = j(res)
    assert d["verdict"]["risk_level"] == "high" and d["family_review"] == "not paired"
    res = run(["check", "qr", str(ROOT / "samples" / "qr" / "shop.png"), "--json"])
    d = j(res)
    assert d["verdict"]["risk_level"] == "low" and d["handoff"] == "mock" and d["executed"] is False


def test_low_risk_qr_hands_off_and_prints_link(paired):
    res = run(["check", "qr", str(ROOT / "samples" / "qr" / "shop.png")], "amma")
    assert res.exit_code == 0
    assert "Mock handoff" in res.stdout and "upi://pay" in res.stdout


def test_hindi_output(paired):
    res = run(["check", "msg", "-f", str(ROOT / "samples" / "messages" / "electricity_hi.txt"), "--no-wait"], "amma")
    assert "रुकिए" in res.stdout


def test_parent_to_guardian_loop(paired):
    d = j(run(["check", "qr", "--payload",
               "upi://pay?pa=rewards.desk.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback",
               "--no-wait", "--json"], "amma"))
    assert d["verdict"]["risk_level"] == "high" and d["case_state"] == "held"
    cid = d["case_id"]
    watch = j(run(["guardian", "watch", "--json"], "rohan"))
    assert [c["id"] for c in watch["cases"]] == [cid]
    show = run(["guardian", "show", cid[-6:]], "rohan")  # short id works
    assert "QR-RECEIVE-MONEY" in show.stdout
    assert run(["guardian", "approve", cid], "amma").exit_code == 1  # parent cannot decide
    res = run(["guardian", "block", cid, "--note", "fake"], "rohan")
    assert "blocked" in res.stdout
    status = j(run(["status", cid, "--json"], "amma"))
    assert status["state"] == "blocked"
    again = j(run(["check", "qr", "--payload", "upi://pay?pa=rewards.desk.demo@okhdfcbank&pn=Shop",
                   "--no-wait", "--json"], "amma"))
    assert "QR-REPORTED-PAYEE" in [r["rule_id"] for r in again["verdict"]["reasons"]]


def test_message_with_code_word_prompt(paired):
    d = j(run(["check", "msg", "-f", str(ROOT / "samples" / "messages" / "relative.txt"), "--no-wait", "--json"],
              "amma"))
    assert d["ask_code_word"] is True
    assert "ravi.help.demo" not in d["masked_content"]
    assert "matches" in run(["codeword", "verify", "Mango"], "amma").stdout
    assert "NOT match" in run(["codeword", "verify", "papaya"], "amma").stdout


def test_explain_trace(paired):
    res = run(["check", "url", "https://paytrn.com/kyc", "--explain", "--no-wait"], "amma")
    assert "Rule trace" in res.stdout and "URL-LOOKALIKE" in res.stdout


def test_emergency_stop_flow(paired, tmp_path):
    d = j(run(["check", "msg", "-f", str(ROOT / "samples" / "messages" / "cbi_call.txt"), "--no-wait", "--json"],
              "amma"))
    stop = j(run(["stop", "--reason", "CBI call", "--minutes-ago", "5", "--out", str(tmp_path), "--json"], "rohan"))
    assert stop["locked_cases"] == [d["case_id"]]
    assert Path(stop["files"]["json"]).exists() and Path(stop["files"]["markdown"]).exists()
    low = j(run(["check", "qr", str(ROOT / "samples" / "qr" / "shop.png"), "--json"], "amma"))
    assert low["case_state"] == "stopped" and "handoff" not in low
    ev = run(["evidence", d["case_id"]], "amma")
    assert "1930" in ev.stdout
    assert "unlocked" in run(["guardian", "unlock"], "rohan").stdout
    assert j(run(["check", "qr", str(ROOT / "samples" / "qr" / "shop.png"), "--json"], "amma"))["case_state"] == "allowed"


def test_trusted_payee(paired):
    run(["guardian", "set-limit", "1000"], "rohan")
    payload = "upi://pay?pa=pharmacy.demo@okaxis&pn=Pharmacy&am=1500"
    assert j(run(["check", "qr", "--payload", payload, "--no-wait", "--json"], "amma"))["verdict"]["risk_level"] == "medium"
    run(["payees", "add", "pharmacy.demo@okaxis", "--label", "Pharmacy"], "amma")
    assert "Pharmacy" in run(["payees", "list"], "amma").stdout
    assert j(run(["check", "qr", "--payload", payload, "--json"], "amma"))["verdict"]["risk_level"] == "low"


def test_chat_scan(paired):
    res = run(["check", "chat", str(ROOT / "samples" / "chats" / "family_chat.txt")], "amma")
    assert "2 of 5 messages" in res.stdout


def test_eval_command_json():
    d = j(run(["eval", "--json"]))
    assert d["recall"] >= 0.9 and d["specificity"] >= 0.9


def test_guardian_commands_need_guardian(paired):
    res = run(["guardian", "watch", "--once"], "amma")
    assert res.exit_code == 1 and "guardian" in res.stdout


def test_stats_and_audit(paired):
    assert "Decisions" in run(["guardian", "stats"], "rohan").stdout
    assert "guardian_joined" in run(["audit"], "amma").stdout
