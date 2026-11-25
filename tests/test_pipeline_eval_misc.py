from pathlib import Path

import pytest

from bharosa.chat import parse_chat
from bharosa.clipboard import worth_checking
from bharosa.evaluate import run_eval
from bharosa.pipeline import DirectRunner, check_message, check_qr, check_url
from bharosa.qrdecode import QRDecodeError, decode_image

ROOT = Path(__file__).resolve().parents[1]


def test_message_fans_out_to_url_and_upi_checks():
    r = check_message("Your KYC expired, account will be blocked. Update at http://sbi-kyc-update.xyz/login "
                      "or pay upi://pay?pa=kyc.desk.demo@fastpayx&am=10", DirectRunner())
    assert r.verdict.risk_level == "high"
    assert sorted(r.fanout) == ["inspect_upi_qr", "inspect_url"]
    tools = {v["tool"] for v in r.verdict.details["tools"]}
    assert tools == {"match_scam_playbook", "inspect_url", "inspect_upi_qr"}
    assert r.upi_uri and r.payee_masked == "ky***@fastpayx"


def test_bare_upi_id_in_message_is_masked_and_checked():
    r = check_message("Send to ravi.help.demo@ybl please", DirectRunner())
    assert "ravi.help.demo" not in r.masked_content
    assert r.payee_masked == "ra***@ybl"
    assert r.verdict.risk_level == "low"  # a bare UPI ID alone is not a warning sign


def test_check_results_never_store_raw_unless_asked():
    r = check_qr("upi://pay?pa=a.demo@ybl&pn=Ram", DirectRunner())
    assert r.case_payload()["raw_content"] is None
    assert r.case_payload(keep_raw=True)["raw_content"].startswith("upi://")
    assert "a.demo" not in r.masked_content


def test_url_check_result():
    r = check_url("https://paytrn.com/kyc", DirectRunner())
    assert r.verdict.risk_level == "high" and r.input_type == "url"


def test_eval_meets_targets():
    r = run_eval()
    assert r["n"] >= 40
    assert r["recall"] >= 0.9, r["misses"]
    assert r["specificity"] >= 0.9, r["misses"]
    assert sum(r["per_rule_hits"].values()) > 0


@pytest.mark.parametrize("name,expected", [("shop.png", "low"), ("milk.png", "low"), ("cashback.png", "high"),
                                           ("refund.png", "high"), ("not_upi.png", "high")])
def test_sample_qr_images_decode_and_score(name, expected):
    payload = decode_image(ROOT / "samples" / "qr" / name)
    assert check_qr(payload, DirectRunner()).verdict.risk_level == expected


def test_decode_errors(tmp_path):
    with pytest.raises(QRDecodeError):
        decode_image(tmp_path / "missing.png")
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image")
    with pytest.raises(QRDecodeError):
        decode_image(bad)


def test_parse_whatsapp_export():
    msgs = parse_chat((ROOT / "samples" / "chats" / "family_chat.txt").read_text(encoding="utf-8"))
    assert len(msgs) == 5  # media line dropped
    assert msgs[0].sender == "Rohan" and msgs[0].when.startswith("21/11/26")
    flagged = [m for m in msgs if check_message(m.text, DirectRunner()).verdict.risk_level != "low"]
    assert len(flagged) == 2


def test_parse_bracket_format_and_continuations():
    msgs = parse_chat("[12/03/2026, 22:15:03] Ann: first line\nsecond line\n[12/03/2026, 22:16:00] Bob: hi")
    assert msgs[0].text == "first line\nsecond line" and msgs[1].sender == "Bob"


def test_clipboard_filter():
    assert worth_checking("http://sbi-kyc.xyz")
    assert worth_checking("pay ravi.help.demo@ybl")
    assert not worth_checking("ok")
    assert not worth_checking("")


def test_voice_falls_back_to_text(monkeypatch):
    from bharosa.voice import speak

    r = speak("Stop. This looks like a scam.", "kn")
    assert r.engine == "text" and r.path is None and r.played is False


def test_llm_layer_is_off_without_key():
    from bharosa.llm import available, explain_with_llm
    from bharosa.verdict import make_verdict

    assert available() is False
    assert explain_with_llm(make_verdict("t", [], "v"), "hi") is None


def test_evidence_markdown_and_files(tmp_path, service, family):
    from bharosa.evidence import save_packet

    r = check_message("CBI officer: you are under digital arrest, do not tell anyone, pay now", DirectRunner())
    service.submit_case(family["parent"], r.case_payload())
    res = service.emergency_stop(family["parent"], "test")
    paths = save_packet(res["packet"], res["sha256"], tmp_path)
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "1930" in md and "cybercrime.gov.in" in md and res["sha256"] in md
    assert paths["json"].exists()
