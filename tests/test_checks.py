import pytest

from bharosa.checks import CheckContext, InputTooLarge, hash_vpa
from bharosa.checks.extract import extract_upi_uris, extract_urls, extract_vpas
from bharosa.checks.playbook import find_signals, match_scam_playbook
from bharosa.checks.qr import inspect_upi_qr, mask_vpa, parse_upi
from bharosa.checks.url import inspect_url, levenshtein, split_host


def ids(v):
    return {r.rule_id for r in v.reasons}


# ---------------- QR ----------------

SHOP = "upi://pay?pa=sharmagrocery.demo@okaxis&pn=Sharma%20Grocery&am=240&cu=INR"


def test_parse_upi_fields():
    f = parse_upi(SHOP)
    assert f["pa"] == "sharmagrocery.demo@okaxis" and f["pn"] == "Sharma Grocery" and f["am"] == "240"


def test_clean_shop_qr_is_low():
    v = inspect_upi_qr(SHOP)
    assert v.risk_level == "low"
    assert ids(v) == {"QR-FIRST-PAYEE"}
    assert v.details["payee_vpa_masked"] == "sh***@okaxis"


def test_known_payee_has_no_first_payee_reason():
    ctx = CheckContext(known_payees=frozenset({hash_vpa("sharmagrocery.demo@okaxis")}))
    v = inspect_upi_qr(SHOP, ctx)
    assert v.reasons == [] and v.risk_level == "low"


def test_receive_money_note_is_always_high():
    v = inspect_upi_qr("upi://pay?pa=a.demo@ybl&pn=Ram&am=10&tn=receive%20cashback")
    assert "QR-RECEIVE-MONEY" in ids(v) and v.risk_level == "high"


def test_hindi_refund_note():
    v = inspect_upi_qr("upi://pay?pa=a.demo@ybl&pn=Ram&tn=" + "रिफंड")
    assert "QR-RECEIVE-MONEY" in ids(v)


def test_non_upi_and_malformed():
    assert ids(inspect_upi_qr("https://bit.ly/x")) == {"QR-NOT-UPI"}
    v = inspect_upi_qr("upi://pay?pn=Nobody&am=abc")
    assert "QR-MALFORMED" in ids(v) and v.risk_level == "medium"


def test_unknown_psp_authority_name_and_currency():
    v = inspect_upi_qr("upi://pay?pa=x.demo@fastpayx&pn=Customer%20Care&cu=USD")
    assert {"QR-UNKNOWN-PSP", "QR-AUTHORITY-NAME", "QR-NON-INR"} <= ids(v)


def test_reported_payee_is_high():
    ctx = CheckContext(reported_payees=frozenset({hash_vpa("bad.demo@ybl")}))
    v = inspect_upi_qr("upi://pay?pa=bad.demo@ybl&pn=Ram", ctx)
    assert "QR-REPORTED-PAYEE" in ids(v) and v.risk_level == "high"


def test_first_payee_above_review_limit_goes_to_review_but_trusted_passes():
    payload = "upi://pay?pa=rent.demo@oksbi&pn=Landlord&am=15000"
    assert inspect_upi_qr(payload).risk_level == "medium"
    trusted = CheckContext(trusted_payees=frozenset({hash_vpa("rent.demo@oksbi")}))
    v = inspect_upi_qr(payload, trusted)
    assert v.risk_level == "low" and v.details["trusted_payee"] is True


def test_trusted_payee_does_not_hide_scam_note():
    trusted = CheckContext(trusted_payees=frozenset({hash_vpa("rent.demo@oksbi")}))
    v = inspect_upi_qr("upi://pay?pa=rent.demo@oksbi&tn=claim%20your%20prize", trusted)
    assert v.risk_level == "high"


def test_amount_with_urgent_note():
    v = inspect_upi_qr("upi://pay?pa=x.demo@ybl&pn=Ram&am=500&tn=pay%20immediately%20or%20penalty")
    assert "QR-AMOUNT-URGENT" in ids(v)


def test_qr_payload_limit():
    with pytest.raises(InputTooLarge):
        inspect_upi_qr("upi://pay?pa=a@ybl&tn=" + "x" * 3000)


def test_qr_determinism():
    p = "upi://pay?pa=rewards.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback"
    assert inspect_upi_qr(p).to_dict() == inspect_upi_qr(p).to_dict()


def test_mask_vpa():
    assert mask_vpa("ramesh.k@oksbi") == "ra***@oksbi"


# ---------------- URL ----------------

@pytest.mark.parametrize("url", [
    "https://www.onlinesbi.sbi/", "https://www.npci.org.in/", "https://www.amazon.in/deals",
    "https://cybercrime.gov.in/", "https://pay.google.com/", "https://www.irctc.co.in/nget",
])
def test_official_urls_are_low(url):
    v = inspect_url(url)
    assert v.risk_level == "low", (url, ids(v))
    assert v.details["fetched"] is False


@pytest.mark.parametrize("url,rule", [
    ("http://192.168.10.5/login", "URL-RAW-IP"),
    ("http://3232235777/login", "URL-RAW-IP"),
    ("https://paytrn.com/", "URL-LOOKALIKE"),
    ("https://hdfcbamk.com/", "URL-LOOKALIKE"),
    ("https://icic1bank.com/", "URL-LOOKALIKE"),
    ("https://xn--pytm-6za.com/", "URL-PUNYCODE"),
    ("https://sbi-rewards.xyz/", "URL-RISKY-TLD"),
    ("https://sbi-rewards.xyz/", "URL-BRAND-IN-DOMAIN"),
    ("https://www.icicibank.com@evil.top/", "URL-AT-SIGN"),
    ("https://bit.ly/abc", "URL-SHORTENER"),
    ("http://example.org/kyc/verify", "URL-HTTP-LOGIN"),
    ("https://example.org/app/Bill.apk", "URL-APK"),
    ("https://update-kyc-now.in/", "URL-LURE-KEYWORD"),
    ("https://example.org:8443/", "URL-NONSTANDARD-PORT"),
])
def test_url_rules(url, rule):
    assert rule in ids(inspect_url(url)), (url, ids(inspect_url(url)))


def test_mixed_script_cyrillic_is_high():
    v = inspect_url("https://рaytm.com/")  # Cyrillic er + Latin letters
    assert {"URL-PUNYCODE", "URL-MIXED-SCRIPT"} <= ids(v)
    assert v.risk_level == "high"


def test_scheme_less_url_does_not_trigger_http_rule():
    assert "URL-HTTP-LOGIN" not in ids(inspect_url("example.org/login"))


def test_short_brand_names_do_not_false_positive():
    assert inspect_url("https://abi.com/").risk_level == "low"
    assert inspect_url("https://www.thehindu.com/news").risk_level == "low"


def test_split_host_multi_part_suffix():
    assert split_host("www.sbi.co.in", ["co.in"]) == ("sbi.co.in", "co.in", ["www"])
    assert split_host("a.b.example.com", ["co.in"]) == ("example.com", "com", ["a", "b"])


def test_levenshtein():
    assert levenshtein("paytm", "paytrn") == 2
    assert levenshtein("abc", "abc") == 0


# ---------------- playbooks ----------------

def test_digital_arrest_english():
    v = match_scam_playbook("This is CBI. You are under digital arrest for money laundering. "
                            "Do not tell anyone and transfer Rs 50000 now.")
    assert "PB-DIGITAL-ARREST" in ids(v) and v.risk_level == "high"


def test_digital_arrest_hindi_and_kannada():
    hi = match_scam_playbook("मैं सीबीआई अधिकारी हूँ। आपको गिरफ्तार किया जाएगा। किसी को मत बताना।")
    kn = match_scam_playbook("ನಾನು ಪೊಲೀಸ್ ಅಧಿಕಾರಿ. ನಿಮ್ಮನ್ನು ಬಂಧನ ಮಾಡಲಾಗುವುದು. ಯಾರಿಗೂ ಹೇಳಬೇಡಿ.")
    assert "PB-DIGITAL-ARREST" in ids(hi)
    assert "PB-DIGITAL-ARREST" in ids(kn)


def test_single_keyword_does_not_fire():
    assert match_scam_playbook("The police station is near the temple.").risk_level == "low"
    assert match_scam_playbook("Please pay the milk bill today.").risk_level == "low"


def test_relative_in_trouble_asks_for_code_word():
    v = match_scam_playbook("Mummy I had an accident, I am in hospital, please send money")
    assert "PB-RELATIVE-IN-TROUBLE" in ids(v)
    assert v.details["ask_code_word"] is True


def test_otp_request_always_high():
    v = match_scam_playbook("Please share the OTP you received")
    assert v.risk_level == "high"


def test_rs_amount_with_digits_is_payment_signal():
    assert "payment" in find_signals("send rs.5000 now")


def test_message_limit():
    with pytest.raises(InputTooLarge):
        match_scam_playbook("a" * 5000)


# ---------------- extraction ----------------

def test_extraction():
    text = ("Pay at upi://pay?pa=x.demo@ybl&am=5 or to ravi.help.demo@ybl, see http://sbi-kyc.xyz/login "
            "and www.example.org. Mail me at a.person@gmail.com")
    assert extract_upi_uris(text) == ["upi://pay?pa=x.demo@ybl&am=5"]
    assert extract_vpas(text) == ["ravi.help.demo@ybl"]
    urls = extract_urls(text)
    assert "http://sbi-kyc.xyz/login" in urls and "www.example.org" in urls
    assert not any("gmail" in u for u in urls)
