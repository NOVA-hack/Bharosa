from bharosa.explain import explain, truth_card, voice_script
from bharosa.rules import all_rule_ids, load_pack, rule_meta, ruleset_version
from bharosa.verdict import Reason, Verdict, combine, make_verdict, score_reasons


def r(rule_id, sev, always=False):
    return Reason(rule_id, sev, rule_id, always_high=always)


def test_scoring_thresholds():
    assert score_reasons([]) == (0, "low")
    assert score_reasons([r("a", "low"), r("b", "low")]) == (20, "low")
    assert score_reasons([r("a", "medium")]) == (30, "medium")
    assert score_reasons([r("a", "medium"), r("b", "low"), r("c", "low")]) == (50, "medium")
    assert score_reasons([r("a", "high")]) == (60, "high")
    assert score_reasons([r("a", "high"), r("b", "high")]) == (100, "high")  # capped
    assert score_reasons([r("a", "low", always=True)]) == (10, "high")


def test_make_verdict_is_order_independent_and_dedupes():
    a = make_verdict("t", [r("Z", "low"), r("A", "high"), r("A", "high")], "v")
    b = make_verdict("t", [r("A", "high"), r("Z", "low")], "v")
    assert [x.rule_id for x in a.reasons] == ["A", "Z"]
    assert a.to_dict() == b.to_dict()


def test_combine_highest_risk_wins():
    low = make_verdict("x", [r("L", "low")], "v")
    high = make_verdict("y", [r("H", "high")], "v")
    c = combine([low, high], "v")
    assert c.risk_level == "high" and {x.rule_id for x in c.reasons} == {"L", "H"}
    assert Verdict.from_dict(c.to_dict()).to_dict() == c.to_dict()


def test_every_rule_has_hindi_and_kannada_and_valid_truth_card():
    i18n = load_pack("i18n")["rules"]
    for rid in all_rule_ids():
        assert rid in i18n, rid
        assert i18n[rid].get("hi") and i18n[rid].get("kn"), rid
        meta = rule_meta(rid)
        assert meta["severity"] in ("high", "medium", "low")
        if meta.get("truth_card"):
            assert truth_card(meta["truth_card"], "kn"), meta["truth_card"]


def test_ui_strings_in_all_languages():
    for key, entry in load_pack("i18n")["ui"].items():
        for lang in ("en", "hi", "kn"):
            assert entry.get(lang), (key, lang)


def test_ruleset_version_is_stable():
    assert ruleset_version() == ruleset_version()
    assert ruleset_version().startswith("qr-")


def test_explain_low_says_no_known_signs_not_safe():
    v = make_verdict("t", [], "v")
    e = explain(v, "en")
    assert e["headline"] == "No known warning signs found"
    assert "does not prove" in e["disclaimer"]
    assert "safe" not in e["headline"].lower()


def test_voice_script_languages():
    v = make_verdict("t", [Reason("PB-OTP-REQUEST", "high", "x", always_high=True, truth_card="TC-OTP")], "v")
    assert "OTP" in voice_script(v, "en")
    assert "ओटीपी" in voice_script(v, "hi") or "OTP" in voice_script(v, "hi")
    assert any("ಀ" <= ch <= "೿" for ch in voice_script(v, "kn"))
