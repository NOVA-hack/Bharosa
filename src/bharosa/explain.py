"""Turn a verdict into plain words in English, Hindi or Kannada using fixed templates.

Templates are the default and the offline fallback. The optional LLM layer (bharosa.llm) may only
rephrase what these templates say; it never changes the risk level or the reasons.
"""

from __future__ import annotations

from .rules import load_pack
from .verdict import Verdict

LANGS = ("en", "hi", "kn")


def ui(key: str, lang: str = "en", **fmt) -> str:
    entry = load_pack("i18n")["ui"][key]
    text = entry.get(lang) or entry["en"]
    return text.format(**fmt) if fmt else text


def reason_text(rule_id: str, english_title: str, lang: str = "en") -> str:
    if lang == "en":
        return english_title
    entry = load_pack("i18n")["rules"].get(rule_id, {})
    return entry.get(lang) or english_title


def truth_card(card_id: str | None, lang: str = "en") -> dict | None:
    if not card_id:
        return None
    card = load_pack("truth_cards")["cards"].get(card_id)
    if not card:
        return None
    return {"id": card_id, "text": card.get(lang) or card["en"], "source": card["source"], "url": card["url"]}


def headline(v: Verdict, lang: str = "en") -> str:
    return ui(f"level_{v.risk_level}", lang)


def explain(v: Verdict, lang: str = "en", max_reasons: int = 5) -> dict:
    reasons = [
        {"rule_id": r.rule_id, "severity": r.severity, "text": reason_text(r.rule_id, r.title, lang),
         "evidence": r.evidence}
        for r in v.reasons if r.severity != "info"
    ][:max_reasons]
    cards, seen = [], set()
    for r in v.reasons:
        c = truth_card(r.truth_card, lang)
        if c and c["id"] not in seen:
            seen.add(c["id"])
            cards.append(c)
    return {
        "headline": headline(v, lang),
        "reasons": reasons,
        "truth_cards": cards,
        "disclaimer": ui("low_disclaimer", lang) if v.risk_level == "low" else ui("do_not_pay", lang),
    }


def voice_script(v: Verdict, lang: str = "en") -> str:
    """Short text for the spoken warning: headline, top reason, the one instruction that matters."""
    e = explain(v, lang, max_reasons=1)
    parts = [e["headline"] + "."]
    if e["reasons"]:
        parts.append(e["reasons"][0]["text"] + ".")
    if v.risk_level != "low":
        parts.append(ui("do_not_pay", lang))
    if e["truth_cards"]:
        parts.append(e["truth_cards"][0]["text"])
    return " ".join(parts)
