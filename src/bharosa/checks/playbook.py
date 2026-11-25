"""match_scam_playbook: match (masked) message text against known coercion and scam patterns."""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from ..rules import load_pack, ruleset_version
from ..verdict import Reason, Verdict, make_verdict
from . import MAX_TEXT_BYTES, enforce_limit


def normalise_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = text.replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", text).strip().lower()


@lru_cache(maxsize=None)
def _compiled(version: str) -> dict[str, list[tuple[str, re.Pattern | None]]]:
    signals = load_pack("playbooks")["signals"]
    out: dict[str, list[tuple[str, re.Pattern | None]]] = {}
    for name, words in signals.items():
        items = []
        for w in words:
            w_low = normalise_text(str(w))
            if w_low.isascii() and re.search(r"[a-z0-9]", w_low):
                pre = r"(?<![a-z0-9])" if w_low[0].isalnum() else ""
                post = r"(?![a-z0-9])" if w_low[-1].isalnum() else ""
                pat = re.compile(pre + re.escape(w_low) + post)
                items.append((w_low, pat))
            else:
                items.append((w_low, None))  # substring match (Devanagari, Kannada, symbols)
        out[name] = items
    return out


def find_signals(text: str) -> dict[str, list[str]]:
    """Return {signal: [matched keywords]} for every signal present in the text."""
    norm = normalise_text(text)
    found: dict[str, list[str]] = {}
    for name, items in _compiled(load_pack("playbooks")["version"]).items():
        hits = []
        for word, pat in items:
            if (pat.search(norm) if pat else word in norm):
                hits.append(word)
        if hits:
            found[name] = sorted(set(hits))
    return found


def match_scam_playbook(text: str) -> Verdict:
    enforce_limit(text, MAX_TEXT_BYTES, "Message text")
    pack = load_pack("playbooks")
    version = ruleset_version()
    signals = find_signals(text)
    reasons: list[Reason] = []
    fired = []
    for pb_id, pb in pack["playbooks"].items():
        all_of = pb.get("all_of", [])
        any_of = pb.get("any_of", [])
        min_any = int(pb.get("min_any", 1 if any_of else 0))
        if not all(s in signals for s in all_of):
            continue
        present_any = [s for s in any_of if s in signals]
        if len(present_any) < min_any:
            continue
        used = all_of + present_any
        evidence = "; ".join(f"{s}: {', '.join(signals[s][:3])}" for s in used)
        reasons.append(
            Reason(
                rule_id=pb_id,
                severity=pb["severity"],
                title=pb["title"],
                evidence=evidence,
                always_high=bool(pb.get("always_high", False)),
                truth_card=pb.get("truth_card"),
            )
        )
        fired.append(pb_id)

    code_word = any(pack["playbooks"][p].get("code_word_prompt") for p in fired)
    details = {"signals": signals, "playbooks": fired, "ask_code_word": code_word}
    return make_verdict("match_scam_playbook", reasons, version, details)
