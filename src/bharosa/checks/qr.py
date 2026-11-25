"""inspect_upi_qr: parse a UPI QR payload and flag suspicious payment details."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..rules import load_pack, ruleset_version
from ..verdict import Reason, Verdict, make_verdict
from . import MAX_QR_PAYLOAD_BYTES, CheckContext, enforce_limit, hash_vpa

VPA_RE = re.compile(r"^[a-z0-9.\-_]{2,256}@[a-z][a-z0-9.\-]{1,64}$", re.IGNORECASE)


def _reason(rules: dict, rule_id: str, evidence: str = "") -> Reason:
    meta = rules[rule_id]
    return Reason(
        rule_id=rule_id,
        severity=meta["severity"],
        title=meta["title"],
        evidence=evidence,
        always_high=bool(meta.get("always_high", False)),
        truth_card=meta.get("truth_card"),
    )


def _contains_word(text: str, words: list[str]) -> str | None:
    low = text.lower()
    for w in words:
        w_low = w.lower()
        if w_low.isascii():
            if re.search(r"(?<![a-z0-9])" + re.escape(w_low) + r"(?![a-z0-9])", low):
                return w
        elif w_low in low:
            return w
    return None


def mask_vpa(vpa: str) -> str:
    """Display form of a UPI ID: first two characters of the local part, handle kept."""
    if "@" not in vpa:
        return "<UPI_ID>"
    local, handle = vpa.split("@", 1)
    return f"{local[:2]}***@{handle}"


def parse_upi(payload: str) -> dict:
    """Parse a ``upi://pay?...`` string into a dict of fields. Raises ValueError when not UPI."""
    payload = payload.strip()
    parts = urlsplit(payload)
    if parts.scheme.lower() != "upi":
        raise ValueError("not a upi:// URI")
    action = (parts.netloc or parts.path.strip("/")).lower()
    fields = {k.lower(): v for k, v in parse_qsl(parts.query, keep_blank_values=True)}
    fields["_action"] = action
    return fields


def inspect_upi_qr(payload: str, ctx: CheckContext | None = None) -> Verdict:
    ctx = ctx or CheckContext()
    enforce_limit(payload, MAX_QR_PAYLOAD_BYTES, "QR payload")
    pack = load_pack("qr")
    rules = pack["rules"]
    version = ruleset_version()
    reasons: list[Reason] = []

    try:
        f = parse_upi(payload)
    except ValueError:
        scheme = urlsplit(payload.strip()).scheme or "none"
        return make_verdict(
            "inspect_upi_qr",
            [_reason(rules, "QR-NOT-UPI", f"scheme: {scheme}")],
            version,
            {"parsed": False},
        )

    vpa = f.get("pa", "").strip()
    name = f.get("pn", "").strip()
    note = f.get("tn", "").strip()
    amount_raw = f.get("am", "").strip()
    currency = f.get("cu", "").strip()
    handle = vpa.split("@", 1)[1].lower() if "@" in vpa else ""

    problems = []
    if f["_action"] not in ("pay", "mandate", "collect"):
        problems.append(f"action '{f['_action']}'")
    if not vpa:
        problems.append("missing payee UPI ID (pa)")
    elif not VPA_RE.match(vpa):
        problems.append("payee UPI ID (pa) is not a valid format")
    amount = None
    if amount_raw:
        try:
            amount = float(amount_raw)
            if amount <= 0:
                problems.append("amount is zero or negative")
        except ValueError:
            problems.append("amount (am) is not a number")
    if problems:
        reasons.append(_reason(rules, "QR-MALFORMED", "; ".join(problems)))

    hit = _contains_word(note, pack["receive_money_words"]) if note else None
    if hit:
        reasons.append(_reason(rules, "QR-RECEIVE-MONEY", f"note says '{hit}'"))

    if handle and handle not in {h.lower() for h in pack["known_psp_handles"]}:
        reasons.append(_reason(rules, "QR-UNKNOWN-PSP", f"handle @{handle}"))

    auth = _contains_word(name, pack["authority_name_words"]) if name else None
    if auth:
        reasons.append(_reason(rules, "QR-AUTHORITY-NAME", f"payee name contains '{auth}'"))

    urgent = _contains_word(note, pack["urgent_words"]) if note else None
    if amount is not None and urgent:
        reasons.append(_reason(rules, "QR-AMOUNT-URGENT", f"amount {amount:g} with note '{urgent}'"))

    if currency and currency.upper() != "INR":
        reasons.append(_reason(rules, "QR-NON-INR", f"currency {currency}"))

    payee_hash = hash_vpa(vpa) if vpa else None
    trusted = payee_hash in ctx.trusted_payees if payee_hash else False
    if payee_hash and payee_hash in ctx.reported_payees:
        reasons.append(_reason(rules, "QR-REPORTED-PAYEE", mask_vpa(vpa)))
    elif payee_hash and not trusted and payee_hash not in ctx.known_payees:
        if amount is not None and amount > ctx.review_amount:
            reasons.append(
                _reason(rules, "QR-FIRST-PAYEE-HIGH-AMOUNT", f"amount {amount:g} > limit {ctx.review_amount:g}")
            )
        else:
            reasons.append(_reason(rules, "QR-FIRST-PAYEE", mask_vpa(vpa)))

    if amount is not None and amount >= ctx.large_amount and not trusted:
        reasons.append(_reason(rules, "QR-LARGE-AMOUNT", f"amount {amount:g}"))

    details = {
        "parsed": True,
        "payee_vpa_masked": mask_vpa(vpa) if vpa else None,
        "payee_handle": handle or None,
        "payee_hash": payee_hash,
        "payee_name": name or None,
        "amount": amount,
        "currency": currency or None,
        "note": note or None,
        "trusted_payee": trusted,
    }
    return make_verdict("inspect_upi_qr", reasons, version, details)
