"""Deterministic PII masking. Runs on the parent's laptop before anything is stored, logged or sent.

Detectors are validated where a checksum exists (Verhoeff for Aadhaar, Luhn for card numbers).
The token map stays in memory for the current run only and is never written to disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .checks import hash_vpa

# --- checksum validators ---------------------------------------------------------------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def aadhaar_valid(number: str) -> bool:
    return len(number) == 12 and number[0] not in "01" and verhoeff_valid(number)


# --- detectors -------------------------------------------------------------------------

_SEP_DIGITS = r"\d(?:[ \-]?\d)"
AADHAAR_RE = re.compile(r"(?<!\d)(\d{4}[ \-]?\d{4}[ \-]?\d{4})(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(\d(?:[ \-]?\d){12,18})(?!\d)")
PAN_RE = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b")
PHONE_RE = re.compile(r"(?<![\d+])((?:\+91[\-\s]?|0)?[6-9]\d{4}[\-\s]?\d{5})(?!\d)")
OTP_RE = re.compile(
    r"((?:otp|one[\s\-]time[\s\-]password|verification code|code|pin|पासवर्ड|ओटीपी|कोड|ಒಟಿಪಿ)"
    r"[^\d\n]{0,20})(\d{4,8})(?!\d)",
    re.IGNORECASE,
)
ACCOUNT_RE = re.compile(
    r"((?:a/c|a\/c|acct|account|ac no|account no|account number|खाता|ಖಾತೆ)[^\d\n]{0,15})(\d{9,18})(?!\d)",
    re.IGNORECASE,
)
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
VPA_RE = re.compile(r"(?<![\w.\-])([a-z0-9.\-_]{2,64})@([a-z][a-z0-9]{1,30})(?![\w@]|\.\w)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+\-]+@[\w\-]+\.[\w.\-]+\b")


@dataclass
class MaskResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)
    token_map: dict[str, str] = field(default_factory=dict, repr=False)  # in memory only

    def summary(self) -> str:
        if not self.counts:
            return "no personal details found"
        return ", ".join(f"{n} {k.lower()}" for k, n in sorted(self.counts.items()))


class Masker:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.token_map: dict[str, str] = {}
        self._seen: dict[tuple[str, str], str] = {}

    def _token(self, kind: str, raw: str, fmt: str | None = None) -> str:
        key = (kind, raw)
        if key in self._seen:
            return self._seen[key]
        self.counts[kind] = self.counts.get(kind, 0) + 1
        tok = fmt or f"<{kind}_{self.counts[kind]}>"
        self._seen[key] = tok
        self.token_map[tok] = raw
        return tok

    def mask(self, text: str) -> MaskResult:
        # Order matters: longer, checksum-validated numbers first.
        def sub_aadhaar(m: re.Match) -> str:
            digits = re.sub(r"\D", "", m.group(1))
            return self._token("AADHAAR", digits, "<AADHAAR>") if aadhaar_valid(digits) else m.group(0)

        def sub_card(m: re.Match) -> str:
            digits = re.sub(r"\D", "", m.group(1))
            if 13 <= len(digits) <= 19 and luhn_valid(digits):
                return self._token("CARD", digits, f"<CARD_LAST4:{digits[-4:]}>")
            return m.group(0)

        def sub_account(m: re.Match) -> str:
            return m.group(1) + self._token("ACCOUNT", m.group(2), "<ACCOUNT>")

        def sub_otp(m: re.Match) -> str:
            return m.group(1) + self._token("OTP", m.group(2), "<OTP>")

        def sub_phone(m: re.Match) -> str:
            digits = re.sub(r"\D", "", m.group(1))[-10:]
            return self._token("PHONE", digits)

        def sub_pan(m: re.Match) -> str:
            return self._token("PAN", m.group(1), "<PAN>")

        def sub_email(m: re.Match) -> str:
            return self._token("EMAIL", m.group(0))

        def sub_vpa(m: re.Match) -> str:
            vpa = m.group(0)
            # Local part replaced by a short hash (stable, so the report list still works); handle kept.
            return f"<UPI:{hash_vpa(vpa)[:8]}>@{m.group(2)}"

        t = text
        t = AADHAAR_RE.sub(sub_aadhaar, t)
        t = CARD_RE.sub(sub_card, t)
        t = ACCOUNT_RE.sub(sub_account, t)
        t = OTP_RE.sub(sub_otp, t)
        t = PAN_RE.sub(sub_pan, t)
        t = EMAIL_RE.sub(sub_email, t)
        t = VPA_RE.sub(sub_vpa_counted(self, sub_vpa), t)
        t = PHONE_RE.sub(sub_phone, t)
        return MaskResult(t, dict(self.counts), dict(self.token_map))


def sub_vpa_counted(masker: Masker, fn):
    def inner(m: re.Match) -> str:
        masker.counts["UPI_ID"] = masker.counts.get("UPI_ID", 0) + 1
        return fn(m)

    return inner


def mask_text(text: str) -> MaskResult:
    return Masker().mask(text)


def contains_unmasked_pii(text: str) -> list[str]:
    """Used by tests and the relay as a last line of defence: report anything that still looks like PII."""
    found = []
    for m in AADHAAR_RE.finditer(text):
        if aadhaar_valid(re.sub(r"\D", "", m.group(1))):
            found.append("AADHAAR")
    for m in CARD_RE.finditer(text):
        d = re.sub(r"\D", "", m.group(1))
        if 13 <= len(d) <= 19 and luhn_valid(d):
            found.append("CARD")
    if PHONE_RE.search(text):
        found.append("PHONE")
    if PAN_RE.search(text):
        found.append("PAN")
    if VPA_RE.search(text):
        found.append("UPI_ID")
    return found
