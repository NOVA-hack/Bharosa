"""Deterministic checks. Pure functions: same input + same context + same ruleset = same verdict."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Fixed salt so the same payee hashes the same way on every family's laptop. This allows
# "flagged by other families" style sharing of hashes without sharing the UPI ID itself.
PAYEE_HASH_SALT = "bharosa-payee-v1:"

MAX_TEXT_BYTES = 4 * 1024
MAX_QR_PAYLOAD_BYTES = 2 * 1024
MAX_URL_BYTES = 2 * 1024


def hash_vpa(vpa: str) -> str:
    return hashlib.sha256((PAYEE_HASH_SALT + vpa.strip().lower()).encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class CheckContext:
    """Family-specific facts a check may use. Defaults describe a family with no history."""

    known_payees: frozenset[str] = field(default_factory=frozenset)  # hashes of payees paid before
    trusted_payees: frozenset[str] = field(default_factory=frozenset)  # hashes on the Trusted Payee list
    reported_payees: frozenset[str] = field(default_factory=frozenset)  # hashes blocked or reported
    review_amount: float = 2000.0  # first-time payee above this goes to review
    large_amount: float = 50000.0


class InputTooLarge(ValueError):
    pass


def enforce_limit(value: str, limit: int, what: str) -> None:
    if len(value.encode("utf-8")) > limit:
        raise InputTooLarge(f"{what} is larger than the {limit // 1024} KB limit")
