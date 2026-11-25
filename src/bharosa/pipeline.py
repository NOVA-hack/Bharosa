"""The parent-side check pipeline: validate, mask, call the check tools, combine the verdicts.

Check tools are reached through a *runner*: :class:`DirectRunner` imports the rules package, and
:class:`bharosa.mcp_client.McpRunner` calls the Bharosa MCP server over stdio. Both return the same
verdict dicts, so the CLI does not care which one it has.
"""

from __future__ import annotations

import hashlib
import uuid
from urllib.parse import unquote
from dataclasses import dataclass, field
from typing import Any, Protocol

from .checks import (MAX_QR_PAYLOAD_BYTES, MAX_TEXT_BYTES, MAX_URL_BYTES, CheckContext, enforce_limit,
                     hash_vpa)
from .checks.extract import extract_upi_uris, extract_urls, extract_vpas
from .checks.playbook import match_scam_playbook
from .checks.qr import inspect_upi_qr, mask_vpa
from .checks.url import inspect_url
from .masking import mask_text
from .rules import ruleset_version
from .verdict import Verdict, combine

MAX_FANOUT = 10  # links or UPI IDs checked per message


class Runner(Protocol):
    def inspect_upi_qr(self, payload: str, family_context: dict | None = None) -> dict: ...
    def inspect_url(self, url: str) -> dict: ...
    def match_scam_playbook(self, text: str) -> dict: ...


def context_from_dict(d: dict | None) -> CheckContext:
    if not d:
        return CheckContext()
    return CheckContext(
        known_payees=frozenset(d.get("known_payees", [])),
        trusted_payees=frozenset(d.get("trusted_payees", [])),
        reported_payees=frozenset(d.get("reported_payees", [])),
        review_amount=float(d.get("review_amount", 2000)),
    )


class DirectRunner:
    """Calls the deterministic checks in-process (fallback when the MCP server cannot start)."""

    name = "direct"

    def inspect_upi_qr(self, payload: str, family_context: dict | None = None) -> dict:
        return inspect_upi_qr(payload, context_from_dict(family_context)).to_dict()

    def inspect_url(self, url: str) -> dict:
        return inspect_url(url).to_dict()

    def match_scam_playbook(self, text: str) -> dict:
        return match_scam_playbook(mask_text(text).text).to_dict()

    def close(self) -> None:
        pass


@dataclass
class CheckResult:
    case_id: str
    input_type: str
    masked_content: str
    mask_summary: str
    input_sha256: str
    verdict: Verdict
    payee_hash: str | None = None
    payee_masked: str | None = None
    amount: float | None = None
    upi_uri: str | None = None  # raw upi:// link for the mock handoff (stays on this laptop)
    ask_code_word: bool = False
    fanout: list[str] = field(default_factory=list)
    raw_content: str | None = None

    def case_payload(self, keep_raw: bool = False) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "input_type": self.input_type,
            "masked_content": self.masked_content,
            "input_sha256": self.input_sha256,
            "raw_content": self.raw_content if keep_raw else None,
            "payee_hash": self.payee_hash,
            "payee_masked": self.payee_masked,
            "amount": self.amount,
            "verdict": self.verdict.to_dict(),
        }


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_case_id() -> str:
    return "case_" + uuid.uuid4().hex[:10]


def check_qr(payload: str, runner: Runner, family_context: dict | None = None) -> CheckResult:
    payload = payload.strip()
    enforce_limit(payload, MAX_QR_PAYLOAD_BYTES, "QR payload")
    v = Verdict.from_dict(runner.inspect_upi_qr(payload, family_context))
    d = v.details
    m = mask_text(unquote(payload))  # decoded so the guardian can read the note
    return CheckResult(
        case_id=new_case_id(),
        input_type="qr",
        masked_content=m.text,
        mask_summary=m.summary(),
        input_sha256=_sha(payload),
        verdict=v,
        payee_hash=d.get("payee_hash"),
        payee_masked=d.get("payee_vpa_masked"),
        amount=d.get("amount"),
        upi_uri=payload if d.get("parsed") else None,
        raw_content=payload,
    )


def check_url(url: str, runner: Runner) -> CheckResult:
    url = url.strip()
    enforce_limit(url, MAX_URL_BYTES, "URL")
    v = Verdict.from_dict(runner.inspect_url(url))
    m = mask_text(url)
    return CheckResult(new_case_id(), "url", m.text, m.summary(), _sha(url), v, raw_content=url)


def check_message(text: str, runner: Runner, family_context: dict | None = None,
                  input_type: str = "msg") -> CheckResult:
    enforce_limit(text, MAX_TEXT_BYTES, "Message text")
    m = mask_text(text)
    verdicts = [Verdict.from_dict(runner.match_scam_playbook(m.text))]
    fanout: list[str] = []
    payee_hash = payee_masked = upi_uri = None
    amount = None
    for uri in extract_upi_uris(text)[:MAX_FANOUT]:
        qv = Verdict.from_dict(runner.inspect_upi_qr(uri, family_context))
        verdicts.append(qv)
        fanout.append("inspect_upi_qr")
        payee_hash = payee_hash or qv.details.get("payee_hash")
        payee_masked = payee_masked or qv.details.get("payee_vpa_masked")
        amount = amount or qv.details.get("amount")
        upi_uri = upi_uri or uri
    for vpa in extract_vpas(text)[:MAX_FANOUT]:
        qv = Verdict.from_dict(runner.inspect_upi_qr(f"upi://pay?pa={vpa}", family_context))
        # A bare UPI ID in a message is not a payment request: keep only the payee-specific findings.
        qv.reasons = [r for r in qv.reasons if r.rule_id in ("QR-UNKNOWN-PSP", "QR-REPORTED-PAYEE")]
        from .verdict import make_verdict

        qv = make_verdict(qv.tool, qv.reasons, qv.ruleset_version, qv.details)
        verdicts.append(qv)
        fanout.append("inspect_upi_qr")
        payee_hash = payee_hash or hash_vpa(vpa)
        payee_masked = payee_masked or mask_vpa(vpa)
    for url in extract_urls(text)[:MAX_FANOUT]:
        verdicts.append(Verdict.from_dict(runner.inspect_url(url)))
        fanout.append("inspect_url")
    combined = combine(verdicts, ruleset_version())
    ask = bool(verdicts[0].details.get("ask_code_word"))
    return CheckResult(
        case_id=new_case_id(),
        input_type=input_type,
        masked_content=m.text,
        mask_summary=m.summary(),
        input_sha256=_sha(text),
        verdict=combined,
        payee_hash=payee_hash,
        payee_masked=payee_masked,
        amount=amount,
        upi_uri=upi_uri,
        ask_code_word=ask,
        fanout=fanout,
        raw_content=text,
    )
