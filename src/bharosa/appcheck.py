"""The check-and-route step behind the relay's ``POST /check`` (used by the Android app).

A phone cannot run the Python rule packs, so it sends what it scanned or was shared to the relay,
which runs the same deterministic checks as ``bharosa check`` and the chat bots. The raw input is
used in memory for the check only: the relay stores the masked case, exactly as when the CLI or a
bot submits one. The app keeps the raw ``upi://`` link on the phone and launches it itself.

For a paired parent the result is routed through the family queue:

* low risk -> case ``allowed``; the app may hand off to a UPI app (``action: proceed``)
* medium or high risk -> case ``held`` with an approval request; a guardian decides from the app or
  from a chat bot running against the same relay (``action: hold``)
* Emergency Stop on -> case ``stopped`` (``action: stop``)

Without a token (not paired yet) nothing is stored: low risk returns ``proceed`` and anything else
returns ``warn``, because there is no guardian to ask.
"""

from __future__ import annotations

import re
from typing import Any

from .checks import InputTooLarge
from .checks.qr import parse_upi
from .explain import LANGS, explain, ui
from .pipeline import CheckResult, DirectRunner, Runner, check_message, check_qr, check_url
from .service import ServiceError

KINDS = ("auto", "qr", "url", "msg")

_URL_ONLY = re.compile(r"^(https?://|www\.)\S+$", re.IGNORECASE)
_UPI_ONLY = re.compile(r"^upi://\S+$", re.IGNORECASE)


def detect_kind(content: str) -> str:
    text = content.strip()
    if _UPI_ONLY.match(text):
        return "qr"
    if _URL_ONLY.match(text):
        return "url"
    return "msg"


def run_check(content: str, kind: str, runner: Runner, context: dict | None) -> CheckResult:
    """Run the deterministic checks. Raises InputTooLarge for oversized input."""
    if kind == "auto":
        kind = detect_kind(content)
    text = content.strip()
    if kind == "qr":
        # A scanned QR that is not a upi:// link (a plain URL, say) is checked as what it is.
        if not _UPI_ONLY.match(text):
            kind = detect_kind(text)
        else:
            return check_qr(text, runner, context)
    if kind == "url":
        return check_url(text if "://" in text else "http://" + text, runner)
    return check_message(content, runner, context)


def _is_payment_link(uri: str | None) -> bool:
    if not uri:
        return False
    try:
        f = parse_upi(uri)
    except ValueError:
        return False
    return f.get("_action") == "pay" and bool(f.get("pa"))


def _verdict_view(result: CheckResult, lang: str) -> dict[str, Any]:
    v = result.verdict
    e = explain(v, lang)
    return {
        "case_id": result.case_id,
        "input_type": result.input_type,
        "risk_level": v.risk_level,
        "score": v.score,
        "ruleset_version": v.ruleset_version,
        "headline": e["headline"],
        "reasons": e["reasons"],
        "truth_cards": e["truth_cards"],
        "disclaimer": e["disclaimer"],
        "mask_summary": result.mask_summary,
        "payee_masked": result.payee_masked,
        "amount": result.amount,
        "is_payment": _is_payment_link(result.upi_uri) and result.input_type == "qr",
        "input_sha256": result.input_sha256,
        "ask_code_word": result.ask_code_word,
        "code_word_prompt": ui("code_word", lang) if result.ask_code_word else None,
    }


def check_for_app(service: Any, token: str | None, content: str, kind: str = "auto", lang: str = "en",
                  runner: Runner | None = None) -> dict[str, Any]:
    """Check ``content`` and, for a paired parent, put the case in the family queue.

    ``service`` is a :class:`bharosa.service.FamilyService` (or anything with the same methods).
    """
    lang = lang if lang in LANGS else "en"
    runner = runner or DirectRunner()
    user = service.whoami(token) if token else None
    is_parent = bool(user and user.get("role") == "parent")
    context = service.check_context(token) if is_parent else None
    try:
        result = run_check(content, kind if kind in KINDS else "auto", runner, context)
    except InputTooLarge as exc:
        raise ServiceError(str(exc)) from exc

    out = _verdict_view(result, lang)
    risky = result.verdict.is_risky
    if not is_parent:
        out.update(state="unpaired", action="warn" if risky else "proceed", approval=None,
                   message=None if not risky else ui("do_not_pay", lang))
        return out

    try:
        case = service.submit_case(token, result.case_payload(keep_raw=False))
        approval = None
        if case["state"] in ("checked", "held"):
            approval = service.request_approval(token, result.case_id)
    except ServiceError as exc:
        # The verdict matters more than the queue: always return it.
        out.update(state="not_queued", action="warn" if risky else "proceed", approval=None,
                   queue_error=str(exc), message=ui("do_not_pay", lang) if risky else None)
        return out

    state = case["state"]
    if approval and approval.get("case_state"):
        state = approval["case_state"]
    if state == "allowed":
        action, message = "proceed", None
    elif state == "stopped":
        action, message = "stop", ui("stopped", lang)
    else:
        action, message = "hold", ui("held", lang)
    out.update(state=state, action=action, message=message, approval=approval,
               guardians_notified=(approval or {}).get("guardians_notified"))
    return out
