"""Bharosa MCP server (official Python MCP SDK, stdio transport).

Six tools. The three check tools are deterministic and never use the network. The family tools
talk to the local queue (or the relay, when the active profile is in relay mode).

Run: ``bharosa mcp`` (or ``python -m bharosa.mcp_server``). Register the same command in Claude
Desktop or Claude Code to let an assistant answer "is this safe?" from Bharosa's rule verdict.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import __version__
from .checks.playbook import match_scam_playbook as _match
from .checks.qr import inspect_upi_qr as _inspect_qr
from .checks.url import inspect_url as _inspect_url
from .config import load_profile
from .masking import mask_text
from .pipeline import context_from_dict
from .rules import ruleset_version
from .service import NotFound, ServiceError
from .verdict import Reason, make_verdict

INSTRUCTIONS = (
    "Bharosa checks UPI QR payloads, links and messages for scam patterns using fixed, deterministic rules. "
    "Report the risk_level and reasons the tools return; do not override them with your own judgement. "
    "A 'low' result means no known warning pattern was found, not that the content is proven safe. "
    "Never ask the user for an OTP, UPI PIN, Aadhaar or card number."
)


def _family_backend():
    from .backend import get_backend

    profile = load_profile()
    token = profile.get_token()
    if not token:
        raise ServiceError("this laptop is not paired with a family yet; run `bharosa pair` first")
    return get_backend(profile), token


def _local_context() -> dict | None:
    try:
        backend, token = _family_backend()
        return backend.check_context(token)
    except Exception:
        return None


def tool_inspect_upi_qr(payload: str, family_context: dict | None = None) -> dict:
    ctx = family_context if family_context is not None else _local_context()
    return _inspect_qr(payload, context_from_dict(ctx)).to_dict()


def tool_inspect_url(url: str) -> dict:
    return _inspect_url(url).to_dict()


def tool_match_scam_playbook(text: str) -> dict:
    # Mask again inside the server: an assistant may pass raw text. Masking is idempotent.
    return _match(mask_text(text).text).to_dict()


def tool_request_family_approval(case_id: str, risk_level: str, masked_summary: str,
                                 reasons: list[dict] | list[str] | None = None) -> dict:
    backend, token = _family_backend()
    try:
        return backend.request_approval(token, case_id)
    except NotFound:
        pass
    # The case was not checked through the CLI (e.g. it came from an assistant): record it first.
    masked = mask_text(masked_summary).text
    rs = []
    for r in reasons or []:
        if isinstance(r, str):
            rs.append(Reason(rule_id=r, severity="info", title=r))
        else:
            rs.append(Reason.from_dict({"severity": "info", "title": r.get("rule_id", "reason"), **r}))
    v = make_verdict("request_family_approval", rs, ruleset_version())
    v.risk_level = risk_level if risk_level in ("low", "medium", "high") else "medium"
    v.score = max(v.score, {"low": 0, "medium": 30, "high": 60}[v.risk_level])
    backend.submit_case(token, {
        "case_id": case_id,
        "input_type": "assistant",
        "masked_content": masked,
        "input_sha256": hashlib.sha256(masked.encode("utf-8")).hexdigest(),
        "verdict": v.to_dict(),
    })
    return backend.request_approval(token, case_id)


def tool_get_case_status(case_id: str) -> dict:
    backend, token = _family_backend()
    return backend.case_status(token, case_id)


def tool_emergency_stop(family_id: str | None = None, reason: str = "") -> dict:
    backend, token = _family_backend()
    me = backend.whoami(token)
    if family_id and family_id != me["family_id"]:
        raise ServiceError("this laptop can only stop its own family")
    out = backend.emergency_stop(token, reason)
    return {"locked": out["locked"], "locked_cases": out["locked_cases"],
            "packet_id": out["packet"]["packet_id"], "sha256": out["sha256"],
            "report_to": out["packet"]["report_to"]}


def build_server():
    try:
        from mcp.server.mcpserver import MCPServer as Server  # MCP SDK 2.x
    except ImportError:  # pragma: no cover - MCP SDK 1.x
        from mcp.server.fastmcp import FastMCP as Server  # type: ignore

    try:
        from mcp.server.mcpserver.exceptions import ToolError
    except ImportError:  # pragma: no cover
        from mcp.server.fastmcp.exceptions import ToolError  # type: ignore

    def safe(fn, *args):
        """Report expected failures (not paired, wrong state, input too large) to the assistant in words."""
        try:
            return fn(*args)
        except (ServiceError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    try:
        server = Server(name="bharosa", instructions=INSTRUCTIONS, version=__version__)
    except TypeError:  # pragma: no cover - older SDKs have no version argument
        server = Server(name="bharosa", instructions=INSTRUCTIONS)

    @server.tool()
    def inspect_upi_qr(payload: str, family_context: dict[str, Any] | None = None) -> dict:
        """Parse a raw UPI QR payload (upi://pay?...) and flag suspicious payment details.
        Returns {tool, risk_level, score, reasons[], ruleset_version, details}. Deterministic."""
        return safe(tool_inspect_upi_qr, payload, family_context)

    @server.tool()
    def inspect_url(url: str) -> dict:
        """Check a link for phishing indicators (lookalike brands, raw IPs, punycode, .apk ...).
        Never opens or fetches the URL. Deterministic."""
        return safe(tool_inspect_url, url)

    @server.tool()
    def match_scam_playbook(text: str) -> dict:
        """Match message text against scam playbooks (digital arrest, KYC expiry, electricity cut-off,
        parcel/customs, lottery/cashback, task job, relative in trouble, OTP or remote-app request).
        English, Hindi and Kannada. Personal details are masked before matching. Deterministic."""
        return safe(tool_match_scam_playbook, text)

    @server.tool()
    def request_family_approval(case_id: str, risk_level: str, masked_summary: str,
                                reasons: list[dict[str, Any]] | None = None) -> dict:
        """Hold a risky case and ask the linked family guardian to approve or block it.
        Returns {approval_id, status, expires_at}."""
        return safe(tool_request_family_approval, case_id, risk_level, masked_summary, reasons)

    @server.tool()
    def get_case_status(case_id: str) -> dict:
        """Return the current state of a case and its guardian decision, if any."""
        return safe(tool_get_case_status, case_id)

    @server.tool()
    def emergency_stop(family_id: str | None = None, reason: str = "") -> dict:
        """Emergency Stop: lock every pending case in Bharosa's own flow and build a redacted evidence
        packet. It cannot block payments inside other apps."""
        return safe(tool_emergency_stop, family_id, reason)

    return server


TOOL_NAMES = ["inspect_upi_qr", "inspect_url", "match_scam_playbook", "request_family_approval",
              "get_case_status", "emergency_stop"]


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
