"""The MCP server: in-process through the SDK client, and once over real stdio like the CLI uses it."""

import asyncio
import json

import pytest

from bharosa.mcp_server import TOOL_NAMES, build_server


def _result(res):
    sc = getattr(res, "structured_content", None)
    if isinstance(sc, dict):
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(res.content[0].text)


async def _call(tool, args):
    from mcp import Client

    async with Client(build_server()) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
        res = await client.call_tool(tool, args)
        return tools, res


def test_server_lists_all_six_tools():
    tools, _ = asyncio.run(_call("inspect_url", {"url": "https://www.npci.org.in/"}))
    assert sorted(tools) == sorted(TOOL_NAMES)


def test_check_tools_return_the_verdict_shape():
    _, res = asyncio.run(_call("inspect_url", {"url": "http://sbi-kyc-update.xyz/login"}))
    v = _result(res)
    assert set(v) >= {"tool", "risk_level", "score", "reasons", "ruleset_version", "details"}
    assert v["risk_level"] == "high"
    _, res = asyncio.run(_call("match_scam_playbook", {"text": "Share the OTP now. Call 9999900001"}))
    v = _result(res)
    assert v["risk_level"] == "high"
    assert "9999900001" not in json.dumps(v)  # the server masks raw text itself
    _, res = asyncio.run(_call("inspect_upi_qr", {"payload": "upi://pay?pa=a.demo@ybl&tn=receive%20refund"}))
    assert _result(res)["risk_level"] == "high"


def test_family_tools_explain_when_not_paired():
    _, res = asyncio.run(_call("get_case_status", {"case_id": "case_x"}))
    assert res.is_error
    assert "not paired" in res.content[0].text


def test_family_tools_with_local_profile(monkeypatch):
    from bharosa.backend import get_backend
    from bharosa.config import Profile, save_profile

    monkeypatch.setenv("BHAROSA_PROFILE", "amma")
    prof = Profile(name="amma")
    backend = get_backend(prof)
    p = backend.create_family("Amma")
    prof.role, prof.user_id, prof.family_id = "parent", p["user_id"], p["family_id"]
    prof.set_token(p["token"])
    save_profile(prof)
    backend.join_family(p["pair_code"], "Rohan")

    _, res = asyncio.run(_call("request_family_approval", {
        "case_id": "case_fromassistant1", "risk_level": "high",
        "masked_summary": "Caller claims CBI, asks to transfer money. Phone 9999900001",
        "reasons": [{"rule_id": "PB-DIGITAL-ARREST", "severity": "high", "title": "digital arrest"}]}))
    a = _result(res)
    assert a["status"] == "pending" and a["approval_id"]
    _, res = asyncio.run(_call("get_case_status", {"case_id": "case_fromassistant1"}))
    assert _result(res)["state"] == "held"
    case = backend.get_case(p["token"], "case_fromassistant1")
    assert "9999900001" not in case["masked_content"]
    _, res = asyncio.run(_call("emergency_stop", {"reason": "test"}))
    assert _result(res)["locked"] is True


def test_stdio_runner_matches_direct_runner():
    from bharosa.mcp_client import McpRunner
    from bharosa.pipeline import DirectRunner, check_message

    text = "Dear customer your KYC expired, account will be blocked today. Update http://sbi-kyc-update.xyz/login"
    with McpRunner() as runner:
        via_mcp = check_message(text, runner).verdict.to_dict()
    direct = check_message(text, DirectRunner()).verdict.to_dict()
    assert via_mcp == direct
