"""The `bharosa` command line.

Parent commands: check qr|url|msg|chat, pair, stop, evidence, payees, codeword, watch clipboard.
Guardian commands: pair --join, guardian watch|show|approve|block|unlock|set-code-word|set-limit|stats.
Tools: eval, mcp, relay, voice, config.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.text import Text

from . import __version__
from .backend import get_backend
from .checks import InputTooLarge, hash_vpa
from .checks.qr import mask_vpa
from .config import Profile, evidence_dir, load_profile, save_profile
from .evidence import save_packet, to_markdown, upload_to_s3
from .explain import LANGS, explain, ui, voice_script
from .pipeline import CheckResult, DirectRunner, check_message, check_qr, check_url
from .service import ServiceError
from .ui import cases_table, console, cooloff_panel, rule_trace_table, ts, verdict_panel

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # Hindi and Kannada output on Windows consoles
    except Exception:
        pass

app = typer.Typer(help="Bharosa: a family safety layer for suspicious UPI QR codes, links and scam messages.",
                  no_args_is_help=True, add_completion=False, pretty_exceptions_enable=False)
check_app = typer.Typer(help="Check a QR code, link, message or exported chat.", no_args_is_help=True)
guardian_app = typer.Typer(help="Guardian commands: watch the queue and decide held cases.", no_args_is_help=True)
payees_app = typer.Typer(help="Trusted Payee list (pharmacy, milk, rent...).", no_args_is_help=True)
voice_app = typer.Typer(help="Voice warnings.", no_args_is_help=True)
config_app = typer.Typer(help="Show or change this profile's settings.", no_args_is_help=True)
watch_app = typer.Typer(help="Watch the clipboard for links and UPI IDs.", no_args_is_help=True)
codeword_app = typer.Typer(help="Family code word.", no_args_is_help=True)
app.add_typer(check_app, name="check")
app.add_typer(guardian_app, name="guardian")
app.add_typer(payees_app, name="payees")
app.add_typer(voice_app, name="voice")
app.add_typer(config_app, name="config")
app.add_typer(watch_app, name="watch")
app.add_typer(codeword_app, name="codeword")

out = console()

LangOpt = typer.Option(None, "--lang", "-l", help="en, hi or kn (default: profile language)")
JsonOpt = typer.Option(False, "--json", help="Machine-readable output")
VoiceOpt = typer.Option(False, "--voice", help="Play the spoken warning")


# ---------------------------------------------------------------------------------------------
# helpers


def _lang(lang: str | None, profile: Profile) -> str:
    lang = (lang or profile.language or "en").lower()
    if lang not in LANGS:
        raise typer.BadParameter("language must be en, hi or kn")
    return lang


def _fail(msg: str, code: int = 1, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps({"error": msg}))
    else:
        out.print(f"[bold red]Error:[/] {msg}")
    raise typer.Exit(code)


def _runner(direct: bool):
    """MCP server over stdio by default; in-process rules when --direct or BHAROSA_DIRECT=1."""
    if direct or os.environ.get("BHAROSA_DIRECT") == "1":
        return DirectRunner()
    try:
        from .mcp_client import McpRunner

        return McpRunner()
    except Exception as exc:  # fallback keeps the demo alive
        out.print(f"[dim]MCP server unavailable ({exc}); using the rules package directly.[/]")
        return DirectRunner()


def _family(profile: Profile):
    if not profile.paired:
        return None, None
    return get_backend(profile), profile.get_token()


def _require_family(profile: Profile, role: str | None = None, as_json: bool = False):
    backend, token = _family(profile)
    if not backend:
        _fail("this profile is not paired with a family yet. Run `bharosa pair` (parent) or "
              "`bharosa pair --join CODE` (guardian).", as_json=as_json)
    if role and profile.role != role:
        _fail(f"this command is for the {role}; this profile is the {profile.role}.", as_json=as_json)
    return backend, token


def _print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _resolve_case_id(backend, token, case_id: str) -> str:
    if case_id.startswith("case_") and len(case_id) >= 15:
        return case_id
    matches = [c["id"] for c in backend.list_cases(token, None, 200) if c["id"].startswith(case_id)
               or c["id"].endswith(case_id)]
    if len(matches) == 1:
        return matches[0]
    raise ServiceError("case id not found" if not matches else "that short id matches more than one case")


def _mock_handoff(result: CheckResult, as_json: bool) -> dict:
    info = {"handoff": "mock", "executed": False}
    if result.upi_uri:
        info["upi_link"] = result.upi_uri
    if as_json:
        return info
    out.print("\n[bold green]Mock handoff[/]: Bharosa never makes the payment. Open your own UPI app to pay.")
    if result.upi_uri:
        out.print(f"Payment link (not executed): [cyan]{result.upi_uri}[/]")
        try:
            import io

            import qrcode

            q = qrcode.QRCode(border=1)
            q.add_data(result.upi_uri)
            buf = io.StringIO()
            q.print_ascii(out=buf, invert=True)
            out.print(buf.getvalue(), highlight=False)
            out.print("[dim]Scan this QR with your real UPI app if you choose to pay.[/]")
        except Exception:
            pass
    return info


def _speak(v, lang: str, enabled: bool, as_json: bool) -> dict | None:
    if not enabled:
        return None
    from .voice import speak

    script = voice_script(v, lang)
    res = speak(script, lang, play_audio=True)
    if not as_json:
        if res.engine == "text":
            out.print(f"[dim]Voice: no speech engine found, warning text:[/] {script}")
        else:
            out.print(f"[dim]Voice warning played with {res.engine}{' (cached)' if res.cached else ''}.[/]")
    return {"engine": res.engine, "played": res.played, "cached": res.cached, "text": script}


def _wait_for_decision(backend, token, case_id: str, family: dict, lang: str, cooloff: int, high: bool,
                       timeout: int, as_json: bool) -> dict:
    from rich.live import Live

    guardians = family.get("guardians") or []
    g = guardians[0] if guardians else {}
    script = ui("cooloff", lang, guardian=g.get("display_name") or "your family")
    start = time.time()
    status = backend.case_status(token, case_id)
    if as_json:
        while status["state"] == "held" and time.time() - start < timeout:
            time.sleep(1)
            status = backend.case_status(token, case_id)
        return status
    try:
        with Live(console=out, refresh_per_second=2, transient=False) as live:
            while True:
                status = backend.case_status(token, case_id)
                remaining = max(0, cooloff - (time.time() - start)) if high else 0
                label = {"held": "waiting for a decision"}.get(status["state"], status["state"])
                if high:
                    live.update(cooloff_panel(remaining, script, label, g.get("display_name"), g.get("phone")))
                else:
                    live.update(Text(f"Waiting for {g.get('display_name') or 'your family'} to review... "
                                     f"({int(time.time() - start)}s, Ctrl+C to stop waiting)", style="yellow"))
                if status["state"] != "held" or time.time() - start > timeout:
                    break
                time.sleep(1)
    except KeyboardInterrupt:
        out.print("[yellow]Stopped waiting. The payment stays paused until your family decides.[/]")
    return status


def _report_decision(status: dict, lang: str, result: CheckResult, backend, token, as_json: bool) -> dict:
    state = status["state"]
    info: dict = {"final_state": state}
    if state == "approved":
        if not as_json:
            out.print(f"\n[bold green]{ui('approved', lang)}[/]")
        backend.record_handoff(token, result.case_id)
        info.update(_mock_handoff(result, as_json))
    elif state == "blocked":
        if not as_json:
            out.print(f"\n[bold red]{ui('blocked', lang)}[/]")
            note = (status.get("approval") or {}).get("note")
            if note:
                out.print(f"Note from your family: {note}")
    elif state == "stopped":
        if not as_json:
            out.print(f"\n[bold red]{ui('stopped', lang)}[/]")
    elif state == "expired":
        if not as_json:
            out.print(f"\n[magenta]{ui('expired', lang)}[/]")
    return info


def _run_check(result: CheckResult, *, lang: str, voice: bool, as_json: bool, explain_trace: bool,
               wait: bool, keep_raw: bool, cooloff: int, timeout: int, llm: bool, title: str) -> None:
    profile = load_profile()
    v = result.verdict
    payload: dict = {"case_id": result.case_id, "input_type": result.input_type,
                     "masked_content": result.masked_content, "pii_masked": result.mask_summary,
                     "verdict": v.to_dict(), "explanation": explain(v, lang)}
    extra = []
    if llm:
        from .llm import explain_with_llm

        text = explain_with_llm(v, lang)
        payload["llm_explanation"] = text
        if text:
            extra = [Text(""), Text("In plain words: ", style="bold").append(Text(text, style=""))]
    if result.ask_code_word:
        extra += [Text(""), Text(ui("code_word", lang), style="bold magenta")]
        payload["ask_code_word"] = True

    if not as_json:
        out.print(verdict_panel(v, lang, title=title, explain_trace=explain_trace, extra=extra))
        out.print(f"[dim]Case {result.case_id} · personal details masked: {result.mask_summary}[/]")
    payload["voice"] = _speak(v, lang, voice, as_json)

    backend, token = _family(profile)
    if not backend or profile.role != "parent":
        payload["family_review"] = "not paired"
        if v.risk_level == "low":
            payload.update(_mock_handoff(result, as_json))
        elif not as_json:
            out.print("[yellow]This laptop is not paired with family, so nobody was asked to review. "
                      "Do not pay. Run `bharosa pair` to set up family review.[/]")
        if as_json:
            _print_json(payload)
        return

    case = backend.submit_case(token, result.case_payload(keep_raw))
    payload["case_state"] = case["state"]
    if case["state"] == "stopped":
        if not as_json:
            out.print(f"[bold red]{ui('stopped', lang)}[/]")
    elif case["state"] == "allowed":
        backend.record_handoff(token, result.case_id)
        payload.update(_mock_handoff(result, as_json))
    else:
        approval = backend.request_approval(token, result.case_id)
        payload["approval"] = approval
        payload["case_state"] = approval.get("case_state", "held")
        family = backend.family_info(token)
        if not as_json:
            out.print(f"\n[bold yellow]{ui('held', lang)}[/]")
            if approval.get("guardians_notified") == 0:
                out.print("[yellow]No guardian has joined yet. Share a pairing code with `bharosa pair --new-code`.[/]")
        if wait and approval["status"] == "pending":
            status = _wait_for_decision(backend, token, result.case_id, family, lang, cooloff,
                                        v.risk_level == "high", timeout, as_json)
            payload.update(_report_decision(status, lang, result, backend, token, as_json))
        elif not as_json:
            out.print(f"[dim]Check the decision later with: bharosa status {result.case_id}[/]")
    if as_json:
        _print_json(payload)


# ---------------------------------------------------------------------------------------------
# check


@check_app.command("qr")
def check_qr_cmd(
    image: Optional[Path] = typer.Argument(None, help="QR image file (png/jpg)"),
    payload: Optional[str] = typer.Option(None, "--payload", "-p", help="Raw upi:// string instead of an image"),
    camera: bool = typer.Option(False, "--camera", help="Scan with the webcam"),
    lang: Optional[str] = LangOpt, voice: bool = VoiceOpt, as_json: bool = JsonOpt,
    explain_trace: bool = typer.Option(False, "--explain", help="Print the full rule trace"),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for the guardian's decision"),
    keep_raw: bool = typer.Option(False, "--keep-raw", help="Also store the raw input locally (consent)"),
    cooloff: int = typer.Option(600, "--cooloff", help="Cool-off clock seconds for high risk"),
    timeout: int = typer.Option(1800, "--timeout", help="Stop waiting after this many seconds"),
    direct: bool = typer.Option(False, "--direct", help="Skip the MCP server and call the rules directly"),
    llm: bool = typer.Option(False, "--llm", help="Add an LLM explanation (needs ANTHROPIC_API_KEY)"),
) -> None:
    """Decode and inspect a UPI QR code."""
    from .qrdecode import QRDecodeError, decode_camera, decode_image

    profile = load_profile()
    lg = _lang(lang, profile)
    try:
        if payload:
            raw = payload
        elif camera:
            raw = decode_camera()
        elif image:
            raw = decode_image(image)
        else:
            _fail("give a QR image, --payload or --camera", as_json=as_json)
            return
    except QRDecodeError as exc:
        _fail(str(exc), as_json=as_json)
        return
    runner = _runner(direct)
    try:
        fam_ctx = _context(profile)
        result = check_qr(raw, runner, fam_ctx)
        _run_check(result, lang=lg, voice=voice, as_json=as_json, explain_trace=explain_trace, wait=wait,
                   keep_raw=keep_raw, cooloff=cooloff, timeout=timeout, llm=llm, title="Bharosa · QR check")
    except (InputTooLarge, ServiceError) as exc:
        _fail(str(exc), as_json=as_json)
    finally:
        runner.close()


def _context(profile: Profile) -> dict | None:
    backend, token = _family(profile)
    if not backend:
        return None
    try:
        return backend.check_context(token)
    except ServiceError:
        return None


@check_app.command("url")
def check_url_cmd(
    url: str = typer.Argument(..., help="The link (it is never opened)"),
    lang: Optional[str] = LangOpt, voice: bool = VoiceOpt, as_json: bool = JsonOpt,
    explain_trace: bool = typer.Option(False, "--explain"),
    wait: bool = typer.Option(True, "--wait/--no-wait"),
    keep_raw: bool = typer.Option(False, "--keep-raw"),
    cooloff: int = typer.Option(600, "--cooloff"),
    timeout: int = typer.Option(1800, "--timeout"),
    direct: bool = typer.Option(False, "--direct"),
    llm: bool = typer.Option(False, "--llm"),
) -> None:
    """Inspect a link without opening it."""
    profile = load_profile()
    lg = _lang(lang, profile)
    runner = _runner(direct)
    try:
        result = check_url(url, runner)
        _run_check(result, lang=lg, voice=voice, as_json=as_json, explain_trace=explain_trace, wait=wait,
                   keep_raw=keep_raw, cooloff=cooloff, timeout=timeout, llm=llm, title="Bharosa · link check")
    except (InputTooLarge, ServiceError) as exc:
        _fail(str(exc), as_json=as_json)
    finally:
        runner.close()


@check_app.command("msg")
def check_msg_cmd(
    text: Optional[str] = typer.Argument(None, help="Message text (or use -f)"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read the message from a file"),
    lang: Optional[str] = LangOpt, voice: bool = VoiceOpt, as_json: bool = JsonOpt,
    explain_trace: bool = typer.Option(False, "--explain"),
    wait: bool = typer.Option(True, "--wait/--no-wait"),
    keep_raw: bool = typer.Option(False, "--keep-raw"),
    cooloff: int = typer.Option(600, "--cooloff"),
    timeout: int = typer.Option(1800, "--timeout"),
    direct: bool = typer.Option(False, "--direct"),
    llm: bool = typer.Option(False, "--llm"),
) -> None:
    """Match a message against scam playbooks; links and UPI IDs inside it are checked too."""
    profile = load_profile()
    lg = _lang(lang, profile)
    if file:
        text = file.read_text(encoding="utf-8")
    elif text == "-":
        text = sys.stdin.read()
    if not text:
        _fail("give the message text or --file", as_json=as_json)
    runner = _runner(direct)
    try:
        result = check_message(text, runner, _context(profile))
        _run_check(result, lang=lg, voice=voice, as_json=as_json, explain_trace=explain_trace, wait=wait,
                   keep_raw=keep_raw, cooloff=cooloff, timeout=timeout, llm=llm, title="Bharosa · message check")
    except (InputTooLarge, ServiceError) as exc:
        _fail(str(exc), as_json=as_json)
    finally:
        runner.close()


@check_app.command("chat")
def check_chat_cmd(
    file: Path = typer.Argument(..., help="Exported chat .txt (WhatsApp: Export chat, without media)"),
    lang: Optional[str] = LangOpt, as_json: bool = JsonOpt,
    hold: bool = typer.Option(True, "--hold/--no-hold", help="Send the riskiest message for family review"),
    direct: bool = typer.Option(False, "--direct"),
) -> None:
    """Scan a whole exported chat and list the messages with warning signs."""
    from .chat import parse_chat

    profile = load_profile()
    lg = _lang(lang, profile)
    msgs = parse_chat(file.read_text(encoding="utf-8", errors="replace"))
    runner = _runner(direct)
    rows = []
    worst: CheckResult | None = None
    order = {"low": 0, "medium": 1, "high": 2}
    try:
        ctx = _context(profile)
        for m in msgs:
            try:
                r = check_message(m.text[:4000], runner, ctx, input_type="chat")
            except InputTooLarge:
                continue
            rows.append((m, r))
            if worst is None or (order[r.verdict.risk_level], r.verdict.score) > \
                    (order[worst.verdict.risk_level], worst.verdict.score):
                worst = r
    finally:
        runner.close()
    flagged = [(m, r) for m, r in rows if r.verdict.risk_level != "low"]
    if as_json:
        _print_json({"messages": len(rows), "flagged": [
            {"index": m.index, "when": m.when, "sender_masked": m.sender[:1] + "***" if m.sender else "",
             "masked_text": r.masked_content, "risk_level": r.verdict.risk_level,
             "rules": [x.rule_id for x in r.verdict.reasons]} for m, r in flagged]})
    else:
        from rich.table import Table

        t = Table(title=f"Chat scan: {len(flagged)} of {len(rows)} messages have warning signs", expand=True)
        t.add_column("#", justify="right")
        t.add_column("When")
        t.add_column("Risk")
        t.add_column("Why")
        t.add_column("Message (masked)", overflow="fold")
        for m, r in flagged:
            e = explain(r.verdict, lg, max_reasons=1)
            t.add_row(str(m.index), m.when, Text(r.verdict.risk_level, style="red" if r.verdict.risk_level == "high"
                                                    else "yellow"),
                      e["reasons"][0]["text"] if e["reasons"] else "", r.masked_content[:160])
        out.print(t)
    backend, token = _family(profile)
    if hold and worst and worst.verdict.is_risky and backend and profile.role == "parent":
        backend.submit_case(token, worst.case_payload())
        backend.request_approval(token, worst.case_id)
        if not as_json:
            out.print(f"[yellow]The riskiest message was sent to your family for review as {worst.case_id}.[/]")


@app.command("status")
def status_cmd(case_id: str, as_json: bool = JsonOpt, lang: Optional[str] = LangOpt) -> None:
    """Show the state of one of your cases."""
    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    try:
        cid = _resolve_case_id(backend, token, case_id)
        c = backend.get_case(token, cid)
    except ServiceError as exc:
        _fail(str(exc), as_json=as_json)
        return
    if as_json:
        _print_json(c)
        return
    _show_case(c, _lang(lang, profile))


def _show_case(c: dict, lang: str) -> None:
    from .verdict import Reason, Verdict

    v = Verdict("case", c["risk_level"], c["score"],
                [Reason(r["rule_id"], r["severity"], r["title"], r.get("evidence") or "", truth_card=r.get("truth_card"))
                 for r in c["reasons"]],
                (c["verdicts"][0]["ruleset_version"] if c["verdicts"] else "?"))
    out.print(verdict_panel(v, lang, title=f"{c['id']} · from {c.get('parent_name') or '-'} · {c['input_type']}",
                            explain_trace=True))
    out.print(f"Masked content: [cyan]{c['masked_content']}[/]")
    a = c.get("approval") or {}
    out.print(f"State: [bold]{c['state']}[/]  ·  checked {ts(c['created_at'])}"
              + (f"  ·  expires {ts(a.get('expires_at'))}" if c["state"] == "held" else "")
              + (f"  ·  decided {ts(a.get('decided_at'))}" if a.get("decided_at") else ""))


@app.command("history")
def history_cmd(limit: int = 20, as_json: bool = JsonOpt) -> None:
    """List recent cases for this family member."""
    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    cases = backend.list_cases(token, None, limit)
    if as_json:
        _print_json(cases)
    else:
        out.print(cases_table(cases, "Recent cases"))


# ---------------------------------------------------------------------------------------------
# pairing


@app.command("pair")
def pair_cmd(
    join: Optional[str] = typer.Option(None, "--join", help="Guardian: join with the parent's pairing code"),
    name: Optional[str] = typer.Option(None, "--name", help="Your display name, e.g. Amma or Rohan"),
    lang: str = typer.Option("en", "--lang", "-l", help="Preferred language: en, hi or kn"),
    phone: Optional[str] = typer.Option(None, "--phone", help="Guardian: number shown on the cool-off screen"),
    code_word: Optional[str] = typer.Option(None, "--code-word", help="Guardian: set the family code word"),
    relay: Optional[str] = typer.Option(None, "--relay", help="Family relay URL; omit for local mode"),
    new_code: bool = typer.Option(False, "--new-code", help="Parent: issue a fresh pairing code"),
    status: bool = typer.Option(False, "--status", help="Show this profile and its family"),
    reset: bool = typer.Option(False, "--reset", help="Forget this profile's pairing"),
    as_json: bool = JsonOpt,
) -> None:
    """Link a parent and a guardian with a one-time code (expires in 10 minutes)."""
    profile = load_profile()
    if lang not in LANGS:
        _fail("language must be en, hi or kn", as_json=as_json)
    if reset:
        save_profile(Profile(name=profile.name))
        out.print("Pairing removed for this profile.")
        return
    if relay:
        profile.relay_url = relay.rstrip("/")
    try:
        if status:
            if not profile.paired:
                _fail("not paired", as_json=as_json)
            backend = get_backend(profile)
            info = backend.family_info(profile.get_token())
            info["profile"] = {"name": profile.name, "role": profile.role, "relay_url": profile.relay_url}
            if as_json:
                _print_json(info)
            else:
                out.print(f"Profile [bold]{profile.name}[/] is the [bold]{profile.role}[/] "
                          f"({'relay ' + profile.relay_url if profile.relay_url else 'local mode'}).")
                out.print(f"Family {info['family_id']} · locked: {info['locked']} · review limit "
                          f"Rs {info['review_amount']:g} · code word set: {info['code_word_set']}")
                for p in info["parents"]:
                    out.print(f"  parent:   {p['display_name']} ({p['language']})")
                for g in info["guardians"]:
                    out.print(f"  guardian: {g['display_name']} ({g['language']}) {g.get('phone') or ''}")
            return
        backend = get_backend(profile)
        if new_code:
            if not profile.paired or profile.role != "parent":
                _fail("only a paired parent profile can issue a new code", as_json=as_json)
            res = backend.new_pair_code(profile.get_token())
        elif join:
            res = backend.join_family(join, name or "Guardian", lang, phone, code_word)
            _store_identity(profile, res, name or "Guardian", lang)
        else:
            if profile.paired:
                _fail("this profile is already paired. Use --new-code, --status or --reset.", as_json=as_json)
            res = backend.create_family(name or "Parent", lang)
            _store_identity(profile, res, name or "Parent", lang)
    except ServiceError as exc:
        _fail(str(exc), as_json=as_json)
        return
    public = {k: v for k, v in res.items() if k != "token"}
    if as_json:
        _print_json(public)
        return
    if "pair_code" in res:
        out.print(f"Pairing code: [bold cyan]{res['pair_code']}[/] (valid until {ts(res['pair_expires_at'])})")
        hint = f" --relay {profile.relay_url}" if profile.relay_url else ""
        out.print(f"On the guardian's laptop run: [bold]bharosa pair --join {res['pair_code']} --name <name>{hint}[/]")
        if not profile.relay_url:
            out.print("[dim]Local mode: run the guardian in a second terminal with BHAROSA_PROFILE=guardian.[/]")
    else:
        out.print(f"[green]Joined family {res['family_id']} as guardian.[/]")


def _store_identity(profile: Profile, res: dict, name: str, lang: str) -> None:
    profile.role = res["role"]
    profile.user_id = res["user_id"]
    profile.family_id = res["family_id"]
    profile.display_name = name
    profile.language = lang
    profile.set_token(res["token"])
    save_profile(profile)


# ---------------------------------------------------------------------------------------------
# guardian


@guardian_app.command("watch")
def guardian_watch(
    once: bool = typer.Option(False, "--once", help="Print the queue once and exit"),
    all_cases: bool = typer.Option(False, "--all", help="Show recent decided cases too"),
    interval: float = typer.Option(1.5, "--interval"),
    as_json: bool = JsonOpt,
) -> None:
    """Live-updating table of held cases."""
    from rich.console import Group
    from rich.live import Live

    profile = load_profile()
    backend, token = _require_family(profile, "guardian", as_json=as_json)

    def snapshot():
        states = None if all_cases else ["held"]
        cases = backend.list_cases(token, states, 30)
        info = backend.family_info(token)
        return cases, info

    if once or as_json:
        cases, info = snapshot()
        if as_json:
            _print_json({"locked": info["locked"], "cases": cases})
        else:
            out.print(cases_table(cases, "Held cases" if not all_cases else "Recent cases"))
        return

    def render():
        cases, info = snapshot()
        head = Text(f"Guardian: {profile.display_name} · family {info['family_id']}"
                    + ("  ·  EMERGENCY STOP ON" if info["locked"] else ""),
                    style="bold red" if info["locked"] else "bold")
        foot = Text("Decide with: bharosa guardian approve|block <case-id>   ·   "
                    "bharosa stop   ·   Ctrl+C to exit", style="dim")
        return Group(head, cases_table(cases, "Held cases (live)" if not all_cases else "Recent cases (live)"), foot)

    try:
        with Live(render(), console=out, refresh_per_second=2) as live:
            while True:
                time.sleep(interval)
                live.update(render())
    except KeyboardInterrupt:
        pass


@guardian_app.command("show")
def guardian_show(case_id: str, lang: Optional[str] = LangOpt, as_json: bool = JsonOpt) -> None:
    """Case detail with every reason and the rule trace."""
    profile = load_profile()
    backend, token = _require_family(profile, "guardian", as_json=as_json)
    try:
        c = backend.get_case(token, _resolve_case_id(backend, token, case_id))
    except ServiceError as exc:
        _fail(str(exc), as_json=as_json)
        return
    if as_json:
        _print_json(c)
    else:
        _show_case(c, _lang(lang, profile))


def _decide(case_id: str, decision: str, note: str | None, as_json: bool) -> None:
    profile = load_profile()
    backend, token = _require_family(profile, "guardian", as_json=as_json)
    try:
        cid = _resolve_case_id(backend, token, case_id)
        c = backend.decide(token, cid, decision, note)
    except ServiceError as exc:
        _fail(str(exc), as_json=as_json)
        return
    if as_json:
        _print_json({"case_id": c["id"], "state": c["state"]})
    else:
        style = "green" if c["state"] == "approved" else "red"
        out.print(f"[{style}]Case {c['id']} {c['state']}.[/]")
        if c["state"] == "blocked" and c.get("payee_masked"):
            out.print(f"Payee {c['payee_masked']} added to your family's report list.")


@guardian_app.command("approve")
def guardian_approve(case_id: str, note: Optional[str] = typer.Option(None, "--note"), as_json: bool = JsonOpt):
    """Approve a held case (an extra check, not proof the payment is genuine)."""
    _decide(case_id, "approve", note, as_json)


@guardian_app.command("block")
def guardian_block(case_id: str, note: Optional[str] = typer.Option(None, "--note"), as_json: bool = JsonOpt):
    """Block a held case; its payee goes on the family report list."""
    _decide(case_id, "block", note, as_json)


@guardian_app.command("unlock")
def guardian_unlock(as_json: bool = JsonOpt) -> None:
    """Turn Emergency Stop off for the family."""
    profile = load_profile()
    backend, token = _require_family(profile, "guardian", as_json=as_json)
    res = backend.unlock(token)
    _print_json(res) if as_json else out.print("[green]Family unlocked. New checks can hand off again.[/]")


@guardian_app.command("set-code-word")
def guardian_code_word(word: str = typer.Argument(..., help="A private word only the family knows")) -> None:
    """Set the family code word used against 'relative in trouble' scams."""
    profile = load_profile()
    backend, token = _require_family(profile, "guardian")
    backend.set_code_word(token, word)
    out.print("[green]Family code word saved (only a salted hash is stored).[/]")


@guardian_app.command("set-limit")
def guardian_set_limit(amount: float = typer.Argument(..., help="Rupees; first-time payees above this go to review")):
    """Set the family review limit for first-time payees."""
    profile = load_profile()
    backend, token = _require_family(profile, "guardian")
    backend.set_review_amount(token, amount)
    out.print(f"[green]Review limit set to Rs {amount:g}.[/]")


@guardian_app.command("stats")
def guardian_stats(as_json: bool = JsonOpt) -> None:
    """Review-time metrics (median time from flag to decision)."""
    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    s = backend.stats(token)
    if as_json:
        _print_json(s)
        return
    med = s["median_review_seconds"]
    out.print(f"Decisions: {s['decisions']} · median review time: "
              f"{'-' if med is None else f'{med:.0f} s'} · cases by state: {s['cases_by_state']}")


@app.command("audit")
def audit_cmd(limit: int = 30, as_json: bool = JsonOpt) -> None:
    """Show the family's append-only audit log."""
    from rich.table import Table

    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    rows = backend.audit(token, limit)
    if as_json:
        _print_json(rows)
        return
    t = Table(title="Audit log (newest first)")
    for col in ("When", "Who", "Action", "Case"):
        t.add_column(col)
    for r in rows:
        t.add_row(ts(r["at"]), r.get("actor") or "system", r["action"], r.get("case_id") or "")
    out.print(t)


# ---------------------------------------------------------------------------------------------
# Emergency Stop and evidence


@app.command("stop")
def stop_cmd(
    reason: str = typer.Option("", "--reason", help="What happened (kept masked)"),
    minutes_ago: Optional[int] = typer.Option(None, "--minutes-ago", help="When the incident started"),
    out_dir: Optional[Path] = typer.Option(None, "--out", help="Where to save the evidence packet"),
    as_json: bool = JsonOpt,
) -> None:
    """Emergency Stop: lock all pending cases and build the redacted evidence packet."""
    from .masking import mask_text

    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    incident = time.time() - minutes_ago * 60 if minutes_ago is not None else None
    res = backend.emergency_stop(token, mask_text(reason).text, incident)
    paths = save_packet(res["packet"], res["sha256"], out_dir or evidence_dir())
    links = upload_to_s3(paths)
    if as_json:
        _print_json({"locked": True, "locked_cases": res["locked_cases"], "packet_id": res["packet"]["packet_id"],
                     "sha256": res["sha256"], "files": {k: str(v) for k, v in paths.items()}, "s3_links": links})
        return
    g = res["packet"]["golden_hour"]
    out.print(f"[bold red]EMERGENCY STOP ON.[/] {len(res['locked_cases'])} pending case(s) locked. "
              "Bharosa will not hand off any payment until a guardian runs `bharosa guardian unlock`.")
    out.print("[dim]Bharosa can pause only its own flow. It cannot block payments inside other apps.[/]")
    out.print(f"\n[bold]Call 1930 now[/] or file at [cyan]https://cybercrime.gov.in/[/]. "
              f"Minutes since the first flagged case: {g['minutes_since_incident']}"
              + (" (inside the golden hour: report now so the bank can try to freeze funds)" if g["within_golden_hour"] else ""))
    out.print(f"\nEvidence packet {res['packet']['packet_id']} (SHA-256 {res['sha256'][:16]}...):")
    for k, p in paths.items():
        out.print(f"  {k}: {p}")
    for l in links:
        out.print(f"  download (15 min): {l}")


@app.command("evidence")
def evidence_cmd(
    case_id: Optional[str] = typer.Argument(None, help="Case id; omit for the latest packet"),
    out_dir: Optional[Path] = typer.Option(None, "--out", help="Export JSON + Markdown here"),
    as_json: bool = JsonOpt,
) -> None:
    """Show or export the redacted evidence packet."""
    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    try:
        if case_id:
            res = backend.build_case_packet(token, _resolve_case_id(backend, token, case_id))
        else:
            res = backend.get_packet(token, None)
    except ServiceError as exc:
        _fail(str(exc), as_json=as_json)
        return
    if out_dir:
        paths = save_packet(res["packet"], res["sha256"], out_dir)
        if not as_json:
            for k, p in paths.items():
                out.print(f"{k}: {p}")
    if as_json:
        _print_json(res)
    elif not out_dir:
        from rich.markdown import Markdown

        out.print(Markdown(to_markdown(res["packet"], res["sha256"])))


# ---------------------------------------------------------------------------------------------
# payees, code word, clipboard


@payees_app.command("add")
def payees_add(vpa: str = typer.Argument(..., help="UPI ID, e.g. pharmacy@okaxis"),
               label: str = typer.Option(..., "--label", help="e.g. Pharmacy")) -> None:
    """Add a regular payee; first-time-payee checks skip it."""
    profile = load_profile()
    backend, token = _require_family(profile)
    backend.add_trusted_payee(token, hash_vpa(vpa), mask_vpa(vpa), label)
    out.print(f"[green]Trusted payee added:[/] {label} ({mask_vpa(vpa)}). Only a hash of the UPI ID is stored.")


@payees_app.command("list")
def payees_list(as_json: bool = JsonOpt) -> None:
    """List trusted payees."""
    profile = load_profile()
    backend, token = _require_family(profile, as_json=as_json)
    rows = backend.list_trusted_payees(token)
    if as_json:
        _print_json(rows)
        return
    for r in rows:
        out.print(f"  {r['label']}: {r['vpa_masked']}  (added {ts(r['added_at'])})")
    if not rows:
        out.print("No trusted payees yet. Add one with: bharosa payees add <upi-id> --label Pharmacy")


@payees_app.command("remove")
def payees_remove(vpa: str) -> None:
    """Remove a trusted payee."""
    profile = load_profile()
    backend, token = _require_family(profile)
    ok = backend.remove_trusted_payee(token, hash_vpa(vpa))
    out.print("Removed." if ok else "That payee was not on the list.")


@codeword_app.command("verify")
def codeword_verify(word: str = typer.Argument(..., help="The word the caller gave you")) -> None:
    """Check the word a 'relative' gives you against the family code word."""
    profile = load_profile()
    backend, token = _require_family(profile)
    try:
        ok = backend.verify_code_word(token, word)
    except ServiceError as exc:
        _fail(str(exc))
        return
    if ok:
        out.print("[green]The code word matches.[/] Still call them back on their usual number before paying.")
    else:
        out.print("[bold red]The code word does NOT match.[/] Hang up. This is very likely a scam.")


@watch_app.command("clipboard")
def watch_clipboard(interval: float = typer.Option(1.0, "--interval"), lang: Optional[str] = LangOpt,
                    direct: bool = typer.Option(False, "--direct")) -> None:
    """Check every copied link, UPI ID or message until Ctrl+C."""
    from .clipboard import read_clipboard, worth_checking

    profile = load_profile()
    lg = _lang(lang, profile)
    runner = _runner(direct)
    last = read_clipboard()
    out.print("[bold]Watching the clipboard.[/] Copy a link, UPI ID or message to check it. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(interval)
            clip = read_clipboard()
            if clip == last:
                continue
            last = clip
            if not worth_checking(clip):
                continue
            r = check_message(clip, runner, _context(profile))
            out.print(verdict_panel(r.verdict, lg, title="Bharosa · clipboard"))
    except KeyboardInterrupt:
        pass
    finally:
        runner.close()


# ---------------------------------------------------------------------------------------------
# eval, mcp, relay, voice, config


@app.command("eval")
def eval_cmd(corpus: Optional[Path] = typer.Option(None, "--corpus", help="Labeled cases YAML"),
             as_json: bool = JsonOpt, mcp: bool = typer.Option(False, "--mcp", help="Run through the MCP server")):
    """Run the labeled corpus and print recall, specificity and per-rule hits."""
    from rich.table import Table

    from .evaluate import run_eval

    runner = _runner(not mcp)
    try:
        r = run_eval(corpus, runner)
    finally:
        runner.close()
    if as_json:
        _print_json({k: v for k, v in r.items() if k != "outcomes"})
        return
    out.print(f"[bold]On our {r['n']} synthetic cases[/] ({r['scam_n']} scam, {r['benign_n']} benign), "
              f"ruleset {r['ruleset_version']}:")
    out.print(f"  Recall (scams flagged medium or high): [bold]{r['recall']:.0%}[/]")
    out.print(f"  Specificity (benign left low):        [bold]{r['specificity']:.0%}[/]")
    out.print(f"  Exact expected level:                 {r['exact_level_accuracy']:.0%}")
    t = Table(title="Per-rule hits")
    t.add_column("Rule")
    t.add_column("Hits", justify="right")
    for rule, n in r["per_rule_hits"].items():
        t.add_row(rule, str(n))
    out.print(t)
    for m in r["misses"]:
        out.print(f"[red]MISS[/] {m['id']} ({m['label']}): got {m['got']}, rules {m['rules']}")


@app.command("mcp")
def mcp_cmd() -> None:
    """Start the Bharosa MCP server on stdio (for Claude Desktop or Claude Code)."""
    from .mcp_server import main as mcp_main

    mcp_main()


@app.command("relay")
def relay_cmd(host: str = typer.Option("127.0.0.1", "--host"), port: int = typer.Option(8765, "--port"),
              db: Path = typer.Option(Path("bharosa-relay.db"), "--db", help="Relay SQLite file"),
              retention_days: float = typer.Option(7, "--retention-days", help="Delete decided cases older than this")) -> None:
    """Run the family relay (FastAPI) so parent and guardian can be on different laptops."""
    import uvicorn

    from .relay.app import create_app
    from .service import FamilyService
    from .store import Store

    svc = FamilyService(Store(db))
    purged = svc.purge_expired(retention_days)
    out.print(f"Bharosa relay on http://{host}:{port} (database {db}); retention purge: {purged}")
    uvicorn.run(create_app(svc), host=host, port=port, log_level="info")


bot_app = typer.Typer(help="Chat app bots (Telegram, WhatsApp) for checks and guardian review.",
                      no_args_is_help=True)
app.add_typer(bot_app, name="bot")


@bot_app.command("serve")
def bot_serve_cmd(
    telegram: Optional[bool] = typer.Option(None, "--telegram/--no-telegram",
                                            help="Run the Telegram bot (default: when BHAROSA_TELEGRAM_TOKEN is set)"),
    whatsapp: Optional[bool] = typer.Option(None, "--whatsapp/--no-whatsapp",
                                            help="Run the WhatsApp webhook (default: when its four env vars are set)"),
    host: str = typer.Option("127.0.0.1", "--host", help="WhatsApp webhook host"),
    port: int = typer.Option(8780, "--port", help="WhatsApp webhook port"),
) -> None:
    """Run the chat bots. Credentials come only from environment variables."""
    from .chatbot.serve import BotSettings, serve

    s = BotSettings.from_env()
    tg = s.telegram_ready if telegram is None else telegram
    wa = s.whatsapp_ready if whatsapp is None else whatsapp
    if tg and not s.telegram_ready:
        _fail("Set BHAROSA_TELEGRAM_TOKEN (from @BotFather) first.")
    if wa and not s.whatsapp_ready:
        _fail("Set these first: " + ", ".join(s.whatsapp_missing()))
    if not tg and not wa:
        _fail("No chat platform configured. Set BHAROSA_TELEGRAM_TOKEN and/or the BHAROSA_WHATSAPP_* variables.")
    where = f"relay {s.relay_url}" if s.relay_url else "local family database"
    out.print(f"Bharosa bot: telegram={'on' if tg else 'off'}, whatsapp={'on' if wa else 'off'}, queue: {where}, "
              f"chat links: {s.bot_db}")
    serve(s, telegram=tg, whatsapp=wa, host=host, port=port)


@voice_app.command("test")
def voice_test(lang: str = typer.Option("en", "--lang", "-l"),
               text: Optional[str] = typer.Option(None, "--text")) -> None:
    """Speak a sample warning to check audio on this laptop."""
    from .voice import speak

    sample = text or ui("level_high", lang) + ". " + ui("do_not_pay", lang)
    r = speak(sample, lang)
    out.print(f"engine: {r.engine} · played: {r.played} · cached: {r.cached} · file: {r.path or '-'}")


@voice_app.command("cache")
def voice_cache(engine: Optional[str] = typer.Option(None, "--engine", help="espeak, sapi, say or elevenlabs")):
    """Pre-generate voice clips for every rule and language so the demo runs offline."""
    from .rules import all_rule_ids, rule_meta
    from .verdict import Reason, make_verdict
    from .voice import warm_cache

    items = []
    for rid in all_rule_ids():
        meta = rule_meta(rid)
        v = make_verdict("cache", [Reason(rid, meta["severity"], meta["title"],
                                          always_high=bool(meta.get("always_high")),
                                          truth_card=meta.get("truth_card"))], "cache")
        for lang in LANGS:
            items.append((lang, voice_script(v, lang)))
    results = warm_cache(items, engine)
    by_engine: dict[str, int] = {}
    for r in results:
        by_engine[r.engine] = by_engine.get(r.engine, 0) + 1
    out.print(f"{len(results)} clips: {by_engine}")
    if by_engine.get("text"):
        out.print("[yellow]Some languages have no installed speech engine; install espeak-ng for Hindi and "
                  "Kannada, or use --engine elevenlabs with ELEVENLABS_API_KEY (paid).[/]")


@config_app.command("show")
def config_show() -> None:
    """Show this profile's settings."""
    p = load_profile()
    out.print({"profile": p.name, "role": p.role, "family_id": p.family_id, "display_name": p.display_name,
               "language": p.language, "relay_url": p.relay_url, "paired": p.paired,
               "token_storage": "keyring" if p.token_in_keyring else "profile file"})


@config_app.command("set")
def config_set(key: str = typer.Argument(..., help="lang or relay"), value: str = typer.Argument(...)) -> None:
    """Change lang (en/hi/kn) or relay (URL, or 'local')."""
    p = load_profile()
    if key == "lang":
        if value not in LANGS:
            _fail("language must be en, hi or kn")
        p.language = value
    elif key == "relay":
        p.relay_url = None if value == "local" else value.rstrip("/")
    else:
        _fail("unknown setting; use lang or relay")
    save_profile(p)
    out.print(f"{key} = {value}")


@app.command("purge")
def purge_cmd(days: float = typer.Option(7, "--days", help="Delete decided cases older than this many days")) -> None:
    """Apply the retention policy to the local database (decided cases, expired evidence packets)."""
    from .config import db_path
    from .service import FamilyService
    from .store import Store

    out.print(FamilyService(Store(db_path())).purge_expired(days))


@app.command("version")
def version_cmd() -> None:
    """Print the version and ruleset version."""
    from .rules import ruleset_version

    out.print(f"bharosa {__version__} · ruleset {ruleset_version()}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
