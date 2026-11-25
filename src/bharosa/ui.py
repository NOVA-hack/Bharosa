"""Rich terminal rendering: verdict panels, case tables, the cool-off clock."""

from __future__ import annotations

import time
from datetime import datetime

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .explain import explain
from .verdict import Verdict

LEVEL_STYLE = {"low": "green", "medium": "yellow", "high": "red"}
STATE_STYLE = {"held": "yellow", "approved": "green", "allowed": "green", "blocked": "red", "stopped": "red",
               "expired": "magenta", "checked": "cyan"}


def console() -> Console:
    return Console(highlight=False)


def ts(t: float | None) -> str:
    if not t:
        return "-"
    return datetime.fromtimestamp(t).strftime("%d %b %H:%M:%S")


def verdict_panel(v: Verdict, lang: str = "en", title: str = "Bharosa check", explain_trace: bool = False,
                  extra: list | None = None) -> Panel:
    e = explain(v, lang)
    style = LEVEL_STYLE[v.risk_level]
    body: list = [Text(e["headline"], style=f"bold {style}")]
    if e["reasons"]:
        body.append(Text(""))
        for r in e["reasons"]:
            line = Text("  • ", style=style)
            line.append(r["text"])
            body.append(line)
    body.append(Text(""))
    body.append(Text(e["disclaimer"], style="dim" if v.risk_level == "low" else "bold"))
    for c in e["truth_cards"][:2]:
        body.append(Text(""))
        t = Text("Truth card: ", style="bold cyan")
        t.append(c["text"])
        t.append(f"\n  Source: {c['source']} ({c['url']})", style="dim")
        body.append(t)
    if extra:
        body.extend(extra)
    if explain_trace:
        body.append(Text(""))
        body.append(rule_trace_table(v))
    subtitle = f"risk {v.risk_level.upper()} · score {v.score} · rules {v.ruleset_version}"
    return Panel(Group(*body), title=title, subtitle=subtitle, border_style=style, padding=(1, 2))


def rule_trace_table(v: Verdict) -> Table:
    t = Table(title="Rule trace (--explain)", show_lines=False, expand=True)
    t.add_column("Rule id", style="bold")
    t.add_column("Severity")
    t.add_column("Weight", justify="right")
    t.add_column("Matched evidence (masked)")
    for r in v.reasons:
        t.add_row(r.rule_id, r.severity + (" (always high)" if r.always_high else ""), str(r.weight),
                  r.evidence or "-")
    if not v.reasons:
        t.add_row("-", "-", "0", "no rule matched")
    t.caption = (f"Score = sum of weights (high 60, medium 30, low 10), capped at 100. "
                 f">= 60 or any always-high rule = HIGH; 30-59 = MEDIUM; < 30 = LOW. Ruleset {v.ruleset_version}")
    return t


def cases_table(cases: list[dict], title: str = "Cases") -> Table:
    t = Table(title=title, expand=True)
    t.add_column("Case id", style="bold", no_wrap=True)
    t.add_column("From")
    t.add_column("Type")
    t.add_column("Risk")
    t.add_column("State")
    t.add_column("What (masked)", overflow="fold")
    t.add_column("Checked", no_wrap=True)
    t.add_column("Expires", no_wrap=True)
    for c in cases:
        rs, ss = LEVEL_STYLE.get(c["risk_level"], ""), STATE_STYLE.get(c["state"], "")
        t.add_row(c["id"], c.get("parent_name") or "-", c["input_type"], Text(c["risk_level"], style=rs),
                  Text(c["state"], style=ss), (c["masked_content"] or "")[:90], ts(c["created_at"]),
                  ts(c.get("expires_at")) if c["state"] == "held" else "-")
    if not cases:
        t.add_row("-", "", "", "", "", "No cases yet", "", "")
    return t


def countdown_text(remaining: float) -> str:
    remaining = max(0, int(remaining))
    return f"{remaining // 60:02d}:{remaining % 60:02d}"


def cooloff_panel(remaining: float, script: str, status: str, guardian: str | None, phone: str | None) -> Panel:
    body = [Text(f"Cool-off clock  {countdown_text(remaining)}", style="bold cyan"), Text(""), Text(script)]
    if guardian:
        call = Text(f"\nCall {guardian} now", style="bold")
        if phone:
            call.append(f": {phone}")
        body.append(call)
    body.append(Text(f"\nFamily review: {status}", style="yellow"))
    body.append(Text("Press Ctrl+C to stop waiting. The payment stays paused.", style="dim"))
    return Panel(Group(*body), border_style="cyan", title="Pause before you pay")


def now() -> float:
    return time.time()
