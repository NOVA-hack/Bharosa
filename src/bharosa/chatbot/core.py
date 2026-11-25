"""The chat app layer: one bot brain shared by every messaging platform.

A platform adapter (Telegram, WhatsApp) turns what arrived into an :class:`Incoming` event and
gives the bot a :class:`Transport` that can send an :class:`Outgoing` message back. The bot itself
knows nothing about any platform. It:

* runs the same deterministic checks as ``bharosa check`` (:mod:`bharosa.pipeline`, DirectRunner)
* for a paired parent, submits the masked case to the family queue and holds risky ones
* pushes review requests to every guardian who is paired in a chat, with Approve / Block buttons
* tells the parent when a guardian decides, the case expires or Emergency Stop is pressed

The family queue is the existing :class:`bharosa.service.FamilyService` (local SQLite) or
:class:`bharosa.backend.RelayBackend`; both have the same methods. Guardians only ever see the
masked content the service stores. Raw input is never kept.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from ..checks import InputTooLarge
from ..explain import LANGS, reason_text, truth_card, ui
from ..pipeline import CheckResult, DirectRunner, check_message, check_qr, check_url
from ..qrdecode import QRDecodeError, decode_bytes
from ..service import ServiceError
from ..store import Store

MAX_CHAT_TEXT = 3500  # stays under Telegram's 4096 and WhatsApp's 4096 limits
MAX_SHOWN_CONTENT = 500
CHECKS_PER_HOUR = 30  # per chat, on top of the service's own per-family limit

LEVEL_ICON = {"low": "🟢", "medium": "🟠", "high": "🔴"}
TYPE_LABEL = {"qr": "QR code", "url": "Link", "msg": "Message", "chat": "Chat message"}

_URL_ONLY = re.compile(r"^(https?://|www\.)\S+$", re.IGNORECASE)
_UPI_ONLY = re.compile(r"^upi://\S+$", re.IGNORECASE)

CHAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    platform TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'en',
    user_id TEXT,
    family_id TEXT,
    role TEXT,
    display_name TEXT,
    token TEXT,
    linked_at REAL,
    PRIMARY KEY (platform, chat_id)
);
CREATE TABLE IF NOT EXISTS chat_cases (
    case_id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    notified INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pushed_reviews (
    case_id TEXT NOT NULL,
    guardian_id TEXT NOT NULL,
    pushed_at REAL NOT NULL,
    PRIMARY KEY (case_id, guardian_id)
);
"""


# ---- what adapters exchange with the bot --------------------------------------------------


@dataclass(frozen=True)
class Button:
    label: str
    data: str  # "approve:<case_id>", "block:<case_id>" or "show:<case_id>"


@dataclass
class Outgoing:
    text: str
    buttons: list[Button] = field(default_factory=list)


@dataclass
class Incoming:
    platform: str
    chat_id: str
    name: str = ""
    text: str | None = None
    image: bytes | None = None
    action: str | None = None  # button data, when a button was pressed


class Transport(Protocol):
    platform: str

    def send(self, chat_id: str, message: Outgoing) -> None: ...


# ---- chat link storage ----------------------------------------------------------------------


class ChatStore:
    """Which chat belongs to which family member.

    The member's Bharosa API token is kept here so the bot can act for them, the same way a CLI
    profile keeps it. Keep this file on the machine that runs the bot, readable only by that user.
    """

    def __init__(self, path: str | Path):
        self.store = Store(path)  # also creates the family tables; harmless in a separate file
        with self.store.transaction() as conn:
            conn.executescript(CHAT_SCHEMA)

    def get(self, platform: str, chat_id: str) -> dict | None:
        return self.store.one("SELECT * FROM chats WHERE platform = ? AND chat_id = ?", (platform, chat_id))

    def set_language(self, platform: str, chat_id: str, lang: str) -> None:
        self.store.execute(
            "INSERT INTO chats (platform, chat_id, language) VALUES (?,?,?)"
            " ON CONFLICT(platform, chat_id) DO UPDATE SET language = excluded.language",
            (platform, chat_id, lang),
        )

    def link(self, platform: str, chat_id: str, *, user_id: str, family_id: str, role: str, name: str,
             token: str, lang: str, now: float) -> None:
        self.store.execute(
            "INSERT INTO chats (platform, chat_id, language, user_id, family_id, role, display_name, token,"
            " linked_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(platform, chat_id) DO UPDATE SET"
            " language = excluded.language, user_id = excluded.user_id, family_id = excluded.family_id,"
            " role = excluded.role, display_name = excluded.display_name, token = excluded.token,"
            " linked_at = excluded.linked_at",
            (platform, chat_id, lang, user_id, family_id, role, name, token, now),
        )

    def unlink(self, platform: str, chat_id: str) -> None:
        self.store.execute(
            "UPDATE chats SET user_id = NULL, family_id = NULL, role = NULL, display_name = NULL, token = NULL,"
            " linked_at = NULL WHERE platform = ? AND chat_id = ?",
            (platform, chat_id),
        )

    def family_chats(self, family_id: str, role: str | None = None) -> list[dict]:
        sql = "SELECT * FROM chats WHERE family_id = ? AND token IS NOT NULL"
        params: tuple = (family_id,)
        if role:
            sql += " AND role = ?"
            params += (role,)
        return self.store.query(sql + " ORDER BY linked_at", params)

    def chats_for_user(self, user_id: str) -> list[dict]:
        return self.store.query("SELECT * FROM chats WHERE user_id = ? AND token IS NOT NULL", (user_id,))

    def all_linked(self, role: str) -> list[dict]:
        return self.store.query("SELECT * FROM chats WHERE role = ? AND token IS NOT NULL", (role,))

    # cases this bot submitted, so the parent hears about the outcome
    def track_case(self, case_id: str, platform: str, chat_id: str, family_id: str, now: float) -> None:
        self.store.execute(
            "INSERT OR IGNORE INTO chat_cases (case_id, platform, chat_id, family_id, created_at) VALUES (?,?,?,?,?)",
            (case_id, platform, chat_id, family_id, now),
        )

    def open_cases(self) -> list[dict]:
        return self.store.query("SELECT * FROM chat_cases WHERE notified = 0 ORDER BY created_at")

    def mark_notified(self, case_id: str) -> None:
        self.store.execute("UPDATE chat_cases SET notified = 1 WHERE case_id = ?", (case_id,))

    def mark_family_notified(self, family_id: str) -> None:
        self.store.execute("UPDATE chat_cases SET notified = 1 WHERE family_id = ?", (family_id,))

    def was_pushed(self, case_id: str, guardian_id: str) -> bool:
        return bool(self.store.one(
            "SELECT 1 FROM pushed_reviews WHERE case_id = ? AND guardian_id = ?", (case_id, guardian_id)))

    def mark_pushed(self, case_id: str, guardian_id: str, now: float) -> None:
        self.store.execute(
            "INSERT OR IGNORE INTO pushed_reviews (case_id, guardian_id, pushed_at) VALUES (?,?,?)",
            (case_id, guardian_id, now),
        )


# ---- formatting -------------------------------------------------------------------------------


def _clip(text: str, n: int) -> str:
    text = text.strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _reason_lines(reasons: list[dict], lang: str, limit: int = 5) -> list[str]:
    lines = []
    for r in [r for r in reasons if r.get("severity") != "info"][:limit]:
        line = "• " + reason_text(r["rule_id"], r.get("title", r["rule_id"]), lang)
        if r.get("evidence"):
            line += f" ({_clip(r['evidence'], 80)})"
        lines.append(line)
    return lines


def render_verdict(result: CheckResult, lang: str) -> str:
    v = result.verdict
    lines = [f"{LEVEL_ICON[v.risk_level]} {ui('level_' + v.risk_level, lang)} (score {v.score}/100)"]
    reason_lines = _reason_lines([r.to_dict() for r in v.reasons], lang)
    if reason_lines:
        lines += ["", "Why:"] + reason_lines
    lines.append("")
    lines.append(ui("low_disclaimer", lang) if v.risk_level == "low" else ui("do_not_pay", lang))
    seen = set()
    for r in v.reasons:
        card = truth_card(r.truth_card, lang)
        if card and card["id"] not in seen:
            seen.add(card["id"])
            lines += ["", f"ⓘ {card['text']} ({card['source']}: {card['url']})"]
            break
    if result.ask_code_word:
        lines += ["", ui("code_word", lang)]
    lines += ["", f"Personal details masked: {result.mask_summary}"]
    return "\n".join(lines)


def render_review(case: dict, lang: str, now: float | None = None) -> str:
    """The review request a guardian sees. Built only from the masked case the service returns."""
    level = case["risk_level"]
    lines = [
        f"🔔 Review request from {case.get('parent_name') or 'your family'}",
        f"{TYPE_LABEL.get(case['input_type'], case['input_type'])} · {LEVEL_ICON[level]} {level.upper()}"
        f" ({case['score']}/100)",
    ]
    if case.get("payee_masked") or case.get("amount"):
        bits = []
        if case.get("payee_masked"):
            bits.append(f"Payee {case['payee_masked']}")
        if case.get("amount"):
            bits.append(f"Rs {case['amount']:g}")
        lines.append(" · ".join(bits))
    lines += ["", "Content (personal details masked):", _clip(case["masked_content"], MAX_SHOWN_CONTENT)]
    reason_lines = _reason_lines(case.get("reasons", []), lang)
    if reason_lines:
        lines += ["", "Why:"] + reason_lines
    approval = case.get("approval") or {}
    if approval.get("expires_at"):
        mins = max(0, round((approval["expires_at"] - (now if now is not None else time.time())) / 60))
        lines += ["", f"Case {case['id']} · waits about {mins} min for your decision"]
    else:
        lines += ["", f"Case {case['id']}"]
    return "\n".join(lines)


def review_buttons(case_id: str) -> list[Button]:
    return [Button("✅ Approve", f"approve:{case_id}"), Button("⛔ Block", f"block:{case_id}"),
            Button("Details", f"show:{case_id}")]


HELP = """Bharosa checks suspicious payment QR codes, links and messages.

Send me a message, a link, a upi:// link or a photo of a QR code and I will tell you the warning signs I find.

Family review:
/parent <your name> : set up family review; I give you a code for your guardian
/join <code> <your name> : join as a guardian with the code
/code : a fresh pairing code (parent)
/pending : cases waiting for you (guardian)
/approve <case> · /block <case> [note] : decide a case (guardian)
/status <case> : where a case stands
/stop [reason] : Emergency Stop, locks every pending payment
/unlock : lift Emergency Stop (guardian)
/lang en|hi|kn : language
/unlink : forget this chat's family link

Bharosa never makes a payment and cannot guarantee that something is safe. Report fraud on 1930."""


# ---- the bot ---------------------------------------------------------------------------------


class ChatBot:
    def __init__(self, backend: Any, chats: ChatStore, transports: dict[str, Transport] | None = None,
                 runner: Any | None = None, clock: Callable[[], float] = time.time, default_lang: str = "en"):
        self.backend = backend
        self.chats = chats
        self.transports: dict[str, Transport] = dict(transports or {})
        self.runner = runner or DirectRunner()
        self.now = clock
        self.default_lang = default_lang if default_lang in LANGS else "en"
        self._lock = threading.RLock()
        self._recent: dict[tuple[str, str], deque] = defaultdict(deque)

    def add_transport(self, transport: Transport) -> None:
        self.transports[transport.platform] = transport

    # ---- sending ----------------------------------------------------------------------

    def send(self, platform: str, chat_id: str, text: str, buttons: list[Button] | None = None) -> None:
        transport = self.transports.get(platform)
        if transport is None:
            return  # that platform is not running in this process
        try:
            transport.send(chat_id, Outgoing(_clip(text, MAX_CHAT_TEXT), list(buttons or [])))
        except Exception:  # one failed delivery must not stop the rest of the flow
            pass

    def _reply(self, ev: Incoming, text: str, buttons: list[Button] | None = None) -> None:
        self.send(ev.platform, ev.chat_id, text, buttons)

    # ---- entry points -----------------------------------------------------------------

    def handle(self, ev: Incoming) -> None:
        with self._lock:
            try:
                self._handle(ev)
            except ServiceError as exc:
                self._reply(ev, f"Sorry, that did not work: {exc}")

    def tick(self) -> None:
        """Push new review requests and report finished cases. Call every few seconds."""
        with self._lock:
            for g in self.chats.all_linked("guardian"):
                try:
                    self._push_reviews_to(g)
                except ServiceError:
                    continue
            for c in self.chats.open_cases():
                try:
                    self._report_outcome(c)
                except ServiceError:
                    continue

    # ---- dispatch ---------------------------------------------------------------------

    def _handle(self, ev: Incoming) -> None:
        chat = self.chats.get(ev.platform, ev.chat_id) or {}
        lang = chat.get("language") or self.default_lang
        if ev.action:
            return self._on_action(ev, chat, lang, ev.action)
        text = (ev.text or "").strip()
        if text.startswith("/"):
            return self._on_command(ev, chat, lang, text)
        if text.lower() in ("help", "start", "hi", "hello", "menu") and not ev.image:
            return self._reply(ev, HELP)
        if not text and not ev.image:
            return self._reply(ev, HELP)
        if not self._allow_check(ev):
            return self._reply(ev, "You have sent a lot of checks in the last hour. Please wait a little and try again.")
        self._on_check(ev, chat, lang, text)

    def _allow_check(self, ev: Incoming) -> bool:
        q = self._recent[(ev.platform, ev.chat_id)]
        now = self.now()
        while q and q[0] < now - 3600:
            q.popleft()
        if len(q) >= CHECKS_PER_HOUR:
            return False
        q.append(now)
        return True

    # ---- checks -----------------------------------------------------------------------

    def _run_checks(self, ev: Incoming, text: str, context: dict | None) -> CheckResult | str:
        if ev.image:
            try:
                return check_qr(decode_bytes(ev.image), self.runner, context)
            except QRDecodeError:
                if not text:
                    return ("I could not find a QR code in that photo. Send a sharper, straight-on photo of just the "
                            "QR, or paste the message text.")
        try:
            if _UPI_ONLY.match(text):
                return check_qr(text, self.runner, context)
            if _URL_ONLY.match(text):
                return check_url(text if "://" in text else "http://" + text, self.runner)
            return check_message(text, self.runner, context)
        except InputTooLarge as exc:
            return f"That is too long for me to check: {exc}"

    def _on_check(self, ev: Incoming, chat: dict, lang: str, text: str) -> None:
        is_parent = chat.get("role") == "parent" and chat.get("token")
        context = self.backend.check_context(chat["token"]) if is_parent else None
        result = self._run_checks(ev, text, context)
        if isinstance(result, str):
            return self._reply(ev, result)
        reply = render_verdict(result, lang)
        if not is_parent:
            if result.verdict.is_risky:
                reply += "\n\nDo not pay. To have family review cases like this, send /parent <your name>."
            return self._reply(ev, reply)

        token = chat["token"]
        try:
            case = self.backend.submit_case(token, result.case_payload(keep_raw=False))
            if case["state"] in ("checked", "held"):
                approval = self.backend.request_approval(token, result.case_id)
        except ServiceError as exc:
            # The verdict matters more than the queue: always show it.
            extra = "\n\nDo not pay." if result.verdict.is_risky else ""
            return self._reply(ev, reply + f"{extra}\n\nFamily review is not available right now: {exc}")
        if case["state"] == "stopped":
            return self._reply(ev, reply + "\n\n" + ui("stopped", lang))
        if case["state"] == "allowed":
            return self._reply(ev, reply)
        if approval.get("case_state") == "stopped":
            return self._reply(ev, reply + "\n\n" + ui("stopped", lang))
        reply += "\n\n" + ui("held", lang)
        guardians = self.chats.family_chats(chat["family_id"], "guardian")
        if approval.get("guardians_notified") == 0:
            reply += "\nNo guardian has joined yet. Send /code and share the code with them."
        elif not guardians:
            reply += "\nYour guardian will see it in Bharosa."
        reply += f"\nCase {result.case_id} · /status {result.case_id[-6:]}"
        self._reply(ev, reply)
        self.chats.track_case(result.case_id, ev.platform, ev.chat_id, chat["family_id"], self.now())
        for g in guardians:
            self._push_reviews_to(g)

    # ---- guardian review --------------------------------------------------------------

    def _push_reviews_to(self, g: dict) -> None:
        held = self.backend.list_cases(g["token"], ["held"])
        for row in held:
            if self.chats.was_pushed(row["id"], g["user_id"]):
                continue
            case = self.backend.get_case(g["token"], row["id"])
            self.send(g["platform"], g["chat_id"], render_review(case, g["language"], self.now()), review_buttons(row["id"]))
            self.chats.mark_pushed(row["id"], g["user_id"], self.now())

    def _resolve_case(self, token: str, ref: str) -> str:
        ref = ref.strip()
        if ref.startswith("case_"):
            return ref
        matches = [c["id"] for c in self.backend.list_cases(token, None, 200) if c["id"].endswith(ref)]
        if len(matches) == 1:
            return matches[0]
        raise ServiceError("no single case matches that id; use the full case id")

    def _decide(self, ev: Incoming, chat: dict, lang: str, case_id: str, decision: str, note: str | None) -> None:
        if chat.get("role") != "guardian":
            return self._reply(ev, "Only a paired guardian can approve or block. Send /join <code> <name> first.")
        case = self.backend.decide(chat["token"], case_id, decision, note)
        word = "approved" if decision == "approve" else "blocked"
        self._reply(ev, f"Done: you {word} case {case_id} from {case.get('parent_name') or 'your family'}.")
        self._tell_parent(case, case["state"], note)
        # Let the other guardians know it is settled.
        for g in self.chats.family_chats(chat["family_id"], "guardian"):
            if (g["platform"], g["chat_id"]) != (ev.platform, ev.chat_id):
                self.send(g["platform"], g["chat_id"], f"{chat['display_name']} {word} case {case_id}.")

    def _tell_parent(self, case: dict, state: str, note: str | None = None) -> None:
        for p in self.chats.chats_for_user(case["parent_id"]):
            msg = self._outcome_text(case["id"], state, p["language"], note)
            if msg:
                self.send(p["platform"], p["chat_id"], msg)
        self.chats.mark_notified(case["id"])

    @staticmethod
    def _outcome_text(case_id: str, state: str, lang: str, note: str | None = None) -> str | None:
        key = {"approved": "approved", "blocked": "blocked", "stopped": "stopped", "expired": "expired"}.get(state)
        if not key:
            return None
        icon = {"approved": "✅", "blocked": "⛔", "stopped": "🛑", "expired": "⏳"}[key]
        text = f"{icon} Case {case_id}: {ui(key, lang)}"
        if note:
            text += f"\nNote from your family: {note}"
        return text

    def _report_outcome(self, tracked: dict) -> None:
        parent = self.chats.get(tracked["platform"], tracked["chat_id"])
        if not parent or not parent.get("token"):
            return self.chats.mark_notified(tracked["case_id"])
        status = self.backend.case_status(parent["token"], tracked["case_id"])
        if status["state"] in ("held", "checked"):
            return
        note = (status.get("approval") or {}).get("note")
        msg = self._outcome_text(tracked["case_id"], status["state"], parent["language"], note)
        if msg:
            self.send(parent["platform"], parent["chat_id"], msg)
        self.chats.mark_notified(tracked["case_id"])

    # ---- buttons ----------------------------------------------------------------------

    def _on_action(self, ev: Incoming, chat: dict, lang: str, action: str) -> None:
        verb, _, case_id = action.partition(":")
        if not chat.get("token") or not case_id:
            return self._reply(ev, "This chat is not paired with a family. Send /help.")
        if verb in ("approve", "block"):
            return self._decide(ev, chat, lang, case_id, verb, None)
        if verb == "show":
            case = self.backend.get_case(chat["token"], case_id)
            lines = [render_review(case, lang, self.now()), "", f"State: {case['state']}", "Rule trace:"]
            for r in case.get("reasons", []):
                lines.append(f"  {r['rule_id']} [{r['severity']}] via {r['tool']}")
            buttons = review_buttons(case_id) if case["state"] == "held" and chat.get("role") == "guardian" else []
            return self._reply(ev, "\n".join(lines), buttons)
        self._reply(ev, "I did not understand that button.")

    # ---- commands ---------------------------------------------------------------------

    def _on_command(self, ev: Incoming, chat: dict, lang: str, text: str) -> None:
        cmd, _, rest = text.partition(" ")
        cmd = cmd.lower().split("@", 1)[0]  # Telegram may send /cmd@botname
        rest = rest.strip()
        token = chat.get("token")
        role = chat.get("role")

        if cmd in ("/start", "/help"):
            return self._reply(ev, HELP)
        if cmd == "/lang":
            if rest not in LANGS:
                return self._reply(ev, "Choose one of: /lang en, /lang hi, /lang kn")
            self.chats.set_language(ev.platform, ev.chat_id, rest)
            return self._reply(ev, f"Language set to {rest}.")
        if cmd == "/parent":
            if token:
                return self._reply(ev, "This chat is already paired. Send /unlink first to start again.")
            name = _clip(rest or ev.name or "Parent", 40)
            res = self.backend.create_family(name, lang)
            self.chats.link(ev.platform, ev.chat_id, user_id=res["user_id"], family_id=res["family_id"],
                            role="parent", name=name, token=res["token"], lang=lang, now=self.now())
            return self._reply(ev, f"Family review is on for {name}.\n\nAsk your guardian to send me:\n"
                                   f"/join {res['pair_code']} <their name>\n\nThe code works for 10 minutes.")
        if cmd == "/join":
            if token:
                return self._reply(ev, "This chat is already paired. Send /unlink first to start again.")
            parts = rest.split(None, 1)
            if not parts:
                return self._reply(ev, "Send /join <code> <your name>, for example /join 3f9a-482913 Rohan")
            name = _clip(parts[1] if len(parts) > 1 else (ev.name or "Guardian"), 40)
            res = self.backend.join_family(parts[0], name, lang)
            self.chats.link(ev.platform, ev.chat_id, user_id=res["user_id"], family_id=res["family_id"],
                            role="guardian", name=name, token=res["token"], lang=lang, now=self.now())
            self._reply(ev, f"You are now a guardian, {name}. I will send review requests here with Approve and "
                            "Block buttons. /pending shows what is waiting.")
            for p in self.chats.family_chats(res["family_id"], "parent"):
                self.send(p["platform"], p["chat_id"], f"{name} joined as your guardian.")
            return self._push_reviews_to(self.chats.get(ev.platform, ev.chat_id))
        if cmd == "/unlink":
            self.chats.unlink(ev.platform, ev.chat_id)
            return self._reply(ev, "This chat is no longer linked to a family. Your family's cases are kept.")

        if cmd not in ("/code", "/pending", "/approve", "/block", "/status", "/stop", "/unlock"):
            return self._reply(ev, "I do not know that command. Send /help.")
        if not token:
            return self._reply(ev, "This chat is not paired with a family yet. Send /parent <your name> or "
                                   "/join <code> <your name>.")
        if cmd == "/code":
            if role != "parent":
                return self._reply(ev, "Only the parent can make a pairing code.")
            res = self.backend.new_pair_code(token)
            return self._reply(ev, f"Ask your guardian to send me:\n/join {res['pair_code']} <their name>")
        if cmd == "/pending":
            rows = self.backend.list_cases(token, ["held"])
            if not rows:
                return self._reply(ev, "Nothing is waiting for review.")
            for row in rows[:5]:
                case = self.backend.get_case(token, row["id"])
                buttons = review_buttons(row["id"]) if role == "guardian" else []
                self._reply(ev, render_review(case, lang, self.now()), buttons)
            return None
        if cmd in ("/approve", "/block"):
            parts = rest.split(None, 1)
            if not parts:
                return self._reply(ev, f"Send {cmd} <case id>")
            case_id = self._resolve_case(token, parts[0])
            return self._decide(ev, chat, lang, case_id, cmd[1:], parts[1] if len(parts) > 1 else None)
        if cmd == "/status":
            if not rest:
                rows = self.backend.list_cases(token, None, 5)
                if not rows:
                    return self._reply(ev, "No cases yet.")
                return self._reply(ev, "\n".join(
                    f"{r['id']} · {r['input_type']} · {r['risk_level']} · {r['state']}" for r in rows))
            case_id = self._resolve_case(token, rest)
            st = self.backend.case_status(token, case_id)
            return self._reply(ev, f"Case {case_id}: {st['state']} (risk {st['risk_level']})")
        if cmd == "/stop":
            res = self.backend.emergency_stop(token, rest or "Emergency Stop from chat")
            self.chats.mark_family_notified(chat["family_id"])
            packet_id = res["packet"]["packet_id"]
            for member in self.chats.family_chats(chat["family_id"]):
                self.send(member["platform"], member["chat_id"],
                          f"🛑 {chat['display_name']} pressed Emergency Stop. {ui('stopped', member['language'])}\n"
                          f"Locked cases: {len(res['locked_cases'])} · evidence packet {packet_id}")
            return None
        if cmd == "/unlock":
            if role != "guardian":
                return self._reply(ev, "Only a guardian can lift Emergency Stop.")
            self.backend.unlock(token)
            for member in self.chats.family_chats(chat["family_id"]):
                self.send(member["platform"], member["chat_id"], f"{chat['display_name']} lifted Emergency Stop.")
            return None
        self._reply(ev, "I do not know that command. Send /help.")
