"""Telegram adapter: long polling against the Telegram Bot API over httpx.

Long polling needs no public URL, so the bot runs from a laptop behind venue Wi-Fi. Set the token
from @BotFather in ``BHAROSA_TELEGRAM_TOKEN``. The token is part of every Bot API URL, so errors
raised here never include the URL.

Only private chats are served: in a group anyone could press a guardian's Approve button.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import httpx

from ..qrdecode import MAX_IMAGE_BYTES
from .core import ChatBot, Incoming, Outgoing

log = logging.getLogger("bharosa.telegram")
API = "https://api.telegram.org"


class TelegramError(RuntimeError):
    pass


class TelegramTransport:
    platform = "telegram"

    def __init__(self, token: str, client: httpx.Client | None = None, api_base: str = API):
        if not token:
            raise TelegramError("BHAROSA_TELEGRAM_TOKEN is not set")
        self._token = token
        self.api_base = api_base.rstrip("/")
        self.client = client or httpx.Client(timeout=40)

    def __repr__(self) -> str:  # never show the token
        return "TelegramTransport(***)"

    def call(self, method: str, **params: Any) -> Any:
        url = f"{self.api_base}/bot{self._token}/{method}"
        try:
            r = self.client.post(url, json=params)
        except httpx.HTTPError as exc:
            raise TelegramError(f"Telegram {method} failed: {type(exc).__name__}") from None
        try:
            body = r.json()
        except ValueError:
            raise TelegramError(f"Telegram {method} returned HTTP {r.status_code}") from None
        if not body.get("ok"):
            raise TelegramError(f"Telegram {method}: {body.get('description', r.status_code)}")
        return body["result"]

    def send(self, chat_id: str, message: Outgoing) -> None:
        params: dict[str, Any] = {"chat_id": chat_id, "text": message.text, "disable_web_page_preview": True}
        if message.buttons:
            params["reply_markup"] = {"inline_keyboard": [[{"text": b.label, "callback_data": b.data[:64]}
                                                           for b in message.buttons]]}
        self.call("sendMessage", **params)

    def download_file(self, file_id: str, max_bytes: int = MAX_IMAGE_BYTES) -> bytes | None:
        info = self.call("getFile", file_id=file_id)
        if info.get("file_size", 0) > max_bytes or not info.get("file_path"):
            return None
        try:
            r = self.client.get(f"{self.api_base}/file/bot{self._token}/{info['file_path']}")
        except httpx.HTTPError:
            raise TelegramError("Telegram file download failed") from None
        if r.status_code != 200 or len(r.content) > max_bytes:
            return None
        return r.content


def update_to_event(update: dict, transport: TelegramTransport) -> tuple[Incoming | None, str | None]:
    """Turn one Telegram update into an Incoming event. Returns (event, callback_query_id)."""
    if "callback_query" in update:
        cq = update["callback_query"]
        msg = cq.get("message") or {}
        chat = msg.get("chat") or {}
        if chat.get("type") != "private":
            return None, cq.get("id")
        return Incoming("telegram", str(chat["id"]), cq.get("from", {}).get("first_name", ""),
                        action=cq.get("data")), cq.get("id")
    msg = update.get("message")
    if not msg or (msg.get("chat") or {}).get("type") != "private":
        return None, None
    chat_id = str(msg["chat"]["id"])
    name = (msg.get("from") or {}).get("first_name", "")
    text = msg.get("text") or msg.get("caption")
    image = None
    file_id = None
    if msg.get("photo"):
        file_id = msg["photo"][-1]["file_id"]  # largest size comes last
    elif (msg.get("document") or {}).get("mime_type", "").startswith("image/"):
        file_id = msg["document"]["file_id"]
    if file_id:
        image = transport.download_file(file_id)
        if image is None and not text:
            transport.send(chat_id, Outgoing("That image is too large. Send a photo under 5 MB."))
            return None, None
    if text is None and image is None:
        return Incoming("telegram", chat_id, name, text=""), None
    return Incoming("telegram", chat_id, name, text=text, image=image), None


def poll_once(bot: ChatBot, transport: TelegramTransport, offset: int | None, timeout: int = 25) -> int | None:
    params: dict[str, Any] = {"timeout": timeout, "allowed_updates": ["message", "callback_query"]}
    if offset is not None:
        params["offset"] = offset
    updates = transport.call("getUpdates", **params)
    for update in updates:
        offset = update["update_id"] + 1
        try:
            ev, cq_id = update_to_event(update, transport)
            if cq_id:
                try:
                    transport.call("answerCallbackQuery", callback_query_id=cq_id)
                except TelegramError:
                    pass
            if ev is not None:
                bot.handle(ev)
        except TelegramError as exc:
            log.warning("%s", exc)
        except Exception as exc:  # one bad update must not stop the bot or be replayed forever
            log.warning("update %s failed: %s", update.get("update_id"), type(exc).__name__)
    return offset


def run_polling(bot: ChatBot, transport: TelegramTransport, stop: Callable[[], bool] = lambda: False) -> None:
    me = transport.call("getMe")
    log.info("Telegram bot @%s is polling", me.get("username"))
    offset = None
    backoff = 1.0
    while not stop():
        try:
            offset = poll_once(bot, transport, offset)
            backoff = 1.0
        except Exception as exc:  # TelegramError or anything unexpected: keep polling
            log.warning("%s; retrying in %.0fs", exc if isinstance(exc, TelegramError) else type(exc).__name__,
                        backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
