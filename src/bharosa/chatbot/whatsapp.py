"""WhatsApp adapter: Meta WhatsApp Cloud API webhook (FastAPI) plus the Graph API for replies.

Environment (all from your Meta app; nothing is hardcoded):

* ``BHAROSA_WHATSAPP_TOKEN``         access token for the Graph API
* ``BHAROSA_WHATSAPP_PHONE_ID``      the WhatsApp phone number id that sends replies
* ``BHAROSA_WHATSAPP_VERIFY_TOKEN``  any string you choose; Meta echoes it when you register the webhook
* ``BHAROSA_WHATSAPP_APP_SECRET``    app secret, used to check the ``X-Hub-Signature-256`` header
* ``BHAROSA_WHATSAPP_API_VERSION``   optional, default ``v21.0``

Every webhook POST must carry a valid signature, or it is rejected with 403.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections import OrderedDict
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from starlette.concurrency import run_in_threadpool

from ..qrdecode import MAX_IMAGE_BYTES
from .core import ChatBot, Incoming, Outgoing

log = logging.getLogger("bharosa.whatsapp")
GRAPH = "https://graph.facebook.com"
MAX_BUTTON_BODY = 1024  # interactive message body limit
MAX_BUTTON_TITLE = 20


class WhatsAppError(RuntimeError):
    pass


class WhatsAppTransport:
    platform = "whatsapp"

    def __init__(self, token: str, phone_id: str, api_version: str = "v21.0", client: httpx.Client | None = None,
                 graph_base: str = GRAPH):
        if not token or not phone_id:
            raise WhatsAppError("BHAROSA_WHATSAPP_TOKEN and BHAROSA_WHATSAPP_PHONE_ID must be set")
        self._token = token
        self.phone_id = phone_id
        self.base = f"{graph_base.rstrip('/')}/{api_version}"
        self.client = client or httpx.Client(timeout=20)

    def __repr__(self) -> str:
        return f"WhatsAppTransport(phone_id={self.phone_id}, token=***)"

    @property
    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    def _post(self, payload: dict) -> None:
        try:
            r = self.client.post(f"{self.base}/{self.phone_id}/messages", json=payload, headers=self._auth)
        except httpx.HTTPError as exc:
            raise WhatsAppError(f"WhatsApp send failed: {type(exc).__name__}") from None
        if r.status_code >= 400:
            raise WhatsAppError(f"WhatsApp send failed: HTTP {r.status_code}")

    def send(self, chat_id: str, message: Outgoing) -> None:
        base = {"messaging_product": "whatsapp", "to": chat_id}
        if not message.buttons:
            self._post({**base, "type": "text", "text": {"body": message.text, "preview_url": False}})
            return
        body = message.text
        if len(body) > MAX_BUTTON_BODY:
            # Long review: send the full text, then a short message that carries the buttons.
            self._post({**base, "type": "text", "text": {"body": body, "preview_url": False}})
            body = "Your decision:"
        buttons = [{"type": "reply", "reply": {"id": b.data[:256], "title": b.label[:MAX_BUTTON_TITLE]}}
                   for b in message.buttons[:3]]
        self._post({**base, "type": "interactive",
                    "interactive": {"type": "button", "body": {"text": body}, "action": {"buttons": buttons}}})

    def download_media(self, media_id: str, max_bytes: int = MAX_IMAGE_BYTES) -> bytes | None:
        try:
            meta = self.client.get(f"{self.base}/{media_id}", headers=self._auth)
            if meta.status_code != 200:
                return None
            info = meta.json()
            if int(info.get("file_size", 0)) > max_bytes or not info.get("url"):
                return None
            r = self.client.get(info["url"], headers=self._auth)
        except (httpx.HTTPError, ValueError):
            raise WhatsAppError("WhatsApp media download failed") from None
        if r.status_code != 200 or len(r.content) > max_bytes:
            return None
        return r.content


def valid_signature(app_secret: str, body: bytes, header: str | None) -> bool:
    if not app_secret or not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[len("sha256="):])


def payload_to_events(payload: dict, transport: WhatsAppTransport) -> list[tuple[str, Incoming | None]]:
    """Return (message_id, event) pairs. Status callbacks (delivered, read) are ignored."""
    out: list[tuple[str, Incoming | None]] = []
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            names = {c.get("wa_id"): (c.get("profile") or {}).get("name", "") for c in value.get("contacts", [])}
            for m in value.get("messages", []):
                sender = m.get("from")
                if not sender:
                    continue
                name = names.get(sender, "")
                kind = m.get("type")
                ev: Incoming | None
                if kind == "text":
                    ev = Incoming("whatsapp", sender, name, text=m["text"].get("body", ""))
                elif kind == "interactive":
                    reply = m["interactive"].get("button_reply") or m["interactive"].get("list_reply") or {}
                    ev = Incoming("whatsapp", sender, name, action=reply.get("id"))
                elif kind == "button":
                    ev = Incoming("whatsapp", sender, name, action=(m.get("button") or {}).get("payload"))
                elif kind in ("image", "document") and str((m.get(kind) or {}).get("mime_type", "")).startswith("image/"):
                    media = m[kind]
                    image = transport.download_media(media["id"])
                    caption = media.get("caption")
                    if image is None and not caption:
                        transport.send(sender, Outgoing("That image is too large. Send a photo under 5 MB."))
                        ev = None
                    else:
                        ev = Incoming("whatsapp", sender, name, text=caption, image=image)
                else:
                    transport.send(sender, Outgoing("I can check text, links and photos of QR codes. Send 'help'."))
                    ev = None
                out.append((m.get("id", ""), ev))
    return out


def create_webhook_app(bot: ChatBot, transport: WhatsAppTransport, verify_token: str, app_secret: str) -> FastAPI:
    if not verify_token or not app_secret:
        raise WhatsAppError("BHAROSA_WHATSAPP_VERIFY_TOKEN and BHAROSA_WHATSAPP_APP_SECRET must be set")
    app = FastAPI(title="Bharosa WhatsApp webhook", docs_url=None, redoc_url=None, openapi_url=None)
    seen: OrderedDict[str, None] = OrderedDict()  # Meta retries deliveries; handle each message once

    @app.get("/health")
    def health() -> dict:
        return {"ok": True}

    @app.get("/whatsapp/webhook", response_class=PlainTextResponse)
    def verify(mode: str = Query("", alias="hub.mode"), token: str = Query("", alias="hub.verify_token"),
               challenge: str = Query("", alias="hub.challenge")) -> str:
        if mode == "subscribe" and hmac.compare_digest(token, verify_token):
            return challenge
        raise HTTPException(status_code=403, detail="verification failed")

    @app.post("/whatsapp/webhook")
    async def receive(request: Request) -> dict:
        body = await request.body()
        if not valid_signature(app_secret, body, request.headers.get("x-hub-signature-256")):
            raise HTTPException(status_code=403, detail="bad signature")
        try:
            payload: Any = json.loads(body)
        except ValueError:
            raise HTTPException(status_code=400, detail="bad json") from None
        try:
            events = await run_in_threadpool(payload_to_events, payload, transport)
        except WhatsAppError as exc:
            log.warning("%s", exc)
            return {"ok": True}
        for msg_id, ev in events:
            if msg_id and msg_id in seen:
                continue
            if msg_id:
                seen[msg_id] = None
                while len(seen) > 1000:
                    seen.popitem(last=False)
            if ev is not None:
                await run_in_threadpool(bot.handle, ev)
        return {"ok": True}

    return app
