"""Start the chat bots from environment variables (``bharosa bot serve``).

One process runs every configured platform, so a parent on Telegram can have a guardian on
WhatsApp. Telegram polls in a background thread, a ticker pushes review requests and outcomes,
and the WhatsApp webhook (when configured) runs in uvicorn in the foreground.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..backend import RelayBackend
from ..config import db_path, home
from ..service import FamilyService
from ..store import Store
from .core import ChatBot, ChatStore

log = logging.getLogger("bharosa.bot")


@dataclass
class BotSettings:
    telegram_token: str | None
    wa_token: str | None
    wa_phone_id: str | None
    wa_verify_token: str | None
    wa_app_secret: str | None
    wa_api_version: str
    relay_url: str | None
    bot_db: Path
    lang: str

    @classmethod
    def from_env(cls) -> "BotSettings":
        e = os.environ.get
        return cls(
            telegram_token=e("BHAROSA_TELEGRAM_TOKEN") or None,
            wa_token=e("BHAROSA_WHATSAPP_TOKEN") or None,
            wa_phone_id=e("BHAROSA_WHATSAPP_PHONE_ID") or None,
            wa_verify_token=e("BHAROSA_WHATSAPP_VERIFY_TOKEN") or None,
            wa_app_secret=e("BHAROSA_WHATSAPP_APP_SECRET") or None,
            wa_api_version=e("BHAROSA_WHATSAPP_API_VERSION") or "v21.0",
            relay_url=e("BHAROSA_RELAY_URL") or None,
            bot_db=Path(e("BHAROSA_BOT_DB") or home() / "bot.db"),
            lang=e("BHAROSA_BOT_LANG") or "en",
        )

    @property
    def telegram_ready(self) -> bool:
        return bool(self.telegram_token)

    @property
    def whatsapp_ready(self) -> bool:
        return all((self.wa_token, self.wa_phone_id, self.wa_verify_token, self.wa_app_secret))

    def whatsapp_missing(self) -> list[str]:
        names = {"BHAROSA_WHATSAPP_TOKEN": self.wa_token, "BHAROSA_WHATSAPP_PHONE_ID": self.wa_phone_id,
                 "BHAROSA_WHATSAPP_VERIFY_TOKEN": self.wa_verify_token,
                 "BHAROSA_WHATSAPP_APP_SECRET": self.wa_app_secret}
        return [k for k, v in names.items() if not v]


def build_bot(settings: BotSettings) -> ChatBot:
    backend = RelayBackend(settings.relay_url) if settings.relay_url else FamilyService(Store(db_path()))
    return ChatBot(backend, ChatStore(settings.bot_db), default_lang=settings.lang)


def _ticker(bot: ChatBot, every: float, stop: threading.Event) -> None:
    while not stop.wait(every):
        try:
            bot.tick()
        except Exception as exc:  # keep ticking; the next round may succeed
            log.warning("tick failed: %s", type(exc).__name__)


def serve(settings: BotSettings, *, telegram: bool, whatsapp: bool, host: str, port: int,
          tick_seconds: float = 5.0) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # its INFO lines would print the Telegram token URL

    bot = build_bot(settings)
    stop = threading.Event()
    threads = [threading.Thread(target=_ticker, args=(bot, tick_seconds, stop), daemon=True, name="tick")]

    if telegram:
        from .telegram import TelegramTransport, run_polling

        tg = TelegramTransport(settings.telegram_token or "")
        bot.add_transport(tg)
        threads.append(threading.Thread(target=run_polling, args=(bot, tg, stop.is_set), daemon=True,
                                        name="telegram"))
    app = None
    if whatsapp:
        from .whatsapp import WhatsAppTransport, create_webhook_app

        wa = WhatsAppTransport(settings.wa_token or "", settings.wa_phone_id or "", settings.wa_api_version)
        bot.add_transport(wa)
        app = create_webhook_app(bot, wa, settings.wa_verify_token or "", settings.wa_app_secret or "")

    for t in threads:
        t.start()
    try:
        if app is not None:
            import uvicorn

            log.info("WhatsApp webhook on http://%s:%d/whatsapp/webhook", host, port)
            uvicorn.run(app, host=host, port=port, log_level="warning")
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
