"""Chat app layer: the shared bot core with fake transports, then the Telegram and WhatsApp adapters.

No test talks to Telegram or Meta. All data is synthetic.
"""

import hashlib
import hmac
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from bharosa.chatbot.core import CHECKS_PER_HOUR, ChatBot, ChatStore, Incoming
from bharosa.pipeline import DirectRunner, check_qr

ROOT = Path(__file__).resolve().parents[1]
CASHBACK = ("upi://pay?pa=rewards.desk.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&cu=INR"
            "&tn=Scan%20to%20receive%20cashback%20Rs%204999")
SHOP = "upi://pay?pa=sharmagrocery.demo@okaxis&pn=Sharma%20Grocery&am=240&cu=INR&tn=Order%2017"


class FakeTransport:
    def __init__(self, platform):
        self.platform = platform
        self.sent = []  # (chat_id, Outgoing)

    def send(self, chat_id, message):
        self.sent.append((chat_id, message))

    def to(self, chat_id):
        return [m for c, m in self.sent if c == chat_id]

    def last(self, chat_id):
        msgs = self.to(chat_id)
        return msgs[-1] if msgs else None


@pytest.fixture
def tg():
    return FakeTransport("telegram")


@pytest.fixture
def wa():
    return FakeTransport("whatsapp")


@pytest.fixture
def bot(service, clock, tg, wa, tmp_path):
    return ChatBot(service, ChatStore(tmp_path / "bot.db"), {"telegram": tg, "whatsapp": wa}, clock=clock)


def say(bot, platform, chat_id, text=None, image=None, action=None, name="Test"):
    bot.handle(Incoming(platform, chat_id, name, text=text, image=image, action=action))


@pytest.fixture
def paired(bot, tg, wa):
    """Amma on Telegram (chat 100), Rohan on WhatsApp (chat 9100000000)."""
    say(bot, "telegram", "100", "/parent Amma")
    code = tg.last("100").text.split("/join ", 1)[1].split()[0]
    say(bot, "whatsapp", "9100000000", f"/join {code} Rohan")
    return {"parent": ("telegram", "100"), "guardian": ("whatsapp", "9100000000")}


# ---- unpaired checks ------------------------------------------------------------------------


def test_help_and_unknown_command(bot, tg):
    say(bot, "telegram", "1", "/start")
    assert "Send me a message" in tg.last("1").text
    say(bot, "telegram", "1", "/nonsense")
    assert "do not know that command" in tg.last("1").text


def test_anyone_gets_a_verdict_for_a_scam_link(bot, tg):
    say(bot, "telegram", "1", "http://sbi-kyc-update.xyz/login")
    text = tg.last("1").text
    assert text.startswith("🔴")
    assert "Do not pay" in text and "/parent" in text


def test_qr_photo_is_decoded(bot, tg):
    say(bot, "telegram", "1", image=(ROOT / "samples/qr/shop.png").read_bytes())
    assert tg.last("1").text.startswith("🟢")
    say(bot, "telegram", "1", image=(ROOT / "samples/qr/cashback.png").read_bytes())
    assert tg.last("1").text.startswith("🔴")


def test_photo_without_qr_says_so(bot, tg):
    import cv2
    import numpy as np

    ok, png = cv2.imencode(".png", np.full((50, 50, 3), 255, dtype=np.uint8))
    say(bot, "telegram", "1", image=png.tobytes())
    assert "could not find a QR code" in tg.last("1").text


def test_scam_message_in_hindi(bot, tg):
    say(bot, "telegram", "1", "/lang hi")
    say(bot, "telegram", "1", (ROOT / "samples/messages/cbi_call.txt").read_text(encoding="utf-8"))
    text = tg.last("1").text
    assert text.startswith("🔴") and "OTP" in text


def test_per_chat_rate_limit(bot, tg):
    for _ in range(CHECKS_PER_HOUR):
        say(bot, "telegram", "1", "upi://pay?pa=x.demo@okaxis")
    say(bot, "telegram", "1", "upi://pay?pa=x.demo@okaxis")
    assert "a lot of checks" in tg.last("1").text


# ---- pairing and guardian review ------------------------------------------------------------


def test_pairing_across_platforms(bot, tg, wa, paired):
    assert "You are now a guardian, Rohan" in wa.last("9100000000").text
    assert "Rohan joined as your guardian" in tg.last("100").text
    say(bot, "telegram", "100", "/parent Again")
    assert "already paired" in tg.last("100").text


def test_risky_qr_is_held_and_guardian_blocks_it(bot, tg, wa, paired, service):
    say(bot, "telegram", "100", CASHBACK)
    parent_msg = tg.last("100").text
    assert "paused this payment" in parent_msg
    review = wa.last("9100000000")
    assert review.text.startswith("🔔 Review request from Amma")
    assert "rewards.desk.demo@okhdfcbank" not in review.text  # guardian sees the masked payee only
    assert [b.data.split(":")[0] for b in review.buttons] == ["approve", "block", "show"]
    case_id = review.buttons[1].data.split(":", 1)[1]

    say(bot, "whatsapp", "9100000000", action=f"block:{case_id}")
    assert "you blocked case" in wa.last("9100000000").text
    assert "Your family blocked this" in tg.last("100").text

    # Nothing more to report on the next tick, and the guardian is not asked twice.
    n_tg, n_wa = len(tg.sent), len(wa.sent)
    bot.tick()
    assert (len(tg.sent), len(wa.sent)) == (n_tg, n_wa)


def test_low_risk_case_is_allowed_without_review(bot, tg, wa, paired):
    n_wa = len(wa.sent)
    say(bot, "telegram", "100", SHOP)
    assert tg.last("100").text.startswith("🟢")
    assert "paused" not in tg.last("100").text
    assert len(wa.sent) == n_wa


def test_approve_by_typed_short_id_with_note(bot, tg, wa, paired):
    say(bot, "telegram", "100", CASHBACK)
    case_id = wa.last("9100000000").buttons[0].data.split(":", 1)[1]
    say(bot, "whatsapp", "9100000000", f"/approve {case_id[-6:]} I called them")
    assert "you approved" in wa.last("9100000000").text
    last = tg.last("100").text
    assert "approved it" in last and "I called them" in last


def test_parent_cannot_approve_and_strangers_see_nothing(bot, tg, wa, paired):
    say(bot, "telegram", "100", CASHBACK)
    case_id = wa.last("9100000000").buttons[0].data.split(":", 1)[1]
    say(bot, "telegram", "100", action=f"approve:{case_id}")
    assert "Only a paired guardian" in tg.last("100").text
    say(bot, "telegram", "555", action=f"approve:{case_id}")
    assert "not paired" in tg.last("555").text
    # A guardian of another family gets "not found", never the case.
    say(bot, "telegram", "200", "/parent Other")
    code = tg.last("200").text.split("/join ", 1)[1].split()[0]
    say(bot, "telegram", "201", f"/join {code} Stranger")
    say(bot, "telegram", "201", action=f"block:{case_id}")
    assert "case not found" in tg.last("201").text


def test_details_button_shows_rule_trace(bot, tg, wa, paired):
    say(bot, "telegram", "100", CASHBACK)
    case_id = wa.last("9100000000").buttons[0].data.split(":", 1)[1]
    say(bot, "whatsapp", "9100000000", action=f"show:{case_id}")
    msg = wa.last("9100000000")
    assert "Rule trace:" in msg.text and "State: held" in msg.text
    assert msg.buttons


def test_emergency_stop_and_unlock(bot, tg, wa, paired):
    say(bot, "telegram", "100", CASHBACK)
    case_id = wa.last("9100000000").buttons[0].data.split(":", 1)[1]
    say(bot, "telegram", "100", "/stop CBI call")
    assert "pressed Emergency Stop" in tg.last("100").text
    assert "pressed Emergency Stop" in wa.last("9100000000").text
    say(bot, "whatsapp", "9100000000", action=f"approve:{case_id}")
    assert "Emergency Stop is on" in wa.last("9100000000").text
    say(bot, "telegram", "100", "/unlock")
    assert "Only a guardian" in tg.last("100").text
    say(bot, "whatsapp", "9100000000", "/unlock")
    assert "lifted Emergency Stop" in tg.last("100").text


def test_tick_reports_cli_decisions_and_expiry(bot, tg, wa, paired, service, clock):
    say(bot, "telegram", "100", CASHBACK)
    first = wa.last("9100000000").buttons[0].data.split(":", 1)[1]
    # The guardian decides from the CLI instead of the chat.
    g_token = bot.chats.get("whatsapp", "9100000000")["token"]
    service.decide(g_token, first, "block", "seen in CLI")
    bot.tick()
    assert "seen in CLI" in tg.last("100").text

    say(bot, "telegram", "100", CASHBACK.replace("4999", "4998"))
    clock.advance(31 * 60)
    bot.tick()
    assert "Nobody reviewed this in time" in tg.last("100").text


def test_tick_pushes_cases_submitted_from_the_cli(bot, wa, paired, service):
    p_token = bot.chats.get("telegram", "100")["token"]
    r = check_qr(CASHBACK, DirectRunner(), service.check_context(p_token))
    service.submit_case(p_token, r.case_payload())
    service.request_approval(p_token, r.case_id)
    bot.tick()
    assert wa.last("9100000000").buttons[0].data == f"approve:{r.case_id}"
    n = len(wa.sent)
    bot.tick()
    assert len(wa.sent) == n


def test_guardian_who_joins_late_gets_waiting_cases(bot, tg, wa):
    say(bot, "telegram", "100", "/parent Amma")
    say(bot, "telegram", "100", CASHBACK)
    assert "No guardian has joined yet" in tg.last("100").text
    say(bot, "telegram", "100", "/code")
    code = tg.last("100").text.split("/join ", 1)[1].split()[0]
    say(bot, "whatsapp", "9100000000", f"/join {code} Rohan")
    assert wa.last("9100000000").text.startswith("🔔 Review request")


def test_unlink_forgets_the_token(bot, tg, paired):
    say(bot, "telegram", "100", "/unlink")
    assert bot.chats.get("telegram", "100")["token"] is None
    say(bot, "telegram", "100", "/code")
    assert "not paired" in tg.last("100").text


# ---- Telegram adapter ---------------------------------------------------------------------


class FakeTelegramAPI:
    def __init__(self, updates):
        self.updates = updates
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        body = json.loads(request.content) if request.content else {}
        self.calls.append((method, body))
        if request.url.path.startswith("/file/"):
            return httpx.Response(200, content=(ROOT / "samples/qr/cashback.png").read_bytes())
        if method == "getUpdates":
            ups, self.updates = self.updates, []
            return httpx.Response(200, json={"ok": True, "result": ups})
        if method == "getFile":
            return httpx.Response(200, json={"ok": True, "result": {"file_path": "photos/a.png", "file_size": 2000}})
        return httpx.Response(200, json={"ok": True, "result": {}})

    def sent(self):
        return [b for m, b in self.calls if m == "sendMessage"]


def _telegram(updates, service, clock, tmp_path):
    from bharosa.chatbot.telegram import TelegramTransport

    api = FakeTelegramAPI(updates)
    transport = TelegramTransport("123:SECRET", client=httpx.Client(transport=httpx.MockTransport(api)),
                                  api_base="https://tg.test")
    bot = ChatBot(service, ChatStore(tmp_path / "bot.db"), {"telegram": transport}, clock=clock)
    return api, transport, bot


def _msg(update_id, chat_id, text=None, chat_type="private", **extra):
    m = {"message_id": update_id, "chat": {"id": chat_id, "type": chat_type}, "from": {"first_name": "Amma"}}
    if text is not None:
        m["text"] = text
    m.update(extra)
    return {"update_id": update_id, "message": m}


def test_telegram_polling_text_photo_and_groups(service, clock, tmp_path):
    from bharosa.chatbot.telegram import poll_once

    api, transport, bot = _telegram([
        _msg(1, 100, "http://sbi-kyc-update.xyz/login"),
        _msg(2, 100, photo=[{"file_id": "small"}, {"file_id": "big"}]),
        _msg(3, -500, "http://sbi-kyc-update.xyz/login", chat_type="group"),
    ], service, clock, tmp_path)
    offset = poll_once(bot, transport, None, timeout=0)
    assert offset == 4
    sent = api.sent()
    assert len(sent) == 2  # the group message is ignored
    assert all(s["chat_id"] == "100" for s in sent)
    assert sent[0]["text"].startswith("🔴") and sent[1]["text"].startswith("🔴")
    assert ("getFile", {"file_id": "big"}) in api.calls


def test_telegram_buttons_and_callback(service, clock, tmp_path):
    from bharosa.chatbot.telegram import poll_once

    api, transport, bot = _telegram([_msg(1, 100, "/parent Amma")], service, clock, tmp_path)
    poll_once(bot, transport, None, timeout=0)
    code = api.sent()[-1]["text"].split("/join ", 1)[1].split()[0]
    api.updates = [_msg(2, 200, f"/join {code} Rohan"), _msg(3, 100, CASHBACK)]
    poll_once(bot, transport, 2, timeout=0)
    review = [s for s in api.sent() if s["chat_id"] == "200" and "reply_markup" in s][-1]
    buttons = review["reply_markup"]["inline_keyboard"][0]
    block = next(b["callback_data"] for b in buttons if b["callback_data"].startswith("block:"))
    api.updates = [{"update_id": 4, "callback_query": {
        "id": "cq1", "data": block, "from": {"id": 200, "first_name": "Rohan"},
        "message": {"chat": {"id": 200, "type": "private"}}}}]
    poll_once(bot, transport, 4, timeout=0)
    assert ("answerCallbackQuery", {"callback_query_id": "cq1"}) in api.calls
    assert "Your family blocked this" in api.sent()[-1]["text"]


def test_telegram_bad_update_does_not_stop_polling(service, clock, tmp_path, monkeypatch):
    from bharosa.chatbot.telegram import poll_once

    api, transport, bot = _telegram([_msg(1, 100, "boom"), _msg(2, 100, "http://sbi-kyc-update.xyz/login")],
                                    service, clock, tmp_path)
    real = bot.handle

    def flaky(ev):
        if ev.text == "boom":
            raise RuntimeError("unexpected")
        real(ev)

    monkeypatch.setattr(bot, "handle", flaky)
    assert poll_once(bot, transport, None, timeout=0) == 3  # the bad update is skipped, not replayed
    assert api.sent()[-1]["text"].startswith("🔴")


def test_empty_image_is_a_decode_error():
    from bharosa.qrdecode import QRDecodeError, decode_bytes

    with pytest.raises(QRDecodeError):
        decode_bytes(b"")


def test_telegram_errors_never_show_the_token():
    from bharosa.chatbot.telegram import TelegramError, TelegramTransport

    def boom(request):
        raise httpx.ConnectError("down", request=request)

    t = TelegramTransport("123:SECRET", client=httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(TelegramError) as exc:
        t.call("getMe")
    assert "SECRET" not in str(exc.value) and "SECRET" not in repr(t)


# ---- WhatsApp adapter ---------------------------------------------------------------------

APP_SECRET = "test-app-secret"


class FakeGraphAPI:
    def __init__(self):
        self.posts = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer wa-test-token"
        if request.method == "POST":
            self.posts.append(json.loads(request.content))
            return httpx.Response(200, json={"messages": [{"id": "wamid.x"}]})
        if request.url.path.endswith("/media-1"):
            return httpx.Response(200, json={"url": "https://media.test/qr.png", "file_size": 2000})
        if request.url.host == "media.test":
            return httpx.Response(200, content=(ROOT / "samples/qr/cashback.png").read_bytes())
        return httpx.Response(404)


@pytest.fixture
def whatsapp(service, clock, tmp_path):
    from bharosa.chatbot.whatsapp import WhatsAppTransport, create_webhook_app

    api = FakeGraphAPI()
    transport = WhatsAppTransport("wa-test-token", "PHONE1", client=httpx.Client(transport=httpx.MockTransport(api)),
                                  graph_base="https://graph.test")
    bot = ChatBot(service, ChatStore(tmp_path / "bot.db"), {"whatsapp": transport}, clock=clock)
    client = TestClient(create_webhook_app(bot, transport, "verify-me", APP_SECRET))
    return api, client


def _wa_post(client, messages, secret=APP_SECRET):
    body = json.dumps({"object": "whatsapp_business_account", "entry": [{"changes": [{"value": {
        "contacts": [{"wa_id": m["from"], "profile": {"name": "Amma"}} for m in messages],
        "messages": messages}}]}]}).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post("/whatsapp/webhook", content=body,
                       headers={"x-hub-signature-256": sig, "content-type": "application/json"})


def test_whatsapp_verify_handshake(whatsapp):
    _, client = whatsapp
    ok = client.get("/whatsapp/webhook", params={"hub.mode": "subscribe", "hub.verify_token": "verify-me",
                                                 "hub.challenge": "12345"})
    assert ok.status_code == 200 and ok.text == "12345"
    bad = client.get("/whatsapp/webhook", params={"hub.mode": "subscribe", "hub.verify_token": "nope",
                                                  "hub.challenge": "1"})
    assert bad.status_code == 403


def test_whatsapp_rejects_bad_signature(whatsapp):
    api, client = whatsapp
    r = _wa_post(client, [{"from": "9100000001", "id": "m1", "type": "text", "text": {"body": "hi"}}],
                 secret="wrong")
    assert r.status_code == 403 and api.posts == []


def test_whatsapp_text_image_dedupe_and_buttons(whatsapp):
    api, client = whatsapp
    link = {"from": "9100000001", "id": "m1", "type": "text", "text": {"body": "http://sbi-kyc-update.xyz/login"}}
    assert _wa_post(client, [link]).status_code == 200
    assert _wa_post(client, [link]).status_code == 200  # Meta retry: handled once
    assert len(api.posts) == 1 and api.posts[0]["text"]["body"].startswith("🔴")

    _wa_post(client, [{"from": "9100000001", "id": "m2", "type": "image",
                       "image": {"id": "media-1", "mime_type": "image/png"}}])
    assert api.posts[-1]["text"]["body"].startswith("🔴")

    # Pair a family on WhatsApp and check that the review uses reply buttons.
    _wa_post(client, [{"from": "9100000001", "id": "m3", "type": "text", "text": {"body": "/parent Amma"}}])
    code = api.posts[-1]["text"]["body"].split("/join ", 1)[1].split()[0]
    _wa_post(client, [{"from": "9100000002", "id": "m4", "type": "text", "text": {"body": f"/join {code} Rohan"}}])
    _wa_post(client, [{"from": "9100000001", "id": "m5", "type": "text", "text": {"body": CASHBACK}}])
    interactive = [p for p in api.posts if p["type"] == "interactive" and p["to"] == "9100000002"][-1]
    buttons = interactive["interactive"]["action"]["buttons"]
    assert all(len(b["reply"]["title"]) <= 20 for b in buttons)
    block = next(b["reply"]["id"] for b in buttons if b["reply"]["id"].startswith("block:"))
    _wa_post(client, [{"from": "9100000002", "id": "m6", "type": "interactive",
                       "interactive": {"type": "button_reply", "button_reply": {"id": block, "title": "Block"}}}])
    assert "Your family blocked this" in [p for p in api.posts if p["to"] == "9100000001"][-1]["text"]["body"]


# ---- CLI ---------------------------------------------------------------------------------


def test_bot_serve_needs_credentials(monkeypatch):
    from typer.testing import CliRunner

    from bharosa.cli import app

    for var in ("BHAROSA_TELEGRAM_TOKEN", "BHAROSA_WHATSAPP_TOKEN", "BHAROSA_WHATSAPP_PHONE_ID",
                "BHAROSA_WHATSAPP_VERIFY_TOKEN", "BHAROSA_WHATSAPP_APP_SECRET"):
        monkeypatch.delenv(var, raising=False)
    r = CliRunner().invoke(app, ["bot", "serve"])
    assert r.exit_code == 1 and "No chat platform configured" in r.output
    monkeypatch.setenv("BHAROSA_WHATSAPP_TOKEN", "x")
    r = CliRunner().invoke(app, ["bot", "serve", "--whatsapp"])
    assert r.exit_code == 1 and "BHAROSA_WHATSAPP_PHONE_ID" in r.output
