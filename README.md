# Bharosa

**A family safety layer for suspicious payment QR codes, links and scam messages.**

Bharosa is a command-line tool, an MCP server, Telegram/WhatsApp bots and an Android app. Run `bharosa check` on a QR image, a link or a message and it gives a deterministic risk verdict with the reasons, in English, Hindi or Kannada. A risky case is paused and lands in a family guardian's terminal, where they approve it, block it or press Emergency Stop.

> **Prototype scope:** Bharosa does not process UPI payments, replace payment apps, or guarantee that a payment or message is safe. In the CLI the "continue to UPI app" step is a mock handoff that prints the payment link and never executes it. The Android app hands an allowed or guardian-approved `upi://pay` link to Android's UPI app chooser; the payment app then asks for the PIN as usual, and Bharosa never sees it. Bharosa can pause only its own flow; it cannot block a transaction inside another app. All sample data is synthetic.

## Contents

- [Quick start](#quick-start)
- [Demo: the three scenarios](#demo-the-three-scenarios)
- [Parent and guardian](#parent-and-guardian)
- [Chat apps: Telegram and WhatsApp](#chat-apps-telegram-and-whatsapp)
- [Android app](#android-app)
- [Commands](#commands)
- [MCP server](#mcp-server)
- [How a verdict is decided](#how-a-verdict-is-decided)
- [Privacy, data and security as built](#privacy-data-and-security-as-built)
- [Voice warnings](#voice-warnings)
- [Optional paid integrations](#optional-paid-integrations-off-by-default)
- [Tests and evaluation](#tests-and-evaluation)
- [Project layout](#project-layout)
- [Limitations](#limitations)

## Quick start

Needs Python 3.11 or newer (developed on 3.14, CI runs 3.12). Everything runs offline on a laptop.

Windows (PowerShell):

```powershell
cd Bharosa
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
bharosa version
```

macOS or Linux:

```bash
cd Bharosa
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
bharosa version
```

On Windows, if Hindi or Kannada text shows as boxes, use Windows Terminal and run `$env:PYTHONIOENCODING = "utf-8"` once in the session.

Try a check straight away (no pairing needed):

```powershell
bharosa check qr samples/qr/shop.png
bharosa check url "http://sbi-kyc-update.xyz/login"
bharosa check msg -f samples/messages/cbi_call.txt --lang hi
```

## Demo: the three scenarios

The demo uses two terminals: "Amma's laptop" (parent) and "Rohan's laptop" (guardian). On one laptop they share a local SQLite file through two profiles, so no network is needed.

**Terminal 1, Amma (parent):**

```powershell
$env:BHAROSA_PROFILE = "amma"
bharosa pair --name Amma --lang hi
```

This prints a pairing code such as `3f9a-482913`, valid for 10 minutes.

**Terminal 2, Rohan (guardian):**

```powershell
$env:BHAROSA_PROFILE = "rohan"
bharosa pair --join 3f9a-482913 --name Rohan --phone "+91 90000 00000" --code-word mango
bharosa guardian watch
```

**Back in Terminal 1, run the scenarios:**

```powershell
# 1. Clean sample: green panel, "No known warning signs found", mock handoff with the payment link
bharosa check qr samples/qr/shop.png

# 2. Suspicious QR: red panel, Hindi warning and voice, held for Rohan. Rohan blocks it in Terminal 2.
bharosa check qr samples/qr/cashback.png --voice --lang hi

# 3. Digital arrest message: playbook match with authority, threat, secrecy and payment signals
bharosa check msg -f samples/messages/cbi_call.txt --explain
```

While a high-risk case waits, Amma's terminal shows the **Cool-off Clock** (10 minutes by default, `--cooloff 60` for a short demo) with a calm script and "Call Rohan now". Rohan decides in Terminal 2:

```powershell
bharosa guardian show <case-id>          # every reason plus the rule trace
bharosa guardian block <case-id> --note "Fake reward"
bharosa stop --reason "CBI call to Amma" # Emergency Stop + redacted evidence packet + 1930 helpline
bharosa guardian unlock
bharosa guardian stats                   # median time from flag to decision
```

Short ids work too: the last 6 characters of a case id are enough. Use `--no-wait` on a check to return straight away.

More samples: `samples/qr/` (`shop`, `milk`, `cashback`, `refund`, `not_upi`), `samples/messages/` (`cbi_call`, `kyc_sms`, `relative`, `electricity_hi`, `family_kn`) and `samples/chats/family_chat.txt`. Regenerate the QR images with `python scripts/make_samples.py`.

## Parent and guardian

**Local mode (default).** Profiles live in `~/.bharosa/profiles/` and share `~/.bharosa/bharosa.db`. Pick the profile with `BHAROSA_PROFILE`. This is also the offline fallback if venue Wi-Fi fails.

**Relay mode (two laptops).** Run the family relay on one machine, then pair both laptops against it:

```powershell
bharosa relay --host 0.0.0.0 --port 8765 --db bharosa-relay.db
```

```powershell
bharosa pair --name Amma --relay http://<relay-host>:8765
```

```powershell
bharosa pair --join <code> --name Rohan --relay http://<relay-host>:8765
```

After pairing, every command on that profile uses the relay. `bharosa config set relay local` switches back. The relay can also run with `uvicorn bharosa.relay.app:app_factory --factory` and `BHAROSA_RELAY_DB=path.db`. It has no TLS of its own: put it behind HTTPS (for example a Cloudflare Tunnel) before using it outside a local network.

| Environment variable | Meaning | Default |
|---|---|---|
| `BHAROSA_HOME` | Folder for the local DB, profiles, evidence and voice cache | `~/.bharosa` |
| `BHAROSA_PROFILE` | Which identity this terminal uses | `default` |
| `BHAROSA_RELAY_URL` | Force relay mode for this terminal | unset (local) |
| `BHAROSA_DIRECT` | `1` skips the MCP subprocess and calls the rules in-process | unset |
| `BHAROSA_RULES_DIR` | Load an edited copy of the YAML rule packs | built-in packs |
| `BHAROSA_VOICE_ENGINE` | `espeak`, `sapi`, `say`, `elevenlabs` or `text` | auto |
| `BHAROSA_NO_KEYRING` | `1` stores the API token in the profile file instead of the OS keyring | unset |
| `BHAROSA_RELAY_DB` | Relay database when started through uvicorn | `bharosa-relay.db` |

## Chat apps: Telegram and WhatsApp

Parents can forward a suspicious message, link, `upi://` link or a photo of a QR code to the Bharosa bot and get the verdict back in the same chat. Guardians get review requests with **Approve**, **Block** and **Details** buttons. One `bharosa bot serve` process runs every platform you configure, so a parent on Telegram can have a guardian on WhatsApp.

The bot uses the same deterministic checks as `bharosa check` and the same family queue: the local SQLite file, or the relay when `BHAROSA_RELAY_URL` is set. Anyone can get a verdict. A chat paired as a parent also sends its risky cases to the family for review.

**Telegram (free, no public URL needed).** Create a bot with [@BotFather](https://t.me/BotFather), then:

```powershell
$env:BHAROSA_TELEGRAM_TOKEN = "<token from BotFather>"
bharosa bot serve
```

The bot uses long polling, so it works from a laptop on venue Wi-Fi. It answers private chats only, because in a group anyone could press a guardian's buttons.

**WhatsApp (Meta WhatsApp Cloud API).** Create a Meta app with the WhatsApp product and use its test number. Then set:

```powershell
$env:BHAROSA_WHATSAPP_TOKEN = "<access token>"
$env:BHAROSA_WHATSAPP_PHONE_ID = "<phone number id>"
$env:BHAROSA_WHATSAPP_APP_SECRET = "<app secret>"
$env:BHAROSA_WHATSAPP_VERIFY_TOKEN = "<any string you choose>"
bharosa bot serve --port 8780
```

Expose the webhook over HTTPS (for example `cloudflared tunnel --url http://localhost:8780`), and register `https://<tunnel>/whatsapp/webhook` with the same verify token in the Meta app's WhatsApp configuration. Subscribe it to `messages`. Every POST must carry a valid `X-Hub-Signature-256` from your app secret, or it is rejected. Meta's test number can message only the recipient numbers you add in the app. Check Meta's current pricing before you go past the test number.

When both sets of variables are present, `bharosa bot serve` runs both. Use `--no-telegram` or `--no-whatsapp` to turn one off.

**In the chat:**

| Message | What happens |
|---|---|
| Any text, a link, a `upi://` link or a QR photo | Verdict with reasons, Truth Card and masking summary |
| `/parent <name>` | Turn on family review for this chat; prints a pairing code |
| `/join <code> <name>` | Join as a guardian; cases already waiting are sent straight away |
| `/code` | A fresh pairing code (parent) |
| Approve / Block / Details buttons, or `/approve <case>` and `/block <case> [note]` | Guardian decision; the parent is told at once. The last 6 characters of a case id are enough |
| `/pending`, `/status [case]` | What is waiting, and where a case stands |
| `/stop [reason]` / `/unlock` | Emergency Stop for the whole family, and lifting it (guardian) |
| `/lang en\|hi\|kn`, `/unlink`, `/help` | Language, forget this chat's link, help |

Every few seconds the bot also pushes held cases that came from the CLI to guardians paired in a chat, and tells the parent's chat when a case was decided from the CLI, expired or was stopped. CLI and chat family members can therefore mix.

**Privacy in chat mode.** This differs from the CLI, so read it before a demo:

- The parent's original message or photo goes through Telegram's or Meta's servers to the bot, because the parent sent it there. Masking runs on the machine that runs the bot, not on the parent's phone.
- The bot does not keep raw input. The family queue gets only the masked case. Guardians see only masked content, the masked payee and the reasons.
- The chat link file (`BHAROSA_BOT_DB`, default `~/.bharosa/bot.db`) maps chat ids to family members and holds each member's Bharosa API token, as a CLI profile does. Keep it on the bot machine, readable only by you, and delete it after the event.
- Bot tokens and API credentials are read only from environment variables and never logged. httpx request logging is turned down because Telegram puts the token in the URL. The tests use fake transports and never call Telegram or Meta.
- Each chat is limited to 30 checks per hour, on top of the family limit of 30 cases per hour.

| Variable | Meaning | Default |
|---|---|---|
| `BHAROSA_TELEGRAM_TOKEN` | Telegram bot token | unset (Telegram off) |
| `BHAROSA_WHATSAPP_TOKEN`, `_PHONE_ID`, `_APP_SECRET`, `_VERIFY_TOKEN` | WhatsApp Cloud API credentials | unset (WhatsApp off) |
| `BHAROSA_WHATSAPP_API_VERSION` | Graph API version | `v21.0` |
| `BHAROSA_BOT_DB` | Chat link file | `~/.bharosa/bot.db` |
| `BHAROSA_BOT_LANG` | Language for chats that have not chosen one | `en` |

## Android app

A native Kotlin app in [android/](android/) for the parent's and the guardian's phones. It talks to the family relay, so the risk decision stays in the Python rule packs and the app never scores anything itself.

**What it does**

- **Scan a payment QR in the app** (ZXing). The relay checks it. Low risk shows the reasons and a **Continue to UPI app** button, which opens Android's UPI app chooser with the same `upi://pay` link, prefilled.
- **Risky payments wait for family.** A medium or high result is held as a guardian review case in the same queue the CLI and the bots use. The parent sees "waiting for your family". When a guardian approves, the parent gets the Continue button; when they block, the parent is told not to pay. The app checks the link's SHA-256 against the approved case before handing it off.
- **Guardians decide from the app or from the bot.** The guardian's home screen lists held cases (masked content, payee, amount, reasons) with Approve and Block. A guardian paired with the Telegram or WhatsApp bot gets the same case as a push with buttons, provided the bot runs against the same relay (`BHAROSA_RELAY_URL`).
- **Opens `upi://` links.** Bharosa registers as a handler for `upi://`, so a payment link tapped in a browser or chat can be opened with Bharosa and checked first. Its own hand-off leaves Bharosa out of the chooser.
- **Share target for text.** In WhatsApp, Messages or a browser, Share a message or link and pick **Check with Bharosa**. Shared text is checked as a message, link or UPI link. Shared messages are never turned into payments.
- **Emergency Stop** for either role, **Lift Emergency Stop** for guardians, English, Hindi or Kannada warnings, and pairing in either direction (the app's pairing code works with the bot's `/join`).

**Run it**

1. Start the relay so the phone can reach it:

   ```powershell
   bharosa relay --host 0.0.0.0 --port 8765
   ```

   To let the bot's guardians decide app cases, run the bot against the same relay:

   ```powershell
   $env:BHAROSA_RELAY_URL = "http://127.0.0.1:8765"; bharosa bot serve
   ```

2. Build and install. You need the Android SDK (platform 35) and JDK 17. The Gradle wrapper downloads everything else.

   ```powershell
   cd android; .\gradlew.bat assembleDebug
   ```

   ```powershell
   adb install -r android\app\build\outputs\apk\debug\app-debug.apk
   ```

   Or open `android/` in Android Studio and press Run. If Gradle fails with "Unable to establish loopback connection" on Windows, point Java's socket temp folder at a short existing folder and try again: `$env:JAVA_TOOL_OPTIONS = "-Djdk.net.unixdomain.tmpdir=C:\gradle-tmp"`.

3. In the app, open **Setup**. The emulator reaches the laptop at `http://10.0.2.2:8765` (the default). A real phone on the same Wi-Fi uses `http://<laptop IP>:8765`; allow port 8765 through Windows Firewall for private networks. Then **Create our family** on the parent's phone, and **Join family** with the pairing code on the guardian's phone (or `/join <code> <name>` in the bot).

To try it without printing QRs, show `samples/qr/*.png` on the laptop screen and scan them, or open a link with Bharosa from adb:

```powershell
adb shell am start -a android.intent.action.VIEW -d "upi://pay?pa=rewards.desk.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback"
```

The emulator has no UPI app, so an allowed payment ends with "No UPI app on this phone", which is the safe outcome for a demo. **On a real phone, do not enter a UPI PIN for the demo payees**: the sample UPI IDs are synthetic, but a real payment app would still try to pay them.

**The check API** (added to the relay for the app):

| Route | Use |
|---|---|
| `POST /check` `{content, kind: auto\|qr\|url\|msg, lang}` | Run the checks. With a parent's token the masked case is queued, and `action` is `proceed`, `hold` (sent for review) or `stop` (Emergency Stop on). Without a token nothing is stored and a risky result is `warn`. Returns the headline, reasons, Truth Card, masked payee, amount, `is_payment` and `input_sha256` |
| `GET /cases?state=held`, `GET /cases/{id}`, `POST /cases/{id}/decision` | Guardian queue and decisions (existing routes) |
| `GET /cases/{id}/status`, `POST /cases/{id}/handoff` | The parent waits for a decision, then records the hand-off (refused unless allowed or approved) |

**Privacy in app mode.** The CLI masks on the parent's laptop. The phone cannot run the rule packs, so the app sends what it scanned or was shared to the relay over HTTP. The relay checks it in memory and stores only the masked case, as with the bots. The raw `upi://` link stays on the parent's phone until hand-off. The app keeps its relay token in app-private preferences (move it to the Android Keystore before real use), and allows plain HTTP because the hackathon relay runs on a laptop; put the relay behind HTTPS for anything beyond a demo. Checks without a token are limited to 60 per hour per address.

## Commands

Every check command takes `--lang en|hi|kn`, `--voice`, `--json`, `--explain` (full rule trace), `--no-wait`, `--direct` and `--keep-raw`.

| Command | What it does |
|---|---|
| `bharosa check qr <image>` / `--payload <upi://...>` / `--camera` | Decode and inspect a UPI QR |
| `bharosa check url <url>` | Inspect a link without opening it |
| `bharosa check msg "<text>"` / `-f file` | Match a message against scam playbooks; links and UPI IDs inside it are checked too |
| `bharosa check chat <export.txt>` | Scan a whole exported WhatsApp chat |
| `bharosa watch clipboard` | Check every copied link, UPI ID or message |
| `bharosa status <case-id>` / `bharosa history` | A case's state / recent cases |
| `bharosa pair` / `pair --join <code>` / `--new-code` / `--status` / `--reset` | Link parent and guardian |
| `bharosa guardian watch` | Live table of held cases (`--once`, `--all`) |
| `bharosa guardian show\|approve\|block <case-id>` | Review and decide a held case |
| `bharosa guardian unlock` | Turn Emergency Stop off |
| `bharosa guardian set-code-word <word>` / `set-limit <rupees>` / `stats` | Family code word, first-payee review limit, review-time metrics |
| `bharosa stop [--reason] [--minutes-ago N]` | Emergency Stop: lock pending cases, build the evidence packet |
| `bharosa evidence [case-id] [--out dir]` | Show or export the redacted packet |
| `bharosa payees add <upi-id> --label <name>` / `list` / `remove` | Trusted Payee list |
| `bharosa codeword verify <word>` | Check the word a "relative" gives against the family code word |
| `bharosa audit` | The family's append-only audit log |
| `bharosa eval` | Run the labeled corpus: recall, specificity, per-rule hits |
| `bharosa mcp` | Start the MCP server on stdio |
| `bharosa relay` | Run the family relay |
| `bharosa bot serve [--telegram/--no-telegram] [--whatsapp/--no-whatsapp] [--port]` | Run the Telegram and WhatsApp bots |
| `bharosa voice test` / `voice cache` | Test audio / pre-generate every clip for offline use |
| `bharosa purge [--days 7]` | Apply the retention policy to the local DB |
| `bharosa config show` / `config set lang\|relay <value>` | Profile settings |

### Differentiators that are built

- **Cool-off Clock:** a high-risk verdict starts a countdown with a calm script and the guardian's name and number.
- **Family Code Word:** set by the guardian, stored as a salted PBKDF2 hash. A "relative in trouble" message prints "Ask them for the family code word", and `bharosa codeword verify` checks it.
- **Trusted Payee list:** regular payees skip the first-time-payee checks, so the warnings that remain mean something. Scam signals such as a "receive cashback" note still fire for a trusted payee.
- **Family report list:** a blocked case's payee is flagged high the next time anyone in the family scans it.
- **Truth Cards:** every playbook prints one official fact with the NPCI, RBI or I4C source.
- **Golden-hour reporting:** `bharosa stop` prints the minutes since the first flagged case, the 1930 helpline and a packet pre-mapped to the National Cyber Crime Reporting Portal form.
- **`--explain` rule trace:** rule id, matched evidence, weight and ruleset version for every verdict.
- **Chat and clipboard scan:** `check chat` and `watch clipboard`.
- **Assistant guardrail:** the same tools inside Claude Desktop or Claude Code (next section).

## MCP server

The parent's CLI spawns the Bharosa MCP server (official Python MCP SDK, stdio transport) and calls its tools for every check. If the server cannot start, the CLI says so and calls the rules package directly. The same server plugs into any MCP client.

| Tool | Purpose |
|---|---|
| `inspect_upi_qr(payload, family_context?)` | Parse a `upi://pay` payload and flag suspicious payment details |
| `inspect_url(url)` | Flag lookalike domains, raw IPs, punycode, risky TLDs, `.apk` downloads and more. Never fetches the URL |
| `match_scam_playbook(text)` | Match text against 10 scam playbooks in English, Hindi and Kannada; masks PII first |
| `request_family_approval(case_id, risk_level, masked_summary, reasons)` | Hold a case and notify the linked guardian |
| `get_case_status(case_id)` | Poll the guardian's decision |
| `emergency_stop(family_id?, reason)` | Lock pending cases and build the evidence packet |

Every check tool returns the same shape: `{tool, risk_level, score, reasons[{rule_id, severity, title, evidence, weight, always_high, truth_card}], ruleset_version, details}`.

**Claude Desktop:** add the server to `claude_desktop_config.json` (see [examples/claude_desktop_config.json](examples/claude_desktop_config.json)), using the full path to `bharosa.exe` in your virtual environment and the parent's profile name. Restart Claude Desktop, then ask "Is this message safe?" with a sample pasted in.

**Claude Code:**

```powershell
claude mcp add bharosa -- "C:\path\to\Bharosa\.venv\Scripts\bharosa.exe" mcp
```

To inspect the server by hand: `npx @modelcontextprotocol/inspector .venv/Scripts/bharosa mcp`.

## How a verdict is decided

Rules, not a language model, decide the risk level. Rule packs are versioned YAML files in [src/bharosa/rules/packs](src/bharosa/rules/packs): `qr.yaml` (11 rules), `url.yaml` (14 rules), `playbooks.yaml` (10 playbooks built from 16 keyword signals), `truth_cards.yaml` and `i18n.yaml`.

- Each matched rule has a weight from its severity: high 60, medium 30, low 10.
- The score is the sum, capped at 100. A score of 60 or more, or any rule marked `always_high`, is **high**; 30 to 59 is **medium**; below 30 is **low**.
- A message that contains links or UPI IDs fans out to every relevant tool; the highest risk wins.
- A playbook fires only on a combination of signals (for example authority + threat + one of payment, secrecy, video call or urgency for digital arrest), never on one keyword.
- The same input with the same ruleset version always gives the same output. The ruleset version (pack versions plus a content hash) is printed with every verdict.
- A low result says "No known warning signs found" and that this does not prove the request is safe.

The optional LLM layer (`--llm`) only rephrases a verdict that the rules already produced, and the risk level shown always comes from the rules.

## Privacy, data and security as built

**PII masking** runs on the parent's laptop before anything is stored or sent ([masking.py](src/bharosa/masking.py)):

| Data | Detector | Mask |
|---|---|---|
| Aadhaar | 12 digits passing the Verhoeff check | `<AADHAAR>` |
| Card number | 13 to 19 digits passing Luhn | `<CARD_LAST4:1234>` |
| PAN | `[A-Z]{5}[0-9]{4}[A-Z]` | `<PAN>` |
| Phone | `(+91)?[6-9]` and 9 digits | `<PHONE_n>` |
| OTP | 4 to 8 digits near "OTP", "code", "PIN", "ओटीपी" and similar | `<OTP>` |
| Bank account | digit runs near "A/c" or "account" | `<ACCOUNT>` (IFSC kept, it is public) |
| UPI ID | `name@handle` | local part replaced by a short hash, handle kept |
| E-mail | standard pattern | `<EMAIL_n>` |

The token map stays in memory for the run only. The relay and the service refuse to store content that still looks like a phone, Aadhaar, card, PAN or UPI ID.

**What is stored** (SQLite, same schema locally and on the relay):

- Cases: masked content, a SHA-256 of the input, the masked payee, amount, verdict and state. Raw input is stored only on the parent's own laptop and only with `--keep-raw`; it is never sent to the relay and never shown to the guardian.
- Verdicts and reasons with masked evidence; approvals with decision times.
- Payees only as salted SHA-256 hashes (known, trusted and reported lists). The family code word only as a salted PBKDF2 hash.
- An append-only audit log (SQLite triggers reject updates and deletes).

**Access control:** pairing uses a one-time 6-digit code (10-minute expiry). Each side gets a random API token, stored in the OS keyring when the optional `keyring` package is installed (`pip install -e ".[keyring]"`), otherwise in the profile file under `BHAROSA_HOME`. The server stores only a SHA-256 of each token. Every request checks the token and the family link: only a linked guardian can read or decide a family's case, and only a guardian can approve, block, unlock, or set the code word or limit. Another family's case ids return "not found".

**Limits:** 4 KB message text, 2 KB QR payload, 5 MB image, 30 cases per hour per family.

**Retention as built:** approvals expire after 30 minutes. `bharosa relay` and `bharosa purge` delete decided cases older than 7 days (`--retention-days` / `--days`) and evidence packets after their 30-day expiry. Held cases stay until decided or expired. The audit log is not purged.

**Network:** `inspect_url` never opens a link. The check tools make no network calls. Only the relay (if you use one) and the opt-in services below go online.

**Evidence packet:** JSON and Markdown in `~/.bharosa/evidence/` (plus PDF if `reportlab` is installed), with masked content, rule reasons, input hashes, the audit trail, the packet's SHA-256 and fields mapped to the National Cyber Crime Reporting Portal form. Optional S3 upload with SSE-KMS and 15-minute presigned links when `BHAROSA_S3_BUCKET` is set and `boto3` is installed (`pip install -e ".[s3]"`); this path is not covered by the tests.

## Voice warnings

`--voice` speaks the headline, the top reason, "do not pay" and a Truth Card in the chosen language. Clips are cached in `~/.bharosa/voice_cache/`, so a demo works offline once generated.

| Engine | Languages | Notes |
|---|---|---|
| `espeak` (espeak-ng on PATH) | en, hi, kn | Free; install from the espeak-ng releases page for Hindi and Kannada |
| `sapi` (Windows built-in) | whichever voices are installed | English works out of the box; Hindi needs the Hindi speech pack |
| `say` (macOS built-in) | en | |
| `elevenlabs` | en, hi, kn | Paid, opt-in only (below) |
| `text` | all | No audio; the script is printed |

```powershell
bharosa voice test --lang en
bharosa voice cache
```

On the team laptop used to build this, `sapi` played English and Hindi fell back to text because no Hindi voice was installed.

## Optional paid integrations (off by default)

Neither runs unless you set the key yourself. Nothing in the tests calls them.

- **LLM explanation (`--llm`):** set `ANTHROPIC_API_KEY` and `pip install anthropic`. The model gets only the verdict JSON (rule ids, titles, masked evidence) and returns two or three plain sentences. Model: `claude-opus-5-5` by default, override with `BHAROSA_LLM_MODEL`. Any error or refusal falls back to the templates.
- **ElevenLabs voice:** set `ELEVENLABS_API_KEY` and `BHAROSA_VOICE_ENGINE=elevenlabs` (optionally `ELEVENLABS_VOICE_ID`), then run `bharosa voice cache --engine elevenlabs` once before the demo.

Keep keys in environment variables or a `.env` that git ignores.

## Tests and evaluation

```powershell
python -m pytest
```

```powershell
bharosa eval
```

The Python test suite (152 tests) covers every rule pack, scoring, masking validators, the family service (pairing, approvals, expiry, cross-family isolation, rate limit, Emergency Stop, retention, append-only audit), the relay over HTTP, the MCP server both in-process and over real stdio, QR image decoding of the samples, chat parsing, end-to-end CLI flows with two profiles, and the chat bots (the shared core with fake transports, Telegram polling and buttons against a mocked Bot API, and the WhatsApp webhook with signature checks, retries and reply buttons against a mocked Graph API), and the app check API (`POST /check` routing, hand-off rules, Emergency Stop, the app-to-bot review loop, and that the Android test fixtures match the relay). CI runs it on Ubuntu and Windows ([.github/workflows/tests.yml](.github/workflows/tests.yml)).

The Android app has JVM unit tests (11) for link parsing, the hand-off rule, share text, hashing and parsing real relay responses (fixtures written by `scripts/make_android_fixtures.py`):

```powershell
cd android; .\gradlew.bat testDebugUnitTest
```

`bharosa eval` runs the labeled corpus in [samples/cases.yaml](samples/cases.yaml). Current result on our 48 synthetic cases (28 scam, 20 benign): recall 100%, specificity 100%. The team wrote both the rules and the corpus, so these numbers show the rules do what we intended; they are not a measure of real-world accuracy. Add new cases (especially ones the rules miss) before quoting numbers in the pitch. `bharosa eval --mcp` runs the same corpus through the MCP server.

## Project layout

```text
src/bharosa/
  checks/            qr.py, url.py, playbook.py, extract.py (deterministic checks)
  rules/packs/       versioned YAML rule packs, truth cards, translations
  masking.py         PII masking with Verhoeff and Luhn
  pipeline.py        validate, mask, call the tools, combine verdicts
  mcp_server.py      MCP server with the six tools
  mcp_client.py      stdio MCP client used by the CLI
  service.py         family service: pairing, approvals, Emergency Stop, audit
  store.py           SQLite schema
  relay/app.py       FastAPI family relay (with an SSE event stream)
  chatbot/           chat app layer: core.py (shared bot), telegram.py, whatsapp.py, serve.py
  appcheck.py        check-and-route behind the relay's POST /check (Android app)
  backend.py         local mode or relay client
  evidence.py        redacted evidence packet
  explain.py, llm.py templates and the optional LLM layer
  voice.py           cached voice warnings
  cli.py, ui.py      Typer + Rich CLI
samples/             synthetic QR images, messages, a chat export and the labeled corpus
tests/               pytest suite
android/             Kotlin Android app (scan, verdict, UPI hand-off, guardian review, share target)
scripts/             sample QR generator and the Android test fixture writer
```

## Limitations

- Bharosa is a decision-support prototype, not a bank, payment provider, law-enforcement service or fraud guarantee.
- A low result means the configured checks did not find a known warning pattern; it does not prove the content is safe. New scam patterns need new rules.
- It pauses only its own flow and cannot block payments in other UPI apps or control a device.
- A guardian approval is an extra review step, not proof that a payment is genuine.
- Hindi and Kannada keywords and translations were written by the team and should be reviewed by native speakers.
- The PSP handle list and brand allowlist are small demo lists.
- The chat bots were tested against mocked Telegram and Meta APIs, not live accounts. Telegram groups are not supported. WhatsApp outside the 24-hour customer-service window needs approved message templates, which are not built. The bot cannot see or block a payment made in another app.
- The Android app was built and unit-tested on this laptop, not yet run end to end on a phone with a real UPI app. It cannot stop a payment the parent starts from another app's own scanner; it only checks what reaches Bharosa. Guardians in the app see new cases by polling while the app is open (no push notifications yet; the bots push).

## Sources and references

- [NPCI fraud awareness: UPI QR and cashback scam guidance](https://www.npci.org.in/fraud-awareness)
- [I4C Digital Arrest advisory](https://cybercrime.gov.in/pdf/Advisories/ADVISORYTAU-ADV-003DigitalArrest06.03.2025.pdf)
- [National Cyber Crime Reporting Portal and helpline information](https://cybercrime.gov.in/Webform/crmcondi.aspx)
- [Government of India / PIB report discussing cyber-enabled fraud losses](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2270875&lang=2&reg=48)

## Team

**Team Hydreigon** · M.S. Ramaiah Institute of Technology · wHACKiest 2026, Track 1: Make MCP Matter
