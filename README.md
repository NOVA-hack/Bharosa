# Bharosa

**A family safety layer for suspicious payment QR codes, links, and scam messages.**

Bharosa is a hackathon prototype concept for helping families pause and review suspicious payment requests before continuing to an existing UPI app. It combines rule-based checks exposed through MCP with clear warnings and a trusted-family review flow.

> **Prototype scope:** Bharosa does not process UPI payments, replace payment apps, or guarantee that a payment or message is safe. Its demo uses sample cases and a mock handoff.

## The problem

Scam messages, fake QR codes, phishing links, and impersonation calls can pressure people into transferring money before they verify a request. Older adults and families may be especially vulnerable to fear-based scams such as “digital arrest.” Existing spam alerts and reporting services help, but Bharosa focuses on adding a review step before a risky handoff.

## How Bharosa works

1. A user scans a QR code or shares a suspicious link or message.
2. The app masks selected personal details before inspection.
3. The Bharosa MCP server applies deterministic checks and returns a risk level with reasons.
4. For a safe result, the user can continue to their existing UPI app.
5. For a medium- or high-risk result, Bharosa pauses its own handoff and sends a review request to a trusted family member.
6. The user or guardian can activate an Emergency Stop in the prototype flow and prepare redacted evidence for reporting.

## Key features

- **SafeScan:** Inspect UPI QR payloads, URLs, and suspicious text.
- **Explainable checks:** Show the rules or warning signs that caused a risk result.
- **Family review:** Provide a guardian dashboard to review, approve, or block a flagged case.
- **Local-language warnings:** Planned voice warnings in Hindi, Kannada, and English.
- **Emergency Stop:** Lock pending actions in the Bharosa demo and prepare a redacted evidence packet.

## MCP tools

The planned MCP server exposes focused tools that an MCP-compatible assistant or the Bharosa app can call:

| Tool | Purpose |
|---|---|
| `inspect_upi_qr(payload)` | Parse a UPI QR payload and flag suspicious payment details or patterns. |
| `inspect_url(url)` | Check a URL for simple phishing indicators such as lookalike domains or raw IP addresses. |
| `match_scam_playbook(text)` | Match message text against known coercion and scam patterns. |
| `request_family_approval(...)` | Place a risky case in the guardian review queue. |

Checks are intended to be deterministic and testable. Any language model use is limited to explaining a structured result or translating it; it should not make the final risk decision.

## Architecture

```text
Parent mobile web app
        │ QR / message / link
        ▼
FastAPI orchestrator ── masks selected PII
        │
        ▼
Bharosa MCP server ── deterministic QR, URL, and text checks
        │ verdict + reason
        ├── Safe ── user may open existing UPI app
        └── Risky ── SQLite approval queue ── Guardian dashboard
                                      │
                                      └── approve / block / emergency stop
```

## Planned technology stack

- **Web UI:** Responsive, mobile-first parent screen and guardian dashboard
- **Backend:** Python and FastAPI
- **MCP:** Official Python MCP SDK
- **Database:** SQLite for demo cases, approval state, and action history
- **QR scanning:** `html5-qrcode`
- **Voice warnings:** ElevenLabs (planned integration)
- **Hosting and evidence storage:** AWS EC2 or Lambda and S3 (planned; use protected storage)

## Demo scenarios

1. **Suspicious QR:** A QR with a payment amount or description that matches a known warning pattern is flagged and held for review.
2. **Impersonation message:** A sample “digital arrest” or urgent KYC message triggers a warning with the reason shown.
3. **Clean sample:** A benign sample QR or message returns a low-risk result and demonstrates the normal handoff path.

Use synthetic or redacted data in demonstrations. Do not put real bank credentials, UPI PINs, Aadhaar numbers, or private messages in sample files.

## Safety and limitations

- Bharosa is a decision-support prototype, not a bank, payment provider, law-enforcement service, or fraud guarantee.
- A “safe” result means the configured checks did not find a known warning pattern; it does not prove the content is safe.
- The prototype can pause only actions inside its own flow. It cannot block transactions inside other UPI apps or control a user's device.
- A guardian approval is an additional review step, not proof that a payment is legitimate.
- Mask personal information before sending content to external services; avoid storing raw content unless needed and explicitly consented to.
- The repo should document actual data retention, encryption, and access controls as implementation is added.

## Success measures for the prototype

Evaluate the demo with a fixed set of labeled sample cases:

- Scam examples correctly flagged
- Benign examples correctly allowed through
- Time required for a guardian to review a case
- Clarity of warning reasons and voice prompts

These are evaluation targets, not claimed results.

## Build status

This README describes the Bharosa design in the project blueprint and pitch deck. The current workspace did not include the application source code, so no installation or run commands are listed yet. Add verified setup instructions, environment variables, and test commands here when the implementation is committed.

## Sources and references

- [NPCI fraud awareness: UPI QR and cashback scam guidance](https://www.npci.org.in/fraud-awareness)
- [I4C Digital Arrest advisory](https://cybercrime.gov.in/pdf/Advisories/ADVISORYTAU-ADV-003DigitalArrest06.03.2025.pdf)
- [National Cyber Crime Reporting Portal and helpline information](https://cybercrime.gov.in/Webform/crmcondi.aspx)
- [Government of India / PIB report discussing cyber-enabled fraud losses](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2270875&lang=2&reg=48)

## Team

**Team Hydreigon** · M.S. Ramaiah Institute of Technology · wHACKiest 2026, Track 1: Make MCP Matter
