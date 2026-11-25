"""Redacted evidence packet built by Emergency Stop (and by ``bharosa evidence``).

The packet holds only masked content, rule reasons, hashes and the audit trail. Its fields are
mapped to what the National Cyber Crime Reporting Portal complaint form asks for, so a family can
copy them across quickly. It is saved locally as JSON and Markdown; upload to S3 is optional.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

HELPLINE = "1930"
PORTAL_URL = "https://cybercrime.gov.in/"
RETENTION_SECONDS = 30 * 24 * 3600
GOLDEN_HOUR_SECONDS = 3600


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _urls(text: str) -> list[str]:
    from .checks.extract import extract_urls

    return extract_urls(text)


def _category(cases: list[dict]) -> str:
    rule_ids = {r["rule_id"] for c in cases for r in c.get("reasons", [])}
    if "PB-DIGITAL-ARREST" in rule_ids:
        return "Online financial fraud: impersonation of police or government official (digital arrest)"
    if any(r.startswith("QR-") for r in rule_ids):
        return "Online financial fraud: UPI / QR code related fraud"
    if "PB-KYC-EXPIRY" in rule_ids or any(r.startswith("URL-") for r in rule_ids):
        return "Online financial fraud: phishing link or fake KYC"
    if "PB-RELATIVE-IN-TROUBLE" in rule_ids:
        return "Online financial fraud: impersonation of a relative"
    return "Online financial fraud: other"


def build_packet(*, family_id: str, requested_by: dict, reason: str, cases: list[dict], audit: list[dict],
                 generated_at: float, incident_at: float) -> dict:
    elapsed = max(0, int(generated_at - incident_at))
    suspect_payees = sorted({c["payee_masked"] for c in cases if c.get("payee_masked")})
    amounts = [c["amount"] for c in cases if c.get("amount")]
    return {
        "packet_id": "pkt_" + uuid.uuid4().hex[:10],
        "schema": "bharosa.evidence/1",
        "generated_at": _iso(generated_at),
        "family_ref": family_id,
        "requested_by": requested_by,
        "reason": reason,
        "golden_hour": {
            "incident_at": _iso(incident_at),
            "minutes_since_incident": elapsed // 60,
            "within_golden_hour": elapsed <= GOLDEN_HOUR_SECONDS,
            "advice": "Report within the first hour: call 1930 or file at cybercrime.gov.in so the bank can try to freeze funds.",
        },
        "report_to": {"helpline": HELPLINE, "portal": PORTAL_URL},
        "ncrp_form": {
            "complaint_category": _category(cases),
            "incident_datetime": _iso(incident_at),
            "suspect_upi_ids_masked": suspect_payees,
            "amount_requested_inr": sum(amounts) if amounts else None,
            "amount_lost_inr": None,
            "suspect_websites": sorted({
                c["masked_content"] for c in cases if c["input_type"] == "url"
            } | {
                u for c in cases if c["input_type"] in ("msg", "chat") for u in _urls(c["masked_content"])
            })[:10],
            "description_masked": " | ".join(c["masked_content"][:300] for c in cases)[:1500],
            "note": "UPI IDs and phone numbers are masked. The family can add the real values from their own phone when filing.",
        },
        "cases": [
            {
                "case_id": c["id"],
                "input_type": c["input_type"],
                "masked_content": c["masked_content"],
                "input_sha256": c["input_sha256"],
                "risk_level": c["risk_level"],
                "score": c["score"],
                "state": c["state"],
                "checked_at": _iso(c["created_at"]),
                "payee_masked": c.get("payee_masked"),
                "amount": c.get("amount"),
                "reasons": c.get("reasons", []),
                "approval": c.get("approval"),
            }
            for c in cases
        ],
        "audit_trail": [
            {"at": _iso(a["at"]), "action": a["action"], "case_id": a.get("case_id")} for a in audit
        ],
        "disclaimer": (
            "Prepared by the Bharosa prototype. Bharosa is decision support, not a bank, payment provider or "
            "law-enforcement service. It can pause only its own flow and cannot block payments in other apps."
        ),
    }


def to_markdown(packet: dict, sha256: str | None = None) -> str:
    g = packet["golden_hour"]
    f = packet["ncrp_form"]
    lines = [
        f"# Bharosa evidence packet {packet['packet_id']}",
        "",
        f"Generated {packet['generated_at']} by {packet['requested_by']['name']} ({packet['requested_by']['role']}).",
        "",
        f"**Report now: call {packet['report_to']['helpline']} or file at {packet['report_to']['portal']}.**",
        f"Minutes since the first flagged case: {g['minutes_since_incident']}"
        + (" (inside the golden hour)" if g["within_golden_hour"] else ""),
        "",
        "## For the National Cyber Crime Reporting Portal form",
        "",
        f"- Category: {f['complaint_category']}",
        f"- Incident date and time: {f['incident_datetime']}",
        f"- Suspect UPI IDs (masked): {', '.join(f['suspect_upi_ids_masked']) or 'none'}",
        f"- Amount requested (INR): {f['amount_requested_inr'] if f['amount_requested_inr'] is not None else 'not stated'}",
        f"- Suspect websites: {', '.join(f['suspect_websites']) or 'none'}",
        f"- Description (masked): {f['description_masked']}",
        "",
        "## Cases",
    ]
    for c in packet["cases"]:
        lines += ["", f"### {c['case_id']} ({c['input_type']}, {c['risk_level']}, {c['state']})", "",
                  f"Masked content: `{c['masked_content'][:500]}`", f"Input SHA-256: `{c['input_sha256']}`", ""]
        for r in c["reasons"]:
            lines.append(f"- {r['rule_id']} ({r['severity']}): {r['title']}" + (f" [{r['evidence']}]" if r.get("evidence") else ""))
    lines += ["", "## Audit trail", ""]
    lines += [f"- {a['at']} {a['action']} {a['case_id'] or ''}".rstrip() for a in packet["audit_trail"]]
    lines += ["", packet["disclaimer"]]
    if sha256:
        lines += ["", f"Packet SHA-256: `{sha256}`"]
    return "\n".join(lines) + "\n"


def save_packet(packet: dict, sha256: str, directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    base = directory / packet["packet_id"]
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    json_path.write_text(json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(packet, sha256), encoding="utf-8")
    out = {"json": json_path, "markdown": md_path}
    pdf = _try_pdf(packet, sha256, base.with_suffix(".pdf"))
    if pdf:
        out["pdf"] = pdf
    return out


def _try_pdf(packet: dict, sha256: str, path: Path) -> Path | None:
    """Write a PDF when the optional reportlab package is installed."""
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.pdfgen import canvas  # type: ignore
    except Exception:
        return None
    c = canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    y = height - 50
    for line in to_markdown(packet, sha256).splitlines():
        text = line.replace("**", "").replace("`", "")
        while text:
            c.drawString(40, y, text[:100])
            text = text[100:]
            y -= 14
            if y < 50:
                c.showPage()
                y = height - 50
    c.save()
    return path


def upload_to_s3(paths: dict[str, Path]) -> list[str]:
    """Optional upload with SSE-KMS. Runs only when BHAROSA_S3_BUCKET is set and boto3 is installed."""
    bucket = os.environ.get("BHAROSA_S3_BUCKET")
    if not bucket:
        return []
    import boto3  # type: ignore

    s3 = boto3.client("s3")
    keys = []
    for kind, p in paths.items():
        key = f"evidence/{p.name}"
        extra = {"ServerSideEncryption": "aws:kms"}
        if os.environ.get("BHAROSA_KMS_KEY_ID"):
            extra["SSEKMSKeyId"] = os.environ["BHAROSA_KMS_KEY_ID"]
        s3.upload_file(str(p), bucket, key, ExtraArgs=extra)
        keys.append(s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=900))
    return keys
