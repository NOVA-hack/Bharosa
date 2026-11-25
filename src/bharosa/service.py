"""Family service: pairing, the approval queue, decisions, Emergency Stop and the audit log.

The same class runs in two places:

* in local mode the CLI uses it directly on the shared SQLite file
* the family relay (``bharosa relay``) wraps it in a small HTTP API

Every call is authenticated by an API token and checks the family link, so only a linked guardian
can read or decide a family's case.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import statistics
import time
import uuid
from typing import Any, Callable

from . import evidence as evidence_mod
from .masking import contains_unmasked_pii
from .store import Store

CASE_STATES = ("new", "checked", "allowed", "held", "approved", "blocked", "stopped", "expired")
PENDING_STATES = ("checked", "held")
APPROVAL_TTL_SECONDS = 30 * 60
PAIR_CODE_TTL_SECONDS = 10 * 60
RATE_LIMIT_PER_HOUR = 30
MAX_MASKED_CONTENT = 8 * 1024


class ServiceError(Exception):
    status = 400
    code = "bad_request"


class AuthError(ServiceError):
    status = 401
    code = "unauthorized"


class Forbidden(ServiceError):
    status = 403
    code = "forbidden"


class NotFound(ServiceError):
    status = 404
    code = "not_found"


class Conflict(ServiceError):
    status = 409
    code = "conflict"


class RateLimited(ServiceError):
    status = 429
    code = "rate_limited"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class FamilyService:
    def __init__(self, store: Store, clock: Callable[[], float] = time.time):
        self.store = store
        self.now = clock

    # ---- auth -----------------------------------------------------------------------

    def _user(self, token: str | None) -> dict:
        if not token:
            raise AuthError("missing token")
        user = self.store.one("SELECT * FROM users WHERE token_hash = ?", (_sha(token),))
        if not user:
            raise AuthError("unknown token")
        return user

    def _require_role(self, user: dict, role: str) -> None:
        if user["role"] != role:
            raise Forbidden(f"only a {role} can do this")

    def _audit(self, family_id: str | None, actor_id: str | None, action: str, case_id: str | None = None,
               detail: str | dict | None = None) -> None:
        if isinstance(detail, dict):
            detail = json.dumps(detail, ensure_ascii=False, sort_keys=True)
        self.store.execute(
            "INSERT INTO audit_log (family_id, actor_id, action, case_id, detail, at) VALUES (?,?,?,?,?,?)",
            (family_id, actor_id, action, case_id, detail, self.now()),
        )

    def _family(self, family_id: str) -> dict:
        fam = self.store.one("SELECT * FROM families WHERE id = ?", (family_id,))
        if not fam:
            raise NotFound("family not found")
        return fam

    def _case_for(self, user: dict, case_id: str) -> dict:
        case = self.store.one("SELECT * FROM cases WHERE id = ?", (case_id,))
        if not case or case["family_id"] != user["family_id"]:
            # Same answer for "missing" and "not your family": do not leak case ids.
            raise NotFound("case not found")
        if user["role"] == "guardian":
            link = self.store.one(
                "SELECT 1 FROM family_links WHERE parent_id = ? AND guardian_id = ? AND status = 'active'",
                (case["parent_id"], user["id"]),
            )
            if not link:
                raise NotFound("case not found")
        elif user["id"] != case["parent_id"]:
            raise NotFound("case not found")
        return case

    # ---- pairing --------------------------------------------------------------------

    def create_family(self, parent_name: str, language: str = "en", phone: str | None = None) -> dict:
        now = self.now()
        family_id = _new_id("fam")
        user_id = _new_id("usr")
        token = secrets.token_urlsafe(32)
        self.store.execute("INSERT INTO families (id, created_at) VALUES (?, ?)", (family_id, now))
        self.store.execute(
            "INSERT INTO users (id, family_id, role, display_name, language, phone, token_hash, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (user_id, family_id, "parent", parent_name, language, phone, _sha(token), now),
        )
        self._audit(family_id, user_id, "family_created")
        code = self._issue_pair_code(family_id)
        return {"family_id": family_id, "user_id": user_id, "role": "parent", "token": token, **code}

    def _issue_pair_code(self, family_id: str) -> dict:
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = self.now() + PAIR_CODE_TTL_SECONDS
        self.store.execute(
            "INSERT OR REPLACE INTO pair_codes (code_hash, family_id, expires_at, used) VALUES (?,?,?,0)",
            (_sha(family_id + ":" + code), family_id, expires),
        )
        # The family id is folded into the stored hash; the code the guardian types includes it as a prefix.
        return {"pair_code": f"{family_id[-4:]}-{code}", "pair_expires_at": expires}

    def new_pair_code(self, token: str) -> dict:
        user = self._user(token)
        self._require_role(user, "parent")
        self._audit(user["family_id"], user["id"], "pair_code_issued")
        return self._issue_pair_code(user["family_id"])

    def join_family(self, pair_code: str, guardian_name: str, language: str = "en", phone: str | None = None,
                    code_word: str | None = None) -> dict:
        pair_code = pair_code.strip()
        if "-" not in pair_code:
            raise AuthError("pairing code should look like ABCD-123456")
        prefix, code = pair_code.split("-", 1)
        candidates = self.store.query(
            "SELECT * FROM pair_codes WHERE used = 0 AND expires_at > ?", (self.now(),)
        )
        match = None
        for row in candidates:
            if row["family_id"].endswith(prefix) and hmac.compare_digest(
                row["code_hash"], _sha(row["family_id"] + ":" + code)
            ):
                match = row
                break
        if not match:
            raise AuthError("pairing code is wrong or has expired")
        family_id = match["family_id"]
        now = self.now()
        user_id = _new_id("usr")
        token = secrets.token_urlsafe(32)
        with self.store.transaction() as conn:
            conn.execute("UPDATE pair_codes SET used = 1 WHERE code_hash = ?", (match["code_hash"],))
            conn.execute(
                "INSERT INTO users (id, family_id, role, display_name, language, phone, token_hash, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (user_id, family_id, "guardian", guardian_name, language, phone, _sha(token), now),
            )
            for parent in conn.execute(
                "SELECT id FROM users WHERE family_id = ? AND role = 'parent'", (family_id,)
            ).fetchall():
                conn.execute(
                    "INSERT OR IGNORE INTO family_links (parent_id, guardian_id, paired_at) VALUES (?,?,?)",
                    (parent[0], user_id, now),
                )
        self._audit(family_id, user_id, "guardian_joined")
        if code_word:
            self.set_code_word(token, code_word)
        return {"family_id": family_id, "user_id": user_id, "role": "guardian", "token": token}

    def whoami(self, token: str) -> dict:
        u = self._user(token)
        return {k: u[k] for k in ("id", "family_id", "role", "display_name", "language")}

    def family_info(self, token: str) -> dict:
        user = self._user(token)
        fam = self._family(user["family_id"])
        members = self.store.query(
            "SELECT id, role, display_name, language, phone FROM users WHERE family_id = ? ORDER BY created_at",
            (fam["id"],),
        )
        return {
            "family_id": fam["id"],
            "locked": bool(fam["locked"]),
            "locked_at": fam["locked_at"],
            "lock_reason": fam["lock_reason"],
            "review_amount": fam["review_amount"],
            "code_word_set": bool(fam["code_word_hash"]),
            "parents": [m for m in members if m["role"] == "parent"],
            "guardians": [m for m in members if m["role"] == "guardian"],
        }

    # ---- family settings ------------------------------------------------------------

    def set_review_amount(self, token: str, amount: float) -> dict:
        user = self._user(token)
        self._require_role(user, "guardian")
        if amount < 0:
            raise ServiceError("amount must be positive")
        self.store.execute("UPDATE families SET review_amount = ? WHERE id = ?", (amount, user["family_id"]))
        self._audit(user["family_id"], user["id"], "review_amount_set", detail=str(amount))
        return {"review_amount": amount}

    def set_code_word(self, token: str, word: str) -> dict:
        user = self._user(token)
        self._require_role(user, "guardian")
        word = word.strip().lower()
        if len(word) < 3:
            raise ServiceError("the family code word needs at least 3 characters")
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", word.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()
        self.store.execute(
            "UPDATE families SET code_word_hash = ?, code_word_salt = ? WHERE id = ?",
            (digest, salt, user["family_id"]),
        )
        self._audit(user["family_id"], user["id"], "code_word_set")
        return {"code_word_set": True}

    def verify_code_word(self, token: str, word: str) -> bool:
        user = self._user(token)
        fam = self._family(user["family_id"])
        if not fam["code_word_hash"]:
            raise Conflict("no family code word has been set yet")
        digest = hashlib.pbkdf2_hmac(
            "sha256", word.strip().lower().encode("utf-8"), bytes.fromhex(fam["code_word_salt"]), 200_000
        ).hex()
        ok = hmac.compare_digest(digest, fam["code_word_hash"])
        self._audit(user["family_id"], user["id"], "code_word_checked", detail="match" if ok else "no match")
        return ok

    # ---- payees -------------------------------------------------------------------------

    def add_trusted_payee(self, token: str, vpa_hash: str, vpa_masked: str, label: str) -> dict:
        user = self._user(token)
        self.store.execute(
            "INSERT OR REPLACE INTO trusted_payees (vpa_hash, family_id, label, vpa_masked, added_by, added_at)"
            " VALUES (?,?,?,?,?,?)",
            (vpa_hash, user["family_id"], label, vpa_masked, user["id"], self.now()),
        )
        self._audit(user["family_id"], user["id"], "trusted_payee_added", detail=vpa_masked)
        return {"vpa_masked": vpa_masked, "label": label}

    def remove_trusted_payee(self, token: str, vpa_hash: str) -> bool:
        user = self._user(token)
        cur = self.store.execute(
            "DELETE FROM trusted_payees WHERE vpa_hash = ? AND family_id = ?", (vpa_hash, user["family_id"])
        )
        if cur.rowcount:
            self._audit(user["family_id"], user["id"], "trusted_payee_removed")
        return bool(cur.rowcount)

    def list_trusted_payees(self, token: str) -> list[dict]:
        user = self._user(token)
        return self.store.query(
            "SELECT vpa_hash, label, vpa_masked, added_at FROM trusted_payees WHERE family_id = ? ORDER BY label",
            (user["family_id"],),
        )

    def check_context(self, token: str) -> dict:
        user = self._user(token)
        fid = user["family_id"]
        fam = self._family(fid)
        q = lambda sql: sorted(r["vpa_hash"] for r in self.store.query(sql, (fid,)))  # noqa: E731
        return {
            "known_payees": q("SELECT vpa_hash FROM known_payees WHERE family_id = ?"),
            "trusted_payees": q("SELECT vpa_hash FROM trusted_payees WHERE family_id = ?"),
            "reported_payees": q("SELECT vpa_hash FROM payee_reports WHERE family_id = ?"),
            "review_amount": fam["review_amount"],
        }

    # ---- cases ----------------------------------------------------------------------

    def expire_stale(self) -> int:
        now = self.now()
        rows = self.store.query(
            "SELECT a.case_id, c.family_id FROM approvals a JOIN cases c ON c.id = a.case_id"
            " WHERE a.decision IS NULL AND a.expires_at <= ? AND c.state = 'held'",
            (now,),
        )
        for r in rows:
            self.store.execute("UPDATE approvals SET decision = 'expired', decided_at = ? WHERE case_id = ?",
                               (now, r["case_id"]))
            self.store.execute("UPDATE cases SET state = 'expired', updated_at = ? WHERE id = ?", (now, r["case_id"]))
            self._audit(r["family_id"], None, "case_expired", r["case_id"])
        return len(rows)

    def submit_case(self, token: str, case: dict[str, Any]) -> dict:
        """Record a checked case. ``case`` holds only masked content plus the verdict."""
        user = self._user(token)
        self._require_role(user, "parent")
        masked = str(case.get("masked_content", ""))
        if len(masked.encode("utf-8")) > MAX_MASKED_CONTENT:
            raise ServiceError("masked content is too large")
        leaks = contains_unmasked_pii(masked)
        if leaks:
            raise ServiceError(f"refusing to store content that still contains PII: {', '.join(sorted(set(leaks)))}")
        hour_ago = self.now() - 3600
        n = self.store.one(
            "SELECT COUNT(*) AS n FROM cases WHERE family_id = ? AND created_at > ?", (user["family_id"], hour_ago)
        )["n"]
        if n >= RATE_LIMIT_PER_HOUR:
            raise RateLimited(f"more than {RATE_LIMIT_PER_HOUR} cases in the last hour")

        verdict = case["verdict"]
        fam = self._family(user["family_id"])
        now = self.now()
        case_id = case.get("case_id") or _new_id("case")
        state = "checked"
        if fam["locked"]:
            state = "stopped"
        elif verdict["risk_level"] == "low":
            state = "allowed"
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO cases (id, family_id, parent_id, input_type, masked_content, input_sha256, raw_content,"
                " payee_hash, payee_masked, amount, risk_level, score, state, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, user["family_id"], user["id"], case["input_type"], masked, case["input_sha256"],
                 case.get("raw_content"), case.get("payee_hash"), case.get("payee_masked"), case.get("amount"),
                 verdict["risk_level"], int(verdict["score"]), state, now, now),
            )
            tool_verdicts = verdict.get("details", {}).get("tools") or [verdict]
            for tv in tool_verdicts:
                cur = conn.execute(
                    "INSERT INTO verdicts (case_id, tool, risk_level, score, ruleset_version) VALUES (?,?,?,?,?)",
                    (case_id, tv["tool"], tv["risk_level"], int(tv["score"]), tv["ruleset_version"]),
                )
                for r in tv.get("reasons", []):
                    conn.execute(
                        "INSERT INTO reasons (verdict_id, rule_id, severity, title, evidence_masked, truth_card)"
                        " VALUES (?,?,?,?,?,?)",
                        (cur.lastrowid, r["rule_id"], r["severity"], r["title"], r.get("evidence", ""),
                         r.get("truth_card")),
                    )
        self._audit(user["family_id"], user["id"], "case_checked", case_id,
                    {"risk_level": verdict["risk_level"], "state": state})
        return self.get_case(token, case_id)

    def request_approval(self, token: str, case_id: str, ttl_seconds: int = APPROVAL_TTL_SECONDS) -> dict:
        user = self._user(token)
        case = self._case_for(user, case_id)
        fam = self._family(case["family_id"])
        if case["state"] == "held":
            a = self.store.one("SELECT * FROM approvals WHERE case_id = ?", (case_id,))
            return self._approval_view(a, case)
        if case["state"] not in ("checked", "allowed", "stopped"):
            raise Conflict(f"case is already {case['state']}")
        guardians = self.store.query(
            "SELECT guardian_id FROM family_links WHERE parent_id = ? AND status = 'active'", (case["parent_id"],)
        )
        now = self.now()
        approval_id = _new_id("apr")
        new_state = "stopped" if fam["locked"] else "held"
        self.store.execute(
            "INSERT INTO approvals (id, case_id, created_at, expires_at, decision, decided_at) VALUES (?,?,?,?,?,?)",
            (approval_id, case_id, now, now + ttl_seconds, "stopped" if fam["locked"] else None,
             now if fam["locked"] else None),
        )
        self.store.execute("UPDATE cases SET state = ?, updated_at = ? WHERE id = ?", (new_state, now, case_id))
        self._audit(case["family_id"], user["id"], "approval_requested", case_id,
                    {"guardians_notified": len(guardians)})
        a = self.store.one("SELECT * FROM approvals WHERE case_id = ?", (case_id,))
        view = self._approval_view(a, self.store.one("SELECT * FROM cases WHERE id = ?", (case_id,)))
        view["guardians_notified"] = len(guardians)
        return view

    @staticmethod
    def _approval_view(a: dict | None, case: dict) -> dict:
        if not a:
            return {"approval_id": None, "case_id": case["id"], "status": case["state"], "expires_at": None}
        status = a["decision"] or "pending"
        return {
            "approval_id": a["id"],
            "case_id": case["id"],
            "status": status,
            "case_state": case["state"],
            "expires_at": a["expires_at"],
            "decided_at": a["decided_at"],
            "note": a["note"],
        }

    def get_case(self, token: str, case_id: str) -> dict:
        self.expire_stale()
        user = self._user(token)
        case = self._case_for(user, case_id)
        case = dict(case)
        if user["role"] == "guardian":
            case.pop("raw_content", None)  # raw content, if kept, never leaves the parent's own view
        case["reasons"] = self.store.query(
            "SELECT r.rule_id, r.severity, r.title, r.evidence_masked AS evidence, r.truth_card, v.tool"
            " FROM reasons r JOIN verdicts v ON v.id = r.verdict_id WHERE v.case_id = ? ORDER BY r.id",
            (case_id,),
        )
        case["verdicts"] = self.store.query(
            "SELECT tool, risk_level, score, ruleset_version FROM verdicts WHERE case_id = ? ORDER BY id", (case_id,)
        )
        a = self.store.one("SELECT * FROM approvals WHERE case_id = ?", (case_id,))
        case["approval"] = self._approval_view(a, case) if a else None
        parent = self.store.one("SELECT display_name FROM users WHERE id = ?", (case["parent_id"],))
        case["parent_name"] = parent["display_name"] if parent else None
        return case

    def case_status(self, token: str, case_id: str) -> dict:
        c = self.get_case(token, case_id)
        return {"case_id": case_id, "state": c["state"], "risk_level": c["risk_level"], "approval": c["approval"]}

    def list_cases(self, token: str, states: list[str] | None = None, limit: int = 50) -> list[dict]:
        self.expire_stale()
        user = self._user(token)
        params: list[Any] = [user["family_id"]]
        sql = ("SELECT c.id, c.input_type, c.masked_content, c.risk_level, c.score, c.state, c.created_at,"
               " c.updated_at, c.amount, c.payee_masked, u.display_name AS parent_name, a.expires_at"
               " FROM cases c JOIN users u ON u.id = c.parent_id LEFT JOIN approvals a ON a.case_id = c.id"
               " WHERE c.family_id = ?")
        if user["role"] == "parent":
            sql += " AND c.parent_id = ?"
            params.append(user["id"])
        else:
            sql += (" AND c.parent_id IN (SELECT parent_id FROM family_links WHERE guardian_id = ?"
                    " AND status = 'active')")
            params.append(user["id"])
        if states:
            sql += " AND c.state IN (%s)" % ",".join("?" * len(states))
            params.extend(states)
        sql += " ORDER BY c.created_at DESC LIMIT ?"
        params.append(int(limit))
        return self.store.query(sql, tuple(params))

    def decide(self, token: str, case_id: str, decision: str, note: str | None = None) -> dict:
        self.expire_stale()
        user = self._user(token)
        self._require_role(user, "guardian")
        if decision not in ("approve", "block"):
            raise ServiceError("decision must be approve or block")
        case = self._case_for(user, case_id)
        fam = self._family(case["family_id"])
        if fam["locked"] and decision == "approve":
            raise Conflict("Emergency Stop is on; unlock the family before approving anything")
        if case["state"] != "held":
            raise Conflict(f"case is {case['state']}, not waiting for a decision")
        now = self.now()
        final = "approved" if decision == "approve" else "blocked"
        self.store.execute(
            "UPDATE approvals SET guardian_id = ?, decision = ?, note = ?, decided_at = ? WHERE case_id = ?",
            (user["id"], final, note, now, case_id),
        )
        self.store.execute("UPDATE cases SET state = ?, updated_at = ? WHERE id = ?", (final, now, case_id))
        if final == "blocked" and case["payee_hash"]:
            self._report_payee(case["family_id"], case["payee_hash"])
        self._audit(case["family_id"], user["id"], f"case_{final}", case_id, note)
        return self.get_case(token, case_id)

    def _report_payee(self, family_id: str, vpa_hash: str) -> None:
        existing = self.store.one(
            "SELECT * FROM payee_reports WHERE vpa_hash = ? AND family_id = ?", (vpa_hash, family_id)
        )
        if existing:
            self.store.execute(
                "UPDATE payee_reports SET report_count = report_count + 1 WHERE vpa_hash = ? AND family_id = ?",
                (vpa_hash, family_id),
            )
        else:
            self.store.execute(
                "INSERT INTO payee_reports (vpa_hash, family_id, report_count, first_seen) VALUES (?,?,1,?)",
                (vpa_hash, family_id, self.now()),
            )

    def record_handoff(self, token: str, case_id: str) -> dict:
        """The parent continued to their UPI app (mock). Only allowed or approved cases may hand off."""
        user = self._user(token)
        self._require_role(user, "parent")
        case = self._case_for(user, case_id)
        fam = self._family(case["family_id"])
        if fam["locked"]:
            raise Conflict("Emergency Stop is on; Bharosa will not hand off any payment until a guardian unlocks")
        if case["state"] not in ("allowed", "approved"):
            raise Conflict(f"case is {case['state']}; Bharosa will not hand it off")
        if case["payee_hash"]:
            self.store.execute(
                "INSERT OR IGNORE INTO known_payees (vpa_hash, family_id, first_paid) VALUES (?,?,?)",
                (case["payee_hash"], case["family_id"], self.now()),
            )
        self._audit(case["family_id"], user["id"], "mock_handoff", case_id)
        return {"case_id": case_id, "handoff": "mock", "state": case["state"]}

    # ---- Emergency Stop ---------------------------------------------------------------

    def emergency_stop(self, token: str, reason: str = "", incident_at: float | None = None) -> dict:
        user = self._user(token)
        fid = user["family_id"]
        now = self.now()
        pending = self.store.query(
            "SELECT id FROM cases WHERE family_id = ? AND state IN ('checked', 'held')", (fid,)
        )
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE families SET locked = 1, locked_at = ?, lock_reason = ? WHERE id = ?", (now, reason, fid)
            )
            for row in pending:
                conn.execute("UPDATE cases SET state = 'stopped', updated_at = ? WHERE id = ?", (now, row["id"]))
                conn.execute(
                    "UPDATE approvals SET decision = 'stopped', decided_at = ?, guardian_id = COALESCE(guardian_id, ?)"
                    " WHERE case_id = ? AND decision IS NULL",
                    (now, user["id"] if user["role"] == "guardian" else None, row["id"]),
                )
        self._audit(fid, user["id"], "emergency_stop", detail={"reason": reason, "locked_cases": len(pending)})

        # The packet covers the stopped cases, or, when nothing was pending, the most recent risky cases.
        case_ids = [r["id"] for r in pending]
        if not case_ids:
            case_ids = [r["id"] for r in self.store.query(
                "SELECT id FROM cases WHERE family_id = ? AND risk_level != 'low' ORDER BY created_at DESC LIMIT 5",
                (fid,),
            )]
        cases = [self._case_for_packet(cid) for cid in case_ids]
        audit = self.store.query(
            "SELECT actor_id, action, case_id, detail, at FROM audit_log WHERE family_id = ? ORDER BY id", (fid,)
        )
        packet = evidence_mod.build_packet(
            family_id=fid,
            requested_by={"role": user["role"], "name": user["display_name"]},
            reason=reason,
            cases=cases,
            audit=audit,
            generated_at=now,
            incident_at=incident_at or (min((c["created_at"] for c in cases), default=now)),
        )
        packet_json = json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2)
        digest = hashlib.sha256(packet_json.encode("utf-8")).hexdigest()
        self.store.execute(
            "INSERT INTO evidence_packets (id, family_id, case_ids, location, sha256, packet_json, created_at,"
            " expires_at) VALUES (?,?,?,?,?,?,?,?)",
            (packet["packet_id"], fid, json.dumps(case_ids), None, digest, packet_json, now,
             now + evidence_mod.RETENTION_SECONDS),
        )
        self._audit(fid, user["id"], "evidence_packet_created", detail={"packet_id": packet["packet_id"]})
        return {"locked": True, "locked_cases": [r["id"] for r in pending], "packet": packet, "sha256": digest}

    def _case_for_packet(self, case_id: str) -> dict:
        c = self.store.one(
            "SELECT id, input_type, masked_content, input_sha256, payee_masked, amount, risk_level, score, state,"
            " created_at FROM cases WHERE id = ?",
            (case_id,),
        )
        c["reasons"] = self.store.query(
            "SELECT r.rule_id, r.severity, r.title, r.evidence_masked AS evidence, v.tool, v.ruleset_version"
            " FROM reasons r JOIN verdicts v ON v.id = r.verdict_id WHERE v.case_id = ? ORDER BY r.id",
            (case_id,),
        )
        c["approval"] = self.store.one(
            "SELECT decision, note, created_at, decided_at FROM approvals WHERE case_id = ?", (case_id,)
        )
        return c

    def unlock(self, token: str) -> dict:
        user = self._user(token)
        self._require_role(user, "guardian")
        self.store.execute(
            "UPDATE families SET locked = 0, locked_at = NULL, lock_reason = NULL WHERE id = ?", (user["family_id"],)
        )
        self._audit(user["family_id"], user["id"], "unlocked")
        return {"locked": False}

    def get_packet(self, token: str, packet_or_case_id: str | None = None) -> dict:
        user = self._user(token)
        rows = self.store.query(
            "SELECT * FROM evidence_packets WHERE family_id = ? ORDER BY created_at DESC", (user["family_id"],)
        )
        for r in rows:
            if packet_or_case_id in (None, r["id"]) or packet_or_case_id in json.loads(r["case_ids"]):
                packet = json.loads(r["packet_json"])
                return {"packet": packet, "sha256": r["sha256"]}
        raise NotFound("no evidence packet found")

    def build_case_packet(self, token: str, case_id: str) -> dict:
        """A packet for one case without triggering Emergency Stop (bharosa evidence <case-id>)."""
        user = self._user(token)
        self._case_for(user, case_id)
        try:
            return self.get_packet(token, case_id)
        except NotFound:
            pass
        audit = self.store.query(
            "SELECT actor_id, action, case_id, detail, at FROM audit_log WHERE family_id = ? AND case_id = ?"
            " ORDER BY id",
            (user["family_id"], case_id),
        )
        case = self._case_for_packet(case_id)
        packet = evidence_mod.build_packet(
            family_id=user["family_id"],
            requested_by={"role": user["role"], "name": user["display_name"]},
            reason="evidence export",
            cases=[case],
            audit=audit,
            generated_at=self.now(),
            incident_at=case["created_at"],
        )
        packet_json = json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2)
        return {"packet": packet, "sha256": hashlib.sha256(packet_json.encode("utf-8")).hexdigest()}

    # ---- retention ----------------------------------------------------------------------

    def purge_expired(self, case_days: float = 7) -> dict:
        """Delete decided cases older than ``case_days`` and evidence packets past their expiry.

        Pending (held) cases are kept until decided or expired. The audit log is append-only and is
        not purged by this call.
        """
        cutoff = self.now() - case_days * 86400
        old = [r["id"] for r in self.store.query(
            "SELECT id FROM cases WHERE created_at < ? AND state NOT IN ('held', 'checked')", (cutoff,))]
        with self.store.transaction() as conn:
            for cid in old:
                conn.execute("DELETE FROM reasons WHERE verdict_id IN (SELECT id FROM verdicts WHERE case_id = ?)",
                             (cid,))
                conn.execute("DELETE FROM verdicts WHERE case_id = ?", (cid,))
                conn.execute("DELETE FROM approvals WHERE case_id = ?", (cid,))
                conn.execute("DELETE FROM cases WHERE id = ?", (cid,))
            packets = conn.execute("DELETE FROM evidence_packets WHERE expires_at < ?", (self.now(),)).rowcount
            conn.execute("DELETE FROM pair_codes WHERE expires_at < ?", (self.now(),))
        return {"cases_deleted": len(old), "packets_deleted": packets}

    # ---- history and metrics ------------------------------------------------------------

    def audit(self, token: str, limit: int = 100) -> list[dict]:
        user = self._user(token)
        return self.store.query(
            "SELECT a.id, a.action, a.case_id, a.detail, a.at, u.display_name AS actor FROM audit_log a"
            " LEFT JOIN users u ON u.id = a.actor_id WHERE a.family_id = ? ORDER BY a.id DESC LIMIT ?",
            (user["family_id"], int(limit)),
        )

    def events_since(self, token: str, after_id: int = 0) -> list[dict]:
        user = self._user(token)
        self.expire_stale()
        return self.store.query(
            "SELECT id, action, case_id, at FROM audit_log WHERE family_id = ? AND id > ? ORDER BY id",
            (user["family_id"], int(after_id)),
        )

    def stats(self, token: str) -> dict:
        user = self._user(token)
        rows = self.store.query(
            "SELECT a.created_at, a.decided_at, a.decision FROM approvals a JOIN cases c ON c.id = a.case_id"
            " WHERE c.family_id = ? AND a.decided_at IS NOT NULL AND a.decision IN ('approved', 'blocked')",
            (user["family_id"],),
        )
        times = [r["decided_at"] - r["created_at"] for r in rows]
        counts = {r["state"]: r["n"] for r in self.store.query(
            "SELECT state, COUNT(*) AS n FROM cases WHERE family_id = ? GROUP BY state", (user["family_id"],)
        )}
        return {
            "decisions": len(times),
            "median_review_seconds": statistics.median(times) if times else None,
            "fastest_review_seconds": min(times) if times else None,
            "cases_by_state": counts,
        }
