"""SQLite storage for cases, verdicts, approvals, the audit log and family data.

The same schema serves the parent's local database and the family relay's database.
Only masked, structured data is stored. Raw input is stored only when the parent passes --keep-raw.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS families (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0,
    locked_at REAL,
    lock_reason TEXT,
    review_amount REAL NOT NULL DEFAULT 2000,
    code_word_hash TEXT,
    code_word_salt TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    family_id TEXT NOT NULL REFERENCES families(id),
    role TEXT NOT NULL CHECK (role IN ('parent', 'guardian')),
    display_name TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'en',
    phone TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pair_codes (
    code_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL REFERENCES families(id),
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS family_links (
    parent_id TEXT NOT NULL REFERENCES users(id),
    guardian_id TEXT NOT NULL REFERENCES users(id),
    paired_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    PRIMARY KEY (parent_id, guardian_id)
);
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    family_id TEXT NOT NULL REFERENCES families(id),
    parent_id TEXT NOT NULL REFERENCES users(id),
    input_type TEXT NOT NULL,
    masked_content TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    raw_content TEXT,
    payee_hash TEXT,
    payee_masked TEXT,
    amount REAL,
    risk_level TEXT NOT NULL,
    score INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS cases_family_state ON cases(family_id, state);
CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    tool TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    score INTEGER NOT NULL,
    ruleset_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reasons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id INTEGER NOT NULL REFERENCES verdicts(id),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence_masked TEXT,
    truth_card TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL UNIQUE REFERENCES cases(id),
    guardian_id TEXT REFERENCES users(id),
    decision TEXT,
    note TEXT,
    created_at REAL NOT NULL,
    decided_at REAL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id TEXT,
    actor_id TEXT,
    action TEXT NOT NULL,
    case_id TEXT,
    detail TEXT,
    at REAL NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TABLE IF NOT EXISTS evidence_packets (
    id TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    case_ids TEXT NOT NULL,
    location TEXT,
    sha256 TEXT NOT NULL,
    packet_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS payee_reports (
    vpa_hash TEXT NOT NULL,
    family_id TEXT NOT NULL,
    report_count INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    PRIMARY KEY (vpa_hash, family_id)
);
CREATE TABLE IF NOT EXISTS known_payees (
    vpa_hash TEXT NOT NULL,
    family_id TEXT NOT NULL,
    first_paid REAL NOT NULL,
    PRIMARY KEY (vpa_hash, family_id)
);
CREATE TABLE IF NOT EXISTS trusted_payees (
    vpa_hash TEXT NOT NULL,
    family_id TEXT NOT NULL,
    label TEXT NOT NULL,
    vpa_masked TEXT NOT NULL,
    added_by TEXT,
    added_at REAL NOT NULL,
    PRIMARY KEY (vpa_hash, family_id)
);
"""


class Store:
    """Thin wrapper over one SQLite file. Thread-safe enough for the relay (one lock per store)."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple | dict = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _Tx:
    def __init__(self, store: Store):
        self.store = store

    def __enter__(self) -> sqlite3.Connection:
        self.store._lock.acquire()
        return self.store._conn

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self.store._conn.commit()
            else:
                self.store._conn.rollback()
        finally:
            self.store._lock.release()
