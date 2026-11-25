"""Pick where the family queue lives.

* Local mode (no relay URL): the CLI calls :class:`FamilyService` directly on the shared SQLite file.
  Two terminals on one laptop (two profiles) share the queue. This is the offline demo fallback.
* Relay mode: :class:`RelayBackend` calls the family relay over HTTP with the same method names.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

import httpx

from .config import Profile, db_path
from .service import (AuthError, Conflict, FamilyService, Forbidden, NotFound, RateLimited, ServiceError)
from .store import Store

_ERRORS = {401: AuthError, 403: Forbidden, 404: NotFound, 409: Conflict, 429: RateLimited}


class RelayBackend:
    def __init__(self, base_url: str, timeout: float = 10.0, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(base_url=self.base_url, timeout=timeout)

    def _call(self, method: str, path: str, token: str | None = None, **kw) -> Any:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            r = self.client.request(method, path, headers=headers, **kw)
        except httpx.HTTPError as exc:
            raise ServiceError(f"cannot reach the family relay at {self.base_url}: {exc}") from exc
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise _ERRORS.get(r.status_code, ServiceError)(str(detail))
        return r.json()

    # Same surface as FamilyService --------------------------------------------------

    def create_family(self, parent_name, language="en", phone=None):
        return self._call("POST", "/families", json={"parent_name": parent_name, "language": language, "phone": phone})

    def new_pair_code(self, token):
        return self._call("POST", "/pair-codes", token)

    def join_family(self, pair_code, guardian_name, language="en", phone=None, code_word=None):
        return self._call("POST", "/join", json={"pair_code": pair_code, "guardian_name": guardian_name,
                                                 "language": language, "phone": phone, "code_word": code_word})

    def whoami(self, token):
        return self._call("GET", "/me", token)

    def family_info(self, token):
        return self._call("GET", "/family", token)

    def set_review_amount(self, token, amount):
        return self._call("PUT", "/family/review-amount", token, json={"amount": amount})

    def set_code_word(self, token, word):
        return self._call("PUT", "/family/code-word", token, json={"word": word})

    def verify_code_word(self, token, word):
        return self._call("POST", "/family/code-word/verify", token, json={"word": word})["match"]

    def check_context(self, token):
        return self._call("GET", "/context", token)

    def list_trusted_payees(self, token):
        return self._call("GET", "/payees", token)

    def add_trusted_payee(self, token, vpa_hash, vpa_masked, label):
        return self._call("POST", "/payees", token, json={"vpa_hash": vpa_hash, "vpa_masked": vpa_masked,
                                                          "label": label})

    def remove_trusted_payee(self, token, vpa_hash):
        return self._call("DELETE", f"/payees/{vpa_hash}", token)["removed"]

    def submit_case(self, token, case):
        case = {k: v for k, v in case.items() if k != "raw_content"}
        return self._call("POST", "/cases", token, json=case)

    def list_cases(self, token, states=None, limit=50):
        params = [("limit", str(limit))] + [("state", s) for s in (states or [])]
        return self._call("GET", "/cases", token, params=params)

    def get_case(self, token, case_id):
        return self._call("GET", f"/cases/{case_id}", token)

    def case_status(self, token, case_id):
        return self._call("GET", f"/cases/{case_id}/status", token)

    def request_approval(self, token, case_id, ttl_seconds=1800):
        return self._call("POST", f"/cases/{case_id}/approval", token, json={"ttl_seconds": ttl_seconds})

    def decide(self, token, case_id, decision, note=None):
        return self._call("POST", f"/cases/{case_id}/decision", token, json={"decision": decision, "note": note})

    def record_handoff(self, token, case_id):
        return self._call("POST", f"/cases/{case_id}/handoff", token)

    def build_case_packet(self, token, case_id):
        return self._call("GET", f"/cases/{case_id}/evidence", token)

    def emergency_stop(self, token, reason="", incident_at=None):
        return self._call("POST", "/stop", token, json={"reason": reason, "incident_at": incident_at})

    def unlock(self, token):
        return self._call("POST", "/unlock", token)

    def get_packet(self, token, packet_or_case_id=None):
        params = {"id": packet_or_case_id} if packet_or_case_id else {}
        return self._call("GET", "/evidence", token, params=params)

    def audit(self, token, limit=100):
        return self._call("GET", "/audit", token, params={"limit": limit})

    def stats(self, token):
        return self._call("GET", "/stats", token)

    def events_since(self, token, after_id=0):
        """Read the SSE stream once and return the events after ``after_id``."""
        out = []
        for ev in self.stream_events(token, after_id, once=True):
            out.append(ev)
        return out

    def stream_events(self, token, after_id=0, once=False) -> Iterator[dict]:
        headers = {"Authorization": f"Bearer {token}", "Accept": "text/event-stream"}
        params = {"after": after_id, "once": str(once).lower()}
        with self.client.stream("GET", "/events", headers=headers, params=params, timeout=None) as r:
            if r.status_code >= 400:
                raise _ERRORS.get(r.status_code, ServiceError)(r.read().decode())
            for line in r.iter_lines():
                if line.startswith("data: "):
                    yield json.loads(line[6:])


def get_backend(profile: Profile):
    if profile.relay_url:
        return RelayBackend(profile.relay_url)
    return FamilyService(Store(db_path()))
