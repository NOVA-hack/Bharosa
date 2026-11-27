"""HTTP API for the family relay. Every route except pairing needs ``Authorization: Bearer <token>``.

The relay stores masked, structured data only, and rejects content that still looks like PII.
Run it with ``bharosa relay --host 0.0.0.0 --port 8765``.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .. import __version__
from ..appcheck import check_for_app
from ..service import FamilyService, ServiceError
from ..store import Store


class CreateFamily(BaseModel):
    parent_name: str = Field(min_length=1, max_length=60)
    language: str = Field(default="en", pattern="^(en|hi|kn)$")
    phone: str | None = Field(default=None, max_length=20)


class JoinFamily(BaseModel):
    pair_code: str = Field(min_length=6, max_length=20)
    guardian_name: str = Field(min_length=1, max_length=60)
    language: str = Field(default="en", pattern="^(en|hi|kn)$")
    phone: str | None = Field(default=None, max_length=20)
    code_word: str | None = Field(default=None, max_length=60)


class Amount(BaseModel):
    amount: float = Field(ge=0)


class Word(BaseModel):
    word: str = Field(min_length=1, max_length=60)


class Payee(BaseModel):
    vpa_hash: str = Field(min_length=8, max_length=64)
    vpa_masked: str = Field(max_length=80)
    label: str = Field(min_length=1, max_length=60)


class Decision(BaseModel):
    decision: str = Field(pattern="^(approve|block)$")
    note: str | None = Field(default=None, max_length=280)


class Stop(BaseModel):
    reason: str = Field(default="", max_length=280)
    incident_at: float | None = None


class CheckRequest(BaseModel):
    content: str = Field(min_length=1, max_length=8 * 1024)
    kind: str = Field(default="auto", pattern="^(auto|qr|url|msg)$")
    lang: str = Field(default="en", pattern="^(en|hi|kn)$")


ANON_CHECKS_PER_HOUR = 60  # per client address, for checks made without a token


class Approval(BaseModel):
    ttl_seconds: int = Field(default=1800, ge=60, le=24 * 3600)


def create_app(service: FamilyService | None = None) -> FastAPI:
    if service is None:
        db = os.environ.get("BHAROSA_RELAY_DB", "bharosa-relay.db")
        service = FamilyService(Store(db))
    app = FastAPI(title="Bharosa family relay", version=__version__)
    app.state.service = service

    @app.exception_handler(ServiceError)
    async def _service_error(_: Request, exc: ServiceError):
        return JSONResponse(status_code=exc.status, content={"error": exc.code, "detail": str(exc)})

    def token(authorization: str | None = Header(default=None)) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        return authorization.split(" ", 1)[1].strip()

    def optional_token(authorization: str | None = Header(default=None)) -> str | None:
        if not authorization:
            return None
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="malformed bearer token")
        return authorization.split(" ", 1)[1].strip() or None

    svc = service
    anon_hits: dict[str, deque] = defaultdict(deque)
    anon_lock = threading.Lock()

    def allow_anon(client: str) -> bool:
        now = time.time()
        with anon_lock:
            q = anon_hits[client]
            while q and q[0] < now - 3600:
                q.popleft()
            if len(q) >= ANON_CHECKS_PER_HOUR:
                return False
            q.append(now)
            return True

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.post("/families")
    def create_family(body: CreateFamily) -> dict:
        return svc.create_family(body.parent_name, body.language, body.phone)

    @app.post("/join")
    def join(body: JoinFamily) -> dict:
        return svc.join_family(body.pair_code, body.guardian_name, body.language, body.phone, body.code_word)

    @app.post("/pair-codes")
    def pair_code(t: str = Depends(token)) -> dict:
        return svc.new_pair_code(t)

    @app.get("/me")
    def me(t: str = Depends(token)) -> dict:
        return svc.whoami(t)

    @app.get("/family")
    def family(t: str = Depends(token)) -> dict:
        return svc.family_info(t)

    @app.put("/family/review-amount")
    def review_amount(body: Amount, t: str = Depends(token)) -> dict:
        return svc.set_review_amount(t, body.amount)

    @app.put("/family/code-word")
    def code_word(body: Word, t: str = Depends(token)) -> dict:
        return svc.set_code_word(t, body.word)

    @app.post("/family/code-word/verify")
    def verify_code_word(body: Word, t: str = Depends(token)) -> dict:
        return {"match": svc.verify_code_word(t, body.word)}

    @app.get("/context")
    def context(t: str = Depends(token)) -> dict:
        return svc.check_context(t)

    @app.get("/payees")
    def payees(t: str = Depends(token)) -> list[dict]:
        return svc.list_trusted_payees(t)

    @app.post("/payees")
    def add_payee(body: Payee, t: str = Depends(token)) -> dict:
        return svc.add_trusted_payee(t, body.vpa_hash, body.vpa_masked, body.label)

    @app.delete("/payees/{vpa_hash}")
    def remove_payee(vpa_hash: str, t: str = Depends(token)) -> dict:
        return {"removed": svc.remove_trusted_payee(t, vpa_hash)}

    @app.post("/cases")
    def submit_case(body: dict[str, Any], t: str = Depends(token)) -> dict:
        for key in ("input_type", "masked_content", "input_sha256", "verdict"):
            if key not in body:
                raise HTTPException(status_code=422, detail=f"missing field {key}")
        body.pop("raw_content", None)  # raw content never goes to the relay
        return svc.submit_case(t, body)

    @app.post("/check")
    def check(body: CheckRequest, request: Request, t: str | None = Depends(optional_token)) -> dict:
        """Run the deterministic checks on raw input and, for a parent, queue the masked case.

        The raw content is used in memory for the check and is not stored (see bharosa.appcheck).
        """
        if t is None and not allow_anon(request.client.host if request.client else "unknown"):
            raise HTTPException(status_code=429, detail="too many checks; pair the app with a family")
        return check_for_app(svc, t, body.content, body.kind, body.lang)

    @app.get("/cases")
    def list_cases(state: list[str] | None = Query(default=None), limit: int = 50,
                   t: str = Depends(token)) -> list[dict]:
        return svc.list_cases(t, state, min(limit, 200))

    @app.get("/cases/{case_id}")
    def get_case(case_id: str, t: str = Depends(token)) -> dict:
        return svc.get_case(t, case_id)

    @app.get("/cases/{case_id}/status")
    def case_status(case_id: str, t: str = Depends(token)) -> dict:
        return svc.case_status(t, case_id)

    @app.post("/cases/{case_id}/approval")
    def request_approval(case_id: str, body: Approval | None = None, t: str = Depends(token)) -> dict:
        return svc.request_approval(t, case_id, (body or Approval()).ttl_seconds)

    @app.post("/cases/{case_id}/decision")
    def decide(case_id: str, body: Decision, t: str = Depends(token)) -> dict:
        return svc.decide(t, case_id, body.decision, body.note)

    @app.post("/cases/{case_id}/handoff")
    def handoff(case_id: str, t: str = Depends(token)) -> dict:
        return svc.record_handoff(t, case_id)

    @app.get("/cases/{case_id}/evidence")
    def case_evidence(case_id: str, t: str = Depends(token)) -> dict:
        return svc.build_case_packet(t, case_id)

    @app.post("/stop")
    def stop(body: Stop, t: str = Depends(token)) -> dict:
        return svc.emergency_stop(t, body.reason, body.incident_at)

    @app.post("/unlock")
    def unlock(t: str = Depends(token)) -> dict:
        return svc.unlock(t)

    @app.get("/evidence")
    def evidence(id: str | None = None, t: str = Depends(token)) -> dict:
        return svc.get_packet(t, id)

    @app.get("/audit")
    def audit(limit: int = 100, t: str = Depends(token)) -> list[dict]:
        return svc.audit(t, min(limit, 500))

    @app.get("/stats")
    def stats(t: str = Depends(token)) -> dict:
        return svc.stats(t)

    @app.get("/events")
    async def events(after: int = 0, once: bool = False, t: str = Depends(token)):
        svc.whoami(t)  # authenticate before opening the stream

        async def stream():
            last = after
            yield ": connected\n\n"
            while True:
                rows = svc.events_since(t, last)
                for r in rows:
                    last = r["id"]
                    yield f"id: {r['id']}\nevent: {r['action']}\ndata: {json.dumps(r)}\n\n"
                if once:
                    return
                await asyncio.sleep(1.0)

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app


def app_factory() -> FastAPI:  # for `uvicorn bharosa.relay.app:app_factory --factory`
    return create_app()
