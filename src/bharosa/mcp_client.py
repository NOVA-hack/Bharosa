"""Call the Bharosa MCP server over stdio from the (synchronous) CLI.

The server is spawned once per CLI run as ``python -m bharosa.mcp_server`` and the session is kept
open on a background event loop, so several tool calls in one check share one process.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from typing import Any

TIMEOUT_SECONDS = 30


class McpError(RuntimeError):
    pass


class McpRunner:
    name = "mcp"

    def __init__(self, command: list[str] | None = None, env: dict[str, str] | None = None):
        from mcp import Client, StdioServerParameters

        command = command or [sys.executable, "-m", "bharosa.mcp_server"]
        child_env = dict(os.environ)
        child_env.update(env or {})
        child_env.setdefault("PYTHONIOENCODING", "utf-8")
        self._params = StdioServerParameters(command=command[0], args=command[1:], env=child_env)
        self._client_cls = Client
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._client: Any = None
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, name="bharosa-mcp", daemon=True)
        self._thread.start()
        if not self._ready.wait(TIMEOUT_SECONDS):
            raise McpError("the Bharosa MCP server did not start in time")
        if self._error:
            raise McpError(f"could not start the Bharosa MCP server: {self._error}") from self._error

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main())

    async def _main(self) -> None:
        self._stop = asyncio.Event()
        try:
            async with self._client_cls(self._params, read_timeout_seconds=TIMEOUT_SECONDS) as client:
                self._client = client
                self._ready.set()
                await self._stop.wait()
        except BaseException as exc:  # surface start-up errors to the caller
            self._error = exc
            self._ready.set()

    def list_tools(self) -> list[str]:
        res = self._submit(self._client.list_tools())
        return [t.name for t in res.tools]

    def call(self, tool: str, arguments: dict[str, Any]) -> dict:
        args = {k: v for k, v in arguments.items() if v is not None}
        res = self._submit(self._client.call_tool(tool, args))
        if getattr(res, "is_error", False):
            text = " ".join(getattr(c, "text", "") for c in res.content)
            raise McpError(f"{tool} failed: {text}")
        sc = getattr(res, "structured_content", None)
        if isinstance(sc, dict):
            return sc.get("result", sc) if set(sc) == {"result"} else sc
        for c in res.content:
            text = getattr(c, "text", None)
            if text:
                return json.loads(text)
        raise McpError(f"{tool} returned no content")

    def _submit(self, coro):
        if self._error:
            raise McpError(str(self._error))
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(TIMEOUT_SECONDS)

    # Runner protocol ----------------------------------------------------------------

    def inspect_upi_qr(self, payload: str, family_context: dict | None = None) -> dict:
        return self.call("inspect_upi_qr", {"payload": payload, "family_context": family_context})

    def inspect_url(self, url: str) -> dict:
        return self.call("inspect_url", {"url": url})

    def match_scam_playbook(self, text: str) -> dict:
        return self.call("match_scam_playbook", {"text": text})

    def close(self) -> None:
        if self._stop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(timeout=10)

    def __enter__(self) -> "McpRunner":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
