"""HTTP/1.1 admin dashboard: live metrics + health over a second protocol.

Networking concept demonstrated
-------------------------------
**One server process, two protocols.**  The CSCP binary protocol runs on its
TLS listener; an ordinary HTTP/1.1 server (implemented with stock asyncio, no
web framework) runs on a second TCP socket for the admin plane.  Layering
HTTP over TCP with hand-rolled request parsing shows both what HTTP actually
is -- a line-based text protocol with ``CRLF CRLF`` headers -- and how an
event loop can multiplex unrelated application protocols from the same process.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("cscp.server.admin")

_MAX_HEADER_BYTES = 4096
_RESPONSES = {
    200: "OK",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
}

_DASHBOARD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>CSCP server dashboard</title>
<style>
 body{font:14px/1.45 Menlo,monospace;color:#0f1220;padding:28px;max-width:760px}
 h1{font-size:18px} pre{background:#f5f7fb;border:1px solid #dfe4ee;padding:16px;overflow:auto}
 .ok{color:#189a3d;font-weight:bold}
</style></head>
<body><h1>campus-cscp-1 &mdash; live telemetry</h1>
<p class="ok">&#9679; streaming /metrics</p>
<pre id="m">loading&hellip;</pre>
<script>
fetch('/metrics').then(function(r){return r.json();}).then(function(j){
  document.getElementById('m').textContent = JSON.stringify(j, null, 2);
}).catch(function(e){
  document.getElementById('m').textContent = 'error: ' + e;
});
</script></body></html>
"""


@dataclass(slots=True)
class AdminHttpConfig:
    enable: bool = False
    host_v4: str = "127.0.0.1"
    port: int = 9444
    auth_token_env: str | None = None
    require_auth: bool = True

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> AdminHttpConfig:
        return cls(
            enable=bool(m.get("enable", False)),
            host_v4=str(m.get("host_v4", "127.0.0.1")),
            port=int(m.get("port", 9444)),
            auth_token_env=m.get("auth_token_env"),
            require_auth=bool(m.get("require_auth", True)),
        )

    def auth_token(self) -> str | None:
        """Resolve the Bearer token from the environment (never from YAML)."""
        if not self.auth_token_env:
            return None
        import os

        return os.environ.get(self.auth_token_env)


class AdminHttpServer:
    """Tiny asyncio HTTP/1.1 server serving ``/health`` and ``/metrics``."""

    def __init__(
        self,
        cfg: AdminHttpConfig,
        summary: Callable[[], dict[str, object]],
        *,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self.cfg = cfg
        self._summary = summary
        self._host = host if host is not None else cfg.host_v4
        self._port = port if port is not None else cfg.port
        self._started = time.monotonic()
        self._listener: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        self._listener = await asyncio.start_server(self._handle, host=self._host, port=self._port)
        socks = list(self._listener.sockets or [])
        bound = int(socks[0].getsockname()[1]) if socks else self._port
        log.info("admin_http_listening", extra={"host": self._host, "port": bound})
        return bound

    async def shutdown(self) -> None:
        if self._listener is not None:
            self._listener.close()
            await self._listener.wait_closed()
            self._listener = None

    @property
    def is_serving(self) -> bool:
        return self._listener is not None

    # -- HTTP plumbing ------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            await self._respond(writer, 400, b"", "text/plain")
            return
        if len(raw) > _MAX_HEADER_BYTES:
            await self._respond(writer, 431, b"", "text/plain")
            return

        line, _, rest = raw.partition(b"\r\n")
        parts = line.split(b" ")
        if len(parts) != 3:
            await self._respond(writer, 400, b"", "text/plain")
            return
        method, target = parts[0].decode("ascii", "replace"), parts[1].decode("latin-1")
        auth = self._authorization(rest)
        code, body, ctype = self._route(method, target, auth)
        await self._respond(writer, code, body, ctype)

    @staticmethod
    def _authorization(header_bytes: bytes) -> str | None:
        for line in header_bytes.split(b"\r\n"):
            if line.lower().startswith(b"authorization:"):
                return line.split(b":", 1)[1].strip().decode("latin-1")
        return None

    def _route(self, method: str, target: str, auth: str | None) -> tuple[int, bytes, str]:
        token = self.cfg.auth_token()
        allowed = not self.cfg.require_auth or token is None or auth == f"Bearer {token}"
        if target in ("/metrics", "/"):
            if method != "GET":
                return 405, b"", "text/plain"
            if not allowed:
                return 401, b'{"error":"unauthorized"}', "application/json"
        elif target == "/health":
            if method != "GET":
                return 405, b"", "text/plain"
        else:
            return 404, b'{"error":"not found"}', "application/json"

        if target == "/health":
            body = json.dumps(
                {"status": "ok", "uptime_s": round(time.monotonic() - self._started, 2),
                 "admin_on": self.is_serving}
            ).encode()
            return 200, body, "application/json"
        if target == "/metrics":
            body = json.dumps(self._summary(), default=str, indent=2).encode()
            return 200, body, "application/json"
        return 200, _DASHBOARD.encode(), "text/html; charset=utf-8"

    @staticmethod
    async def _respond(
        writer: asyncio.StreamWriter, code: int, body: bytes, ctype: str
    ) -> None:
        reason = _RESPONSES.get(code, "Unknown")
        head = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(head.encode("ascii") + body)
        try:
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001, S110 -- client may already be gone
                pass