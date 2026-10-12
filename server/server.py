"""CSCP server: TLS 1.3 listener (IPv4 + IPv6), lifecycle, graceful shutdown.

Networking concepts demonstrated
--------------------------------
* **TLS 1.3 + mutual TLS.**  The server presents a CA-signed certificate and
  *requires* a client certificate signed by the same CA.  This binds each
  connection to an identity before the application protocol even starts, makes
  traffic unreadable in transit, and provides **certificate pinning** points for
  the client.
* **Dual-stack (IPv4 + IPv6) listening.**  Two ``start_server`` sockets (one
  AF_INET, one AF_INET6) let the campus network reach the server over both
  protocol families; the client prefers IPv6 (happy-eyeballs style) and falls
  back to IPv4.
* **Event-loop socket multiplexing.**  One process, one thread, thousands of
  sockets.  The OS kernel (epoll/kqueue via selector) tells the loop which
  socket is readable; the server only ever touches ready sockets.
* **Graceful shutdown (SIGINT/SIGTERM).**  Close acceptors first (no new work),
  notify connected clients with a fatal ERROR, drain bounded queues, then reap
  sockets -- a "drain then die" pattern for zero message loss.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import secrets
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from protocol.constants import ErrorCode
from protocol.messages import Error
from server.auth import Authenticator, make_authenticator
from server.config import Config, TlsConfig
from server.context import ServerContext
from server.manager import ConnectionManager
from server.metrics import ServerMetrics
from server.rates import RateLimiter
from server.session import Session
from server.storage import InMemoryStore, MessageStore

_SETTLE_SECONDS = 0.1  # allow notification frames to reach writer queues

log = logging.getLogger("cscp.server")


@dataclass(slots=True)
class Listener:
    server: asyncio.AbstractServer
    family: str  # "IPv4" | "IPv6"
    address: tuple[Any, ...] | None = None


def build_ssl_context(cfg: TlsConfig) -> ssl.SSLContext | None:
    """Build a TLS 1.3 server context, or ``None`` when certs are absent.

    ``None`` means **INSECURE PLAIN MODE** -- used only for the Wireshark
    "plain vs secure" comparison build and unit tests (see captures/).
    """
    if not (Path(cfg.certfile).is_file() and Path(cfg.keyfile).is_file()):
        log.warning(
            "TLS certificates missing (%s, %s) -> starting in PLAIN mode (testing only)",
            cfg.certfile,
            cfg.keyfile,
        )
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers(cfg.ciphers)
    ctx.load_cert_chain(cfg.certfile, cfg.keyfile)
    if cfg.require_client_cert:
        ca_path = Path(cfg.ca_file)
        if not ca_path.is_file():
            raise FileNotFoundError(f"CA certificate not found: {cfg.ca_file}")
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(ca_path))
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class CSCPServer:
    """Owns listeners, sessions, and the shared server context."""

    def __init__(
        self,
        cfg: Config,
        *,
        auth_backend: str = "stub",
        auth_userdb: str | None = None,
        auth: Authenticator | None = None,
        secret: bytes | None = None,
        store: MessageStore | None = None,
    ) -> None:
        self.cfg = cfg
        self.metrics = ServerMetrics()
        self.store = store if store is not None else InMemoryStore()
        self.manager = ConnectionManager()
        self.rate = RateLimiter(cfg.rate)
        self.secret = secret if secret is not None else secrets.token_bytes(32)
        self.auth = (
            auth
            if auth is not None
            else make_authenticator(
                auth_backend,
                secret=self.secret,
                userdb=auth_userdb if auth_userdb is not None else cfg.auth.userdb,
                auth_cfg=cfg.auth,
            )
        )
        self.ctx = ServerContext(
            cfg=cfg,
            secret=self.secret,
            manager=self.manager,
            auth=self.auth,
            store=self.store,
            metrics=self.metrics,
            rate=self.rate,
            log=logging.getLogger("cscp.server"),
        )
        self.sessions: dict[int, Session] = {}
        self.listeners: list[Listener] = []
        self._ids = itertools.count(1)
        self._sem = asyncio.Semaphore(cfg.limits.max_connections)
        self._stopping = False
        self._ssl_context: ssl.SSLContext | None = None

    async def start(self) -> None:
        """Bind the IPv4 and/or IPv6 listeners (dual-stack)."""
        self._ssl_context = build_ssl_context(self.cfg.tls)

        factories: list[tuple[str, str, int]] = []
        if self.cfg.net.enable_v4:
            factories.append(("IPv4", self.cfg.net.host_v4, self.cfg.net.port))
        if self.cfg.net.enable_v6:
            factories.append(("IPv6", self.cfg.net.host_v6, self.cfg.net.port))
        if not factories:
            raise RuntimeError("no listener enabled (enable_v4/enable_v6 both false)")

        for family, host, port in factories:
            server = await asyncio.start_server(
                self._on_connect,
                host=host,
                port=port,
                ssl=self._ssl_context,
                limit=self.cfg.limits.max_frame_size + 256,
                reuse_address=True,
            )
            socks = list(cast(Any, server).sockets or [])
            address = socks[0].getsockname() if socks else None
            self.listeners.append(Listener(server, family, address))
        for listener in self.listeners:
            log.info(
                "listening",
                extra={"family": listener.family, "address": listener.address, "tls": self._ssl_context is not None},
            )

    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._sem.acquire()
        try:
            if self._stopping:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    log.debug("extra_connection_dropped_during_shutdown")
                return
            conn_id = next(self._ids)
            peername = writer.get_extra_info("peername") or ("unknown", 0)
            ip = peername[0] if isinstance(peername, tuple) else str(peername)
            port = peername[1] if isinstance(peername, tuple) and len(peername) > 1 else 0
            session = Session(self.ctx, reader, writer, connection_id=conn_id, ip=ip, port=port)
            self.sessions[conn_id] = session
            try:
                await session.run()
            finally:
                self.sessions.pop(conn_id, None)
        finally:
            self._sem.release()

    async def shutdown(self) -> None:
        """Stop accepting, notify peers, flush, and close everything."""
        if self._stopping:
            return
        self._stopping = True
        log.info("shutdown_begin", extra={"active_sessions": len(self.sessions)})

        # 1. Stop accepting new work.  NOTE: we deliberately do NOT await
        #    `wait_closed()` here -- it blocks until every active connection
        #    handler finishes, i.e. until the sessions below are closed.
        for listener in self.listeners:
            listener.server.close()

        # 2. Tell connected peers, give them a beat to flush, then close them.
        for session in list(self.sessions.values()):
            await session.send(
                Error(code=ErrorCode.SHUTTING_DOWN, message="server shutting down", fatal=True)
            )
        await asyncio.sleep(_SETTLE_SECONDS)

        await asyncio.gather(
            *(session.graceful_close() for session in list(self.sessions.values())),
            return_exceptions=True,
        )
        self.sessions.clear()

        # 3. Now that every handler has returned, the listeners can be reaped.
        for listener in self.listeners:
            try:
                await listener.server.wait_closed()
            except Exception:  # noqa: BLE001
                log.debug("listener_wait_closed_error", extra={"family": listener.family})
        log.info("shutdown_complete")

    @property
    def is_tls(self) -> bool:
        return self._ssl_context is not None

    def summary(self) -> dict[str, object]:
        return {
            "server_name": self.cfg.server_name,
            "metrics": self.metrics.snapshot(),
            "online": self.manager.snapshot(),
            "rate_limiter": self.rate.snapshot(),
        }