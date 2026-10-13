"""Client TLS transport and CSCP framing I/O.

Networking concept demonstrated
-------------------------------
**Transport-layer security, client half + application framing.**  This is the
client's mirror of the server socket layer:

* **TLS 1.3 + mutual TLS** -- the client *verifies* the server certificate
  against the campus CA (certificate pinning point) and presents its own
  CA-signed certificate so the server binds the connection to an identity
  before any byte of CSCP is exchanged.  ``require_tls`` turns this into a
  hard failure when a server only offers plaintext, so the Wireshark
  "plain vs secure" build can never be used by accident against a real
  deployment.
* **Frame-layer reading** -- one OS read may deliver many CSCP frames
  (TCP coalescing) or a partial frame; the :class:`FrameDecoder` state
  machine (length-prefixed header + CRC32 trailer) reassembles them exactly
  like the server side, so the two share *identical* framing semantics.
* **Backpressure on the writer** -- ``drain()`` after every write lets the
  TCP window and the peer's queue do their job, instead of silently buffering
  unboundedly in user space.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass

from protocol.codec import FrameDecoder, encode_frame
from protocol.constants import FrameFlags
from protocol.messages import Message, to_frame

log = logging.getLogger("cscp.client.transport")


class TlsUnavailableError(RuntimeError):
    """Raised when the server is not offering TLS but the client requires it."""


@dataclass(slots=True)
class ClientTls:
    ca_file: str | None = None
    certfile: str | None = None
    keyfile: str | None = None

    def build(self, *, require: bool, server_hostname: str | None) -> ssl.SSLContext | None:
        """Build a TLS 1.3 client context, or ``None`` to go PLAIN."""
        has_any_tls = bool(self.ca_file or (self.certfile and self.keyfile))
        if not require and not has_any_tls:
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        if self.ca_file:
            ctx.load_verify_locations(cafile=self.ca_file)
        else:
            ctx.check_hostname = False
        if self.certfile and self.keyfile:
            ctx.load_cert_chain(self.certfile, self.keyfile)
        ctx.verify_mode = ssl.CERT_REQUIRED if self.ca_file else ssl.CERT_NONE
        return ctx


class ClientTransport:
    """Owns one TCP/TLS connection and the frame read pump."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls: ClientTls | None = None,
        require_tls: bool = True,
        connect_timeout: float = 8.0,
        server_hostname: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.tls = tls or ClientTls()
        self.require_tls = require_tls
        self.connect_timeout = connect_timeout
        self.server_hostname = server_hostname or host
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.decoder = FrameDecoder()
        self._tls_active = False

    @property
    def connected(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()

    @property
    def tls_active(self) -> bool:
        """True when this connection is protected by TLS 1.3."""
        return self._tls_active

    async def connect(self) -> None:
        local_ctx = self.tls.build(require=self.require_tls, server_hostname=self.server_hostname)
        self._tls_active = local_ctx is not None
        if not local_ctx and self.require_tls:
            raise TlsUnavailableError(
                "server has no TLS certificates but client requires TLS "
                "(CA file must be configured and present)"
            )
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.host,
                self.port,
                ssl=local_ctx,
                server_hostname=self.server_hostname if local_ctx else None,
            ),
            timeout=self.connect_timeout,
        )
        log.info("connected", extra={"host": self.host, "port": self.port, "tls": self._tls_active})

    def feed(self, data: bytes) -> None:
        """Push raw socket bytes into the frame decoder (called by reader task)."""
        self.decoder.feed(data)

    async def send(self, msg: Message, *, sequence: int, flags: FrameFlags = FrameFlags.NONE) -> None:
        assert self.writer is not None, "transport not connected"
        frame = to_frame(msg, sequence=sequence, flags=flags)
        self.writer.write(encode_frame(frame))
        await self.writer.drain()

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
            except (TimeoutError, ConnectionError):
                pass
            self.writer = None