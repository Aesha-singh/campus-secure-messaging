"""Shared harness: boots a real CSCPServer on an ephemeral port and provides a
wire-level test client that speaks the protocol exactly as a real client would.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable

import pytest_asyncio

from protocol.codec import Frame, FrameDecoder, encode_frame
from protocol.constants import AuthMethod, FrameFlags, MessageType
from protocol.errors import CscpError
from protocol.messages import (
    AuthReq,
    Hello,
    Message,
    decode_message,
    to_frame,
)
from server.auth import StubAuthenticator
from server.config import Config
from server.server import CSCPServer

ServerFixture = Callable[..., Awaitable[tuple[CSCPServer, int]]]


class WireClient:
    """Minimal CSCP client used to exercise the server end-to-end."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.decoder = FrameDecoder()
        self._queue: deque[Frame] = deque()
        self.seq = 0

    @property
    def closed(self) -> bool:
        return self.writer.is_closing()

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def send_with_seq(self, msg: Message, seq: int, flags: FrameFlags = FrameFlags.NONE) -> None:
        frame = to_frame(msg, sequence=seq, flags=flags)
        await self.send_raw(encode_frame(frame))

    async def send(self, msg: Message, flags: FrameFlags = FrameFlags.NONE) -> int:
        self.seq += 1
        await self.send_with_seq(msg, self.seq, flags)
        return self.seq

    async def read_until(self, mtype: MessageType, *, timeout: float = 3.0) -> Frame:  # noqa: ASYNC109
        """Block until a frame of ``mtype`` arrives; raise TimeoutError otherwise."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            for frame in list(self._queue):
                if frame.msg_type is mtype:
                    self._queue.remove(frame)
                    return frame
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(f"no {mtype.name} frame within {timeout}s")
            data = await asyncio.wait_for(self.reader.read(65536), timeout=remaining)
            if not data:
                raise TimeoutError(f"connection closed before {mtype.name}")
            self._drain(data)

    def _drain(self, data: bytes) -> None:
        self.decoder.feed(data)
        while True:
            try:
                frame = self.decoder.next_frame()
            except CscpError:
                raise
            if frame is None:
                return
            self._queue.append(frame)

    async def handshake(self, username: str, password: str) -> Message:
        """HELLO + AUTH_REQ, return the decoded AUTH_OK message."""
        await self.send(Hello(versions=[1], client_id="test", nonce=b"t" * 8, device="py"))
        await self.send(
            AuthReq(
                username=username,
                method=AuthMethod.PASSWORD,
                device_id="test-device",
                client_nonce=b"c" * 8,
                password=password,
            )
        )
        frame = await self.read_until(MessageType.AUTH_OK)
        return decode_message(frame)

    async def close(self) -> None:
        if not self.writer.is_closing():
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:  # noqa: BLE001, S110 -- test teardown; socket may be gone
                pass


@pytest_asyncio.fixture
async def running_server() -> ServerFixture:
    """Factory that boots any number of isolated servers on 127.0.0.1:0."""
    servers: list[CSCPServer] = []

    async def _make(
        cfg: Config | None = None,
        *,
        users: dict[str, str] | None = None,
        secret: bytes | None = None,
    ) -> tuple[CSCPServer, int]:
        cfg = cfg or Config()
        cfg.net.enable_v4 = True
        cfg.net.host_v4 = "127.0.0.1"
        cfg.net.enable_v6 = False
        cfg.net.port = 0
        srv = CSCPServer(
            cfg,
            auth=StubAuthenticator(users or {"alice": "sa", "bob": "sb"}),
            secret=secret or b"k" * 32,
        )
        await srv.start()
        port = srv.listeners[0].server.sockets[0].getsockname()[1]
        servers.append(srv)
        return srv, port

    yield _make

    for srv in servers:
        await srv.shutdown()


async def connect(port: int) -> WireClient:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    return WireClient(reader, writer)


def server_cfg() -> Config:
    """A default Config tweaked for loopback tests (fast heartbeat)."""
    cfg = Config()
    cfg.heartbeat.idle_timeout = 5.0
    cfg.heartbeat.ping_interval = 2.0
    return cfg