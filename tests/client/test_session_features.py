"""End-to-end tests for the client session's channels / files / RTT features.

These drive two real ``ClientSession`` instances through a real CSCPServer and
assert on the high-level callback events the GUI consumes.
"""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
from collections import deque
from pathlib import Path
from typing import Any

import pytest_asyncio

from client.config import ClientConfig
from client.crypto import ClientCrypto
from client.session import (
    ClientCallbacks,
    ClientSession,
    FileEvent,
    GroupMessage,
)
from client.store import ClientStore
from server.auth import StubAuthenticator
from server.config import Config
from server.server import CSCPServer

ALICE = "alice"
BOB = "bob"
PASSWORDS = {ALICE: "sa", BOB: "sb"}  # noqa: S105 -- stub test credentials


@pytest_asyncio.fixture
async def server():  # type: ignore[no-untyped-def]
    cfg = Config()
    cfg.net.enable_v4 = True
    cfg.net.host_v4 = "127.0.0.1"
    cfg.net.enable_v6 = False
    cfg.net.port = 0
    srv = CSCPServer(cfg, auth=StubAuthenticator(dict(PASSWORDS)), secret=b"k" * 32)
    await srv.start()
    yield srv
    await srv.shutdown()


class Harness:
    def __init__(self) -> None:
        self.files: deque[FileEvent] = deque()
        self.groups: deque[GroupMessage] = deque()
        self.channels: deque[Any] = deque()
        self.rtts: deque[float] = deque()

    async def on_file(self, event: FileEvent) -> None:
        self.files.append(event)

    async def on_group(self, msg: GroupMessage) -> None:
        self.groups.append(msg)

    async def on_channel(self, info: Any) -> None:
        self.channels.append(info)

    async def on_rtt(self, rtt_ms: float) -> None:
        self.rtts.append(rtt_ms)


async def _make_session(username: str, server: Any, tmp_path: Path) -> tuple[ClientSession, Harness, ClientStore]:
    port = server.listeners[0].server.sockets[0].getsockname()[1]
    password = PASSWORDS[username]
    cfg = ClientConfig(
        host="127.0.0.1",
        port=port,
        connect_timeout=5.0,
        reconnect_backoff_base=0.1,
        reconnect_backoff_max=1.0,
        client_id="test",
        device_name=f"dev-{username}",
        username=username,
        password=password,
        require_tls=False,
        data_dir=str(tmp_path / username),
    )
    identity_dir = tempfile.mkdtemp(dir=tmp_path)
    own = ClientCrypto.create(f"dev-{username}")
    store = ClientStore(str(Path(identity_dir) / "profile.db"))
    await store.open()
    h = Harness()
    cbs = ClientCallbacks(
        on_file=h.on_file,
        on_group=h.on_group,
        on_channel=h.on_channel,
        on_rtt=h.on_rtt,
    )
    sess = ClientSession(cfg=cfg, crypto=own, store=store, callbacks=cbs)
    sess.set_credentials(username, password)
    return sess, h, store


async def _wait_for(predicate, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]  # noqa: ASYNC109
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise TimeoutError("condition not met in time")
        await asyncio.sleep(0.02)


async def _pair(server: Any, tmp_path: Path, *, pin: bool = True) -> tuple[Any, ...]:
    alice, h_a, store_a = await _make_session(ALICE, server, tmp_path)
    bob, h_b, store_b = await _make_session(BOB, server, tmp_path)
    if pin:
        bob.crypto.pin_peer(f"u_{ALICE}", alice.crypto.own_public())
        alice.crypto.pin_peer(f"u_{BOB}", bob.crypto.own_public())
    ta = asyncio.create_task(alice.run())
    tb = asyncio.create_task(bob.run())
    await asyncio.gather(
        asyncio.wait_for(alice._connected.wait(), 5),
        asyncio.wait_for(bob._connected.wait(), 5),
    )
    return alice, bob, h_a, h_b, store_a, store_b, ta, tb


async def _teardown(*, alice, bob, store_a, store_b, ta, tb) -> None:  # type: ignore[no-untyped-def]
    await alice.stop()
    await bob.stop()
    await ta
    await tb
    await store_a.close()
    await store_b.close()


async def test_ping_round_trip(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, bob, h_a, h_b, store_a, store_b, ta, tb = await _pair(server, tmp_path)
    try:
        rtt = await alice.ping()
        assert rtt > 0.0
        await _wait_for(lambda: len(h_a.rtts) >= 1)
        assert h_a.rtts[-1] > 0.0
    finally:
        await _teardown(alice=alice, bob=bob, store_a=store_a, store_b=store_b, ta=ta, tb=tb)


async def test_channel_create_join_and_group_message(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, bob, h_a, h_b, store_a, store_b, ta, tb = await _pair(server, tmp_path)
    try:
        await alice.create_channel("Study Room", "course")
        await _wait_for(lambda: any(c.name == "Study Room" for c in h_a.channels))
        info = next(c for c in h_a.channels if c.name == "Study Room")
        assert info.kind == "course"
        assert info.role == "owner"
        assert info.created_by == f"u_{ALICE}"
        assert f"u_{ALICE}" in info.members

        await bob.join_channel(info.channel_id)
        await _wait_for(lambda: any(c.channel_id == info.channel_id for c in h_b.channels))
        bob_info = next(c for c in h_b.channels if c.channel_id == info.channel_id)
        assert bob_info.role == "member"
        assert f"u_{BOB}" in bob_info.members

        await alice.send_channel(info.channel_id, "hello room")
        await _wait_for(lambda: len(h_b.groups) >= 1)
        got = h_b.groups.popleft()
        assert got.text == "hello room"
        assert got.sender_id == f"u_{ALICE}"
        assert got.channel_id == info.channel_id
        assert got.direction == "recv"
    finally:
        await _teardown(alice=alice, bob=bob, store_a=store_a, store_b=store_b, ta=ta, tb=tb)


async def test_channel_list_includes_default_and_created(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, bob, h_a, h_b, store_a, store_b, ta, tb = await _pair(server, tmp_path)
    try:
        await alice.create_channel("Study Room", "course")
        await _wait_for(lambda: any(c.name == "Study Room" for c in h_a.channels))
        h_a.channels.clear()
        await alice.list_channels()
        await _wait_for(lambda: any(c.name == "Campus Lobby" for c in h_a.channels))
        names = {c.name for c in h_a.channels}
        assert "Campus Lobby" in names  # config default_channels seed
        assert "Study Room" in names
    finally:
        await _teardown(alice=alice, bob=bob, store_a=store_a, store_b=store_b, ta=ta, tb=tb)


async def test_encrypted_file_transfer_round_trip(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, bob, h_a, h_b, store_a, store_b, ta, tb = await _pair(server, tmp_path)
    try:
        payload = bytes(range(256)) * 300  # 76_800 bytes -> multiple chunks
        src = tmp_path / "payload.bin"
        src.write_bytes(payload)
        expected_sha = hashlib.sha256(payload).hexdigest()

        await alice.send_file(f"u_{BOB}", src)
        await _wait_for(lambda: any(e.state == "offered" for e in h_b.files), timeout=8)
        offer = next(e for e in h_b.files if e.state == "offered")
        assert offer.encrypted is True  # peer key pinned -> E2EE
        assert offer.name == "payload.bin"
        assert offer.size == len(payload)

        dest = tmp_path / "bob_downloads"
        await bob.accept_file(offer.transfer_id, dest)

        await _wait_for(
            lambda: any(e.state == "complete" for e in h_b.files if e.direction == "in"),
            timeout=10,
        )
        done = next(e for e in h_b.files if e.state == "complete" and e.direction == "in")
        assert done.path is not None
        written = Path(done.path).read_bytes()  # noqa: ASYNC240 -- test assertion
        assert written == payload
        assert hashlib.sha256(written).hexdigest() == expected_sha
        # sender saw completion too
        await _wait_for(lambda: any(e.state == "complete" for e in h_a.files if e.direction == "out"))
    finally:
        await _teardown(alice=alice, bob=bob, store_a=store_a, store_b=store_b, ta=ta, tb=tb)


async def test_plaintext_file_transfer_when_unpinned(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, bob, h_a, h_b, store_a, store_b, ta, tb = await _pair(server, tmp_path, pin=False)
    try:
        payload = b"no key pinned -> plaintext chunks" * 100
        src = tmp_path / "plain.txt"
        src.write_bytes(payload)

        await alice.send_file(f"u_{BOB}", src)
        await _wait_for(lambda: any(e.state == "offered" for e in h_b.files), timeout=8)
        offer = next(e for e in h_b.files if e.state == "offered")
        assert offer.encrypted is False

        await bob.accept_file(offer.transfer_id, tmp_path / "bob_dl")
        await _wait_for(
            lambda: any(e.state == "complete" for e in h_b.files if e.direction == "in"),
            timeout=10,
        )
        done = next(e for e in h_b.files if e.state == "complete" and e.direction == "in")
        assert Path(done.path).read_bytes() == payload  # type: ignore[arg-type]  # noqa: ASYNC240
    finally:
        await _teardown(alice=alice, bob=bob, store_a=store_a, store_b=store_b, ta=ta, tb=tb)


async def test_declined_transfer_reports_to_sender(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, bob, h_a, h_b, store_a, store_b, ta, tb = await _pair(server, tmp_path)
    try:
        src = tmp_path / "reject.txt"
        src.write_bytes(b"nope")
        await alice.send_file(f"u_{BOB}", src)
        await _wait_for(lambda: any(e.state == "offered" for e in h_b.files), timeout=8)
        offer = next(e for e in h_b.files if e.state == "offered")
        await bob.accept_file(offer.transfer_id, accepted=False)
        await _wait_for(lambda: any(e.state == "declined" for e in h_a.files if e.direction == "out"), timeout=8)
    finally:
        await _teardown(alice=alice, bob=bob, store_a=store_a, store_b=store_b, ta=ta, tb=tb)
