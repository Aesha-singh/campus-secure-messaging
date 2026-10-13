"""End-to-end tests: two real ClientSessions converse through a real server."""

from __future__ import annotations

import asyncio
import tempfile
from collections import deque
from pathlib import Path

import pytest_asyncio

from client.config import ClientConfig
from client.crypto import ClientCrypto
from client.session import ChatMessage, ClientCallbacks, ClientSession
from client.store import ClientStore
from server.auth import StubAuthenticator
from server.config import Config
from server.server import CSCPServer

ALICE = "alice"
BOB = "bob"


@pytest_asyncio.fixture
async def server():  # type: ignore[no-untyped-def]
    cfg = Config()
    cfg.net.enable_v4 = True
    cfg.net.host_v4 = "127.0.0.1"
    cfg.net.enable_v6 = False
    cfg.net.port = 0
    srv = CSCPServer(cfg, auth=StubAuthenticator({ALICE: "sa", BOB: "sb"}), secret=b"k" * 32)
    await srv.start()
    yield srv
    await srv.shutdown()


class Harness:
    def __init__(self) -> None:
        self.messages: deque[ChatMessage] = deque()
        self.readers: deque[object] = deque()
        self.ready = asyncio.Event()

    async def on_message(self, chat: ChatMessage) -> None:
        self.messages.append(chat)


async def _make_session(  # noqa: PLR0913
    username: str,
    server,
    tmp_path,
    *,
    crypto: ClientCrypto | None = None,
) -> tuple[ClientSession, Harness, ClientStore]:  # type: ignore[no-untyped-def]
    port = server.listeners[0].server.sockets[0].getsockname()[1]
    password = "sa" if username == ALICE else "sb"  # noqa: S106 -- stub test credential
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
    own = crypto or ClientCrypto.create(f"dev-{username}")  # reuse the device identity on restart
    store = ClientStore(str(Path(identity_dir) / "profile.db"))
    await store.open()
    h = Harness()
    cbs = ClientCallbacks(on_message=h.on_message)
    sess = ClientSession(cfg=cfg, crypto=own, store=store, callbacks=cbs)
    sess.set_credentials(username, password)
    return sess, h, store


async def test_login_and_ready(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, h, store = await _make_session(ALICE, server, tmp_path)
    task = asyncio.create_task(alice.run())
    try:
        await asyncio.wait_for(alice._connected.wait(), timeout=5)
        assert alice.is_ready
        assert alice.user_id == f"u_{ALICE}"
        assert alice.username == ALICE
    finally:
        await alice.stop()
        await task
        await store.close()


async def test_peer_key_exchange_then_encrypted_send(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, h_a, store_a = await _make_session(ALICE, server, tmp_path)
    bob, h_b, store_b = await _make_session(BOB, server, tmp_path)

    # Out-of-band key pins happen before either connects (TOFU start).
    bob.crypto.pin_peer(f"u_{ALICE}", alice.crypto.own_public())
    alice.crypto.pin_peer(f"u_{BOB}", bob.crypto.own_public())

    ta = asyncio.create_task(alice.run())
    tb = asyncio.create_task(bob.run())
    try:
        await asyncio.gather(
            asyncio.wait_for(alice._connected.wait(), 5),
            asyncio.wait_for(bob._connected.wait(), 5),
        )
        assert alice.is_ready and bob.is_ready
        msg_id = await alice.send_text(f"u_{BOB}", "hello bob, encrypted")
        ack = await asyncio.wait_for(alice.await_ack(msg_id), 5)
        assert ack.msg_id == msg_id

        await asyncio.wait_for(_wait_bob_message(bob), 5)
        chat = h_b.messages.popleft()
        assert chat.peer_id == f"u_{ALICE}"
        assert chat.direction == "recv"
        assert chat.text == "hello bob, encrypted"
        assert chat.encrypted is False  # succeeded decryption with pinned key
    finally:
        await alice.stop()
        await bob.stop()
        await ta
        await tb
        await store_a.close()
        await store_b.close()


async def test_unpinned_sender_reaches_recipient_as_ciphertext(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, h_a, store_a = await _make_session(ALICE, server, tmp_path)
    bob, h_b, store_b = await _make_session(BOB, server, tmp_path)
    # Only Bob pins Alice's key; Alice has no key for Bob -> she sends the
    # envelope plain, so Bob (who derives a master from his pinned key) cannot
    # decrypt it and must surface the raw ciphertext.
    bob.crypto.pin_peer(f"u_{ALICE}", alice.crypto.own_public())

    ta = asyncio.create_task(alice.run())
    tb = asyncio.create_task(bob.run())
    try:
        await asyncio.gather(
            asyncio.wait_for(alice._connected.wait(), 5),
            asyncio.wait_for(bob._connected.wait(), 5),
        )
        await alice.send_text(f"u_{BOB}", "hi")
        await asyncio.wait_for(_wait_bob_message(bob), 5)
        chat = h_b.messages.popleft()
        assert chat.encrypted is True  # not decryptable for Bob as designed
        assert chat.text is None
    finally:
        await alice.stop()
        await bob.stop()
        await ta
        await tb
        await store_a.close()
        await store_b.close()


async def test_offline_queue_delivered_after_reconnect(server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    alice, h_a, store_a = await _make_session(ALICE, server, tmp_path)
    bob, h_b, store_b = await _make_session(BOB, server, tmp_path)
    bob.crypto.pin_peer(f"u_{ALICE}", alice.crypto.own_public())
    alice.crypto.pin_peer(f"u_{BOB}", bob.crypto.own_public())

    ta = asyncio.create_task(alice.run())
    tb = asyncio.create_task(bob.run())
    try:
        await asyncio.gather(
            asyncio.wait_for(alice._connected.wait(), 5),
            asyncio.wait_for(bob._connected.wait(), 5),
        )
        # Bob goes away (offline); Alice keeps "sending".  A stopped session
        # cannot reuse - the reconnect test below needs a *fresh* client half.
        await bob.stop()
        await tb
        await store_b.close()
        await alice.send_text(f"u_{BOB}", "you will read this later")

        # Bob returns with a *restarted app*: same device identity, so the
        # E2EE thread still decrypts what Alice encrypted to bob's key.
        bob2, h_b2, store_b2 = await _make_session(BOB, server, tmp_path, crypto=bob.crypto)
        bob2.crypto.pin_peer(f"u_{ALICE}", alice.crypto.own_public())
        tb = asyncio.create_task(bob2.run())
        await asyncio.wait_for(_wait_bob_message(bob2), 8)
        await asyncio.wait_for(_bob2_got_chat(h_b2), 8)
        chat = h_b2.messages.popleft()
        assert chat.text == "you will read this later"
        await bob2.stop()
        await store_b2.close()
    finally:
        await alice.stop()
        await ta
        await store_a.close()


async def _bob2_got_chat(h) -> None:  # type: ignore[no-untyped-def]
    while not h.messages:  # noqa: ASYNC110 -- test poller
        await asyncio.sleep(0.05)


async def _wait_bob_message(session: ClientSession) -> None:
    """Busy-wait until the session's store has a received message."""
    while True:
        rows = await session.store.history("dm:u_alice:u_bob", limit=100)
        if any(r.direction == "recv" for r in rows):
            return
        await asyncio.sleep(0.05)