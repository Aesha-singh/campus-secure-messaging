"""End-to-end messaging tests: offline buffering, unread badges, history sync.

These exercise the *wire contract* with a raw client: the same frames a GUI
client would exchange with the server for offline delivery, badge summaries,
thread replay, and read-marking.
"""

from __future__ import annotations

from typing import Any

from messaging.store import SQLiteMessageStore
from protocol.constants import DeliveryStatus, FrameFlags, MessageType
from protocol.messages import (
    Ack,
    MarkRead,
    MsgDirect,
    MsgGroup,
    SyncEnd,
    SyncReq,
    Unread,
    decode_message,
)
from tests.server.conftest import connect

ALICE_ID = "u_alice"
BOB_ID = "u_bob"
DM_CONVO = "dm:u_alice|u_bob"
CHANNEL_CONVO = "ch:c1"


def _users() -> dict[str, str]:
    return {"alice": "sa", "bob": "sb", "charlie": "sc"}


class FakePeer:
    """Minimal Peer stand-in used to seed channel membership server-side."""

    user_id: str
    username: str
    ip: str

    def __init__(self, user_id: str, username: str = "") -> None:
        self.user_id = user_id
        self.username = username or user_id
        self.ip = "127.0.0.1"

    async def send(self, msg: Any, *, flags: FrameFlags = FrameFlags.NONE) -> None:  # noqa: ARG002
        return None


async def _seed_channel(srv: Any) -> None:
    srv.manager.create_channel("c1", "CN Course", "course", FakePeer(ALICE_ID))
    srv.manager.join_channel("c1", FakePeer(BOB_ID))
    srv.manager.join_channel("c1", FakePeer("u_charlie"))


async def test_direct_message_saved_and_acked(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")
    seq = await alice.send(
        MsgDirect(msg_id="m1", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"hi", ts=1.0),
        flags=FrameFlags.ACK_REQUESTED,
    )
    ack = decode_message(await alice.read_until(MessageType.ACK))
    assert isinstance(ack, Ack)
    assert ack.ack_seq == seq
    assert ack.msg_id == "m1"
    assert ack.status in (DeliveryStatus.DELIVERED, DeliveryStatus.SENT)  # bob is offline -> SENT
    await alice.close()


async def test_offline_replay_then_unread_summary(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")
    await alice.send(MsgDirect(msg_id="off1", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"q", ts=1.0))
    await alice.read_until(MessageType.ACK)
    await alice.close()

    bob = await connect(port)
    auth = await bob.handshake("bob", "sb")
    assert auth.username == "bob"

    # Pending frame first (queued BEFORE the unread summary at login).
    queued = decode_message(await bob.read_until(MessageType.MSG_DIRECT))
    assert isinstance(queued, MsgDirect)
    assert queued.msg_id == "off1"
    assert queued.ciphertext == b"q"

    summary = decode_message(await bob.read_until(MessageType.UNREAD))
    assert isinstance(summary, Unread)
    assert summary.convo_unread.get(DM_CONVO) == 1
    await bob.close()


async def test_sync_req_replays_history_and_sync_end(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    alice = await connect(port)
    alice_ok = await alice.handshake("alice", "sa")
    assert alice_ok.username == "alice"
    await alice.send(MsgDirect(msg_id="s1", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"x", ts=2.0))
    await alice.read_until(MessageType.ACK)
    await alice.close()  # bob never came online: "s1" is still queued + stored

    bob = await connect(port)
    await bob.handshake("bob", "sb")
    # Skip the offline replay/Unread frames already delivered at login.
    await bob.read_until(MessageType.MSG_DIRECT)
    await bob.read_until(MessageType.UNREAD)

    await bob.send(SyncReq(convo_kind="dm", convo_id=DM_CONVO))
    replayed = decode_message(await bob.read_until(MessageType.MSG_DIRECT))
    assert isinstance(replayed, MsgDirect)
    assert replayed.msg_id == "s1"
    end = decode_message(await bob.read_until(MessageType.SYNC_END))
    assert isinstance(end, SyncEnd)
    assert end.convo_id == DM_CONVO
    assert end.count == 1
    await bob.close()


async def test_mark_read_returns_fresh_unread_summary(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")
    await alice.send(MsgDirect(msg_id="mr1", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"z", ts=1.0))
    await alice.read_until(MessageType.ACK)
    await alice.close()

    bob = await connect(port)
    await bob.handshake("bob", "sb")
    await bob.read_until(MessageType.MSG_DIRECT)  # the queued message
    start = decode_message(await bob.read_until(MessageType.UNREAD))
    assert isinstance(start, Unread)
    assert start.convo_unread.get(DM_CONVO) == 1

    await bob.send(MarkRead(convo_kind="dm", convo_id=DM_CONVO))
    cleared = decode_message(await bob.read_until(MessageType.UNREAD))
    assert isinstance(cleared, Unread)
    assert cleared.convo_unread == {}
    await bob.close()


async def test_channel_offline_badge_and_sync(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(users=_users())
    await _seed_channel(srv)

    alice = await connect(port)
    await alice.handshake("alice", "sa")
    await alice.send(
        MsgGroup(msg_id="g1", sender_id=ALICE_ID, channel_id="c1", ciphertext=b"hello room", ts=1.0),
        flags=FrameFlags.ACK_REQUESTED,
    )
    ack = decode_message(await alice.read_until(MessageType.ACK))
    assert isinstance(ack, Ack)
    assert ack.status is DeliveryStatus.SENT  # stored + fanned out
    await alice.close()

    bob = await connect(port)
    await bob.handshake("bob", "sb")
    summary = decode_message(await bob.read_until(MessageType.UNREAD))
    assert isinstance(summary, Unread)
    assert summary.convo_unread.get(CHANNEL_CONVO) == 1

    await bob.send(SyncReq(convo_kind="channel", convo_id=CHANNEL_CONVO, limit=50))
    replayed = decode_message(await bob.read_until(MessageType.MSG_GROUP))
    assert isinstance(replayed, MsgGroup)
    assert replayed.channel_id == "c1"
    end = decode_message(await bob.read_until(MessageType.SYNC_END))
    assert isinstance(end, SyncEnd)
    assert end.count == 1
    await bob.close()


async def test_offline_queue_survives_server_restart_with_sqlite(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A SQLite-backed server buffers for an offline user across a restart."""
    store = SQLiteMessageStore(tmp_path / "campus.db")
    await store.init()

    srv, port = await running_server(users=_users(), store=store)
    alice = await connect(port)
    await alice.handshake("alice", "sa")
    await alice.send(
        MsgDirect(msg_id="k1", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"sticky", ts=1.0),
        flags=FrameFlags.ACK_REQUESTED,
    )
    ack = decode_message(await alice.read_until(MessageType.ACK))
    assert isinstance(ack, Ack)
    assert ack.status is DeliveryStatus.SENT  # bob offline -> persisted, acked SENT
    await alice.close()
    await srv.shutdown()
    await store.close()

    # Same file, fresh process-equivalent store + server: the message must
    # still reach bob at his next login.
    store2 = SQLiteMessageStore(tmp_path / "campus.db")
    await store2.init()
    _srv2, port2 = await running_server(users=_users(), store=store2)
    bob = await connect(port2)
    await bob.handshake("bob", "sb")
    replayed = decode_message(await bob.read_until(MessageType.MSG_DIRECT))
    assert isinstance(replayed, MsgDirect)
    assert replayed.msg_id == "k1"
    assert replayed.ciphertext == b"sticky"
    summary = decode_message(await bob.read_until(MessageType.UNREAD))
    assert isinstance(summary, Unread)
    assert summary.convo_unread.get(DM_CONVO) == 1
    await bob.close()
    await store2.close()


def test_inmemory_store_implements_message_store() -> None:
    from server.storage import InMemoryStore, MessageStore

    assert isinstance(InMemoryStore(), MessageStore)