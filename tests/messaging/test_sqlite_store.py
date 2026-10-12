"""Unit tests for the durable SQLite message store."""

from __future__ import annotations

import pytest

from messaging.store import SQLiteMessageStore
from protocol.messages import MsgDirect, MsgGroup


@pytest.fixture
async def store(tmp_path) -> SQLiteMessageStore:  # type: ignore[no-untyped-def]
    s = SQLiteMessageStore(tmp_path / "test.db")
    await s.init()
    yield s
    await s.close()


def _direct(msg_id: str, ts: float, sender: str, recipient: str) -> MsgDirect:
    ciphertext = b"cipher-" + msg_id.encode()
    return MsgDirect(msg_id=msg_id, sender_id=sender, recipient_id=recipient, ciphertext=ciphertext, ts=ts)


async def test_history_roundtrip_and_ordering(store) -> None:  # type: ignore[no-untyped-def]
    convo = "dm:u_a|u_b"
    await store.save_message("dm", convo, _direct("m1", 1.0, "u_a", "u_b"))
    await store.save_message("dm", convo, _direct("m2", 2.0, "u_b", "u_a"))
    batch = await store.history("u_a", "dm", convo)
    assert [m.msg_id for m in batch] == ["m1", "m2"]
    assert all(isinstance(m, MsgDirect) for m in batch)
    # since_ts watermark pulls only newer messages.
    after = await store.history("u_a", "dm", convo, since_ts=1.5)
    assert [m.msg_id for m in after] == ["m2"]


async def test_history_limit_keeps_newest_then_oldest_first(store) -> None:  # type: ignore[no-untyped-def]
    convo = "dm:u_a|u_b"
    for i in range(1, 6):
        await store.save_message("dm", convo, _direct(f"m{i}", float(i), "u_a", "u_b"))
    limited = await store.history("u_a", "dm", convo, limit=3)
    assert [m.msg_id for m in limited] == ["m3", "m4", "m5"]


async def test_offline_queue_fifo_and_clear(store) -> None:  # type: ignore[no-untyped-def]
    await store.enqueue_offline("u_b", _direct("o1", 1.0, "u_a", "u_b"))
    await store.enqueue_offline("u_b", _direct("o2", 2.0, "u_a", "u_b"))
    assert await store.count_offline("u_b") == 2
    taken: list[MsgDirect] = await store.take_offline("u_b")  # type: ignore[assignment]
    assert [m.msg_id for m in taken] == ["o1", "o2"]
    assert await store.count_offline("u_b") == 0
    # Duplicate enqueue is idempotent (msg_id is the PK).
    await store.enqueue_offline("u_b", _direct("o1", 1.0, "u_a", "u_b"))
    assert await store.count_offline("u_b") == 1


async def test_unread_bump_counts_clear(store) -> None:  # type: ignore[no-untyped-def]
    convo = "dm:u_a|u_b"
    assert await store.bump_unread("u_a", convo) == 1
    assert await store.bump_unread("u_a", convo) == 2
    assert await store.bump_unread("u_a", convo + "-x") == 1
    assert await store.unread_counts("u_a") == {convo: 2, convo + "-x": 1}
    await store.clear_unread("u_a", convo)
    assert await store.unread_counts("u_a") == {convo + "-x": 1}
    # A different user's badges are untouched.
    assert await store.unread_counts("u_b") == {}


async def test_group_messages_persisted_as_group(store) -> None:  # type: ignore[no-untyped-def]
    convo = "ch:c1"
    await store.save_message(
        "channel",
        convo,
        MsgGroup(msg_id="g1", sender_id="u_alice", channel_id="c1", ciphertext=b"live", ts=1.0),
    )
    batch = await store.history("u_alice", "channel", convo)
    assert len(batch) == 1
    assert isinstance(batch[0], MsgGroup)
    assert batch[0].channel_id == "c1"


async def test_uninitialised_store_raises() -> None:
    store = SQLiteMessageStore(":memory:")
    with pytest.raises(RuntimeError, match="not initialised"):
        await store.unread_counts("u_a")


async def test_persistence_across_reopen(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "again.db"
    s1 = SQLiteMessageStore(path)
    await s1.init()
    convo = "dm:u_a|u_b"
    await s1.save_message("dm", convo, _direct("m1", 1.0, "u_a", "u_b"))
    await s1.enqueue_offline("u_b", _direct("o1", 1.5, "u_a", "u_b"))
    await s1.bump_unread("u_b", convo)
    await s1.close()

    s2 = SQLiteMessageStore(path)
    await s2.init()
    history = await s2.history("u_a", "dm", convo)
    assert [m.msg_id for m in history] == ["m1"]
    offline = await s2.take_offline("u_b")
    assert [m.msg_id for m in offline] == ["o1"]
    assert await s2.unread_counts("u_b") == {convo: 1}
    await s2.close()


async def test_convo_key_canonical_form() -> None:
    from server.storage import convo_key

    assert convo_key("dm", "u_b", "u_a") == convo_key("dm", "u_a", "u_b") == "dm:u_a|u_b"
    assert convo_key("channel", "c1") == "ch:c1"