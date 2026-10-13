"""Tests for the client-local SQLite store (identity, pins, outbox, history)."""

from __future__ import annotations

import asyncio

import pytest_asyncio

from client.store import ClientStore, HistoryEntry


@pytest_asyncio.fixture
async def store(tmp_path):  # type: ignore[no-untyped-def]
    s = ClientStore(tmp_path / "profile.db")
    await s.open()
    yield s
    await s.close()


async def test_identity_roundtrip(store) -> None:  # type: ignore[no-untyped-def]
    await store.save_identity("dev-1", "aabb" * 32)
    assert await store.load_identity() == ("dev-1", "aabb" * 32)


async def test_peer_pin_and_conflict(store) -> None:  # type: ignore[no-untyped-def]
    assert await store.save_peer("u_bob", "cafe" * 32) is True
    assert await store.save_peer("u_bob", "cafe" * 32) is True  # same key: no-op
    assert await store.save_peer("u_bob", "beef" * 32) is False  # conflict
    peers = await store.load_peers()
    assert peers["u_bob"] == bytes.fromhex("cafe" * 32)


async def test_outbox_spool_and_take_in_order(store) -> None:  # type: ignore[no-untyped-def]
    await store.queue_send(msg_id="m1", convo="dm:u_a:u_b", recipient="u_bob", envelope=b"one")
    await store.queue_send(msg_id="m2", convo="dm:u_a:u_b", recipient="u_bob", envelope=b"two")
    out = await store.take_outbox()
    assert [e.msg_id for e in out] == ["m1", "m2"]
    assert [e.recipient for e in out] == ["u_bob", "u_bob"]
    assert [e.envelope for e in out] == [b"one", b"two"]
    assert await store.take_outbox() == []  # drained


async def test_history_order_and_dedupe(store) -> None:  # type: ignore[no-untyped-def]
    await store.append_history(HistoryEntry("dm:u_a:u_b", "m1", "sent", 1.0, "hi"))
    await store.append_history(HistoryEntry("dm:u_a:u_b", "m2", "recv", 2.0, "yo"))
    await store.append_history(HistoryEntry("dm:u_a:u_b", "m1", "recv", 3.0, "dup"))
    rows = await store.history("dm:u_a:u_b")
    assert [(r.msg_id, r.plaintext) for r in rows] == [("m1", "hi"), ("m2", "yo")]


async def test_session_token_kv(store) -> None:  # type: ignore[no-untyped-def]
    assert await store.load_session_token("alice") is None
    await store.save_session_token("alice", "tok-1")
    assert await store.load_session_token("alice") == "tok-1"


async def test_reopen_persists(tmp_path) -> None:  # type: ignore[no-untyped-def]
    s = ClientStore(tmp_path / "profile.db")
    await s.open()
    await s.save_identity("dev-x", "1234" * 32)
    await s.save_peer("u_bob", "abcd" * 32)
    await s.close()
    s2 = ClientStore(tmp_path / "profile.db")
    await s2.open()
    assert await s2.load_identity() == ("dev-x", "1234" * 32)
    assert bytes.fromhex("abcd" * 32) in (await s2.load_peers()).values()
    await s2.close()


async def test_concurrent_writers(store) -> None:  # type: ignore[no-untyped-def]
    await asyncio.gather(
        *[store.queue_send(msg_id=f"m{i}", convo="c", recipient="u_bob", envelope=b"x") for i in range(50)]
    )
    out = await store.take_outbox()
    assert len(out) == 50