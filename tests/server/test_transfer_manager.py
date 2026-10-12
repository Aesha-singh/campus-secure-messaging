"""Unit tests for the store-and-forward FileTransferManager state machine."""

from __future__ import annotations

import time

import pytest

from protocol.messages import FileChunk, FileDone, FileOffer
from server.config import FileConfig
from server.transfer import FileTransferManager, TransferState

CHUNK = 64
ALICE = "u_alice"
BOB = "u_bob"


class FakePeer:
    user_id: str
    username: str
    ip: str

    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        self.username = user_id
        self.ip = "127.0.0.1"

    async def send(self, msg, *, flags=0):  # type: ignore[no-untyped-def]  # noqa: ARG002
        return None


@pytest.fixture
def manager(tmp_path) -> FileTransferManager:  # type: ignore[no-untyped-def]
    cfg = FileConfig()
    cfg.relay_encrypted_blobs_dir = str(tmp_path / "blobs")
    return FileTransferManager(cfg)


def _offer(tid: str, size: int, recipient: str = BOB) -> FileOffer:
    return FileOffer(
        transfer_id=tid,
        name="f.bin",
        size=size,
        sha256="ab" * 32,
        mime="application/octet-stream",
        chunk_size=CHUNK,
        recipient_id=recipient,
        ts=time.time(),
        wrapped_key=b"wk",
    )


async def test_offer_rejected_when_disabled(tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = FileConfig()
    cfg.enabled = False
    with pytest.raises(RuntimeError, match="disabled"):
        FileTransferManager(cfg)


async def test_bad_name_rejected(manager) -> None:  # type: ignore[no-untyped-def]
    bad = _offer("t2", CHUNK, BOB)
    bad.name = "a/../../etc/passwd"  # path traversal must not become a blob path
    err, _ = await manager.offer(FakePeer(ALICE), bad)
    assert err == "bad_name"


async def test_full_lifecycle_state_machine(manager) -> None:  # type: ignore[no-untyped-def]
    err, transfer = await manager.offer(FakePeer(ALICE), _offer("t1", 3 * CHUNK))
    assert err is None
    assert transfer is not None
    assert transfer.state is TransferState.OFFERED

    await manager.accept("t1")
    assert manager.transfers["t1"].state is TransferState.ACCEPTED

    for i in range(3):
        e, _, wm = await manager.write_chunk(FileChunk(transfer_id="t1", index=i, data=b"x" * CHUNK), FakePeer(ALICE))
        assert e == "" and wm == i + 1
    assert manager.transfers["t1"].state is TransferState.STREAMING

    e, t = await manager.on_done(FileDone(transfer_id="t1", sha256="ab" * 32, size=3 * CHUNK), FakePeer(ALICE))
    assert e == "" and t.state is TransferState.COMPLETE


async def test_out_of_order_watermark_advances_only_contiguously(manager) -> None:  # type: ignore[no-untyped-def]
    await manager.offer(FakePeer(ALICE), _offer("t2", 3 * CHUNK))
    await manager.accept("t2")
    # index 1 first: no contiguous prefix yet -> watermark 0
    _, _, wm = await manager.write_chunk(FileChunk(transfer_id="t2", index=1, data=b"y" * CHUNK), FakePeer(ALICE))
    assert wm == 0
    # index 2 -> still 0
    await manager.write_chunk(FileChunk(transfer_id="t2", index=2, data=b"y" * CHUNK), FakePeer(ALICE))
    # index 0 -> watermark jumps 1,2,3
    _, _, wm = await manager.write_chunk(FileChunk(transfer_id="t2", index=0, data=b"y" * CHUNK), FakePeer(ALICE))
    assert wm == 3


async def test_duplicate_chunk_is_idempotent(manager) -> None:  # type: ignore[no-untyped-def]
    await manager.offer(FakePeer(ALICE), _offer("t3", CHUNK))
    await manager.accept("t3")
    e, _, wm = await manager.write_chunk(FileChunk(transfer_id="t3", index=0, data=b"z" * CHUNK), FakePeer(ALICE))
    assert e == "" and wm == 1
    e, _, _ = await manager.write_chunk(FileChunk(transfer_id="t3", index=0, data=b"z" * CHUNK), FakePeer(ALICE))
    assert e == "duplicate"


async def test_quota_reserved_at_offer_and_refunded_on_refuse(manager) -> None:  # type: ignore[no-untyped-def]
    manager.cfg.quota_bytes = 150
    err, _ = await manager.offer(FakePeer(ALICE), _offer("q1", 100))
    assert err is None
    err, _ = await manager.offer(FakePeer(ALICE), _offer("q2", 100))
    assert err == "quota_exceeded"
    # Refusing the first frees its reservation so the second may be offered.
    await manager.refuse("q1", FakePeer(BOB))
    err, _ = await manager.offer(FakePeer(ALICE), _offer("q2", 100))
    assert err is None


async def test_tail_chunk_clamped_to_file_size(manager) -> None:  # type: ignore[no-untyped-def]
    await manager.offer(FakePeer(ALICE), _offer("c", 100))  # 2 chunks, tail = 36 bytes
    await manager.accept("c")
    e, _, wm = await manager.write_chunk(FileChunk(transfer_id="c", index=0, data=b"a" * CHUNK), FakePeer(ALICE))
    assert e == "" and wm == 1
    # overshooting tail (64 bytes) must be trimmed to the remaining 36
    e, _, wm = await manager.write_chunk(FileChunk(transfer_id="c", index=1, data=b"b" * CHUNK), FakePeer(ALICE))
    assert e == "" and wm == 2
    e, t = await manager.on_done(FileDone(transfer_id="c", sha256="ab" * 32, size=100), FakePeer(ALICE))
    assert e == "" and t.store_bytes == CHUNK + 36


async def test_rejects_wrong_actor(manager) -> None:  # type: ignore[no-untyped-def]
    await manager.offer(FakePeer(ALICE), _offer("t4", CHUNK))
    e, _, _ = await manager.write_chunk(FileChunk(transfer_id="t4", index=0, data=b"z"), FakePeer(BOB))
    assert e == "forbidden"
    e, _ = await manager.on_done(FileDone(transfer_id="t4", sha256="ab" * 32, size=CHUNK), FakePeer(BOB))
    assert e == "forbidden"