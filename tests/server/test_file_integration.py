"""Server tests for the store-and-forward file relay (wire-level)."""

from __future__ import annotations

from protocol.constants import DeliveryStatus, ErrorCode, FrameFlags, MessageType
from protocol.messages import (
    Ack,
    Error,
    FileAccept,
    FileChunk,
    FileDone,
    FileOffer,
    FileResume,
    decode_message,
)
from tests.server.conftest import WireClient, connect
from tests.server.test_messaging_integration import _users

ALICE_ID = "u_alice"
BOB_ID = "u_bob"
CHUNK = 64


def _offer(tid: str, recipient: str, size: int, name: str = "notes.txt", wrapped: bytes | None = b"wk") -> FileOffer:
    return FileOffer(
        transfer_id=tid,
        name=name,
        size=size,
        sha256="ab" * 32,
        mime="text/plain",
        chunk_size=CHUNK,
        recipient_id=recipient,
        ts=1.0,
        wrapped_key=wrapped,
    )


def _chunks(tid: str, size: int, first: int = 0, n: int | None = None, fill: bytes = b"z") -> list[FileChunk]:
    total = (size + CHUNK - 1) // CHUNK
    stop = total if n is None else min(total, first + n)
    return [FileChunk(transfer_id=tid, index=i, data=fill * CHUNK) for i in range(first, stop)]


async def _await_ack(client: WireClient) -> Ack:
    frame = await client.read_until(MessageType.ACK)
    ack = decode_message(frame)
    assert isinstance(ack, Ack)
    return ack


async def _new_cfg(tmp_path, **overrides) -> object:  # type: ignore[no-untyped-def]
    from server.config import Config

    cfg = Config()
    cfg.files.relay_encrypted_blobs_dir = str(tmp_path / "blobs")
    for key, value in overrides.items():
        setattr(cfg.files, key, value)
    return cfg


async def test_offer_relayed_to_online_recipient_ack_delivered(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    bob = await connect(port)
    await alice.handshake("alice", "sa")
    await bob.handshake("bob", "sb")

    await alice.send(_offer("t1", BOB_ID, 200), flags=FrameFlags.ACK_REQUESTED)
    offer = decode_message(await bob.read_until(MessageType.FILE_OFFER))
    assert isinstance(offer, FileOffer)
    assert offer.transfer_id == "t1"
    assert offer.name == "notes.txt"
    ack = await _await_ack(alice)
    assert ack.status is DeliveryStatus.DELIVERED
    await alice.close()
    await bob.close()


async def test_full_stream_with_window_acks_and_done(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    bob = await connect(port)
    await alice.handshake("alice", "sa")
    await bob.handshake("bob", "sb")
    size = 200  # 4 chunks

    await alice.send(_offer("t2", BOB_ID, size), flags=FrameFlags.ACK_REQUESTED)
    await _await_ack(alice)
    await bob.read_until(MessageType.FILE_OFFER)
    await bob.send(FileAccept(transfer_id="t2", accepted=True))
    await alice.read_until(MessageType.FILE_ACCEPT)

    for chunk in _chunks("t2", size):
        await alice.send(chunk, flags=FrameFlags.ACK_REQUESTED)
    # Sliding-window cumulative ACKs, one per chunk.
    for expected in range(1, 5):
        ack = await _await_ack(alice)
        assert ack.msg_id == f"t2:w{expected}"

    # Recipient receives the complete file, in order.
    got: list[bytes] = []
    for i in range(4):
        chunk = decode_message(await bob.read_until(MessageType.FILE_CHUNK))
        assert isinstance(chunk, FileChunk)
        assert chunk.transfer_id == "t2"
        assert chunk.index == i
        got.append(chunk.data)
    assert b"".join(got) == b"z" * size

    await alice.send(FileDone(transfer_id="t2", sha256="ab" * 32, size=size), flags=FrameFlags.ACK_REQUESTED)
    done = decode_message(await bob.read_until(MessageType.FILE_DONE))
    assert isinstance(done, FileDone)
    assert done.size == size
    ack = await _await_ack(alice)
    assert ack.msg_id == "t2"
    await alice.close()
    await bob.close()


async def test_out_of_order_chunks_reassembled_in_order(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    bob = await connect(port)
    await alice.handshake("alice", "sa")
    await bob.handshake("bob", "sb")
    size = 3 * CHUNK

    await alice.send(_offer("t3", BOB_ID, size))
    await bob.read_until(MessageType.FILE_OFFER)
    await bob.send(FileAccept(transfer_id="t3", accepted=True))
    await alice.read_until(MessageType.FILE_ACCEPT)

    # Send index 2, then 0, then 1: relay must only fwd a contiguous prefix.
    for idx in (2, 0, 1):
        await alice.send(_chunks("t3", size)[idx], flags=FrameFlags.ACK_REQUESTED)
    await alice.read_until(MessageType.ACK)  # watermark 1 (after chunk 2 only nothing), etc.
    for i in range(3):
        chunk = decode_message(await bob.read_until(MessageType.FILE_CHUNK))
        assert isinstance(chunk, FileChunk)
        assert chunk.index == i
    await alice.close()
    await bob.close()


async def test_recipient_pulls_stored_tail_via_resume(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    bob = await connect(port)
    await alice.handshake("alice", "sa")
    await bob.handshake("bob", "sb")
    size = 5 * CHUNK

    await alice.send(_offer("t4", BOB_ID, size))
    await _await_ack(alice)
    await bob.read_until(MessageType.FILE_OFFER)
    await bob.send(FileAccept(transfer_id="t4", accepted=True))
    await alice.read_until(MessageType.FILE_ACCEPT)

    # Recipient drops off after chunk 0; sender keeps uploading everything,
    # and we wait for the full cumulative ACK chain so storage is complete
    # before the recipient reconnects (a real client does the same before a
    # controlled disconnect).
    for chunk in _chunks("t4", size):
        await alice.send(chunk, flags=FrameFlags.ACK_REQUESTED)
    for expected in range(1, 6):
        ack = await _await_ack(alice)
        assert ack.msg_id == f"t4:w{expected}"
    await bob.close()

    bob2 = await connect(port)
    await bob2.handshake("bob", "sb")
    # Resume from chunk index 1 -> relay re-streams 1..4 from its buffer.
    await bob2.send(FileResume(transfer_id="t4", last_ack_index=0, last_ack_offset=CHUNK))
    for expected in range(1, 5):
        chunk = decode_message(await bob2.read_until(MessageType.FILE_CHUNK))
        assert isinstance(chunk, FileChunk)
        assert chunk.index == expected
    ack = await _await_ack(bob2)
    assert ack.msg_id == "t4:r4"
    await bob2.close()


async def test_quota_exceeded_rejected(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path, quota_bytes=150, max_size_bytes=100_000)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")

    await alice.send(_offer("q1", BOB_ID, 100), flags=FrameFlags.ACK_REQUESTED)
    await alice.send(_offer("q2", BOB_ID, 100), flags=FrameFlags.ACK_REQUESTED)
    ok = await _await_ack(alice)
    assert ok.status is DeliveryStatus.SENT or ok.status is DeliveryStatus.DELIVERED  # first allowed
    err = decode_message(await alice.read_until(MessageType.ERROR))
    assert isinstance(err, Error)
    assert err.code is ErrorCode.QUOTA_EXCEEDED
    await alice.close()


async def test_oversize_rejected_before_buffering(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path, max_size_bytes=128)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")
    await alice.send(_offer("big", BOB_ID, 256))
    err = decode_message(await alice.read_until(MessageType.ERROR))
    assert isinstance(err, Error)
    assert err.code is ErrorCode.TOO_LARGE
    await alice.close()


async def test_digest_mismatch_aborts_transfer(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    bob = await connect(port)
    await alice.handshake("alice", "sa")
    await bob.handshake("bob", "sb")
    size = CHUNK

    await alice.send(_offer("t5", BOB_ID, size))
    await bob.read_until(MessageType.FILE_OFFER)
    await bob.send(FileAccept(transfer_id="t5", accepted=True))
    await alice.read_until(MessageType.FILE_ACCEPT)
    await alice.send(_chunks("t5", size)[0], flags=FrameFlags.ACK_REQUESTED)
    await _await_ack(alice)
    await alice.send(FileDone(transfer_id="t5", sha256="ff" * 32, size=size))
    err = decode_message(await alice.read_until(MessageType.ERROR))
    assert isinstance(err, Error)
    assert err.code is ErrorCode.TRANSFER_ABORTED
    await alice.close()
    await bob.close()


async def test_offer_queued_for_offline_recipient_then_accepted(running_server, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = await _new_cfg(tmp_path)
    _, port = await running_server(cfg, users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")

    await alice.send(_offer("t6", BOB_ID, CHUNK), flags=FrameFlags.ACK_REQUESTED)
    ack = await _await_ack(alice)
    assert ack.status is DeliveryStatus.SENT  # persisted for later
    await alice.close()

    bob = await connect(port)
    await bob.handshake("bob", "sb")
    offer = decode_message(await bob.read_until(MessageType.FILE_OFFER))
    assert isinstance(offer, FileOffer)
    assert offer.transfer_id == "t6"
    await bob.read_until(MessageType.UNREAD)
    await bob.close()