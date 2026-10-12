"""Codec tests: encoding, decoding, and every documented failure mode."""

from __future__ import annotations

import pytest

from protocol.codec import Frame, FrameDecoder, encode_frame
from protocol.constants import (
    FRAME_OVERHEAD,
    HEADER_SIZE,
    MAX_FRAME_SIZE,
    TRAILER_SIZE,
    FrameFlags,
    MessageType,
)
from protocol.errors import (
    CrcError,
    FrameTooLargeError,
    MagicMismatchError,
    UnknownMessageTypeError,
    VersionMismatchError,
)


def test_wire_constants_are_consistent() -> None:
    assert HEADER_SIZE == 20
    assert TRAILER_SIZE == 4
    assert FRAME_OVERHEAD == 24


@pytest.mark.parametrize("msg_type", list(MessageType))
def test_encode_decode_roundtrip(msg_type: MessageType) -> None:
    frame = Frame(msg_type, sequence=42, payload=b"hello\x00world", flags=FrameFlags.URGENT)
    decoded = FrameDecoder().frames()  # starts empty
    assert decoded == []
    dec = FrameDecoder()
    dec.feed(encode_frame(frame))
    out = dec.frames()
    assert out == [frame]


def test_zero_length_payload_ok() -> None:
    dec = FrameDecoder()
    dec.feed(encode_frame(Frame(MessageType.PING, sequence=1)))
    (frame,) = dec.frames()
    assert frame.payload == b""
    assert frame.sequence == 1


def test_partial_read_returns_none() -> None:
    data = encode_frame(Frame(MessageType.MSG_DIRECT, 7, b"x" * 50))
    dec = FrameDecoder()
    for i in range(len(data) - 1):
        dec.feed(data[i : i + 1])  # one byte at a time
    assert dec.next_frame() is None
    assert dec.buffered == len(data) - 1
    dec.feed(data[-1:])
    assert dec.next_frame() == Frame(MessageType.MSG_DIRECT, 7, b"x" * 50)


def test_coalesced_frames_all_decoded() -> None:
    frames = [Frame(MessageType.PING, i, bytes([i]) * 3) for i in range(5)]
    blob = b"".join(encode_frame(f) for f in frames)
    dec = FrameDecoder()
    dec.feed(blob)
    assert dec.frames() == frames
    assert dec.next_frame() is None


def test_bad_magic_rejected(raw_frame) -> None:
    dec = FrameDecoder()
    dec.feed(raw_frame(magic=b"XXXX"))
    with pytest.raises(MagicMismatchError):
        dec.next_frame()


def test_crc_mismatch_on_payload_rejected(raw_frame) -> None:
    good = raw_frame(payload=b"abcdef")
    tampered = good[:-5] + bytes([good[-5] ^ 0xFF]) + good[-4:]
    dec = FrameDecoder()
    dec.feed(tampered)
    with pytest.raises(CrcError):
        dec.next_frame()


def test_crc_mismatch_on_trailer_rejected(raw_frame) -> None:
    dec = FrameDecoder()
    dec.feed(raw_frame(payload=b"abc", crc=0xDEADBEEF))
    with pytest.raises(CrcError):
        dec.next_frame()


def test_oversized_advertised_length_rejected(raw_frame) -> None:
    # Header claims 1 GiB but no payload follows -> must reject before buffering.
    dec = FrameDecoder(max_frame_size=1024)
    dec.feed(raw_frame(payload_len=1 << 30))
    with pytest.raises(FrameTooLargeError):
        dec.next_frame()


def test_encode_rejects_oversized_payload() -> None:
    frame = Frame(MessageType.FILE_CHUNK, 1, b"y" * 100)
    with pytest.raises(FrameTooLargeError):
        encode_frame(frame, max_frame_size=10)


def test_unknown_message_type_rejected(raw_frame) -> None:
    dec = FrameDecoder()
    dec.feed(raw_frame(mtype=0x99))
    with pytest.raises(UnknownMessageTypeError):
        dec.next_frame()


def test_strict_version_rejected(raw_frame) -> None:
    dec = FrameDecoder(strict_version=True)
    dec.feed(raw_frame(version=99))
    with pytest.raises(VersionMismatchError):
        dec.next_frame()


def test_nonstrict_version_accepted(raw_frame) -> None:
    dec = FrameDecoder()
    dec.feed(raw_frame(version=99))
    frame = dec.next_frame()
    assert frame is not None and frame.version == 99


def test_flags_helpers() -> None:
    frame = Frame(MessageType.MSG_DIRECT, 1, flags=FrameFlags.ENCRYPTED | FrameFlags.ACK_REQUESTED)
    assert frame.is_encrypted
    assert frame.is_ack_requested
    assert frame.with_flags(FrameFlags.URGENT).flags & FrameFlags.URGENT


def test_reset_and_len() -> None:
    dec = FrameDecoder()
    dec.feed(b"\x00" * 10)
    assert len(dec) == 10
    dec.reset()
    assert len(dec) == 0


def test_sequence_bounds() -> None:
    with pytest.raises(ValueError):
        Frame(MessageType.PING, -1)
    with pytest.raises(ValueError):
        Frame(MessageType.PING, 1 << 64)


def test_max_frame_size_default_is_bounded() -> None:
    assert 0 < MAX_FRAME_SIZE <= 64 * 1024 * 1024
