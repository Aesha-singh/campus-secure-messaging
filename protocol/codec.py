r"""CSCP frame codec: encoding plus the streaming :class:`FrameDecoder`.

Networking concepts demonstrated
--------------------------------
**TCP is a byte stream, not a message stream.**  A single ``recv()`` may return
half a frame (a *partial read*) or several frames glued together (a *coalesced*
read).  CSCP therefore uses **length-delimited framing**: every frame begins
with a fixed 20-byte header whose 4-byte length field tells the reader exactly
how many payload bytes to expect.  :class:`FrameDecoder` buffers bytes until a
whole frame is available, then yields it -- this is the classic
``read -> buffer -> emit`` pattern used by every real protocol (HTTP/2, gRPC,
WebSocket, TLS records).

**CRC32 trailer.**  Frames carry a CRC32 over ``header || payload`` so bit
corruption or tampering is detected before the payload reaches an application
parser.  This is integrity *at the framing layer*; authenticity comes later from
TLS and per-message AEAD over E2EE payloads.

**Bounded memory.**  The decoder refuses any advertised length above
``max_frame_size`` *before* buffering, defeating the "declare 4 GiB" DoS.

Wire layout (big-endian / network byte order)::

    +--------+------+-------+-------+--------------+----------------+---------+---------+
    | magic  | ver  | type  | flags | payload len  | sequence num   | payload |  CRC32  |
    | 4 B    | 1 B  | 1 B   | 2 B   | 4 B (uint32) | 8 B (uint64)   | L B     | 4 B     |
    | 'CSCP' |      |       |       |              |                |         |         |
    +--------+------+-------+-------+--------------+----------------+---------+---------+
       \_______________________________ header (20 B) ______________________________/
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field

from protocol.constants import (
    HEADER_SIZE,
    MAGIC,
    MAX_FRAME_SIZE,
    PROTOCOL_VERSION,
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

#: ``>`` big-endian (network byte order); 4s magic, B version, B type,
#: H flags, I payload length, Q sequence number.
_HEADER = struct.Struct(">4sBBHIQ")
_TRAILER = struct.Struct(">I")

assert _HEADER.size == HEADER_SIZE, "header layout drifted from spec"


def compute_crc(header_bytes: bytes, payload: bytes) -> int:
    """CRC32 over ``header_bytes || payload`` (chained to avoid a copy)."""
    crc = zlib.crc32(header_bytes)
    crc = zlib.crc32(payload, crc)
    return crc & 0xFFFFFFFF


@dataclass(slots=True, frozen=True)
class Frame:
    """A fully decoded CSCP frame.

    Attributes:
        msg_type: Application message type.
        sequence: 64-bit monotonic sequence number (replay protection / ACKs).
        payload: Raw payload bytes (may be message-packed or E2EE ciphertext).
        version: Protocol version from the header.
        flags: Bitwise OR of :class:`~protocol.constants.FrameFlags`.
    """

    msg_type: MessageType
    sequence: int
    payload: bytes = b""
    version: int = PROTOCOL_VERSION
    flags: FrameFlags = field(default_factory=lambda: FrameFlags.NONE)

    def __post_init__(self) -> None:
        if not 0 <= self.sequence < (1 << 64):
            raise ValueError("sequence must fit in uint64")

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FrameFlags.ENCRYPTED)

    @property
    def is_ack_requested(self) -> bool:
        return bool(self.flags & FrameFlags.ACK_REQUESTED)

    def with_flags(self, flags: FrameFlags) -> Frame:
        """Return a copy with additional flags OR-ed in (frames are frozen)."""
        return Frame(
            msg_type=self.msg_type,
            sequence=self.sequence,
            payload=self.payload,
            version=self.version,
            flags=FrameFlags(self.flags | flags),
        )


def encode_frame(
    frame: Frame,
    *,
    max_frame_size: int = MAX_FRAME_SIZE,
) -> bytes:
    """Serialise ``frame`` to bytes ready for ``writer.write()``.

    Args:
        frame: The frame to encode.
        max_frame_size: Reject payloads larger than this (defensive, symmetric
            with the decoder limit).

    Returns:
        ``header || payload || crc32``.

    Raises:
        FrameTooLargeError: If the payload exceeds ``max_frame_size``.
    """
    payload = frame.payload
    if len(payload) > max_frame_size:
        raise FrameTooLargeError(
            f"payload {len(payload)} exceeds max_frame_size {max_frame_size}"
        )
    header = _HEADER.pack(
        MAGIC,
        frame.version,
        int(frame.msg_type),
        int(frame.flags),
        len(payload),
        frame.sequence,
    )
    crc = compute_crc(header, payload)
    return header + payload + _TRAILER.pack(crc)


class FrameDecoder:
    """Incremental decoder turning a TCP byte stream into :class:`Frame` objects.

    Feed arbitrary chunks via :meth:`feed` and pull complete frames with
    :meth:`next_frame` (or iterate).  Partial frames are buffered; coalesced
    frames are all returned, one call at a time.  A malformed or oversized
    frame raises immediately and is consumed so the caller can decide to close
    the connection.

    Example:
        >>> dec = FrameDecoder()
        >>> dec.feed(encode_frame(Frame(MessageType.PING, 1))[:10])   # partial
        >>> dec.next_frame() is None
        True
    """

    __slots__ = ("_buf", "max_frame_size", "strict_version", "bytes_received", "frames_decoded")

    def __init__(
        self,
        *,
        max_frame_size: int = MAX_FRAME_SIZE,
        strict_version: bool = False,
    ) -> None:
        self._buf = bytearray()
        self.max_frame_size = max_frame_size
        self.strict_version = strict_version
        self.bytes_received = 0
        self.frames_decoded = 0

    # -- input ------------------------------------------------------------- #
    def feed(self, data: bytes) -> None:
        """Append freshly received bytes to the internal buffer."""
        if data:
            self._buf.extend(data)
            self.bytes_received += len(data)

    # -- output ------------------------------------------------------------ #
    def next_frame(self) -> Frame | None:
        """Return the next complete frame, or ``None`` if more bytes are needed.

        Raises:
            MagicMismatchError: Stream is not CSCP (bad magic).
            FrameTooLargeError: Advertised length exceeds the cap.
            VersionMismatchError: Version differs and ``strict_version`` is set.
            CrcError: Checksum mismatch (corruption or tampering).
            UnknownMessageTypeError: Type byte not in :class:`MessageType`.
        """
        if len(self._buf) < HEADER_SIZE:
            return None

        magic, version, raw_type, raw_flags, payload_len, sequence = _HEADER.unpack_from(
            self._buf, 0
        )
        if magic != MAGIC:
            raise MagicMismatchError(f"bad magic {magic!r}; expected {MAGIC!r}")
        if payload_len > self.max_frame_size:
            raise FrameTooLargeError(
                f"advertised payload {payload_len} exceeds cap {self.max_frame_size}"
            )
        if self.strict_version and version not in (PROTOCOL_VERSION,):
            raise VersionMismatchError(f"unsupported version {version}")

        total = HEADER_SIZE + payload_len + TRAILER_SIZE
        if len(self._buf) < total:
            return None  # partial frame -- wait for more bytes

        header_bytes = bytes(self._buf[:HEADER_SIZE])
        payload = bytes(self._buf[HEADER_SIZE : HEADER_SIZE + payload_len])
        (crc_received,) = _TRAILER.unpack_from(self._buf, HEADER_SIZE + payload_len)
        crc_calc = compute_crc(header_bytes, payload)
        if crc_received != crc_calc:
            del self._buf[:total]  # consume so we don't loop on the same error
            raise CrcError(f"CRC mismatch: got {crc_received:#010x}, want {crc_calc:#010x}")

        del self._buf[:total]
        self.frames_decoded += 1

        try:
            msg_type = MessageType(raw_type)
        except ValueError as exc:
            raise UnknownMessageTypeError(f"unknown message type {raw_type:#04x}") from exc

        return Frame(
            msg_type=msg_type,
            sequence=sequence,
            payload=payload,
            version=version,
            flags=FrameFlags(raw_flags),
        )

    def frames(self) -> list[Frame]:
        """Drain and return every complete frame currently buffered."""
        out: list[Frame] = []
        while (frame := self.next_frame()) is not None:
            out.append(frame)
        return out

    def __iter__(self) -> Iterator[Frame]:
        while (frame := self.next_frame()) is not None:
            yield frame

    # -- introspection / control ------------------------------------------ #
    @property
    def buffered(self) -> int:
        """Bytes currently held awaiting completion."""
        return len(self._buf)

    def reset(self) -> None:
        """Drop any buffered bytes (e.g. before re-synchronising a stream)."""
        self._buf.clear()

    def __len__(self) -> int:
        return len(self._buf)
