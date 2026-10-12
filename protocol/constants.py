"""Wire-format constants, message type registry and small protocol enums.

Networking concept demonstrated
-------------------------------
The message-type and flag fields are *protocol data units* (PDUs) at **OSI
Layer 7** (Application).  Keeping them as fixed-width integers (1 byte type,
2 byte flags) makes the header self-describing and cheap to parse in the
event loop -- parser cost matters when servicing 1000+ sockets.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag

# --------------------------------------------------------------------------- #
# Fixed wire constants
# --------------------------------------------------------------------------- #

#: 4-byte magic that anchors frame synchronisation ("CSCP").
MAGIC: bytes = b"CSCP"

#: Current protocol version carried in every frame header.
PROTOCOL_VERSION: int = 1

#: Versions this implementation understands; used for HELLO negotiation.
SUPPORTED_VERSIONS: tuple[int, ...] = (1,)

#: Header layout: magic(4) ver(1) type(1) flags(2) length(4) seq(8) = 20 bytes.
HEADER_SIZE: int = 20

#: Trailer: CRC32 of (header || payload) = 4 bytes.
TRAILER_SIZE: int = 4

#: Total per-frame overhead a caller must budget for.
FRAME_OVERHEAD: int = HEADER_SIZE + TRAILER_SIZE

#: Hard ceiling on a single payload. Guards against memory-exhaustion DoS where
#: an attacker advertises a 4 GiB length to make us buffer forever.  Overridable
#: per-decoder/per-config; file data travels in 64 KiB chunks, so 16 MiB is
#: generous headroom while still bounded.
MAX_FRAME_SIZE: int = 16 * 1024 * 1024

#: Recommended file-transfer chunk size (fits comfortably under MAX_FRAME_SIZE).
FILE_CHUNK_SIZE: int = 64 * 1024


# --------------------------------------------------------------------------- #
# Message types
# --------------------------------------------------------------------------- #
class MessageType(IntEnum):
    """CSCP application messages.

    Values are grouped by high nibble so a receiver can cheaply classify a
    frame (handshake / messaging / file / keepalive / lifecycle) without a
    full dispatch table.
    """

    # 0x0_ -- session establishment & authentication
    HELLO = 0x01
    AUTH_REQ = 0x02
    AUTH_OK = 0x03
    AUTH_FAIL = 0x04

    # 0x1_ -- messaging & presence
    MSG_DIRECT = 0x10
    MSG_GROUP = 0x11
    ACK = 0x12
    TYPING = 0x13
    PRESENCE = 0x14
    SYNC_REQ = 0x15
    SYNC_END = 0x16
    UNREAD = 0x17
    MARK_READ = 0x18

    # 0x2_ -- file transfer
    FILE_OFFER = 0x20
    FILE_ACCEPT = 0x21
    FILE_CHUNK = 0x22
    FILE_DONE = 0x23
    FILE_RESUME = 0x24

    # 0x3_ -- keepalive / liveness
    PING = 0x30
    PONG = 0x31

    # 0x4_ -- lifecycle / errors
    ERROR = 0x40
    DISCONNECT = 0x41

    @property
    def group(self) -> int:
        """High-nibble group id (``0x0``..``0x4``)."""
        return (int(self) >> 4) & 0xF


class FrameFlags(IntFlag):
    """Bit flags carried in the 2-byte flags field (16 bits available)."""

    NONE = 0x0000
    #: Payload is zlib-compressed.
    COMPRESSED = 0x0001
    #: Payload is E2EE ciphertext -- server relays opaquely, must not parse.
    ENCRYPTED = 0x0002
    #: Sender wants an ACK for this frame's sequence number.
    ACK_REQUESTED = 0x0004
    #: Terminal frame of a logical sequence (e.g. end of a file / stream).
    FINAL = 0x0008
    #: Frame is part of a resumed (post-reconnect) transfer.
    RESUMED = 0x0010
    #: High-priority frame; server QoS scheduler puts it ahead of bulk data.
    URGENT = 0x0020
    #: Frame is a response to an earlier request.
    RESPONSE = 0x0040


# --------------------------------------------------------------------------- #
# Small domain enums (serialised compactly as integers)
# --------------------------------------------------------------------------- #
class PresenceState(IntEnum):
    """Availability state broadcast to the contact list."""

    OFFLINE = 0
    ONLINE = 1
    AWAY = 2


class DeliveryStatus(IntEnum):
    """Per-message delivery state machine (sent -> delivered -> read)."""

    SENT = 1
    DELIVERED = 2
    READ = 3


class AuthMethod(IntEnum):
    """How the client is authenticating in AUTH_REQ."""

    PASSWORD = 1
    TOKEN = 2
    TOTP = 3


class TypingState(IntEnum):
    """Typing indicator state."""

    STOPPED = 0
    TYPING = 1


class ErrorCode(IntEnum):
    """Machine-readable ERROR codes."""

    UNKNOWN = 0
    BAD_REQUEST = 1
    UNAUTHENTICATED = 2
    FORBIDDEN = 3
    NOT_FOUND = 4
    RATE_LIMITED = 5
    CONFLICT = 6
    TOO_LARGE = 7
    UNSUPPORTED_VERSION = 8
    INTERNAL = 9
    SHUTTING_DOWN = 10
    QUOTA_EXCEEDED = 11
    TRANSFER_ABORTED = 12
