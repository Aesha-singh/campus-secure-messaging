"""CSCP: Campus Secure Comm Protocol.

A custom binary application-layer protocol carried over TLS 1.3 / TCP.

Public surface:
    * :mod:`protocol.constants` -- wire constants, message types, flags, enums
    * :mod:`protocol.codec`     -- :class:`Frame` plus the streaming
      :class:`FrameDecoder` that solves TCP framing
    * :mod:`protocol.messages`  -- typed message payloads and (de)serialization
    * :mod:`protocol.errors`    -- protocol exception hierarchy
"""

from __future__ import annotations

from protocol.constants import (
    FRAME_OVERHEAD,
    HEADER_SIZE,
    MAGIC,
    MAX_FRAME_SIZE,
    PROTOCOL_VERSION,
    SUPPORTED_VERSIONS,
    TRAILER_SIZE,
    FrameFlags,
    MessageType,
)
from protocol.errors import (
    CrcError,
    CscpError,
    FrameError,
    FrameTooLargeError,
    MagicMismatchError,
    MessageValidationError,
    ReplayError,
    UnknownMessageTypeError,
    VersionMismatchError,
)
from protocol.replay import ReplayGuard

__all__ = [
    "MAGIC",
    "PROTOCOL_VERSION",
    "SUPPORTED_VERSIONS",
    "HEADER_SIZE",
    "TRAILER_SIZE",
    "FRAME_OVERHEAD",
    "MAX_FRAME_SIZE",
    "MessageType",
    "FrameFlags",
    "CscpError",
    "FrameError",
    "MagicMismatchError",
    "CrcError",
    "FrameTooLargeError",
    "UnknownMessageTypeError",
    "MessageValidationError",
    "VersionMismatchError",
    "ReplayError",
    "ReplayGuard",
]
