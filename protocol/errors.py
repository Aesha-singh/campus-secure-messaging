"""CSCP exception hierarchy.

All protocol errors derive from :class:`CscpError` so the session layer can
catch a single base class and decide whether the fault is recoverable (e.g. a
single bad frame in a lenient mode) or fatal (CRC mismatch, oversize) and close
the connection.
"""

from __future__ import annotations


class CscpError(Exception):
    """Base class for every CSCP protocol error."""


class FrameError(CscpError):
    """Raised when a byte stream cannot be parsed into a valid frame."""


class MagicMismatchError(FrameError):
    """The 4-byte magic did not match ``b'CSCP'`` -- stream desynchronised."""


class CrcError(FrameError):
    """CRC32 trailer did not match the computed checksum (corruption/tamper)."""


class FrameTooLargeError(FrameError):
    """Advertised payload length exceeds the configured maximum."""


class VersionMismatchError(CscpError):
    """Frame version is not acceptable to this peer."""


class UnknownMessageTypeError(CscpError):
    """Frame carries a message type this build does not understand."""


class MessageValidationError(CscpError):
    """A decoded payload is missing fields or has wrong types/ranges."""


class ReplayError(CscpError):
    """A frame's sequence number was seen before (replay / duplication)."""
