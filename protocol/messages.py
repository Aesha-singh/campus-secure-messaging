"""Typed CSCP message payloads and their (de)serialization.

Networking concepts demonstrated
--------------------------------
* **Presentation layer (OSI L6).**  MessagePack is a compact binary
  serialization: integers are variable-width, byte strings stay binary, so a
  ``MSG_DIRECT`` frame is far smaller on the wire than JSON -- important for
  hundreds of small chat frames per second.
* **Deserialization safety.**  We *never* let MessagePack reconstruct arbitrary
  Python objects.  Payloads are explicit ``dict`` maps validated field-by-field
  against a schema, so a malicious peer cannot smuggle objects into the server
  (a classic insecure-deserialization vulnerability).  Unknown/missing fields
  raise :class:`MessageValidationError`.
* **Version negotiation.**  ``HELLO`` advertises a list of supported versions;
  the responder picks the highest common one, so old clients and new servers can
  interoperate (protocol extensibility).
"""

from __future__ import annotations

import dataclasses
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, ClassVar, cast

import msgpack

from protocol.codec import Frame, encode_frame
from protocol.constants import (
    MAX_FRAME_SIZE,
    PROTOCOL_VERSION,
    AuthMethod,
    DeliveryStatus,
    ErrorCode,
    FrameFlags,
    MessageType,
    PresenceState,
    TypingState,
)
from protocol.errors import MessageValidationError, UnknownMessageTypeError


# --------------------------------------------------------------------------- #
# Schema definition
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class FieldSpec:
    """Describes one wire field: its kind, whether it is required, and default.

    ``kind`` is one of: ``str``, ``int``, ``float``, ``bool``, ``bytes``,
    ``enum``, ``list_int``, ``list_str``.
    """

    kind: str
    required: bool = False
    default: Any = None
    enum: type[IntEnum] | None = None


_ENCODERS: dict[str, Any] = {
    "str": lambda v: str(v),
    "int": lambda v: int(v),
    "float": lambda v: float(v),
    "bool": lambda v: bool(v),
    "bytes": lambda v: bytes(v),
    "enum": lambda v: int(v),
    "list_int": lambda v: [int(x) for x in v],
    "list_str": lambda v: [str(x) for x in v],
}


def _decode_value(value: Any, spec: FieldSpec, name: str) -> Any:
    kind = spec.kind
    try:
        if kind == "str":
            if not isinstance(value, str):
                raise MessageValidationError(f"{name}: expected str")
            return value
        if kind == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise MessageValidationError(f"{name}: expected int")
            return value
        if kind == "float":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise MessageValidationError(f"{name}: expected float")
            return float(value)
        if kind == "bool":
            if not isinstance(value, bool):
                raise MessageValidationError(f"{name}: expected bool")
            return value
        if kind == "bytes":
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            raise MessageValidationError(f"{name}: expected bytes")
        if kind == "enum":
            if isinstance(value, bool) or not isinstance(value, int):
                raise MessageValidationError(f"{name}: expected int enum")
            assert spec.enum is not None
            return spec.enum(value)
        if kind == "list_int":
            if not isinstance(value, (list, tuple)):
                raise MessageValidationError(f"{name}: expected list[int]")
            return [int(x) for x in value]
        if kind == "list_str":
            if not isinstance(value, (list, tuple)):
                raise MessageValidationError(f"{name}: expected list[str]")
            return [str(x) for x in value]
    except (ValueError, TypeError) as exc:
        raise MessageValidationError(f"{name}: {exc}") from exc
    raise MessageValidationError(f"{name}: unknown field kind {kind!r}")


# --------------------------------------------------------------------------- #
# Base message
# --------------------------------------------------------------------------- #
class Message:
    """Base class for all CSCP payloads.

    Subclasses set :attr:`TYPE` and :attr:`_SCHEMA`; field names in ``_SCHEMA``
    must match the dataclass fields (checked at import time).
    """

    TYPE: ClassVar[MessageType]
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {}

    def to_map(self) -> dict[str, Any]:
        """Return a MessagePack-ready mapping (optional ``None`` fields omitted)."""
        out: dict[str, Any] = {}
        for name, spec in self._SCHEMA.items():
            value = getattr(self, name)
            if value is None and not spec.required:
                continue
            out[name] = _ENCODERS[spec.kind](value)
        return out

    @classmethod
    def from_map(cls, m: Mapping[str, Any]) -> Message:
        """Validate and construct a message from a decoded mapping."""
        if not isinstance(m, Mapping):
            raise MessageValidationError(f"{cls.__name__}: payload is not a map")
        kwargs: dict[str, Any] = {}
        for name, spec in cls._SCHEMA.items():
            if m.get(name) is not None:
                kwargs[name] = _decode_value(m[name], spec, name)
            elif spec.required:
                raise MessageValidationError(f"{cls.__name__}: missing required field {name!r}")
            else:
                kwargs[name] = _clone_default(spec.default)
        return cls(**kwargs)

    def to_payload(self) -> bytes:
        """Serialize to MessagePack bytes (``use_bin_type`` keeps ``bytes`` binary)."""
        return bytes(msgpack.packb(self.to_map(), use_bin_type=True))

    # Human-readable form for JSON logs (bytes become hex, enums their names).
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.TYPE.name}
        for name in self._SCHEMA:
            value = getattr(self, name)
            if isinstance(value, (bytes, bytearray, memoryview)):
                d[name] = {"__hex__": bytes(value).hex()}
            elif isinstance(value, IntEnum):
                d[name] = value.name
            else:
                d[name] = value
        return d


def _clone_default(default: Any) -> Any:
    """Copy mutable defaults (lists) so instances never share state."""
    if isinstance(default, list):
        return list(default)
    if isinstance(default, dict):
        return dict(default)
    return default


def _check_schema(cls: type[Message]) -> None:
    field_names = {f.name for f in dataclasses.fields(cast(Any, cls))}
    if not cls._SCHEMA:
        raise TypeError(f"{cls.__name__} has no _SCHEMA")
    missing = set(cls._SCHEMA) - field_names
    extra = field_names - set(cls._SCHEMA)
    if missing:
        raise TypeError(f"{cls.__name__} _SCHEMA references non-fields: {missing}")
    if extra:
        raise TypeError(f"{cls.__name__} fields missing from _SCHEMA: {extra}")


# --------------------------------------------------------------------------- #
# Handshake & authentication
# --------------------------------------------------------------------------- #
@dataclass
class Hello(Message):
    """Client's opening frame: version list, identity, capabilities, nonce."""

    TYPE: ClassVar[MessageType] = MessageType.HELLO
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "versions": FieldSpec("list_int", required=True),
        "client_id": FieldSpec("str", required=True),
        "nonce": FieldSpec("bytes", required=True),
        "capabilities": FieldSpec("list_str", default=[]),
        "device": FieldSpec("str", default=""),
    }

    versions: list[int]
    client_id: str
    nonce: bytes
    capabilities: list[str] = field(default_factory=list)
    device: str = ""


@dataclass
class AuthReq(Message):
    """Authentication request (password / token / TOTP)."""

    TYPE: ClassVar[MessageType] = MessageType.AUTH_REQ
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "username": FieldSpec("str", required=True),
        "method": FieldSpec("enum", required=True, enum=AuthMethod),
        "device_id": FieldSpec("str", required=True),
        "client_nonce": FieldSpec("bytes", required=True),
        "password": FieldSpec("str"),
        "token": FieldSpec("str"),
        "totp_code": FieldSpec("str"),
    }

    username: str
    method: AuthMethod
    device_id: str
    client_nonce: bytes
    password: str | None = None
    token: str | None = None
    totp_code: str | None = None


@dataclass
class AuthOk(Message):
    """Authentication succeeded; issues tokens and reports server capabilities."""

    TYPE: ClassVar[MessageType] = MessageType.AUTH_OK
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "user_id": FieldSpec("str", required=True),
        "username": FieldSpec("str", required=True),
        "access_token": FieldSpec("str", required=True),
        "session_token": FieldSpec("str", required=True),
        "expires_at": FieldSpec("float", required=True),
        "server_time": FieldSpec("float", required=True),
        "features": FieldSpec("list_str", default=[]),
        "totp_required": FieldSpec("bool", default=False),
    }

    user_id: str
    username: str
    access_token: str
    session_token: str
    expires_at: float
    server_time: float
    features: list[str] = field(default_factory=list)
    totp_required: bool = False


@dataclass
class AuthFail(Message):
    """Authentication failed; optionally reports lockout/retry state."""

    TYPE: ClassVar[MessageType] = MessageType.AUTH_FAIL
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "reason": FieldSpec("str", required=True),
        "attempts_remaining": FieldSpec("int"),
        "locked_until": FieldSpec("float"),
    }

    reason: str
    attempts_remaining: int | None = None
    locked_until: float | None = None


# --------------------------------------------------------------------------- #
# Messaging & presence
# --------------------------------------------------------------------------- #
@dataclass
class MsgDirect(Message):
    """A 1:1 message. ``ciphertext`` is E2EE; the server relays it opaquely."""

    TYPE: ClassVar[MessageType] = MessageType.MSG_DIRECT
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "msg_id": FieldSpec("str", required=True),
        "sender_id": FieldSpec("str", required=True),
        "recipient_id": FieldSpec("str", required=True),
        "ciphertext": FieldSpec("bytes", required=True),
        "ts": FieldSpec("float", required=True),
        "reply_to": FieldSpec("str"),
        "ratchet_header": FieldSpec("bytes"),
    }

    msg_id: str
    sender_id: str
    recipient_id: str
    ciphertext: bytes
    ts: float
    reply_to: str | None = None
    ratchet_header: bytes | None = None


@dataclass
class MsgGroup(Message):
    """A channel/group message (department, club, course channel or announcement)."""

    TYPE: ClassVar[MessageType] = MessageType.MSG_GROUP
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "msg_id": FieldSpec("str", required=True),
        "sender_id": FieldSpec("str", required=True),
        "channel_id": FieldSpec("str", required=True),
        "ciphertext": FieldSpec("bytes", required=True),
        "ts": FieldSpec("float", required=True),
        "reply_to": FieldSpec("str"),
        "ratchet_header": FieldSpec("bytes"),
    }

    msg_id: str
    sender_id: str
    channel_id: str
    ciphertext: bytes
    ts: float
    reply_to: str | None = None
    ratchet_header: bytes | None = None


@dataclass
class Ack(Message):
    """Acknowledges a frame sequence number and/or a message id."""

    TYPE: ClassVar[MessageType] = MessageType.ACK
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "ack_seq": FieldSpec("int", required=True),
        "msg_id": FieldSpec("str"),
        "status": FieldSpec("enum", enum=DeliveryStatus),
    }

    ack_seq: int
    msg_id: str | None = None
    status: DeliveryStatus | None = None


@dataclass
class Typing(Message):
    """Typing indicator for a direct conversation or a channel."""

    TYPE: ClassVar[MessageType] = MessageType.TYPING
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "scope": FieldSpec("str", required=True),
        "target": FieldSpec("str", required=True),
        "state": FieldSpec("enum", required=True, enum=TypingState),
    }

    scope: str
    target: str
    state: TypingState


@dataclass
class Presence(Message):
    """Presence update (online / away / offline) with last-seen timestamp."""

    TYPE: ClassVar[MessageType] = MessageType.PRESENCE
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "user_id": FieldSpec("str", required=True),
        "state": FieldSpec("enum", required=True, enum=PresenceState),
        "last_seen": FieldSpec("float", required=True),
    }

    user_id: str
    state: PresenceState
    last_seen: float


# --------------------------------------------------------------------------- #
# File transfer
# --------------------------------------------------------------------------- #
@dataclass
class FileOffer(Message):
    """Offers a file: metadata plus the AES key wrapped for the E2EE channel."""

    TYPE: ClassVar[MessageType] = MessageType.FILE_OFFER
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "transfer_id": FieldSpec("str", required=True),
        "name": FieldSpec("str", required=True),
        "size": FieldSpec("int", required=True),
        "sha256": FieldSpec("str", required=True),
        "mime": FieldSpec("str", required=True),
        "chunk_size": FieldSpec("int", required=True),
        "recipient_id": FieldSpec("str", required=True),
        "ts": FieldSpec("float", required=True),
        "wrapped_key": FieldSpec("bytes"),
    }

    transfer_id: str
    name: str
    size: int
    sha256: str
    mime: str
    chunk_size: int
    recipient_id: str
    ts: float
    wrapped_key: bytes | None = None


@dataclass
class FileAccept(Message):
    """Recipient accepts (or refuses) an offer; ``offset`` enables resume."""

    TYPE: ClassVar[MessageType] = MessageType.FILE_ACCEPT
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "transfer_id": FieldSpec("str", required=True),
        "accepted": FieldSpec("bool", required=True),
        "offset": FieldSpec("int", default=0),
        "reason": FieldSpec("str"),
    }

    transfer_id: str
    accepted: bool
    offset: int = 0
    reason: str | None = None


@dataclass
class FileChunk(Message):
    """One encrypted chunk of a file (64 KiB by default)."""

    TYPE: ClassVar[MessageType] = MessageType.FILE_CHUNK
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "transfer_id": FieldSpec("str", required=True),
        "index": FieldSpec("int", required=True),
        "data": FieldSpec("bytes", required=True),
    }

    transfer_id: str
    index: int
    data: bytes


@dataclass
class FileDone(Message):
    """Signals the last chunk; carries the whole-file SHA-256 for verification."""

    TYPE: ClassVar[MessageType] = MessageType.FILE_DONE
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "transfer_id": FieldSpec("str", required=True),
        "sha256": FieldSpec("str", required=True),
        "size": FieldSpec("int", required=True),
    }

    transfer_id: str
    sha256: str
    size: int


@dataclass
class FileResume(Message):
    """Requests resumption of a transfer after a disconnect."""

    TYPE: ClassVar[MessageType] = MessageType.FILE_RESUME
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "transfer_id": FieldSpec("str", required=True),
        "last_ack_index": FieldSpec("int", required=True),
        "last_ack_offset": FieldSpec("int", required=True),
    }

    transfer_id: str
    last_ack_index: int
    last_ack_offset: int


# --------------------------------------------------------------------------- #
# Keepalive & lifecycle
# --------------------------------------------------------------------------- #
@dataclass
class Ping(Message):
    """Heartbeat probe used for RTT/jitter measurement and idle detection."""

    TYPE: ClassVar[MessageType] = MessageType.PING
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "ts": FieldSpec("float", required=True),
        "nonce": FieldSpec("bytes", required=True),
    }

    ts: float
    nonce: bytes


@dataclass
class Pong(Message):
    """Heartbeat reply echoing the probe's timestamp and nonce."""

    TYPE: ClassVar[MessageType] = MessageType.PONG
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "ts": FieldSpec("float", required=True),
        "nonce": FieldSpec("bytes", required=True),
        "server_ts": FieldSpec("float", required=True),
    }

    ts: float
    nonce: bytes
    server_ts: float


@dataclass
class Error(Message):
    """Protocol/application error report."""

    TYPE: ClassVar[MessageType] = MessageType.ERROR
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "code": FieldSpec("enum", required=True, enum=ErrorCode),
        "message": FieldSpec("str", required=True),
        "fatal": FieldSpec("bool", default=False),
    }

    code: ErrorCode
    message: str
    fatal: bool = False


@dataclass
class Disconnect(Message):
    """Graceful connection teardown."""

    TYPE: ClassVar[MessageType] = MessageType.DISCONNECT
    _SCHEMA: ClassVar[dict[str, FieldSpec]] = {
        "reason": FieldSpec("str", required=True),
        "code": FieldSpec("int", default=1000),
    }

    reason: str
    code: int = 1000


# --------------------------------------------------------------------------- #
# Registry & (de)serialization entry points
# --------------------------------------------------------------------------- #
REGISTRY: dict[MessageType, type[Message]] = {}

_ALL_MESSAGES = (
    Hello,
    AuthReq,
    AuthOk,
    AuthFail,
    MsgDirect,
    MsgGroup,
    Ack,
    Typing,
    Presence,
    FileOffer,
    FileAccept,
    FileChunk,
    FileDone,
    FileResume,
    Ping,
    Pong,
    Error,
    Disconnect,
)
for _cls in _ALL_MESSAGES:
    _check_schema(_cls)
    REGISTRY[_cls.TYPE] = _cls


def to_frame(
    msg: Message,
    *,
    sequence: int,
    flags: FrameFlags = FrameFlags.NONE,
    version: int = PROTOCOL_VERSION,
) -> Frame:
    """Wrap a message into a :class:`Frame` (not yet encoded)."""
    return Frame(
        msg_type=msg.TYPE,
        sequence=sequence,
        payload=msg.to_payload(),
        version=version,
        flags=flags,
    )


def encode_message(
    msg: Message,
    *,
    sequence: int,
    flags: FrameFlags = FrameFlags.NONE,
    version: int = PROTOCOL_VERSION,
    max_frame_size: int = MAX_FRAME_SIZE,
) -> bytes:
    """Serialize a message straight to wire bytes (header+payload+crc)."""
    return encode_frame(
        to_frame(msg, sequence=sequence, flags=flags, version=version),
        max_frame_size=max_frame_size,
    )


def decode_message(frame: Frame) -> Message:
    """Deserialize a :class:`Frame` payload into a validated message.

    Raises:
        UnknownMessageTypeError: Frame type is not in the registry.
        MessageValidationError: Payload is not a valid map for that type.
    """
    cls = REGISTRY.get(frame.msg_type)
    if cls is None:
        raise UnknownMessageTypeError(f"no handler for {frame.msg_type!r}")
    try:
        decoded = msgpack.unpackb(frame.payload, raw=False, strict_map_key=False)
    except Exception as exc:  # noqa: BLE001 -- normalise msgpack errors
        raise MessageValidationError(f"undecodable payload: {exc}") from exc
    return cls.from_map(decoded)


# Kept for symmetry with a future zlib-compression helper.
def _compressed_size_hint(payload: bytes) -> int:
    return struct.calcsize(">I") + len(payload)
