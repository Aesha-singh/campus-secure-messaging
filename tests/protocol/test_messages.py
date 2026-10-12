"""Message serialization tests: round-trips, validation, and registry coverage."""

from __future__ import annotations

import pytest

from protocol.constants import (
    AuthMethod,
    DeliveryStatus,
    ErrorCode,
    FrameFlags,
    MessageType,
    PresenceState,
    TypingState,
)
from protocol.errors import MessageValidationError, UnknownMessageTypeError
from protocol.messages import (
    REGISTRY,
    Ack,
    AuthFail,
    AuthOk,
    AuthReq,
    Disconnect,
    Error,
    FileAccept,
    FileChunk,
    FileDone,
    FileOffer,
    FileResume,
    Hello,
    Message,
    MsgDirect,
    MsgGroup,
    Ping,
    Pong,
    Presence,
    Typing,
    decode_message,
    encode_message,
    to_frame,
)

SAMPLES: list[Message] = [
    Hello(versions=[1], client_id="dev-1", nonce=b"\x01\x02", capabilities=["e2ee"]),
    AuthReq(
        username="aesha",
        method=AuthMethod.PASSWORD,
        device_id="laptop",
        client_nonce=b"\xaa\xbb",
        password="hunter2",  # noqa: S106 -- fixture data only
    ),
    AuthOk(
        user_id="u1",
        username="aesha",
        access_token="at",  # noqa: S106 -- fixture data only
        session_token="st",  # noqa: S106 -- fixture data only
        expires_at=1_700_000_000.0,
        server_time=1_699_999_000.0,
        features=["e2ee", "files"],
        totp_required=False,
    ),
    AuthFail(reason="bad password", attempts_remaining=2),
    MsgDirect(
        msg_id="m1",
        sender_id="u1",
        recipient_id="u2",
        ciphertext=b"\x00\x01\x02",
        ts=1.0,
        reply_to="m0",
        ratchet_header=b"rh",
    ),
    MsgGroup(
        msg_id="g1",
        sender_id="u1",
        channel_id="c1",
        ciphertext=b"ct",
        ts=2.0,
    ),
    Ack(ack_seq=9, msg_id="m1", status=DeliveryStatus.DELIVERED),
    Typing(scope="direct", target="u2", state=TypingState.TYPING),
    Presence(user_id="u2", state=PresenceState.ONLINE, last_seen=3.0),
    FileOffer(
        transfer_id="t1",
        name="notes.pdf",
        size=1234,
        sha256="ab" * 32,
        mime="application/pdf",
        chunk_size=65536,
        recipient_id="u2",
        ts=4.0,
        wrapped_key=b"wk",
    ),
    FileAccept(transfer_id="t1", accepted=True, offset=65536),
    FileChunk(transfer_id="t1", index=1, data=b"z" * 16),
    FileDone(transfer_id="t1", sha256="cd" * 32, size=1234),
    FileResume(transfer_id="t1", last_ack_index=1, last_ack_offset=65536),
    Ping(ts=5.0, nonce=b"pn"),
    Pong(ts=5.0, nonce=b"pn", server_ts=5.1),
    Error(code=ErrorCode.RATE_LIMITED, message="slow down", fatal=False),
    Disconnect(reason="bye", code=1000),
]


def test_registry_covers_every_message_type() -> None:
    assert set(REGISTRY) == set(MessageType)
    assert len(SAMPLES) == len(MessageType)


@pytest.mark.parametrize("msg", SAMPLES, ids=lambda m: type(m).__name__)
def test_roundtrip_via_frame(msg: Message) -> None:
    frame = to_frame(msg, sequence=1, flags=FrameFlags.ENCRYPTED)
    decoded = decode_message(frame)
    assert type(decoded) is type(msg)
    assert decoded == msg


@pytest.mark.parametrize("msg", SAMPLES, ids=lambda m: type(m).__name__)
def test_roundtrip_via_wire_bytes(msg: Message) -> None:
    from protocol.codec import FrameDecoder

    wire = encode_message(msg, sequence=5)
    dec = FrameDecoder()
    dec.feed(wire)
    (frame,) = dec.frames()
    assert decode_message(frame) == msg


def test_optional_fields_are_omitted_from_map() -> None:
    m = Ping(ts=1.0, nonce=b"n").to_map()
    assert set(m) == {"ts", "nonce"}
    m2 = Ack(ack_seq=1).to_map()
    assert set(m2) == {"ack_seq"}


def test_missing_required_field_rejected() -> None:
    with pytest.raises(MessageValidationError):
        Ping.from_map({"ts": 1.0})  # no nonce


def test_wrong_type_rejected() -> None:
    with pytest.raises(MessageValidationError):
        Ping.from_map({"ts": "not-a-float", "nonce": b"n"})
    with pytest.raises(MessageValidationError):
        Ping.from_map({"ts": 1.0, "nonce": "should-be-bytes"})


def test_bad_enum_rejected() -> None:
    with pytest.raises(MessageValidationError):
        Presence.from_map({"user_id": "u", "state": 999, "last_seen": 1.0})


def test_payload_not_a_map_rejected() -> None:
    with pytest.raises(MessageValidationError):
        Ping.from_map([1, 2, 3])  # type: ignore[arg-type]


def test_undecodable_payload_rejected() -> None:
    from protocol.codec import Frame

    bad = Frame(MessageType.PING, 1, payload=b"\xc1")  # 0xc1 is never-used msgpack
    with pytest.raises(MessageValidationError):
        decode_message(bad)


def test_decode_unknown_type_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from protocol.codec import Frame

    frame = Frame(MessageType.PING, 1)
    monkeypatch.delitem(REGISTRY, MessageType.PING)
    with pytest.raises(UnknownMessageTypeError):
        decode_message(frame)


def test_to_dict_hex_encodes_bytes() -> None:
    d = Hello(versions=[1], client_id="c", nonce=b"\xde\xad").to_dict()
    assert d["type"] == "HELLO"
    assert d["nonce"] == {"__hex__": "dead"}


def test_schema_matches_dataclass_fields() -> None:
    import dataclasses

    for cls in set(REGISTRY.values()):
        field_names = {f.name for f in dataclasses.fields(cls)}
        assert field_names == set(cls._SCHEMA), cls.__name__


def test_enum_serialized_as_int() -> None:
    m = Presence(user_id="u", state=PresenceState.AWAY, last_seen=1.0).to_map()
    assert m["state"] == int(PresenceState.AWAY)
    assert isinstance(m["state"], int)
