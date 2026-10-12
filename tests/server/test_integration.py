"""End-to-end server tests: handshake, auth, routing, offline queue, replay,
malformed frames, rate limiting, shutdown notifications."""

from __future__ import annotations

import asyncio
import struct

import pytest

from protocol.constants import (
    MAGIC,
    PROTOCOL_VERSION,
    DeliveryStatus,
    ErrorCode,
    FrameFlags,
    MessageType,
    PresenceState,
)
from protocol.messages import (
    Ack,
    Disconnect,
    Error,
    Hello,
    MsgDirect,
    Ping,
    Presence,
    decode_message,
)
from tests.server.conftest import WireClient, connect

ALICE_ID = "u_alice"
BOB_ID = "u_bob"
USER_IDS = {"alice": ALICE_ID, "bob": BOB_ID}


def _users() -> dict[str, str]:
    return {"alice": "sa", "bob": "sb"}


async def _alice_bob(port: int) -> tuple[WireClient, WireClient]:
    alice = await connect(port)
    bob = await connect(port)
    await alice.handshake("alice", "sa")
    await bob.handshake("bob", "sb")
    return alice, bob


async def test_hello_auth_flow(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    auth_ok = await client.handshake("alice", "sa")
    assert auth_ok.username == "alice"
    assert auth_ok.access_token
    assert auth_ok.session_token
    assert auth_ok.server_time > 0
    assert auth_ok.expires_at > auth_ok.server_time
    await client.close()


async def test_bad_password_rejected_but_connection_stays(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    await client.send(Hello(versions=[1], client_id="t", nonce=b"n" * 8))
    await client.send(
        _auth_req("alice", "wrong-password"),
    )
    frame = await client.read_until(MessageType.AUTH_FAIL)
    fail = decode_message(frame)
    assert "invalid credentials" in fail.reason
    # Correct retry on the SAME connection succeeds (no lockout in stub).
    await client.send(_auth_req("alice", "sa"))
    ok = await client.read_until(MessageType.AUTH_OK)
    assert decode_message(ok).username == "alice"
    await client.close()


async def test_presence_broadcast_on_login(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    bob = await connect(port)
    await bob.handshake("bob", "sb")
    alice = await connect(port)
    await alice.handshake("alice", "sa")
    frame = await bob.read_until(MessageType.PRESENCE)
    presence = decode_message(frame)
    assert isinstance(presence, Presence)
    assert presence.state is PresenceState.ONLINE
    await alice.close()
    await bob.close()


async def test_direct_message_online_and_ack(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    alice, bob = await _alice_bob(port)
    seq = await alice.send(
        MsgDirect(
            msg_id="m1",
            sender_id=ALICE_ID,
            recipient_id=BOB_ID,
            ciphertext=b"\x00\x01",
            ts=1.0,
        ),
        flags=FrameFlags.ACK_REQUESTED,
    )
    delivered = await bob.read_until(MessageType.MSG_DIRECT)
    frame = await alice.read_until(MessageType.ACK)
    ack = decode_message(frame)
    assert isinstance(ack, Ack)
    assert ack.ack_seq == seq
    assert ack.msg_id == "m1"
    assert ack.status is DeliveryStatus.DELIVERED
    delivered_msg = decode_message(delivered)
    assert isinstance(delivered_msg, MsgDirect)
    assert delivered_msg.msg_id == "m1"
    await alice.close()
    await bob.close()


async def test_offline_queue_flushed_on_login(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    alice = await connect(port)
    await alice.handshake("alice", "sa")  # bob is OFFLINE right now
    await alice.send(
        MsgDirect(msg_id="off1", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"qq", ts=1.0)
    )
    ack = decode_message(await alice.read_until(MessageType.ACK))
    assert ack.status is DeliveryStatus.SENT  # persisted, not delivered
    await alice.close()

    bob = await connect(port)
    await bob.handshake("bob", "sb")
    frame = await bob.read_until(MessageType.MSG_DIRECT)
    msg = decode_message(frame)
    assert isinstance(msg, MsgDirect)
    assert msg.msg_id == "off1"
    await bob.close()


async def test_replay_detected_and_closed(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    await client.handshake("alice", "sa")
    # Resend the AUTH_REQ sequence number (seq 2) -- a replay.
    await client.send_with_seq(Ping(ts=0.0, nonce=b"r" * 8), seq=2)
    frame = await client.read_until(MessageType.ERROR)
    err = decode_message(frame)
    assert isinstance(err, Error)
    assert err.code is ErrorCode.BAD_REQUEST
    assert "replay" in err.message.lower()
    # Server must drop the session afterwards.
    with pytest.raises((asyncio.TimeoutError, ConnectionError)):
        await client.read_until(MessageType.PING, timeout=1.0)
    await client.close()


async def test_malformed_frame_rejected(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    await client.send_raw(b"this is not a cscp frame at all" * 4)
    frame = await client.read_until(MessageType.ERROR)
    assert decode_message(frame).code is ErrorCode.BAD_REQUEST
    with pytest.raises((asyncio.TimeoutError, ConnectionError)):
        await client.read_until(MessageType.PING, timeout=1.0)
    await client.close()


async def test_oversized_length_rejected(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    header = struct.pack(">4sBBHIQ", MAGIC, PROTOCOL_VERSION, int(MessageType.PING), 0, 1 << 30, 1)
    await client.send_raw(header)
    frame = await client.read_until(MessageType.ERROR)
    assert decode_message(frame).code is ErrorCode.BAD_REQUEST
    await client.close()


async def test_unsupported_version_rejected(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    await client.send(Hello(versions=[99], client_id="t", nonce=b"n" * 8))
    frame = await client.read_until(MessageType.ERROR)
    assert decode_message(frame).code is ErrorCode.UNSUPPORTED_VERSION
    await client.close()


async def test_protocol_violation_fatal(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    # MSG_DIRECT before any HELLO/AUTH is illegal in CONNECTED state.
    await client.send(
        MsgDirect(msg_id="x", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"x", ts=1.0)
    )
    frame = await client.read_until(MessageType.ERROR)
    err = decode_message(frame)
    assert err.fatal is True
    assert "not allowed" in err.message.lower()
    await client.close()


async def test_user_rate_limit(running_server) -> None:  # type: ignore[no-untyped-def]
    from tests.server.conftest import server_cfg

    cfg = server_cfg()
    cfg.rate.per_user.capacity = 3
    cfg.rate.per_user.refill_per_sec = 0.01
    _, port = await running_server(cfg)
    client = await connect(port)
    await client.handshake("alice", "sa")
    for i in range(4):
        await client.send(Ping(ts=float(i), nonce=b"p" * 8))
    frame = await client.read_until(MessageType.ERROR)
    err = decode_message(frame)
    assert err.code is ErrorCode.RATE_LIMITED
    assert "user rate limit" in err.message
    await client.close()


async def test_ip_rate_limit_pre_auth(running_server) -> None:  # type: ignore[no-untyped-def]
    from tests.server.conftest import server_cfg

    cfg = server_cfg()
    cfg.rate.per_ip.capacity = 1
    cfg.rate.per_ip.refill_per_sec = 0.01
    _, port = await running_server(cfg)
    client = await connect(port)
    await client.send(Ping(ts=0.0, nonce=b"a" * 8))
    await client.send(Ping(ts=1.0, nonce=b"b" * 8))
    frame = await client.read_until(MessageType.ERROR)
    assert decode_message(frame).code is ErrorCode.RATE_LIMITED
    await client.close()


async def test_graceful_disconnect(running_server) -> None:  # type: ignore[no-untyped-def]
    _, port = await running_server(users=_users())
    client = await connect(port)
    await client.handshake("alice", "sa")
    await client.send(Disconnect(reason="bye"))
    with pytest.raises((asyncio.TimeoutError, ConnectionError)):
        await client.read_until(MessageType.PING, timeout=1.0)
    await client.close()


async def test_shutdown_notifies_clients(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(users=_users())
    client = await connect(port)
    await client.handshake("alice", "sa")
    await asyncio.sleep(0.05)
    await srv.shutdown()
    frame = await client.read_until(MessageType.ERROR)
    assert decode_message(frame).code is ErrorCode.SHUTTING_DOWN
    await client.close()


async def test_server_metrics_recorded(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(users=_users())
    alice, bob = await _alice_bob(port)
    await alice.send(
        MsgDirect(msg_id="m", sender_id=ALICE_ID, recipient_id=BOB_ID, ciphertext=b"x", ts=1.0)
    )
    await bob.read_until(MessageType.MSG_DIRECT)
    snap = srv.metrics.snapshot()
    assert snap["connections_active"] == 2
    assert snap["auth_success"] >= 2
    assert snap["messages_direct"] >= 1
    await alice.close()
    await bob.close()


def _auth_req(username: str, password: str):
    from protocol.constants import AuthMethod
    from protocol.messages import AuthReq

    return AuthReq(
        username=username,
        method=AuthMethod.PASSWORD,
        device_id="test-device",
        client_nonce=b"c" * 8,
        password=password,
    )