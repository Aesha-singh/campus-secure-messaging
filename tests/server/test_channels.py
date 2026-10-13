"""Channel (room) management plane: create / join / leave / list / broadcast.

Networking concept: application-layer multicast membership (the IGMP idea) --
the server keeps a per-room roster and fans a group message out only to members,
instead of flooding every socket.
"""

from __future__ import annotations

import pytest

from protocol.constants import ErrorCode, MessageType
from protocol.messages import (
    ChannelCreate,
    ChannelInfo,
    ChannelJoin,
    ChannelLeave,
    ChannelList,
    ChannelListEnd,
    Error,
    MsgGroup,
    decode_message,
)
from tests.server.conftest import connect, server_cfg

pytestmark = pytest.mark.asyncio


def _info(frame) -> ChannelInfo:  # type: ignore[no-untyped-def]
    msg = decode_message(frame)
    assert isinstance(msg, ChannelInfo)
    return msg


async def test_create_join_list_broadcast(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(server_cfg())

    alice = await connect(port)
    bob = await connect(port)
    try:
        await alice.handshake("alice", "sa")
        await bob.handshake("bob", "sb")

        # alice creates a room; she is its owner.
        await alice.send(ChannelCreate(name="Networking 101", kind="course"))
        created = _info(await alice.read_until(MessageType.CHANNEL_INFO))
        assert created.role == "owner"
        assert created.member_count == 1
        assert created.created_by == "u_alice"
        assert created.channel_id == "networking-101"

        # bob joins as a member.
        await bob.send(ChannelJoin(channel_id=created.channel_id))
        joined = _info(await bob.read_until(MessageType.CHANNEL_INFO))
        assert joined.role == "member"
        assert joined.member_count == 2
        assert set(joined.members) == {"u_alice", "u_bob"}

        # a group message fans out to the other member.
        group = MsgGroup(
            channel_id=created.channel_id, msg_id="g1", sender_id="u_alice", ciphertext=b"hello room", ts=1.0
        )
        await alice.send(group)
        frame = await bob.read_until(MessageType.MSG_GROUP)
        assert decode_message(frame).ciphertext == b"hello room"
    finally:
        await alice.close()
        await bob.close()


async def test_channel_list_sentinel(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(server_cfg())
    alice = await connect(port)
    try:
        await alice.handshake("alice", "sa")
        await alice.send(ChannelList())
        infos = []
        while True:
            frame = await alice.read_until(MessageType.CHANNEL_INFO, timeout=1.0)
            infos.append(_info(frame))
            # stop once we have every seeded channel
            if len(infos) == len(srv.manager.channels):
                break
        end = await alice.read_until(MessageType.CHANNEL_LIST_END)
        endmsg = decode_message(end)
        assert isinstance(endmsg, ChannelListEnd)
        assert endmsg.count == len(srv.manager.channels)
        assert any(i.channel_id == "lobby" for i in infos)
    finally:
        await alice.close()


async def test_join_unknown_channel_errors(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(server_cfg())
    alice = await connect(port)
    try:
        await alice.handshake("alice", "sa")
        await alice.send(ChannelJoin(channel_id="does-not-exist"))
        frame = await alice.read_until(MessageType.ERROR)
        err = decode_message(frame)
        assert isinstance(err, Error)
        assert err.code is ErrorCode.NOT_FOUND
    finally:
        await alice.close()


async def test_empty_custom_channel_is_reaped(running_server) -> None:  # type: ignore[no-untyped-def]
    srv, port = await running_server(server_cfg())
    alice = await connect(port)
    try:
        await alice.handshake("alice", "sa")
        await alice.send(ChannelCreate(name="Temporary", kind="club"))
        created = _info(await alice.read_until(MessageType.CHANNEL_INFO))
        await alice.send(ChannelLeave(channel_id=created.channel_id))
        stray = MsgGroup(channel_id=created.channel_id, msg_id="g2", sender_id="u_alice", ciphertext=b"x", ts=1.0)
        await alice.send(stray)
        # non-member (after leaving) message is refused
        frame = await alice.read_until(MessageType.ERROR)
        err = decode_message(frame)
        assert isinstance(err, Error)
        assert err.code is ErrorCode.FORBIDDEN
        assert created.channel_id not in srv.manager.channels  # reaped when empty
    finally:
        await alice.close()
