"""ConnectionManager tests: user registry, channels/roles, presence relay."""

from __future__ import annotations

import pytest

from protocol.constants import PresenceState
from protocol.messages import Message, Presence
from server.manager import ConnectionManager, Peer


class FakePeer(Peer):
    def __init__(self, user_id: str, *, ip: str = "10.0.0.1", username: str | None = None) -> None:
        self.user_id = user_id
        self.ip = ip
        self.username = username or user_id
        self.received: list[Message] = []

    async def send(self, msg: Message, *, flags: object = ...) -> None:  # type: ignore[override]
        self.received.append(msg)


@pytest.mark.asyncio
async def test_register_unregister_and_lookup() -> None:
    mgr = ConnectionManager()
    alice, bob = FakePeer("alice"), FakePeer("bob")
    mgr.register(alice)
    mgr.register(bob)
    assert mgr.online_count == 2
    assert mgr.session_for("alice") is alice
    mgr.unregister(alice)
    assert mgr.session_for("alice") is None
    assert mgr.online_count == 1


@pytest.mark.asyncio
async def test_presence_broadcast_excludes_self() -> None:
    mgr = ConnectionManager()
    alice = FakePeer("alice", ip="10.0.0.1")
    bob = FakePeer("bob", ip="10.0.0.2")
    mgr.register(alice)
    mgr.register(bob)
    await mgr.publish_presence(alice, PresenceState.ONLINE)
    assert len(bob.received) == 1
    assert isinstance(bob.received[0], Presence)
    assert bob.received[0].user_id == "alice"
    assert alice.received == []  # self is excluded


@pytest.mark.asyncio
async def test_channels_roles_and_privilege() -> None:
    mgr = ConnectionManager()
    owner = FakePeer("owner")
    admin = FakePeer("admin")
    member = FakePeer("member")
    mgr.create_channel("cse-3a", "CSE 3A", "course", owner)
    mgr.join_channel("cse-3a", admin, "admin")
    mgr.join_channel("cse-3a", member, "member")
    assert mgr.is_privileged("cse-3a", "owner") is True
    assert mgr.is_privileged("cse-3a", "admin") is True
    assert mgr.is_privileged("cse-3a", "member") is False
    assert mgr.user_role_in("cse-3a", "owner") == "owner"
    # Non-privileged member cannot promote others
    assert not mgr.set_role("cse-3a", member, "admin", "member")


@pytest.mark.asyncio
async def test_broadcast_to_and_exclude() -> None:
    mgr = ConnectionManager()
    a, b, c = FakePeer("a"), FakePeer("b"), FakePeer("c")
    for p in (a, b, c):
        mgr.register(p)
    sent = await mgr.broadcast_to(Presence(user_id="x", state=PresenceState.ONLINE, last_seen=1.0))
    assert sent == 3
    assert len(a.received) == len(b.received) == len(c.received) == 1
    sent = await mgr.broadcast_to(
        Presence(user_id="x", state=PresenceState.OFFLINE, last_seen=1.0), exclude="a"
    )
    assert sent == 2
    assert len(a.received) == 1  # excluded
    assert len(b.received) == 2


def test_leave_channel_drops_empty_room() -> None:
    mgr = ConnectionManager()
    owner = FakePeer("owner")
    mgr.create_channel("c1", "C1", "club", owner)
    mgr.leave_channel("c1", "owner")
    assert "c1" not in mgr.channels