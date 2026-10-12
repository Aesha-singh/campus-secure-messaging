"""Connection manager: registry of online users, channels, presence relay.

Networking concept demonstrated
-------------------------------
**Application-layer overlay on the transport mesh.**  TCP/TLS gives the server
one dedicated pipe per peer; the manager maintains a *routing table* keyed by
user identity (a layer-7 equivalent of MAC/ARP tables), so a message for a user
is delivered by consulting ``online_users`` rather than broadcast to every
socket -- O(1) lookup instead of O(N) fanout, exactly like L2 forwarding vs L3
routing.

It also tracks **channels** (department / club / course rooms) with an
*owner/admin/member* role matrix used to authorise group messages and to prune
membership, mirroring group-membership management of multicast/IGMP at L3.
"""

from __future__ import annotations

import itertools
import time
from typing import Protocol

from protocol.constants import FrameFlags, PresenceState
from protocol.messages import Message, Presence

Role = str  # "owner" | "admin" | "member"


class Peer(Protocol):
    """Anything the manager can route a message to (a live session)."""

    user_id: str
    username: str
    ip: str

    async def send(self, msg: Message, *, flags: FrameFlags = FrameFlags.NONE) -> None: ...


class Channel:
    """A room (department / club / course / announcement) with role-based membership."""

    __slots__ = ("channel_id", "name", "kind", "_members")

    def __init__(self, channel_id: str, name: str, kind: str, owner_id: str) -> None:
        self.channel_id = channel_id
        self.name = name
        self.kind = kind
        self._members: dict[str, Role] = {owner_id: "owner"}

    def add(self, user_id: str, role: Role = "member") -> None:
        self._members.setdefault(user_id, role)

    def remove(self, user_id: str) -> None:
        self._members.pop(user_id, None)

    def role_of(self, user_id: str) -> Role | None:
        return self._members.get(user_id)

    def is_privileged(self, user_id: str, minimum: Role = "admin") -> bool:
        rank = {"member": 1, "admin": 2, "owner": 3}
        return rank.get(self.role_of(user_id) or "member", 0) >= rank[minimum]

    @property
    def member_ids(self) -> tuple[str, ...]:
        return tuple(self._members)

    def snapshot(self) -> dict[str, object]:
        return {
            "channel_id": self.channel_id,
            "name": self.name,
            "kind": self.kind,
            "members": dict(self._members),
        }


class ConnectionManager:
    """Central registry of who is connected where, and to which channels."""

    def __init__(self) -> None:
        self.online_users: dict[str, Peer] = {}
        self.by_ip: dict[str, set[str]] = {}
        self.channels: dict[str, Channel] = {}
        self._conn_seq = itertools.count(1)

    # -- user registry ------------------------------------------------------ #
    def register(self, peer: Peer) -> None:
        self.online_users[peer.user_id] = peer
        self.by_ip.setdefault(peer.ip, set()).add(peer.user_id)

    def unregister(self, peer: Peer) -> None:
        self.online_users.pop(peer.user_id, None)
        bucket = self.by_ip.get(peer.ip)
        if bucket is not None:
            bucket.discard(peer.user_id)
            if not bucket:
                self.by_ip.pop(peer.ip, None)

    def session_for(self, user_id: str) -> Peer | None:
        return self.online_users.get(user_id)

    def online_ids(self) -> tuple[str, ...]:
        return tuple(self.online_users)

    @property
    def online_count(self) -> int:
        return len(self.online_users)

    @property
    def ip_count(self) -> int:
        return len(self.by_ip)

    # -- presence ----------------------------------------------------------- #
    async def publish_presence(self, peer: Peer, state: PresenceState) -> None:
        """Broadcast a presence change to every other online peer."""
        msg = Presence(user_id=peer.user_id, state=state, last_seen=time.time())
        for other in self.online_users.values():
            if other.user_id != peer.user_id:
                await other.send(msg)

    # -- channels ----------------------------------------------------------- #
    def create_channel(self, channel_id: str, name: str, kind: str, creator: Peer) -> Channel:
        ch = Channel(channel_id, name, kind, creator.user_id)
        self.channels[channel_id] = ch
        return ch

    def join_channel(self, channel_id: str, peer: Peer, role: Role = "member") -> Channel | None:
        ch = self.channels.get(channel_id)
        if ch is None:
            return None
        ch.add(peer.user_id, role)
        return ch

    def leave_channel(self, channel_id: str, peer_id: str) -> None:
        ch = self.channels.get(channel_id)
        if ch is not None:
            ch.remove(peer_id)
            if not ch.member_ids:
                self.channels.pop(channel_id, None)

    def set_role(self, channel_id: str, actor: Peer, target: str, role: Role) -> bool:
        ch = self.channels.get(channel_id)
        if ch is None or not ch.is_privileged(actor.user_id) or ch.role_of(target) is None:
            return False
        ch._members[target] = role  # noqa: SLF001 -- same module knowledge
        return True

    def channel_members(self, channel_id: str) -> tuple[str, ...]:
        ch = self.channels.get(channel_id)
        return ch.member_ids if ch else ()

    def user_role_in(self, channel_id: str, user_id: str) -> Role | None:
        ch = self.channels.get(channel_id)
        return ch.role_of(user_id) if ch else None

    def is_privileged(self, channel_id: str, user_id: str, minimum: Role = "admin") -> bool:
        ch = self.channels.get(channel_id)
        return ch.is_privileged(user_id, minimum) if ch else False

    # -- broadcast helpers -------------------------------------------------- #
    async def broadcast_to(
        self,
        msg: Message,
        *,
        recipients: tuple[str, ...] | None = None,
        exclude: str | None = None,
        flags: FrameFlags = FrameFlags.NONE,
    ) -> int:
        """Send ``msg`` to a set of online users; returns fanout count."""
        sent = 0
        targets = recipients if recipients is not None else self.online_ids()
        for user_id in targets:
            if user_id == exclude:
                continue
            peer = self.online_users.get(user_id)
            if peer is not None:
                await peer.send(msg, flags=flags)
                sent += 1
        return sent

    async def broadcast_channel(
        self, channel_id: str, msg: Message, *, exclude: str | None = None, flags: FrameFlags = FrameFlags.NONE
    ) -> int:
        return await self.broadcast_to(
            msg, recipients=self.channel_members(channel_id), exclude=exclude, flags=flags
        )

    # -- reports ------------------------------------------------------------ #
    def snapshot(self) -> dict[str, object]:
        return {
            "online": {uid: {"ip": p.ip, "username": p.username} for uid, p in self.online_users.items()},
            "online_count": self.online_count,
            "ip_count": self.ip_count,
            "channels": {cid: ch.snapshot() for cid, ch in self.channels.items()},
        }