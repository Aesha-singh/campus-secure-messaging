"""Per-connection session: explicit FSM, framing, heartbeat, backpressure.

Networking concepts demonstrated
--------------------------------
* **Explicit session state machine** (CONNECTED -> AUTHENTICATING -> ACTIVE ->
  CLOSING).  Guards the protocol: a frame type that is forbidden in the current
  state kills the connection, which is how real servers (SSH, HTTP/1.1 upgrade)
  prevent protocol smuggling and out-of-order abuse.
* **Heartbeat (PING/PONG)** detects dead peers that TCP cannot see -- a laptop
  whose Wi-Fi vanished never sends FIN, so without application keepalives the
  server would accumulate ghost sockets (ESTABLISHED but dead forever).  Idle
  timeout + missed-pong detection evicts them.
* **Per-connection backpressure.**  Outbound data goes through a *bounded* queue
  consumed by a single writer task that calls ``writer.drain()``.  When a slow
  consumer's socket buffer fills, ``drain()`` blocks and the queue fills, which
  in turn makes the producer (this connection's reader) wait -- the classic
  end-to-end **flow control** cascade (compare TCP windowing at L4).
* **Kernel/poll model.**  One event loop multiplexes thousands of sockets via
  epoll/kqueue; each session is only ever "woken" when bytes arrive or a timer
  fires, so the C10k pattern never needs a thread per client.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import os
import time
from enum import StrEnum
from typing import Any, Final, cast

from protocol.codec import Frame, FrameDecoder, encode_frame
from protocol.constants import (
    PROTOCOL_VERSION,
    SUPPORTED_VERSIONS,
    DeliveryStatus,
    ErrorCode,
    FrameFlags,
    MessageType,
    PresenceState,
)
from protocol.errors import (
    FrameError,
    MessageValidationError,
    ReplayError,
    UnknownMessageTypeError,
)
from protocol.messages import (
    CHANNEL_KINDS,
    Ack,
    AuthFail,
    AuthOk,
    AuthReq,
    ChannelCreate,
    ChannelInfo,
    ChannelJoin,
    ChannelLeave,
    ChannelList,
    ChannelListEnd,
    Disconnect,
    Error,
    FileAccept,
    FileChunk,
    FileDone,
    FileOffer,
    FileResume,
    Hello,
    MarkRead,
    Message,
    MsgDirect,
    MsgGroup,
    Ping,
    Pong,
    Presence,
    SyncEnd,
    SyncReq,
    Typing,
    Unread,
    decode_message,
    to_frame,
)
from protocol.replay import ReplayGuard
from server.auth import issue_session
from server.context import ServerContext
from server.manager import Peer
from server.storage import convo_key

_PING_NONCE_LEN = 8
_SENTINEL: Final = object()

log = logging.getLogger("cscp.session")


class SessionState(StrEnum):
    CONNECTED = "CONNECTED"
    AUTHENTICATING = "AUTHENTICATING"
    ACTIVE = "ACTIVE"
    CLOSING = "CLOSING"


#: Legal inbound frame types per state.  Everything else is a protocol violation.
_LEGAL: dict[SessionState, frozenset[MessageType]] = {
    SessionState.CONNECTED: frozenset({MessageType.HELLO, MessageType.PING, MessageType.PONG, MessageType.DISCONNECT}),
    SessionState.AUTHENTICATING: frozenset(
        {MessageType.AUTH_REQ, MessageType.PING, MessageType.PONG, MessageType.DISCONNECT}
    ),
    SessionState.ACTIVE: frozenset(
        {
            MessageType.MSG_DIRECT,
            MessageType.MSG_GROUP,
            MessageType.ACK,
            MessageType.TYPING,
            MessageType.PRESENCE,
            MessageType.FILE_OFFER,
            MessageType.FILE_ACCEPT,
            MessageType.FILE_CHUNK,
            MessageType.FILE_DONE,
            MessageType.FILE_RESUME,
            MessageType.SYNC_REQ,
            MessageType.MARK_READ,
            MessageType.CHANNEL_CREATE,
            MessageType.CHANNEL_JOIN,
            MessageType.CHANNEL_LEAVE,
            MessageType.CHANNEL_LIST,
            MessageType.PING,
            MessageType.PONG,
            MessageType.ERROR,
            MessageType.DISCONNECT,
        }
    ),
    SessionState.CLOSING: frozenset({MessageType.PING, MessageType.PONG, MessageType.DISCONNECT}),
}


class Session:
    """One authenticated-or-pending TCP/TLS connection."""

    def __init__(
        self,
        ctx: ServerContext,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        connection_id: int,
        ip: str,
        port: int,
    ) -> None:
        self.ctx = ctx
        self.reader = reader
        self.writer = writer
        self.connection_id = connection_id
        self.ip = ip
        self.port = port

        self.state: SessionState = SessionState.CONNECTED
        self.decoder = FrameDecoder(max_frame_size=ctx.cfg.limits.max_frame_size)
        self.replay = ReplayGuard()

        self._out_seq = itertools.count(1)
        self._send_queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=ctx.cfg.limits.write_queue_size)
        self._closed = False
        self._fatal = False

        self.user_id: str | None = None
        self.username: str | None = None
        self.role: str = "guest"
        self.device_id: str = ""
        self.negotiated_version: int = PROTOCOL_VERSION
        self.access_token: str | None = None
        self.session_token: str | None = None

        self.last_rx = time.monotonic()
        self._pending_pings: dict[bytes, float] = {}

        self._tasks: list[asyncio.Task[Any]] = []
        self._connected_at = time.monotonic()

    # ------------------------------------------------------------------ #
    # Transport lifecycle
    # ------------------------------------------------------------------ #
    async def run(self) -> None:
        """Drive the connection until it ends."""
        self.ctx.metrics.connect()
        log.info(
            "connection_open",
            extra={"connection_id": self.connection_id, "ip": self.ip, "port": self.port},
        )
        self._tasks.append(asyncio.create_task(self._writer_loop(), name=f"sess-{self.connection_id}-writer"))
        self._tasks.append(asyncio.create_task(self._heartbeat_loop(), name=f"sess-{self.connection_id}-hb"))
        try:
            await self._reader_loop()
        finally:
            await self.graceful_close()
            log.info(
                "connection_closed",
                extra={
                    "connection_id": self.connection_id,
                    "user_id": self.user_id,
                    "duration_s": round(time.monotonic() - self._connected_at, 2),
                },
            )

    async def _reader_loop(self) -> None:
        while self.state is not SessionState.CLOSING and not self.writer.is_closing():
            try:
                data = await self.reader.read(65536)
            except (ConnectionError, asyncio.CancelledError, EOFError):
                break
            except Exception as exc:  # noqa: BLE001 -- TLS layer surprises
                log.info("read_error", extra={"connection_id": self.connection_id, "error": repr(exc)})
                break
            if not data:
                break  # orderly FIN from peer
            self.last_rx = time.monotonic()
            self.ctx.metrics.record_bytes_in(len(data))
            self.decoder.feed(data)
            try:
                while True:
                    frame = self.decoder.next_frame()
                    if frame is None:
                        break
                    await self._on_frame(frame)
                    # `cast` widens the statically-narrowed FSM value back to the full
                    # enum so mypy accepts the comparison (state mutates in `_close`).
                    if cast(SessionState, self.state) is SessionState.CLOSING:
                        return
            except FrameError as exc:
                self.ctx.metrics.malformed_frames += 1
                log.warning(
                    "malformed_frame",
                    extra={"connection_id": self.connection_id, "error": str(exc)},
                )
                await self._send_error(ErrorCode.BAD_REQUEST, f"malformed frame: {exc}", fatal=True)
                return
            except ReplayError as exc:
                self.ctx.metrics.replay_rejected += 1
                log.warning("replay_rejected", extra={"connection_id": self.connection_id, "sequence": exc})
                await self._send_error(ErrorCode.BAD_REQUEST, "replay detected", fatal=True)
                return

    async def _on_frame(self, frame: Frame) -> None:
        self.replay.check(frame.sequence)

        if not self.ctx.rate.ip_allowed(self.ip):
            self.ctx.metrics.rate_limited += 1
            log.warning("rate_limited_ip", extra={"connection_id": self.connection_id, "ip": self.ip})
            await self._send_error(ErrorCode.RATE_LIMITED, "ip rate limit exceeded", fatal=False)
            return
        if self.state is SessionState.ACTIVE and self.user_id is not None:
            if not self.ctx.rate.user_allowed(self.user_id):
                self.ctx.metrics.rate_limited += 1
                log.warning("rate_limited_user", extra={"connection_id": self.connection_id, "user_id": self.user_id})
                await self._send_error(ErrorCode.RATE_LIMITED, "user rate limit exceeded", fatal=False)
                return

        legal = _LEGAL.get(self.state, frozenset())
        if frame.msg_type not in legal:
            await self._send_error(
                ErrorCode.BAD_REQUEST,
                f"{frame.msg_type.name} is not allowed in state {self.state.value}",
                fatal=True,
            )
            return

        try:
            msg = decode_message(frame)
        except (MessageValidationError, UnknownMessageTypeError) as exc:
            self.ctx.metrics.malformed_frames += 1
            log.warning("bad_payload", extra={"connection_id": self.connection_id, "error": str(exc)})
            await self._send_error(ErrorCode.BAD_REQUEST, f"bad payload: {exc}", fatal=True)
            return

        handler = _HANDLERS.get(frame.msg_type)
        if handler is None:
            await self._send_error(
                ErrorCode.NOT_FOUND, f"handler not implemented for {frame.msg_type.name}", fatal=False
            )
            return

        await handler(self, frame, msg)

    # ------------------------------------------------------------------ #
    # Outbound path (bounded queue + drain => flow control)
    # ------------------------------------------------------------------ #
    async def send(self, msg: Message, *, flags: FrameFlags = FrameFlags.NONE) -> None:
        """Enqueue a message as a frame addressed with the next outbound seq."""
        frame = to_frame(
            msg, sequence=next(self._out_seq), version=self.negotiated_version, flags=flags
        )
        await self.send_bytes(encode_frame(frame, max_frame_size=self.ctx.cfg.limits.max_frame_size))

    async def send_bytes(self, data: bytes) -> None:
        """Put raw frame bytes on the bounded queue (blocks when full)."""
        if self._closed:
            return
        await self._send_queue.put(data)

    async def _writer_loop(self) -> None:
        while True:
            item: Any = await self._send_queue.get()
            try:
                if item is _SENTINEL:
                    break
                self.writer.write(item)
                try:
                    await self.writer.drain()
                except (ConnectionError, asyncio.CancelledError):
                    break
                except Exception as exc:  # noqa: BLE001
                    log.info("write_error", extra={"connection_id": self.connection_id, "error": repr(exc)})
                    break
                self.ctx.metrics.record_bytes_out(len(item))
                self.ctx.metrics.messages_out += 1
            finally:
                self._send_queue.task_done()

    async def _send_error(self, code: ErrorCode, message: str, *, fatal: bool) -> None:
        await self.send(Error(code=code, message=message, fatal=fatal))
        if fatal:
            self._fatal = True
            self.state = SessionState.CLOSING

    async def _send_ack(self, ack_seq: int, msg_id: str | None, status: DeliveryStatus) -> None:
        await self.send(Ack(ack_seq=ack_seq, msg_id=msg_id, status=status))

    # ------------------------------------------------------------------ #
    # Heartbeat
    # ------------------------------------------------------------------ #
    async def _heartbeat_loop(self) -> None:
        cfg = self.ctx.cfg.heartbeat
        while not self._closed:
            await asyncio.sleep(cfg.ping_interval)
            if self._closed:
                break
            now = time.monotonic()
            age = now - self.last_rx
            if age > cfg.idle_timeout:
                self.ctx.metrics.connections_evicted += 1
                log.info("idle_timeout", extra={"connection_id": self.connection_id, "idle_s": round(age, 2)})
                break
            if age > cfg.ping_interval:
                nonce = os.urandom(_PING_NONCE_LEN)
                self._pending_pings[nonce] = now
                await self.send(Ping(ts=now, nonce=nonce))

    # ------------------------------------------------------------------ #
    # Handlers
    # ------------------------------------------------------------------ #
    async def _on_hello(self, frame: Frame, msg: Hello) -> None:  # noqa: ARG002
        if self.state is not SessionState.CONNECTED:
            await self._send_error(ErrorCode.BAD_REQUEST, "HELLO already processed", fatal=True)
            return
        common = sorted(set(msg.versions) & set(SUPPORTED_VERSIONS))
        if not common:
            await self._send_error(
                ErrorCode.UNSUPPORTED_VERSION,
                f"no common version (client={msg.versions}, server={list(SUPPORTED_VERSIONS)})",
                fatal=True,
            )
            return
        self.negotiated_version = max(common)
        self.device_id = msg.device
        self.state = SessionState.AUTHENTICATING
        log.info(
            "hello_accepted",
            extra={
                "connection_id": self.connection_id,
                "version": self.negotiated_version,
                "client_id": msg.client_id,
                "capabilities": msg.capabilities,
            },
        )

    async def _on_auth_req(self, frame: Frame, msg: AuthReq) -> None:
        if self.state is not SessionState.AUTHENTICATING:
            await self._send_error(ErrorCode.BAD_REQUEST, "AUTH_REQ not allowed", fatal=True)
            return
        if not self.ctx.rate.auth_attempt_allowed(self.ip):
            remaining = self.ctx.rate.auth_remaining(self.ip)
            await self.send(AuthFail(reason="rate limited", attempts_remaining=remaining))
            return

        result = await self.ctx.auth.authenticate(msg, ip=self.ip)
        self.ctx.metrics.record_auth(result.ok)

        if not result.ok or result.user is None:
            await self.send(
                AuthFail(
                    reason=result.reason,
                    attempts_remaining=result.attempts_remaining,
                    locked_until=result.locked_until,
                )
            )
            return

        self.user_id = result.user.user_id
        self.username = result.user.username
        self.role = result.user.role
        self.device_id = msg.device_id

        issued = issue_session(
            self.ctx.secret,
            user=result.user,
            device_id=self.device_id,
            access_ttl=self.ctx.cfg.auth.token_ttl_seconds,
            session_ttl=self.ctx.cfg.auth.session_resume_ttl_seconds,
        )
        self.access_token = issued.access_token
        self.session_token = issued.session_token

        self.state = SessionState.ACTIVE
        self.ctx.manager.register(_as_peer(self))
        await self.send(
            AuthOk(
                user_id=self.user_id,
                username=self.username,
                access_token=issued.access_token,
                session_token=issued.session_token,
                expires_at=issued.access_expires_at,
                server_time=time.time(),
                features=["e2ee", "files", "channels"],
            ),
            flags=FrameFlags.RESPONSE,
        )
        # Remote presence so contacts see us come online.
        await self.ctx.manager.publish_presence(_as_peer(self), PresenceState.ONLINE)
        # Flush anything queued while we were away, then a fresh unread summary.
        pending = await self.ctx.store.take_offline(self.user_id)
        for queued in pending:
            await self.send(queued)
        await self._send_unread()
        log.info(
            "login_ok",
            extra={
                "connection_id": self.connection_id,
                "user_id": self.user_id,
                "offline_replay": len(pending),
            },
        )

    async def _on_ping(self, frame: Frame, msg: Ping) -> None:  # noqa: ARG002
        self._pending_pings.pop(msg.nonce, None)
        self.last_rx = time.monotonic()
        await self.send(Pong(ts=msg.ts, nonce=msg.nonce, server_ts=time.time()))

    async def _on_pong(self, frame: Frame, msg: Pong) -> None:  # noqa: ARG002
        sent_at = self._pending_pings.pop(msg.nonce, None)
        if sent_at is not None:
            rtt = (time.monotonic() - sent_at) * 1000.0
            self.ctx.metrics.record_rtt(rtt)
            log.debug("pong", extra={"connection_id": self.connection_id, "rtt_ms": round(rtt, 3)})

    async def _on_disconnect(self, frame: Frame, msg: Disconnect) -> None:  # noqa: ARG002
        log.info("disconnect", extra={"connection_id": self.connection_id, "reason": msg.reason, "code": msg.code})
        self.state = SessionState.CLOSING

    async def _on_msg_direct(self, frame: Frame, msg: MsgDirect) -> None:
        self._require_active()
        if msg.sender_id != self.user_id:
            await self._send_error(ErrorCode.FORBIDDEN, "sender id mismatch", fatal=True)
            return
        if len(msg.ciphertext) > self.ctx.cfg.limits.max_message_bytes:
            await self._send_error(ErrorCode.TOO_LARGE, "message too large", fatal=False)
            return
        self.ctx.metrics.record_message(direct=True)

        convo = convo_key("dm", msg.sender_id, msg.recipient_id)
        # Persist every accepted direct message so history/sync can replay it
        # (the sorted-pair convo id collapses a two-user thread into one spine).
        await self.ctx.store.save_message("dm", convo, msg)

        recipient = self.ctx.manager.session_for(msg.recipient_id)
        if recipient is not None:
            await recipient.send(msg)
            await self._send_ack(frame.sequence, msg.msg_id, DeliveryStatus.DELIVERED)
        else:
            # Recipient is offline: queue for flush-on-login and badge the convo.
            await self.ctx.store.enqueue_offline(msg.recipient_id, msg)
            await self.ctx.store.bump_unread(msg.recipient_id, convo)
            await self._send_ack(frame.sequence, msg.msg_id, DeliveryStatus.SENT)
        log.info(
            "msg_direct",
            extra={
                "connection_id": self.connection_id,
                "from": msg.sender_id,
                "to": msg.recipient_id,
                "delivered": recipient is not None,
                "convo_id": convo,
            },
        )

    async def _on_msg_group(self, frame: Frame, msg: MsgGroup) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        if len(msg.ciphertext) > self.ctx.cfg.limits.max_message_bytes:
            await self._send_error(ErrorCode.TOO_LARGE, "message too large", fatal=False)
            return
        if self.ctx.manager.user_role_in(msg.channel_id, self.user_id) is None:
            await self._send_error(ErrorCode.FORBIDDEN, "not a member of channel", fatal=False)
            return
        self.ctx.metrics.record_message(group=True)

        convo = convo_key("channel", msg.channel_id)
        await self.ctx.store.save_message("channel", convo, msg)
        await self.ctx.manager.broadcast_channel(msg.channel_id, msg, exclude=self.user_id)

        # Offline members get an unread badge; when they next log in a
        # client-side SYNC_REQ pulls the thread via history replay.
        online = set(self.ctx.manager.online_ids())
        for member in self.ctx.manager.channel_members(msg.channel_id):
            if member != self.user_id and member not in online:
                await self.ctx.store.bump_unread(member, convo)
        await self._send_ack(frame.sequence, msg.msg_id, DeliveryStatus.SENT)

    async def _on_typing(self, frame: Frame, msg: Typing) -> None:  # noqa: ARG002
        self._require_active()
        if msg.scope == "direct":
            peer = self.ctx.manager.session_for(msg.target)
            if peer is not None and peer.user_id != self.user_id:
                await peer.send(msg)
        elif msg.scope == "group":
            await self.ctx.manager.broadcast_channel(msg.target, msg, exclude=self.user_id)

    async def _on_presence(self, frame: Frame, msg: Presence) -> None:  # noqa: ARG002
        self._require_active()
        # A user may only publish their own presence.
        await self.ctx.manager.publish_presence(_as_peer(self), msg.state)

    async def _on_ack(self, frame: Frame, msg: Ack) -> None:  # noqa: ARG002
        log.debug("ack", extra={"connection_id": self.connection_id, "ack_seq": msg.ack_seq, "msg_id": msg.msg_id})

    async def _on_sync_req(self, frame: Frame, msg: SyncReq) -> None:  # noqa: ARG002
        """Replay history for a conversation as normal message frames + SyncEnd."""
        self._require_active()
        assert self.user_id is not None
        limit = msg.limit or self.ctx.cfg.storage.history_limit
        batch = await self.ctx.store.history(
            self.user_id,
            msg.convo_kind,
            msg.convo_id,
            since_ts=msg.since_ts,
            limit=limit,
        )
        for queued in batch:
            await self.send(queued)
        await self.send(SyncEnd(convo_kind=msg.convo_kind, convo_id=msg.convo_id, count=len(batch)))
        # Replaying a thread means it's now on screen: clear its badge.
        await self.ctx.store.clear_unread(self.user_id, msg.convo_id)
        log.debug(
            "sync",
            extra={
                "connection_id": self.connection_id,
                "user_id": self.user_id,
                "convo_id": msg.convo_id,
                "count": len(batch),
            },
        )

    async def _on_mark_read(self, frame: Frame, msg: MarkRead) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        await self.ctx.store.clear_unread(self.user_id, msg.convo_id)
        await self._send_unread()
        log.debug(
            "mark_read",
            extra={"connection_id": self.connection_id, "convo_id": msg.convo_id},
        )

    async def _send_unread(self) -> None:
        assert self.user_id is not None
        counts = await self.ctx.store.unread_counts(self.user_id)
        await self.send(Unread(convo_unread=counts, server_time=time.time()))

    # ------------------------------------------------------------------ #
    # Channels (rooms): membership management plane
    # ------------------------------------------------------------------ #
    def _channel_info(self, channel_id: str, viewer_id: str) -> ChannelInfo | None:
        ch = self.ctx.manager.channel(channel_id)
        if ch is None:
            return None
        members = ch.member_ids
        return ChannelInfo(
            channel_id=ch.channel_id,
            name=ch.name,
            kind=ch.kind,
            role=ch.role_of(viewer_id) or "guest",
            created_by=ch.owner_id,
            members=list(members),
            member_count=len(members),
        )

    async def _on_channel_create(self, frame: Frame, msg: ChannelCreate) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        name = msg.name.strip()
        if not name or len(name) > 64:
            await self._send_error(ErrorCode.BAD_REQUEST, "channel name must be 1..64 chars", fatal=False)
            return
        kind = msg.kind if msg.kind in CHANNEL_KINDS else "public"
        channel_id = self.ctx.manager.unique_channel_id(name)
        self.ctx.manager.create_channel(channel_id, name, kind, _as_peer(self))
        info = self._channel_info(channel_id, self.user_id)
        if info is not None:
            await self.send(info, flags=FrameFlags.RESPONSE)
        log.info(
            "channel_created",
            extra={"connection_id": self.connection_id, "channel_id": channel_id, "by": self.user_id},
        )

    async def _on_channel_join(self, frame: Frame, msg: ChannelJoin) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        ch = self.ctx.manager.channel(msg.channel_id)
        if ch is None:
            await self._send_error(ErrorCode.NOT_FOUND, "no such channel", fatal=False)
            return
        self.ctx.manager.join_channel(msg.channel_id, _as_peer(self))
        info = self._channel_info(msg.channel_id, self.user_id)
        if info is not None:
            await self.send(info, flags=FrameFlags.RESPONSE)
        log.info(
            "channel_joined",
            extra={"connection_id": self.connection_id, "channel_id": msg.channel_id, "by": self.user_id},
        )

    async def _on_channel_leave(self, frame: Frame, msg: ChannelLeave) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        self.ctx.manager.leave_channel(msg.channel_id, self.user_id)
        log.info(
            "channel_left",
            extra={"connection_id": self.connection_id, "channel_id": msg.channel_id, "by": self.user_id},
        )

    async def _on_channel_list(self, frame: Frame, msg: ChannelList) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        channels = self.ctx.manager.all_channels()
        for ch in channels:
            info = self._channel_info(ch.channel_id, self.user_id)
            if info is not None:
                if not msg.include_members:
                    info = ChannelInfo(
                        channel_id=info.channel_id,
                        name=info.name,
                        kind=info.kind,
                        role=info.role,
                        created_by=info.created_by,
                        members=[],
                        member_count=info.member_count,
                    )
                await self.send(info)
        await self.send(ChannelListEnd(count=len(channels)), flags=FrameFlags.RESPONSE)

    # ------------------------------------------------------------------ #
    # File transfer (store-and-forward relay)
    # ------------------------------------------------------------------ #
    async def _on_file_offer(self, frame: Frame, msg: FileOffer) -> None:
        self._require_active()
        # Stamp the authenticated sender so a recipient can wrap/unwrap the file
        # key against the true origin and a client cannot spoof who sent a file.
        assert self.user_id is not None
        msg.sender_id = self.user_id
        error, transfer = await self.ctx.transfers.offer(_as_peer(self), msg)
        if error is not None:
            await self._send_error(
                ErrorCode.QUOTA_EXCEEDED if error == "quota_exceeded" else ErrorCode.TOO_LARGE,
                f"file offer rejected: {error}",
                fatal=False,
            )
            return
        recipient = self.ctx.manager.session_for(msg.recipient_id)
        if recipient is not None:
            await recipient.send(msg)
            await self._send_ack(frame.sequence, None, DeliveryStatus.DELIVERED)
        else:
            await self.ctx.store.enqueue_offline(msg.recipient_id, msg)
            await self._send_ack(frame.sequence, None, DeliveryStatus.SENT)
        log.info(
            "file_offer_relayed",
            extra={"transfer_id": msg.transfer_id, "to": msg.recipient_id, "size": msg.size},
        )

    async def _on_file_accept(self, frame: Frame, msg: FileAccept) -> None:  # noqa: ARG002
        self._require_active()
        assert self.user_id is not None
        transfer = await self.ctx.transfers.accept(msg.transfer_id) if msg.accepted else None
        if transfer is None and not msg.accepted:
            transfer = await self.ctx.transfers.refuse(msg.transfer_id, _as_peer(self))
        if transfer is None:
            await self._send_error(ErrorCode.NOT_FOUND, "unknown transfer", fatal=False)
            return
        sender = self.ctx.manager.session_for(transfer.sender_id)
        if sender is not None:
            await sender.send(msg, flags=FrameFlags.RESPONSE)
        log.info(
            "file_accept_relayed",
            extra={"transfer_id": msg.transfer_id, "accepted": msg.accepted, "by": self.user_id},
        )

    async def _on_file_chunk(self, frame: Frame, msg: FileChunk) -> None:
        self._require_active()
        error, transfer, watermark = await self.ctx.transfers.write_chunk(msg, _as_peer(self))
        if error != "":
            await self._send_error(ErrorCode.TRANSFER_ABORTED, f"chunk rejected: {error}", fatal=False)
            return
        assert transfer is not None
        # Store-and-forward: drain any newly-contiguous prefix to the recipient.
        recipient = self.ctx.manager.session_for(transfer.recipient_id)
        if recipient is not None:
            await self.ctx.transfers.forward_to(transfer.transfer_id, recipient)
        # Cumulative storage watermark ACK (sliding-window flow control).
        await self._send_ack(frame.sequence, f"{transfer.transfer_id}:w{watermark}", DeliveryStatus.DELIVERED)

    async def _on_file_done(self, frame: Frame, msg: FileDone) -> None:
        self._require_active()
        error, transfer = await self.ctx.transfers.on_done(msg, _as_peer(self))
        if error != "":
            await self._send_error(ErrorCode.TRANSFER_ABORTED, f"complete rejected: {error}", fatal=False)
            return
        assert transfer is not None
        recipient = self.ctx.manager.session_for(transfer.recipient_id)
        if recipient is not None:
            await recipient.send(msg)
        await self._send_ack(frame.sequence, transfer.transfer_id, DeliveryStatus.DELIVERED)
        log.info(
            "transfer_complete",
            extra={"transfer_id": msg.transfer_id, "sha256": msg.sha256[:16]},
        )

    async def _on_file_resume(self, frame: Frame, msg: FileResume) -> None:  # noqa: ARG002
        self._require_active()
        transfer = self.ctx.transfers.transfers.get(msg.transfer_id)
        if transfer is None:
            await self._send_error(ErrorCode.NOT_FOUND, "unknown transfer", fatal=False)
            return
        assert self.user_id is not None
        # Recipient resumes a download: re-stream from its own watermark.
        if self.user_id == transfer.recipient_id:
            sent, error = await self.ctx.transfers.pull_from_watermark(
                msg.transfer_id, _as_peer(self), msg.last_ack_index + 1
            )
            if error != "":
                await self._send_error(ErrorCode.TRANSFER_ABORTED, f"resume failed: {error}", fatal=False)
                return
            await self._send_ack(frame.sequence, f"{msg.transfer_id}:r{sent}", DeliveryStatus.DELIVERED)
        else:  # sender reconnecting: report current storage watermark so it may resume upload.
            await self._send_ack(
                frame.sequence,
                f"{msg.transfer_id}:w{transfer.storage_watermark}",
                DeliveryStatus.DELIVERED,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _require_active(self) -> None:
        if self.state is not SessionState.ACTIVE:
            raise AssertionError("handler invoked outside ACTIVE state")  # guarded by FSM

    async def graceful_close(self) -> None:
        """Flush outgoing data, then tear the socket down. Idempotent."""
        if self._closed:
            return
        self._closed = True

        was_active = self.state is SessionState.ACTIVE
        uid, uname = self.user_id, self.username
        if uid is not None:
            self.ctx.manager.unregister(_as_peer(self))

        if not self.writer.is_closing() and not self._fatal:
            try:
                await asyncio.wait_for(self._send_queue.join(), timeout=self.ctx.cfg.limits.close_timeout)
            except TimeoutError:
                log.info("flush_timeout", extra={"connection_id": self.connection_id})
        if not self.writer.is_closing():
            await self._send_queue.put(_SENTINEL)
            try:
                await asyncio.wait_for(self._send_queue.join(), timeout=self.ctx.cfg.limits.close_timeout)
            except TimeoutError:
                pass

        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        if not self.writer.is_closing():
            self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:  # noqa: BLE001 -- TLS teardown may raise mid-close
            log.debug("writer_close_error", extra={"connection_id": self.connection_id})

        if was_active and uid is not None:
            try:
                await self.ctx.manager.publish_presence(
                    self_like(uid, uname or "", self.ip), PresenceState.OFFLINE
                )
            except Exception:  # noqa: BLE001 -- presence best-effort on teardown
                log.debug("presence_teardown_error", extra={"connection_id": self.connection_id})
        self.ctx.metrics.disconnect()


def _as_peer(session: Session) -> Peer:
    """Narrow an authenticated Session to the :class:`Peer` protocol."""
    return cast(Peer, session)


def self_like(user_id: str, username: str, ip: str) -> Any:
    """Tiny stand-in Peer carrying identity for presence broadcast on logout."""

    class _Shell:
        user_id = user_id
        username = username
        ip = ip

        async def send(self, msg: Message, *, flags: FrameFlags = FrameFlags.NONE) -> None:
            pass  # this peer is already gone

    return _Shell()


_HANDLERS: dict[MessageType, Any] = {
    MessageType.HELLO: Session._on_hello,
    MessageType.AUTH_REQ: Session._on_auth_req,
    MessageType.PING: Session._on_ping,
    MessageType.PONG: Session._on_pong,
    MessageType.DISCONNECT: Session._on_disconnect,
    MessageType.MSG_DIRECT: Session._on_msg_direct,
    MessageType.MSG_GROUP: Session._on_msg_group,
    MessageType.TYPING: Session._on_typing,
    MessageType.PRESENCE: Session._on_presence,
    MessageType.ACK: Session._on_ack,
    MessageType.SYNC_REQ: Session._on_sync_req,
    MessageType.MARK_READ: Session._on_mark_read,
    MessageType.CHANNEL_CREATE: Session._on_channel_create,
    MessageType.CHANNEL_JOIN: Session._on_channel_join,
    MessageType.CHANNEL_LEAVE: Session._on_channel_leave,
    MessageType.CHANNEL_LIST: Session._on_channel_list,
    MessageType.FILE_OFFER: Session._on_file_offer,
    MessageType.FILE_ACCEPT: Session._on_file_accept,
    MessageType.FILE_CHUNK: Session._on_file_chunk,
    MessageType.FILE_DONE: Session._on_file_done,
    MessageType.FILE_RESUME: Session._on_file_resume,
}