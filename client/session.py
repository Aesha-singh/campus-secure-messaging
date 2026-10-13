"""High-level async client session: handshake, keepalive, ack correlation.

Networking concept demonstrated
-------------------------------
**The client side of a stateful session protocol.**  Mirrors the server
``Session`` FSM and demonstrates the classic client problems:

* **Handshake FSM** -- ``CONNECTED -> AUTHENTICATING -> ACTIVE`` mirrors the
  server exactly, so both sides agree on *who* is talking and which features
  ``HELLO``/``AUTH_OK`` negotiated (protocol versioning on a mixed fleet).
* **Keepalive** -- the client answers every server ``PING`` with ``PONG``
  echoing the server's round-trip timing; a silent/dead socket is detected by
  the transport and drives **exponential-backoff reconnection** (the same
  "frames are never acknowledged, so retry with a growing delay" idea as TCP's
  retransmission timer).
* **Ack correlation (send-then-await)** -- every ``MSG_DIRECT`` sent with
  ``ACK_REQUESTED`` is matched back to its ``ACK`` by *message id*; the
  ``DELIVERED`` vs ``SENT`` status tells the UI whether the recipient got it
  synchronously or whether it is spooled server-side.
* **Offline outbox (send-then-sync)** -- messages written while disconnected
  are spooled locally (SMTP-style) and flushed in order on the next reconnect;
  the server complements this with its offline queue for *received* messages,
  giving unified "message now" semantics.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import uuid
from collections.abc import Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidTag

from client.config import ClientConfig
from client.crypto import ClientCrypto
from client.store import ClientStore, HistoryEntry
from client.transport import ClientTls, ClientTransport
from protocol.codec import Frame
from protocol.constants import (
    FILE_CHUNK_SIZE,
    AuthMethod,
    DeliveryStatus,
    ErrorCode,
    FrameFlags,
    MessageType,
    PresenceState,
)
from protocol.errors import CscpError
from protocol.messages import (
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
    Error,
    FileAccept,
    FileChunk,
    FileDone,
    FileOffer,
    Hello,
    MarkRead,
    Message,
    MsgDirect,
    MsgGroup,
    Ping,
    Pong,
    Presence,
    SyncReq,
    Unread,
    decode_message,
)
from security.e2ee import derive_shared, open_seal, seal
from server.storage import convo_key

log = logging.getLogger("cscp.client.session")

_GCM_OVERHEAD = 28  # AES-GCM blob overhead: 12-byte nonce + 16-byte tag

Handler = Callable[..., Coroutine[Any, Any, None]]


@dataclass(slots=True)
class ChatMessage:
    """One decrypted (or raw) direct message surfaced to the UI."""

    msg_id: str
    convo: str
    peer_id: str
    direction: str  # "sent" | "recv"
    ts: float
    text: str | None  # None when the envelope could not be decrypted
    encrypted: bool  # True when ``text`` is None (raw ciphertext shown)
    raw: bytes


@dataclass(slots=True)
class GroupMessage:
    """One channel (room) message surfaced to the UI."""

    msg_id: str
    channel_id: str
    convo: str
    sender_id: str
    direction: str  # "sent" | "recv"
    ts: float
    text: str


@dataclass(slots=True)
class FileEvent:
    """Lifecycle + progress for one file transfer (in or out).

    ``size`` is the *plaintext* file size (what the user cares about); ``total``
    is the number of bytes actually on the wire (ciphertext is a few bytes
    larger under AES-GCM), so ``percent`` tracks true wire progress.
    """

    transfer_id: str
    peer_id: str
    name: str
    size: int
    direction: str  # "in" | "out"
    state: str  # offered|accepted|progress|complete|declined|failed
    received: int = 0
    total: int = 0
    path: str | None = None
    error: str | None = None
    encrypted: bool = True

    @property
    def percent(self) -> float:
        return (100.0 * self.received / self.total) if self.total else 0.0


@dataclass(slots=True)
class _OutgoingFile:
    transfer_id: str
    peer_id: str
    name: str
    plain_size: int
    chunk_size: int
    blob: bytes  # the exact byte stream on the wire (ciphertext when E2EE)
    sha256: str  # digest of ``blob`` (what the relay verifies)
    file_key: bytes | None  # None => plaintext transfer (peer key not pinned)
    accepted: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def wire_size(self) -> int:
        return len(self.blob)


@dataclass(slots=True)
class _IncomingFile:
    transfer_id: str
    sender_id: str
    name: str
    plain_size: int
    wire_size: int
    sha256: str
    chunk_size: int
    wrapped_key: bytes | None
    save_path: Path | None = None
    ct_path: Path | None = None  # staging file for the received (cipher) bytes
    file_key: bytes | None = None
    hasher: Any = None
    received_bytes: int = 0
    received_chunks: int = 0
    total_chunks: int = 0


@dataclass(slots=True)
class ClientCallbacks:
    """Async event sink for the GUI layer or tests."""

    on_ready: Handler | None = None
    on_message: Handler | None = None
    on_unread: Handler | None = None
    on_presence: Handler | None = None
    on_ack: Handler | None = None
    on_error: Handler | None = None
    on_disconnected: Handler | None = None
    on_group: Handler | None = None
    on_channel: Handler | None = None
    on_file: Handler | None = None
    on_rtt: Handler | None = None


class ClientSession:
    """Stateful, self-reconnecting CSCP client."""

    def __init__(
        self,
        *,
        cfg: ClientConfig,
        crypto: ClientCrypto,
        store: ClientStore,
        callbacks: ClientCallbacks,
    ) -> None:
        self.cfg = cfg
        self.crypto = crypto
        self.store = store
        self.cb = callbacks
        self._connected = asyncio.Event()
        self._lost = asyncio.Event()
        self._stopped = asyncio.Event()
        self._auth_ok: AuthOk | None = None
        self._username = ""
        self._seq = 0
        self._close_requested = False
        self._pending_acks: dict[str, asyncio.Future[Ack]] = {}
        self._pending_pings: dict[bytes, float] = {}
        self._rtt_waiters: dict[bytes, tuple[float, asyncio.Future[float]]] = {}
        self._outgoing: dict[str, _OutgoingFile] = {}
        self._incoming: dict[str, _IncomingFile] = {}
        self.channels: dict[str, ChannelInfo] = {}
        self._transport: ClientTransport | None = None
        self._reader_task: asyncio.Task[None] | None = None

    # -- public state ------------------------------------------------------

    def set_credentials(self, username: str, password: str | None = None, totp: str | None = None) -> None:
        """Configure the (storage-backed) identity used for AUTH_REQ."""
        self.cfg.username = username
        self.cfg.password = password
        self.cfg.totp = totp
        self._username = username

    @property
    def is_ready(self) -> bool:
        return self._auth_ok is not None

    @property
    def username(self) -> str:
        return self._username

    @property
    def user_id(self) -> str:
        return self._auth_ok.user_id if self._auth_ok else ""

    @property
    def transport(self) -> ClientTransport | None:
        return self._transport

    # -- lifecycle ---------------------------------------------------------

    async def run(self) -> None:
        """Connect + authenticate, then keep alive (reconnect with backoff)."""
        backoff = self.cfg.reconnect_backoff_base
        first = True
        while not self._close_requested:
            try:
                await self._run_once()
                first = False
                self._lost.clear()
                await self._lost.wait()
            except asyncio.CancelledError:
                break
            except (TimeoutError, ConnectionError, OSError, CscpError) as exc:
                log.warning("connect_failed", extra={"error": repr(exc), "backoff_s": backoff, "first": first})
            if self._close_requested:
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.cfg.reconnect_backoff_max)
        if self._transport is not None:
            await self._transport.close()
        self._stopped.set()

    async def stop(self) -> None:
        self._close_requested = True
        if self._transport is not None:
            await self._transport.close()
        self._lost.set()
        await self._wait_stopped()

    async def _wait_stopped(self) -> None:
        try:
            await asyncio.wait_for(self._stopped.wait(), timeout=3.0)
        except TimeoutError:
            pass  # shutdown best-effort; do not hang the caller
        # Guarantee the reader task is finished before returning: a caller may
        # close the store right after stop(), and a still-running reader would
        # then touch a closed database in teardown.
        task = self._reader_task
        if task is not None and not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task

    async def _run_once(self) -> None:
        tls = ClientTls(ca_file=self.cfg.ca_file, certfile=self.cfg.certfile, keyfile=self.cfg.keyfile)
        transport = ClientTransport(
            host=self.cfg.host,
            port=self.cfg.port,
            tls=tls,
            require_tls=self.cfg.require_tls,
            connect_timeout=self.cfg.connect_timeout,
            server_hostname=self.cfg.host,
        )
        await transport.connect()
        self._transport = transport
        self._reader_task = asyncio.create_task(self._reader_loop(), name="client-reader")
        await self._hello_and_auth()
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=self.cfg.connect_timeout)
        except TimeoutError:
            log.warning("auth_timeout", extra={"host": self.cfg.host})
            await transport.close()
        if self.is_ready:
            log.info("session_active", extra={"user": self.username})

    # -- public send API ---------------------------------------------------

    async def send_text(self, peer_id: str, text: str) -> str:
        """E2EE-encrypt (when the peer key is pinned) and send one direct message."""
        convo = _convo_channel(self.user_id, peer_id)
        msg_id = "m-" + uuid.uuid4().hex[:24]
        env = text.encode()
        encrypted = False
        try:
            env = self.crypto.channel_for(peer_id).send(msg_id, text.encode())
            encrypted = True
        except ValueError:
            pass  # no pinned key yet -> plaintext envelope (TOFU setup stage)
        msg = MsgDirect(
            msg_id=msg_id,
            sender_id=self.user_id,
            recipient_id=peer_id,
            ciphertext=env,
            ts=time.time(),
            reply_to=None,
            ratchet_header=None,
        )
        if self.is_ready:
            await self._send(msg, flags=FrameFlags.ACK_REQUESTED)
        else:
            await self.store.queue_send(msg_id=msg_id, convo=convo, recipient=peer_id, envelope=msg.ciphertext)
        await self.store.append_history(
            HistoryEntry(convo=convo, msg_id=msg_id, direction="sent", ts=msg.ts, plaintext=text)
        )
        if encrypted:
            log.debug("message_encrypted", extra={"msg_id": msg_id, "peer": peer_id})
        return msg_id

    async def sync_history(self, convo_kind: str, convo_id: str) -> None:
        if self.is_ready:
            await self._send(SyncReq(convo_kind=convo_kind, convo_id=convo_id, since_ts=0.0, limit=200))

    async def mark_read(self, convo_kind: str, convo_id: str) -> None:
        if self.is_ready:
            await self._send(MarkRead(convo_kind=convo_kind, convo_id=convo_id))

    async def update_presence(self, state: PresenceState) -> None:
        if self.is_ready:
            await self._send(Presence(user_id=self.user_id, state=state, last_seen=time.time()))

    # -- channels ----------------------------------------------------------

    async def create_channel(self, name: str, kind: str = "public") -> None:
        if self.is_ready:
            await self._send(ChannelCreate(name=name, kind=kind))

    async def join_channel(self, channel_id: str) -> None:
        if self.is_ready:
            await self._send(ChannelJoin(channel_id=channel_id))

    async def leave_channel(self, channel_id: str) -> None:
        if self.is_ready:
            await self._send(ChannelLeave(channel_id=channel_id))
            self.channels.pop(channel_id, None)

    async def list_channels(self, include_members: bool = True) -> None:
        if self.is_ready:
            await self._send(ChannelList(include_members=include_members))

    async def send_channel(self, channel_id: str, text: str) -> str:
        """Post a message to a room.

        Channel traffic is a server-mediated group relay (TLS-protected in
        transit, like IRC/Slack) -- distinct from 1:1 DMs which add E2EE.
        """
        convo = convo_key("channel", channel_id)
        msg_id = "g-" + uuid.uuid4().hex[:24]
        msg = MsgGroup(
            msg_id=msg_id,
            sender_id=self.user_id,
            channel_id=channel_id,
            ciphertext=text.encode(),
            ts=time.time(),
            reply_to=None,
            ratchet_header=None,
        )
        if self.is_ready:
            await self._send(msg, flags=FrameFlags.ACK_REQUESTED)
        await self.store.append_history(
            HistoryEntry(convo=convo, msg_id=msg_id, direction="sent", ts=msg.ts, plaintext=text)
        )
        return msg_id

    # -- RTT / liveness ----------------------------------------------------

    async def ping(self, timeout: float = 3.0) -> float:  # noqa: ASYNC109 -- timeout is an API knob, not a cancel scope
        """Send a PING and await its PONG; returns the round-trip time in ms.

        This is the measurement primitive behind the diagnostics panel: RTT is
        the one-way delay doubled, and successive samples give jitter (delay
        variation) and loss (a timeout == a dropped probe).
        """
        if not self.is_ready or self._transport is None:
            raise ConnectionError("client not connected")
        nonce = os.urandom(8)
        sent = time.monotonic()
        fut: asyncio.Future[float] = asyncio.get_running_loop().create_future()
        self._rtt_waiters[nonce] = (sent, fut)
        await self._send(Ping(ts=time.time(), nonce=nonce))
        try:
            async with asyncio.timeout(timeout):
                return await fut
        finally:
            self._rtt_waiters.pop(nonce, None)

    # -- files -------------------------------------------------------------

    async def send_file(
        self,
        peer_id: str,
        path: str | Path,
        *,
        name: str | None = None,
        mime: str | None = None,
        chunk_size: int = FILE_CHUNK_SIZE,
    ) -> str:
        """Offer a file to ``peer_id``; chunks stream once it is accepted.

        The whole file is sealed with AES-256-GCM as a single blob, then the
        *ciphertext* is what the store-and-forward relay chunks and reassembles.
        Because GCM adds a fixed 28-byte prefix/tag (``nonce||...||tag``), the
        relay sees ciphertext as an opaque, fixed-size-chunked byte stream -- it
        never needs to know a file was encrypted (the design intent).

        The per-file AES key is itself wrapped for the peer's pinned X25519 key
        via ECDH+HKDF, so the server only ever relays ciphertext (E2EE).  With
        no pinned key the transfer degrades to plaintext -- mirroring the
        DM TOFU-setup fallback.
        """
        src = Path(path)
        plain, _ = await asyncio.to_thread(_read_file, src)
        transfer_id = "f-" + uuid.uuid4().hex[:24]
        peer_pub = self.crypto.peer_pinned(peer_id)
        file_key: bytes | None = os.urandom(32) if peer_pub is not None else None
        wrapped: bytes | None = None
        if peer_pub is not None and file_key is not None:
            wrap_key = derive_shared(
                self.crypto.identity.private_key, peer_pub, info=f"CSCP-FILE|{transfer_id}".encode()
            )
            _, wrapped = seal(wrap_key, file_key, aad=transfer_id.encode())
            blob = seal(file_key, plain, aad=transfer_id.encode())[1]
        else:
            blob = plain
        blob_sha = hashlib.sha256(blob).hexdigest()
        transfer = _OutgoingFile(
            transfer_id=transfer_id,
            peer_id=peer_id,
            name=name or src.name,
            plain_size=len(plain),
            chunk_size=chunk_size,
            blob=blob,
            sha256=blob_sha,
            file_key=file_key,
        )
        self._outgoing[transfer_id] = transfer
        offer = FileOffer(
            transfer_id=transfer_id,
            name=transfer.name,
            size=len(blob),
            sha256=blob_sha,
            mime=mime or _guess_mime(transfer.name),
            chunk_size=chunk_size,
            recipient_id=peer_id,
            ts=time.time(),
            wrapped_key=wrapped,
            sender_id=self.user_id,
        )
        await self._send(offer, flags=FrameFlags.ACK_REQUESTED)
        await self._emit_file(
            FileEvent(
                transfer_id=transfer_id,
                peer_id=peer_id,
                name=transfer.name,
                size=transfer.plain_size,
                direction="out",
                state="offered",
                total=transfer.wire_size,
                encrypted=file_key is not None,
            )
        )
        return transfer_id

    async def accept_file(
        self, transfer_id: str, save_dir: str | Path | None = None, *, accepted: bool = True
    ) -> None:
        """Accept (or decline) an incoming offer and pick the destination path."""
        inc = self._incoming.get(transfer_id)
        if inc is None:
            raise KeyError(f"unknown transfer {transfer_id}")
        if not accepted:
            await self._send(FileAccept(transfer_id=transfer_id, accepted=False, offset=0, reason="declined"))
            self._incoming.pop(transfer_id, None)
            await self._emit_file(
                FileEvent(transfer_id, inc.sender_id, inc.name, inc.plain_size, "in", "declined", total=inc.wire_size)
            )
            return
        out_dir = Path(save_dir) if save_dir is not None else Path(self.cfg.receive_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        inc.save_path = _unique_path(out_dir / inc.name)
        inc.ct_path = inc.save_path.with_name(inc.save_path.name + ".part")
        inc.ct_path.touch()
        inc.file_key = self._unwrap_file_key(inc)
        inc.hasher = hashlib.sha256()
        inc.total_chunks = (inc.wire_size + inc.chunk_size - 1) // inc.chunk_size if inc.wire_size else 1
        await self._send(FileAccept(transfer_id=transfer_id, accepted=True, offset=0))
        await self._emit_file(
            FileEvent(
                transfer_id,
                inc.sender_id,
                inc.name,
                inc.plain_size,
                "in",
                "accepted",
                total=inc.wire_size,
                path=str(inc.save_path),
                encrypted=inc.file_key is not None,
            )
        )

    async def await_ack(self, msg_id: str, ttl_seconds: float = 8.0) -> Ack:
        fut = asyncio.get_running_loop().create_future()
        self._pending_acks[msg_id] = fut
        try:
            async with asyncio.timeout(ttl_seconds):
                ack: Ack = await fut
                return ack
        finally:
            self._pending_acks.pop(msg_id, None)

    @staticmethod
    def delivery_status_text(ack: Ack) -> str:
        if ack.status is DeliveryStatus.DELIVERED:
            return "delivered"
        if ack.status is DeliveryStatus.SENT:
            return "queued on server"
        return "unknown"

    # -- handshake ---------------------------------------------------------

    async def _hello_and_auth(self) -> None:
        await self._send(
            Hello(
                versions=[1],
                client_id=self.cfg.client_id,
                nonce=b"client-nonce",
                capabilities=list(self.cfg.capabilities),
                device=self.cfg.device_name,
            )
        )
        token = await self.store.load_session_token(self.username)
        await self._send(
            AuthReq(
                username=self.username,
                method=AuthMethod.TOKEN if token else AuthMethod.PASSWORD,
                device_id=self.crypto.identity.device_id,
                client_nonce=b"client-nonce",
                password=self.cfg.password_from_env() or "",
                token=token,
                totp_code=self.cfg.totp_from_env(),
            )
        )

    async def _flush_outbox(self) -> None:
        for entry in await self.store.take_outbox():
            await self._send(
                MsgDirect(
                    msg_id=entry.msg_id,
                    sender_id=self.user_id,
                    recipient_id=entry.recipient,
                    ciphertext=entry.envelope,
                    ts=entry.created_at,
                    reply_to=None,
                    ratchet_header=None,
                ),
                flags=FrameFlags.ACK_REQUESTED,
            )

    # -- reader pump -------------------------------------------------------

    async def _reader_loop(self) -> None:
        transport = self._transport
        assert transport is not None and transport.reader is not None
        try:
            while True:
                data = await transport.reader.read(65536)
                if not data:
                    break
                transport.feed(data)
                while True:
                    try:
                        frame = transport.decoder.next_frame()
                    except CscpError as exc:
                        log.warning("malformed_frame", extra={"error": repr(exc)})
                        break
                    if frame is None:
                        break
                    await self._on_frame(frame)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            if self.cb.on_disconnected is not None:
                await self.cb.on_disconnected()
            self._lost.set()

    async def _on_frame(self, frame: Frame) -> None:
        msg = decode_message(frame)
        mtype = frame.msg_type
        if mtype is MessageType.AUTH_OK:
            self._auth_ok = cast(AuthOk, msg)
            self.crypto.set_local_id(self.user_id)
            self._connected.set()
            if self._auth_ok.session_token:
                await self.store.save_session_token(self.username, self._auth_ok.session_token)
            if self.cb.on_ready is not None:
                await self.cb.on_ready(self)
            await self._flush_outbox()
            return
        if mtype is MessageType.AUTH_FAIL:
            fail = cast(AuthFail, msg)
            log.warning("auth_failed", extra={"reason": fail.reason})
            if self.cb.on_error is not None:
                await self.cb.on_error(Error(code=ErrorCode.BAD_REQUEST, message=fail.reason, fatal=True))
            await self.stop()
            return
        if mtype is MessageType.ERROR:
            err = cast(Error, msg)
            if self.cb.on_error is not None:
                await self.cb.on_error(err)
            if err.fatal:
                await self.stop()
            return
        if mtype is MessageType.MSG_DIRECT:
            await self._handle_direct(cast(MsgDirect, msg))
        elif mtype is MessageType.MSG_GROUP:
            await self._handle_group(cast(MsgGroup, msg))
        elif mtype is MessageType.ACK:
            await self._handle_ack(cast(Ack, msg))
        elif mtype is MessageType.PING:
            await self._handle_ping(cast(Ping, msg))
        elif mtype is MessageType.PONG:
            await self._handle_pong(cast(Pong, msg))
        elif mtype is MessageType.FILE_OFFER:
            await self._handle_file_offer(cast(FileOffer, msg))
        elif mtype is MessageType.FILE_ACCEPT:
            await self._handle_file_accept(cast(FileAccept, msg))
        elif mtype is MessageType.FILE_CHUNK:
            await self._handle_file_chunk(cast(FileChunk, msg))
        elif mtype is MessageType.FILE_DONE:
            await self._handle_file_done(cast(FileDone, msg))
        elif mtype is MessageType.CHANNEL_INFO:
            await self._handle_channel_info(cast(ChannelInfo, msg))
        elif mtype is MessageType.CHANNEL_LIST_END:
            await self._handle_channel_list_end(cast(ChannelListEnd, msg))
        elif mtype is MessageType.UNREAD:
            if self.cb.on_unread is not None:
                await self.cb.on_unread(cast(Unread, msg))
        elif mtype is MessageType.PRESENCE:
            if self.cb.on_presence is not None:
                await self.cb.on_presence(cast(Presence, msg))
        elif mtype is MessageType.DISCONNECT:
            await self.stop()

    # -- frame handlers ----------------------------------------------------

    async def _handle_direct(self, msg: MsgDirect) -> None:
        convo = _convo_channel(msg.sender_id, msg.recipient_id)
        text: str | None = None
        try:
            text = self.crypto.channel_for(msg.sender_id).recv(msg.msg_id, msg.ciphertext).decode()
        except (ValueError, InvalidTag):
            text = None  # unpinned peer / key change -> surface raw envelope
        # Persist every received message (raw or decrypted) so the local
        # transcript survives restarts -- matching the server's DLOG.
        await self.store.append_history(
            HistoryEntry(
                convo=convo,
                msg_id=msg.msg_id,
                direction="recv",
                ts=msg.ts,
                plaintext=text if text is not None else "[ciphertext]",
            )
        )
        if self.cb.on_message is not None:
            await self.cb.on_message(
                ChatMessage(
                    msg_id=msg.msg_id,
                    convo=convo,
                    peer_id=msg.sender_id,
                    direction="recv",
                    ts=msg.ts,
                    text=text,
                    encrypted=text is None,
                    raw=msg.ciphertext,
                )
            )

    async def _handle_ack(self, ack: Ack) -> None:
        if ack.msg_id is not None:
            fut = self._pending_acks.pop(ack.msg_id, None)
            if fut is not None and not fut.done():
                fut.set_result(ack)
        if self.cb.on_ack is not None:
            await self.cb.on_ack(ack)

    async def _handle_ping(self, ping: Ping) -> None:
        await self._send(Pong(ts=ping.ts, nonce=ping.nonce, server_ts=time.time()))

    async def _handle_pong(self, pong: Pong) -> None:
        self._pending_pings.pop(pong.nonce, None)
        waiter = self._rtt_waiters.get(pong.nonce)
        if waiter is None:
            return
        sent, fut = waiter
        rtt_ms = (time.monotonic() - sent) * 1000.0
        if not fut.done():
            fut.set_result(rtt_ms)
        if self.cb.on_rtt is not None:
            await self.cb.on_rtt(rtt_ms)

    async def _handle_group(self, msg: MsgGroup) -> None:
        convo = convo_key("channel", msg.channel_id)
        text = msg.ciphertext.decode("utf-8", "replace")
        direction = "sent" if msg.sender_id == self.user_id else "recv"
        await self.store.append_history(
            HistoryEntry(convo=convo, msg_id=msg.msg_id, direction=direction, ts=msg.ts, plaintext=text)
        )
        if self.cb.on_group is not None:
            await self.cb.on_group(
                GroupMessage(
                    msg_id=msg.msg_id,
                    channel_id=msg.channel_id,
                    convo=convo,
                    sender_id=msg.sender_id,
                    direction=direction,
                    ts=msg.ts,
                    text=text,
                )
            )

    async def _handle_channel_info(self, info: ChannelInfo) -> None:
        self.channels[info.channel_id] = info
        if self.cb.on_channel is not None:
            await self.cb.on_channel(info)

    async def _handle_channel_list_end(self, msg: ChannelListEnd) -> None:  # noqa: ARG002
        if self.cb.on_channel is not None:
            for info in self.channels.values():
                await self.cb.on_channel(info)

    # -- file transfer handlers -------------------------------------------

    async def _handle_file_offer(self, msg: FileOffer) -> None:
        sender = msg.sender_id or "?"
        encrypted = msg.wrapped_key is not None
        plain_size = msg.size - _GCM_OVERHEAD if encrypted else msg.size
        inc = _IncomingFile(
            transfer_id=msg.transfer_id,
            sender_id=sender,
            name=Path(msg.name).name,  # strip any path components from the peer
            plain_size=plain_size,
            wire_size=msg.size,
            sha256=msg.sha256,
            chunk_size=msg.chunk_size or FILE_CHUNK_SIZE,
            wrapped_key=msg.wrapped_key,
        )
        self._incoming[msg.transfer_id] = inc
        await self._emit_file(
            FileEvent(
                transfer_id=msg.transfer_id,
                peer_id=sender,
                name=inc.name,
                size=inc.plain_size,
                direction="in",
                state="offered",
                total=inc.wire_size,
                encrypted=encrypted,
            )
        )

    async def _handle_file_accept(self, msg: FileAccept) -> None:
        transfer = self._outgoing.get(msg.transfer_id)
        if transfer is None:
            return
        if not msg.accepted:
            self._outgoing.pop(msg.transfer_id, None)
            await self._emit_file(
                FileEvent(
                    msg.transfer_id,
                    transfer.peer_id,
                    transfer.name,
                    transfer.plain_size,
                    "out",
                    "declined",
                    total=transfer.wire_size,
                    error=msg.reason,
                )
            )
            return
        transfer.accepted.set()
        await self._emit_file(
            FileEvent(
                msg.transfer_id,
                transfer.peer_id,
                transfer.name,
                transfer.plain_size,
                "out",
                "accepted",
                total=transfer.wire_size,
                encrypted=transfer.file_key is not None,
            )
        )
        asyncio.create_task(self._stream_file(transfer), name=f"file-stream-{msg.transfer_id}")

    async def _stream_file(self, transfer: _OutgoingFile) -> None:
        blob = transfer.blob
        wire = transfer.wire_size
        total_chunks = (wire + transfer.chunk_size - 1) // transfer.chunk_size if wire else 1
        for index in range(total_chunks):
            chunk = blob[index * transfer.chunk_size : (index + 1) * transfer.chunk_size]
            await self._send(FileChunk(transfer_id=transfer.transfer_id, index=index, data=chunk))
            await self._emit_file(
                FileEvent(
                    transfer.transfer_id,
                    transfer.peer_id,
                    transfer.name,
                    transfer.plain_size,
                    "out",
                    "progress",
                    received=min((index + 1) * transfer.chunk_size, wire),
                    total=wire,
                    encrypted=transfer.file_key is not None,
                )
            )
        await self._send(FileDone(transfer_id=transfer.transfer_id, sha256=transfer.sha256, size=wire))
        self._outgoing.pop(transfer.transfer_id, None)
        await self._emit_file(
            FileEvent(
                transfer.transfer_id,
                transfer.peer_id,
                transfer.name,
                transfer.plain_size,
                "out",
                "complete",
                received=wire,
                total=wire,
                encrypted=transfer.file_key is not None,
            )
        )

    async def _handle_file_chunk(self, msg: FileChunk) -> None:
        inc = self._incoming.get(msg.transfer_id)
        if inc is None or inc.ct_path is None:
            return  # not accepted (or already finished) -> ignore stray chunk
        offset = msg.index * inc.chunk_size
        ct_path = inc.ct_path

        def _write() -> None:
            with open(ct_path, "r+b") as f:
                f.seek(offset)
                f.write(msg.data)

        try:
            await asyncio.to_thread(_write)
        except OSError:
            return
        inc.hasher.update(msg.data)
        inc.received_bytes = min(offset + len(msg.data), inc.wire_size)
        inc.received_chunks += 1
        await self._emit_file(
            FileEvent(
                msg.transfer_id,
                inc.sender_id,
                inc.name,
                inc.plain_size,
                "in",
                "progress",
                received=inc.received_bytes,
                total=inc.wire_size,
                path=str(inc.save_path) if inc.save_path else None,
                encrypted=inc.file_key is not None,
            )
        )

    async def _handle_file_done(self, msg: FileDone) -> None:
        inc = self._incoming.pop(msg.transfer_id, None)
        if inc is None:
            return
        digest_ok = (
            inc.hasher is not None and inc.hasher.hexdigest() == msg.sha256 and inc.received_bytes == inc.wire_size
        )
        final_path = str(inc.save_path) if inc.save_path else None
        error: str | None = None
        if not digest_ok:
            error = "sha256/size mismatch"
        elif inc.file_key is not None:
            try:
                await asyncio.to_thread(_decrypt_into, inc.ct_path, inc.save_path, inc.file_key, inc.transfer_id)
            except (InvalidTag, ValueError, OSError) as exc:
                error = f"decrypt failed: {type(exc).__name__}"
        elif inc.ct_path is not None and inc.save_path is not None:
            inc.ct_path.replace(inc.save_path)  # plaintext: staging file is the file
        # Remove the staging file on any failure so we don't leave ciphertext.
        if error is not None and inc.ct_path is not None:
            inc.ct_path.unlink(missing_ok=True)
            final_path = None
        await self._emit_file(
            FileEvent(
                msg.transfer_id,
                inc.sender_id,
                inc.name,
                inc.plain_size,
                "in",
                "complete" if error is None else "failed",
                received=inc.received_bytes,
                total=inc.wire_size,
                path=final_path,
                error=error,
                encrypted=inc.file_key is not None,
            )
        )

    # -- file crypto helpers ----------------------------------------------

    def _unwrap_file_key(self, inc: _IncomingFile) -> bytes | None:
        if inc.wrapped_key is None:
            return None
        sender_pub = self.crypto.peer_pinned(inc.sender_id)
        if sender_pub is None:
            return None  # sender not pinned -> can't unwrap (blob won't decrypt)
        wrap_key = derive_shared(
            self.crypto.identity.private_key, sender_pub, info=f"CSCP-FILE|{inc.transfer_id}".encode()
        )
        return open_seal(wrap_key, inc.wrapped_key, aad=inc.transfer_id.encode())

    async def _emit_file(self, event: FileEvent) -> None:
        if self.cb.on_file is not None:
            await self.cb.on_file(event)

    async def _send(self, msg: Message, *, flags: FrameFlags = FrameFlags.NONE) -> None:
        if self._transport is None or not self._transport.connected:
            raise ConnectionError("client not connected")
        self._seq += 1
        await self._transport.send(msg, sequence=self._seq, flags=flags)


def _convo_channel(a: str, b: str) -> str:
    """Server-compatible direct message key: ``dm:<sorted-a|b>``."""
    return convo_key("dm", a, b)


def _read_file(path: Path) -> tuple[bytes, int]:
    """Read a file into memory; returns ``(data, size)``.

    File transfers here are buffered client-side before the sealed blob is
    chunked onto the wire -- the *relay* is what provides store-and-forward, so
    the client's job is only to present a faithful byte stream.
    """
    data = path.read_bytes()
    return data, len(data)


def _decrypt_into(ct_path: Path | None, save_path: Path | None, file_key: bytes, transfer_id: str) -> None:
    """Decrypt the staged ciphertext blob to ``save_path`` (runs off-loop)."""
    if ct_path is None or save_path is None:
        raise ValueError("missing staging/destination path")
    blob = ct_path.read_bytes()
    plain = open_seal(file_key, blob, aad=transfer_id.encode())
    save_path.write_bytes(plain)


_MIME_BY_SUFFIX = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain",
    ".md": "text/plain",
    ".zip": "application/zip",
}


def _guess_mime(name: str) -> str:
    return _MIME_BY_SUFFIX.get(Path(name).suffix.lower(), "application/octet-stream")


def _unique_path(path: Path) -> Path:
    """Avoid clobbering an existing download: ``notes.pdf`` -> ``notes (1).pdf``."""
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    n = 1
    while (candidate := parent / f"{stem} ({n}){suffix}").exists():
        n += 1
    return candidate