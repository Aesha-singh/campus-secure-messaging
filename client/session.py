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
import logging
import time
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any, cast

from cryptography.exceptions import InvalidTag

from client.config import ClientConfig
from client.crypto import ClientCrypto
from client.store import ClientStore, HistoryEntry
from client.transport import ClientTls, ClientTransport
from protocol.codec import Frame
from protocol.constants import (
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
    Error,
    Hello,
    MarkRead,
    Message,
    MsgDirect,
    Ping,
    Pong,
    Presence,
    SyncReq,
    Unread,
    decode_message,
)

log = logging.getLogger("cscp.client.session")

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
class ClientCallbacks:
    """Async event sink for the GUI layer or tests."""

    on_ready: Handler | None = None
    on_message: Handler | None = None
    on_unread: Handler | None = None
    on_presence: Handler | None = None
    on_ack: Handler | None = None
    on_error: Handler | None = None
    on_disconnected: Handler | None = None


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
        elif mtype is MessageType.ACK:
            await self._handle_ack(cast(Ack, msg))
        elif mtype is MessageType.PING:
            await self._handle_ping(cast(Ping, msg))
        elif mtype is MessageType.PONG:
            self._pending_pings.pop(cast(Pong, msg).nonce, None)
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

    async def _send(self, msg: Message, *, flags: FrameFlags = FrameFlags.NONE) -> None:
        if self._transport is None or not self._transport.connected:
            raise ConnectionError("client not connected")
        self._seq += 1
        await self._transport.send(msg, sequence=self._seq, flags=flags)


def _convo_channel(a: str, b: str) -> str:
    return "dm:" + ":".join(sorted((a, b)))