"""Server-side E2EE file-transfer relay: store-and-forward with sliding window.

Networking concepts demonstrated
--------------------------------
* **Message switching / store-and-forward** on top of the connection mesh.
  Uploaded chunks are written to a *relay buffer* on disk first; the relay only
  forwards the contiguous prefix to the recipient when it is online.  The
  sender is ACKed against a *storage watermark* (the TCP cumulative-ACK
  analogue) and can stream ahead of the recipient -- exactly like an MTA or a
  CDN ingesting content faster than a slow client can pull it.
* **Random-access reassembly buffer** (analogue of a TCP receive buffer).
  Chunks may arrive out of order; the relay writes each chunk at its byte
  offset (``index * chunk_size``) into a sparse pre-sized file, so it can serve
  a contiguous prefix at any moment without waiting for the file tail.
* **Range-style resumption** (HTTP ``Range`` analogue).  A client that
  disconnected mid-transfer issues ``FILE_RESUME`` with its last-chunk
  watermark; the relay serves every subsequent chunk straight from the
  persisted buffer, even if the original sender is gone.  Combined with the
  per-transfer TTL this mirrors CDN cache-lifetime semantics.
* **E2EE opacity**: chunks are AES ciphertext produced in the client; the
  server persists and relays them byte-for-byte and can never read file
  contents -- at-rest the relay buffer is useless to a disk thief.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import IntEnum
from math import ceil
from pathlib import Path

from protocol.messages import FileChunk, FileDone, FileOffer
from server.config import FileConfig
from server.manager import Peer

log = logging.getLogger("cscp.transfer")


class TransferState(IntEnum):
    """Lifecycle of one file transfer through the relay."""

    OFFERED = 1    # offer recorded, waiting for recipient decision
    ACCEPTED = 2   # recipient accepted, sender may stream chunks
    STREAMING = 3  # at least one chunk persisted
    COMPLETE = 4   # all chunks received and verified contiguous
    ABORTED = 5    # refused or cancelled


@dataclass(slots=True)
class Transfer:
    transfer_id: str
    sender_id: str
    recipient_id: str
    name: str
    size: int
    sha256: str
    mime: str
    chunk_size: int
    wrapped_key: bytes | None
    ts: float
    state: TransferState = TransferState.OFFERED
    storage_watermark: int = 0   # number of leading chunks persisted (cumulative ack)
    relayed_upto: int = 0        # number of leading chunks forwarded to recipient
    bytes_stored: int = 0        # actual payload bytes written (tail clamped)
    path: Path | None = None     # sparse blob file, reserved at offer time
    expires_at: float = 0.0
    received: set[int] = field(default_factory=set)  # indexes persisted on disk

    @property
    def total_chunks(self) -> int:
        return ceil(self.size / self.chunk_size) if self.size else 1

    @property
    def store_bytes(self) -> int:
        return self.bytes_stored


class FileTransferManager:
    """Registers offers, persists chunks, relays contiguous prefixes."""

    def __init__(self, files_cfg: FileConfig) -> None:
        if not files_cfg.enabled:
            raise RuntimeError("file transfer disabled (files.enabled=false)")
        self.cfg = files_cfg
        self.blob_root = Path(files_cfg.relay_encrypted_blobs_dir)
        self.blob_root.mkdir(parents=True, exist_ok=True)
        self.transfers: dict[str, Transfer] = {}

    # -- lifecycle --------------------------------------------------------- #
    async def offer(self, sender: Peer, msg: FileOffer) -> tuple[str | None, Transfer | None]:
        """Register an offer; returns an error code (``None`` = ok).

        Validation happens *before* any bytes are accepted, so a hostile
        client cannot trick the server into buffering data it will refuse.
        """
        await self.cleanup_expired()
        if msg.size > self.cfg.max_size_bytes:
            return "too_large", None
        if not (0 < msg.chunk_size <= self.cfg.chunk_size * 16):
            return "bad_chunk_size", None
        if not msg.name or msg.name != Path(msg.name).name:
            return "bad_name", None
        if msg.transfer_id in self.transfers:
            return "duplicate", None
        if self._quota_bytes(sender.user_id) + msg.size > self.cfg.quota_bytes:
            return "quota_exceeded", None

        blob = self.blob_root / f"{msg.transfer_id}.blob"
        if not self._reserve_blob(blob, msg.size):
            return "too_large", None
        t = Transfer(
            transfer_id=msg.transfer_id,
            sender_id=sender.user_id,
            recipient_id=msg.recipient_id,
            name=msg.name,
            size=msg.size,
            sha256=msg.sha256,
            mime=msg.mime,
            chunk_size=msg.chunk_size,
            wrapped_key=msg.wrapped_key,
            ts=msg.ts,
            path=blob,
            expires_at=time.time() + self.cfg.ttl_seconds,
        )
        self.transfers[msg.transfer_id] = t
        log.info("file_offered", extra={"transfer_id": msg.transfer_id, "size": msg.size})
        return None, t

    async def refuse(self, transfer_id: str, actor: Peer) -> Transfer | None:
        t = self.transfers.get(transfer_id)
        if t is None or actor.user_id != t.recipient_id:
            return t
        t.state = TransferState.ABORTED
        await self._expire(t)
        return t

    async def accept(self, transfer_id: str) -> Transfer | None:
        t = self.transfers.get(transfer_id)
        if t is None or t.state not in (TransferState.OFFERED, TransferState.ABORTED):
            return t
        t.state = TransferState.ACCEPTED
        log.info("file_accepted", extra={"transfer_id": transfer_id})
        return t

    async def write_chunk(self, msg: FileChunk, sender: Peer) -> tuple[str, Transfer | None, int]:
        """Persist one chunk; returns (error, transfer, new storage_watermark)."""
        t = self.transfers.get(msg.transfer_id)
        if t is None:
            return "not_found", None, -1
        if sender.user_id != t.sender_id:
            return "forbidden", t, -1
        if t.state not in (TransferState.ACCEPTED, TransferState.STREAMING):
            return "state", t, -1
        if not (0 <= msg.index < t.total_chunks):
            return "index_out_of_range", t, -1
        if msg.index < t.storage_watermark or msg.index in t.received:
            return "duplicate", t, -1  # idempotent re-send after ACK loss is safe

        # Clamp the final chunk to the file's remaining bytes: a sender may pad
        # the tail (or replay a stale full-length chunk) and the relay must
        # normalize so the reassembled file is exactly `size` bytes.
        offset = msg.index * t.chunk_size
        payload = msg.data[: max(0, t.size - offset)]

        if not await self._persist(t, msg.index, payload):
            return "disk_error", t, -1
        t.received.add(msg.index)
        t.bytes_stored += len(payload)
        t.state = TransferState.STREAMING
        while t.storage_watermark in t.received:
            t.storage_watermark += 1
        return "", t, t.storage_watermark

    async def on_done(self, msg: FileDone, sender: Peer) -> tuple[str, Transfer | None]:
        t = self.transfers.get(msg.transfer_id)
        if t is None:
            return "not_found", None
        if sender.user_id != t.sender_id:
            return "forbidden", t
        if msg.size != t.size or msg.sha256 != t.sha256:
            return "digest_mismatch", t
        if t.storage_watermark != t.total_chunks:
            return "incomplete", t
        t.state = TransferState.COMPLETE
        log.info("file_complete", extra={"transfer_id": msg.transfer_id, "bytes": t.size})
        return "", t

    async def pull_from_watermark(self, transfer_id: str, client: Peer, from_index: int) -> tuple[int, str]:
        """Re-stream the contiguous stored tail to a peer that reconnected.

        The client's ``from_index`` is its own last-received chunk; the relay
        picks up from there.  The session decides who may pull: only the two
        parties of the transfer may.
        """
        t = self.transfers.get(transfer_id)
        if t is None:
            return 0, "not_found"
        if client.user_id not in (t.sender_id, t.recipient_id):
            return 0, "forbidden"
        sent = 0
        start = max(0, min(from_index, t.storage_watermark))
        for idx in range(start, t.storage_watermark):
            if await self._resend_chunk(t, client, idx):
                sent += 1
        return sent, ""

    async def forward_to(self, transfer_id: str, recipient: Peer) -> int:
        """Push any newly-available contiguous chunks to the live recipient.

        Store-and-forward: whatever leading chunk range the relay has persisted
        beyond what the recipient has seen is drained into the recipient's
        connection, and the recipient-side watermark advances to match.
        """
        t = self.transfers.get(transfer_id)
        if t is None or recipient.user_id != t.recipient_id:
            return 0
        sent = 0
        while t.relayed_upto < t.storage_watermark:
            if await self._resend_chunk(t, recipient, t.relayed_upto):
                t.relayed_upto += 1
                sent += 1
        return sent

    async def cleanup_expired(self) -> None:
        now = time.time()
        dead = [tid for tid, t in self.transfers.items() if now > t.expires_at]
        for tid in dead:
            await self._expire(self.transfers[tid])
        if dead:
            log.info("transfers_expired", extra={"count": len(dead)})

    def status(self, transfer_id: str) -> dict[str, object] | None:
        t = self.transfers.get(transfer_id)
        if t is None:
            return None
        return {
            "transfer_id": t.transfer_id,
            "state": t.state.name,
            "storage_watermark": t.storage_watermark,
            "total_chunks": t.total_chunks,
            "relayed_upto": t.relayed_upto,
            "size": t.size,
            "created_at": t.ts,
            "expires_at": t.expires_at,
        }

    # -- internals --------------------------------------------------------- #
    def _quota_bytes(self, user_id: str) -> int:
        # Sum of *reserved* offer sizes for the user's live transfers.  Quota
        # is reserved at offer time (the "book now, pay later" analogue of
        # connection admission control) so a client cannot make the relay
        # buffer data it will then refuse.
        return sum(t.size for t in self.transfers.values() if t.sender_id == user_id)

    def _reserve_blob(self, blob: Path, size: int) -> bool:
        try:
            fd = os.open(blob, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                os.ftruncate(fd, size)  # pre-size (sparse): random writes never EOF
            finally:
                os.close(fd)
            return True
        except OSError:
            return False

    async def _persist(self, t: Transfer, index: int, data: bytes) -> bool:
        def _write() -> None:
            assert t.path is not None
            with open(t.path, "r+b") as f:
                f.seek(index * t.chunk_size)
                f.write(data)

        try:
            await asyncio.to_thread(_write)
            return True
        except OSError as exc:
            log.warning("blob_write_error", extra={"transfer_id": t.transfer_id, "error": repr(exc)})
            return False

    async def _resend_chunk(self, t: Transfer, client: Peer, index: int) -> bool:
        def _read() -> bytes:
            assert t.path is not None
            with open(t.path, "rb") as f:
                f.seek(index * t.chunk_size)
                return f.read(t.chunk_size)

        try:
            data = await asyncio.to_thread(_read)
        except OSError:
            return False
        await client.send(FileChunk(transfer_id=t.transfer_id, index=index, data=data))
        return True

    async def _expire(self, t: Transfer) -> None:
        if t.path is not None:
            try:
                t.path.unlink(missing_ok=True)
            except OSError:
                pass
        self.transfers.pop(t.transfer_id, None)