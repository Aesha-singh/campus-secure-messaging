"""Local client persistence: identity, peer pins, outbox, transcript.

Networking concept demonstrated
-------------------------------
**Offline tolerance at the edge.**  Mobile-first messaging must send-then-
sync: actions performed while disconnected are *queued* locally (an outbox,
like SMTP spooling) and flushed in order on reconnect, while reads come from
a local cache so the UI never blocks on the network.  The server mirrors this
with its offline queue for *received* messages -- both halves together give
"message now" semantics that hide TCP loss/absence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite

log = logging.getLogger("cscp.client.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identity (
    device_id TEXT PRIMARY KEY,
    private_key_hex TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
    peer_id TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    added_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id TEXT NOT NULL UNIQUE,
    convo TEXT NOT NULL,
    recipient TEXT NOT NULL,
    envelope TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
    convo TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    direction TEXT NOT NULL,  -- 'sent' | 'recv'
    ts REAL NOT NULL,
    plaintext TEXT,
    PRIMARY KEY (convo, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_history_convo ON history(convo, ts);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(slots=True)
class OutboxEntry:
    seq: int
    msg_id: str
    convo: str
    recipient: str
    envelope: bytes
    created_at: float


@dataclass(slots=True)
class HistoryEntry:
    convo: str
    msg_id: str
    direction: str
    ts: float
    plaintext: str


class ClientStore:
    """Thin aiosqlite wrapper.  One file per user/device profile."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._db: aiosqlite.Connection | None = None

    @property
    def path(self) -> Path:
        return self._path

    async def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> aiosqlite.Cursor:
        assert self._db is not None
        cur = await self._db.execute(sql, params)
        await self._db.commit()
        return cur

    # -- identity ----------------------------------------------------------

    async def save_identity(self, device_id: str, private_key_hex: str) -> None:
        await self._execute(
            "INSERT INTO identity(device_id, private_key_hex) VALUES(?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET private_key_hex=excluded.private_key_hex",
            (device_id, private_key_hex),
        )

    async def load_identity(self) -> tuple[str, str] | None:
        assert self._db is not None
        cur = await self._db.execute("SELECT device_id, private_key_hex FROM identity LIMIT 1")
        row = await cur.fetchone()
        return (row["device_id"], row["private_key_hex"]) if row else None

    # -- peer pins (TOFU) --------------------------------------------------

    async def save_peer(self, peer_id: str, public_key_hex: str) -> bool:
        """Pin ``peer_id`` -> key.  ``False`` if the key conflicts (mid-thread swap)."""
        assert self._db is not None
        cur = await self._db.execute(
            "SELECT public_key_hex FROM peers WHERE peer_id = ?",
            (peer_id,),
        )
        row = await cur.fetchone()
        if row is not None and row["public_key_hex"] != public_key_hex:
            return False
        import time

        if row is None:
            await self._execute(
                "INSERT INTO peers(peer_id, public_key_hex, added_at) VALUES(?, ?, ?)",
                (peer_id, public_key_hex, time.time()),
            )
        else:
            await self._execute(
                "UPDATE peers SET added_at = ? WHERE peer_id = ?",
                (time.time(), peer_id),
            )
        return True

    async def load_peers(self) -> dict[str, bytes]:
        assert self._db is not None
        res: dict[str, bytes] = {}
        cur = await self._db.execute("SELECT peer_id, public_key_hex FROM peers")
        for row in await cur.fetchall():
            res[row["peer_id"]] = bytes.fromhex(row["public_key_hex"])
        return res

    # -- outbox (offline sends) --------------------------------------------

    async def queue_send(self, *, msg_id: str, convo: str, recipient: str, envelope: bytes) -> None:
        import time

        await self._execute(
            "INSERT INTO outbox(msg_id, convo, recipient, envelope, created_at) VALUES(?, ?, ?, ?, ?)",
            (msg_id, convo, recipient, envelope.hex(), time.time()),
        )

    async def take_outbox(self) -> list[OutboxEntry]:
        assert self._db is not None
        cur = await self._db.execute(
            "SELECT * FROM outbox ORDER BY seq ASC",
        )
        rows = await cur.fetchall()
        entries = [
            OutboxEntry(
                seq=int(r["seq"]),
                msg_id=str(r["msg_id"]),
                convo=str(r["convo"]),
                recipient=str(r["recipient"]),
                envelope=bytes.fromhex(r["envelope"]),
                created_at=float(r["created_at"]),
            )
            for r in rows
        ]
        for e in entries:
            await self._execute("DELETE FROM outbox WHERE seq = ?", (e.seq,))
        return entries

    async def append_history(self, entry: HistoryEntry) -> None:
        await self._execute(
            "INSERT INTO history(convo, msg_id, direction, ts, plaintext) "
            "VALUES(?, ?, ?, ?, ?) ON CONFLICT(convo, msg_id) DO NOTHING",
            (entry.convo, entry.msg_id, entry.direction, entry.ts, entry.plaintext),
        )

    async def history(self, convo: str, limit: int = 200) -> list[HistoryEntry]:
        assert self._db is not None
        cur = await self._db.execute(
            "SELECT convo, msg_id, direction, ts, plaintext FROM history "
            "WHERE convo = ? ORDER BY ts ASC LIMIT ?",
            (convo, limit),
        )
        return [
            HistoryEntry(
                convo=str(r["convo"]),
                msg_id=str(r["msg_id"]),
                direction=str(r["direction"]),
                ts=float(r["ts"]),
                plaintext=str(r["plaintext"] or ""),
            )
            for r in await cur.fetchall()
        ]

    # -- session resumption ------------------------------------------------

    async def save_session_token(self, username: str, token: str) -> None:
        await self._execute(
            "INSERT INTO kv(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"session_token:{username}", token),
        )

    async def load_session_token(self, username: str) -> str | None:
        assert self._db is not None
        cur = await self._db.execute("SELECT value FROM kv WHERE key = ?", (f"session_token:{username}",))
        row = await cur.fetchone()
        return str(row["value"]) if row else None