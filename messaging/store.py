"""Durable SQLite-backed message store (production persistence layer).

Networking concept demonstrated
-------------------------------
**Persistence on the server edge of the message bus.**  Live delivery is
memory-speed (ConnectionManager routes), but the *service contract* promises
no loss -- even if every peer is offline.  SQLite gives us a crash-safe,
single-file store with full **ACID** semantics:

* WAL journaling keeps reads concurrent with the relay path and makes crash
  recovery a replay of a small log.
* Every stored message is serialised with the *same* CSCP codec
  (:func:`protocol.messages.encode_message`), so stored bytes are validated
  wire messages -- offline delivery and live delivery produce byte-identical
  frames (no schema drift between store and wire).
* E2EE ciphertext is stored as-is: the server persists blobs it can never
  read (defence in depth against disk compromise).

``convo_id`` uses the canonical form from :func:`server.storage.convo_key`
(``dm:u_a|u_b`` / ``ch:<channel>``); the *sorted* pair collapses a direct
conversation into one thread.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

import aiosqlite

from protocol.constants import MessageType
from protocol.messages import Message, decode_message_payload
from server.storage import convo_key  # noqa: F401  (re-export for convenience)

log = logging.getLogger("cscp.messaging.store")

_MSG_ID_KEY = "msg_id"
_TS_KEY = "ts"
_SENDER_KEY = "sender_id"
_CIPHERTEXT_KEY = "ciphertext"

_EMPTY = {"msg_id": "", "sender_id": "", "ts": 0.0, "ciphertext": b""}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    convo_kind TEXT NOT NULL,
    convo_id   TEXT NOT NULL,
    msg_id     TEXT NOT NULL UNIQUE,
    msg_type   INTEGER NOT NULL,
    sender_id  TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    ts         REAL NOT NULL,
    reply_to   TEXT,
    ratchet    BLOB,
    payload    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_convo_ts ON messages(convo_id, ts);

CREATE TABLE IF NOT EXISTS offline (
    recipient  TEXT NOT NULL,
    msg_id     TEXT NOT NULL,
    msg_type   INTEGER NOT NULL,
    payload    BLOB NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (recipient, msg_id)
);

CREATE TABLE IF NOT EXISTS unread (
    user_id   TEXT NOT NULL,
    convo_id  TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, convo_id)
);
"""


def _meta(msg: Message, key: str) -> Any:
    """Read an envelope field that only *rich* messages (MsgDirect/MsgGroup) carry.

    Only messages with the transport envelope are ever persisted, so for any
    real call the value exists; a default keeps the store safe against a
    future base-only message type sneaking in.
    """
    return getattr(msg, key, _EMPTY[key])


class SQLiteMessageStore:
    """A :class:`~server.storage.MessageStore` backed by :class:`aiosqlite`."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        """Open the database (creating parent dirs + schema) and enable WAL."""
        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = sqlite3.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _dbc(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("store not initialised; call init() first")
        return self._db

    # -- offline queue ----------------------------------------------------- #
    async def enqueue_offline(self, recipient_id: str, msg: Message) -> str:
        db = self._dbc()
        await db.execute(
            "INSERT OR IGNORE INTO offline (recipient, msg_id, msg_type, payload, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (recipient_id, str(_meta(msg, _MSG_ID_KEY)), int(msg.TYPE), msg.to_payload(), float(_meta(msg, _TS_KEY))),
        )
        await db.commit()
        return str(_meta(msg, _MSG_ID_KEY))

    async def take_offline(self, recipient_id: str) -> list[Message]:
        db = self._dbc()
        cursor = await db.execute(
            "SELECT msg_type, payload FROM offline WHERE recipient = ? ORDER BY created_at ASC",
            (recipient_id,),
        )
        rows = await cursor.fetchall()
        await db.execute("DELETE FROM offline WHERE recipient = ?", (recipient_id,))
        await db.commit()
        return [decode_message_payload(MessageType(row["msg_type"]), row["payload"]) for row in rows]

    async def count_offline(self, recipient_id: str) -> int:
        db = self._dbc()
        cursor = await db.execute("SELECT COUNT(*) AS n FROM offline WHERE recipient = ?", (recipient_id,))
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    # -- history ----------------------------------------------------------- #
    async def save_message(self, convo_kind: str, convo_id: str, msg: Message) -> None:
        db = self._dbc()
        ciphertext = _meta(msg, _CIPHERTEXT_KEY)
        await db.execute(
            "INSERT OR REPLACE INTO messages"
            " (convo_kind, convo_id, msg_id, msg_type, sender_id, ciphertext, ts, reply_to, ratchet, payload)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                convo_kind,
                convo_id,
                str(_meta(msg, _MSG_ID_KEY)),
                int(msg.TYPE),
                str(_meta(msg, _SENDER_KEY)),
                bytes(ciphertext) if isinstance(ciphertext, (bytes, bytearray, memoryview)) else b"",
                float(_meta(msg, _TS_KEY)),
                getattr(msg, "reply_to", None),
                getattr(msg, "ratchet_header", None),
                msg.to_payload(),
            ),
        )
        await db.commit()

    async def history(
        self, user_id: str, convo_kind: str, convo_id: str, *, since_ts: float = 0.0, limit: int = 0
    ) -> list[Message]:
        db = self._dbc()
        query = "SELECT msg_type, payload FROM messages WHERE convo_id = ? AND ts > ? ORDER BY ts ASC"
        args: list[Any] = [convo_id, since_ts]
        if limit:
            # newest N, then oldest-first for presentation
            query = (
                "SELECT msg_type, payload FROM (SELECT ts, msg_type, payload FROM messages"
                " WHERE convo_id = ? AND ts > ? ORDER BY ts DESC LIMIT ?) ORDER BY ts ASC"
            )
            args.append(limit)
        cursor = await db.execute(query, args)
        rows = await cursor.fetchall()
        return [decode_message_payload(MessageType(row["msg_type"]), row["payload"]) for row in rows]

    # -- unread summary ----------------------------------------------------- #
    async def bump_unread(self, user_id: str, convo_id: str, delta: int = 1) -> int:
        db = self._dbc()
        await db.execute(
            "INSERT INTO unread (user_id, convo_id, count) VALUES (?, ?, 0)"
            " ON CONFLICT(user_id, convo_id) DO UPDATE SET count = count + excluded.count",
            (user_id, convo_id),
        )
        await db.execute(
            "UPDATE unread SET count = count + ? WHERE user_id = ? AND convo_id = ?",
            (delta, user_id, convo_id),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT count AS n FROM unread WHERE user_id = ? AND convo_id = ?", (user_id, convo_id)
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else max(0, delta)

    async def unread_counts(self, user_id: str) -> dict[str, int]:
        db = self._dbc()
        cursor = await db.execute("SELECT convo_id, count FROM unread WHERE user_id = ? AND count > 0", (user_id,))
        rows = await cursor.fetchall()
        return {row["convo_id"]: int(row["count"]) for row in rows}

    async def clear_unread(self, user_id: str, convo_id: str) -> None:
        db = self._dbc()
        await db.execute("DELETE FROM unread WHERE user_id = ? AND convo_id = ?", (user_id, convo_id))
        await db.commit()