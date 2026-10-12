"""Message store interface and an in-memory reference implementation.

The server depends only on the :class:`MessageStore` Protocol, so it never
knows whether it talks to the reference RAM store (fast, for tests/dev) or the
durable SQLite store in :mod:`messaging.store` (used in production via
``server.main``). This is plain **dependency inversion** at the storage edge of
the network service.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from protocol.messages import Message

log = logging.getLogger("cscp.storage")

_DM_PREFIX = "dm:"
_CH_PREFIX = "ch:"


def convo_key(kind: str, a_or_id: str, b: str | None = None) -> str:
    """Build a canonical conversation id: ``dm:<pair>`` or ``ch:<id>``.

    Direct conversations are keyed by the *sorted* pair of user ids so that
    ``alice -> bob`` and ``bob -> alice`` share one thread (like a PostgreSQL
    ``GREATEST/LEAST`` composite key for (sender, recipient) uniqueness).
    """
    if kind == "dm":
        assert b is not None
        first, second = sorted((a_or_id, b))
        return f"{_DM_PREFIX}{first}|{second}"
    return f"{_CH_PREFIX}{a_or_id}"


@runtime_checkable
class MessageStore(Protocol):
    """Persistence contract used by the messaging layer."""

    async def enqueue_offline(self, recipient_id: str, msg: Message) -> str: ...
    async def take_offline(self, recipient_id: str) -> list[Message]: ...
    async def count_offline(self, recipient_id: str) -> int: ...

    async def save_message(self, convo_kind: str, convo_id: str, msg: Message) -> None: ...
    async def history(
        self, user_id: str, convo_kind: str, convo_id: str, *, since_ts: float = 0.0, limit: int = 0
    ) -> list[Message]: ...

    async def bump_unread(self, user_id: str, convo_id: str, delta: int = 1) -> int: ...
    async def unread_counts(self, user_id: str) -> dict[str, int]: ...
    async def clear_unread(self, user_id: str, convo_id: str) -> None: ...


@dataclass
class InMemoryStore:
    """Non-persistent store: keeps offline queues + history in RAM (tests/dev)."""

    _queues: dict[str, deque[Message]] = field(default_factory=lambda: defaultdict(deque))
    _history: dict[str, list[Message]] = field(default_factory=lambda: defaultdict(list))
    _unread: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def enqueue_offline(self, recipient_id: str, msg: Message) -> str:
        async with self._lock:
            self._queues[recipient_id].append(msg)
            return str(getattr(msg, "msg_id", ""))

    async def take_offline(self, recipient_id: str) -> list[Message]:
        async with self._lock:
            q = self._queues.pop(recipient_id, deque())
            return list(q)

    async def count_offline(self, recipient_id: str) -> int:
        async with self._lock:
            return len(self._queues.get(recipient_id, ()))

    async def save_message(self, convo_kind: str, convo_id: str, msg: Message) -> None:
        async with self._lock:
            self._history[f"{convo_kind}:{convo_id}"].append(msg)

    async def history(
        self, user_id: str, convo_kind: str, convo_id: str, *, since_ts: float = 0.0, limit: int = 0
    ) -> list[Message]:
        async with self._lock:
            msgs = self._history.get(f"{convo_kind}:{convo_id}", [])
            if since_ts:
                msgs = [m for m in msgs if getattr(m, "ts", 0.0) > since_ts]
            if limit:
                msgs = msgs[-limit:]
            return list(msgs)

    async def bump_unread(self, user_id: str, convo_id: str, delta: int = 1) -> int:
        async with self._lock:
            self._unread[user_id][convo_id] += delta
            return self._unread[user_id][convo_id]

    async def unread_counts(self, user_id: str) -> dict[str, int]:
        async with self._lock:
            return dict(self._unread.get(user_id, {}))

    async def clear_unread(self, user_id: str, convo_id: str) -> None:
        async with self._lock:
            bucket = self._unread.get(user_id)
            if bucket is not None:
                bucket.pop(convo_id, None)
                if not bucket:
                    self._unread.pop(user_id, None)