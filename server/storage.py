"""Message store interface and an in-memory reference implementation.

Phase 2 ships :class:`InMemoryStore` (correct, fast, memory-resident) so the
server and its tests can run end-to-end.  The production SQLite-backed store
lives in the messaging layer (`storage/`) and implements exactly this interface,
so the server never knows which one it talks to (dependency inversion).
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Protocol

from protocol.messages import Message

log = logging.getLogger("cscp.storage")


class MessageStore(Protocol):
    """Persistence contract used by the messaging layer."""

    async def enqueue_offline(self, recipient_id: str, msg: Message) -> str: ...
    async def take_offline(self, recipient_id: str) -> list[Message]: ...
    async def count_offline(self, recipient_id: str) -> int: ...


@dataclass
class InMemoryStore:
    """Non-persistent store: keeps offline queues in RAM (tests/dev)."""

    _queues: dict[str, deque[Message]] = field(default_factory=lambda: defaultdict(deque))
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _seq: int = field(default=0, init=False)

    async def enqueue_offline(self, recipient_id: str, msg: Message) -> str:
        async with self._lock:
            tag = f"{msg.to_dict().get('msg_id', '')!s}"
            self._queues[recipient_id].append(msg)
            self._seq += 1
            return tag

    async def take_offline(self, recipient_id: str) -> list[Message]:
        async with self._lock:
            q = self._queues.pop(recipient_id, deque())
            return list(q)

    async def count_offline(self, recipient_id: str) -> int:
        async with self._lock:
            return len(self._queues.get(recipient_id, ()))