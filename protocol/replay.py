"""Replay protection primitive shared by client and server.

Networking concept demonstrated
-------------------------------
An attacker who captured a valid encrypted frame could **replay** it to cause
duplicate side effects (double file transfer, repeated command).  TCP makes
reordering impossible within a connection, so each connection carries a
strictly increasing 64-bit **sequence number**; the receiver records the highest
sequence seen and rejects any frame whose sequence is not greater.  Combined
with timestamp checks at the message layer this forms replay defence
(see `security/threat_model.md`, STRIDE "Spoofing/Tampering").
"""

from __future__ import annotations

from protocol.errors import ReplayError

__all__ = ["ReplayError", "ReplayGuard"]


class ReplayGuard:
    """Enforces strictly increasing sequence numbers on one connection.

    Example:
        >>> g = ReplayGuard()
        >>> g.check(1); g.check(2)
        >>> g.check(2)  # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
        ReplayError
    """

    __slots__ = ("_last", "_count")

    def __init__(self, start: int = -1) -> None:
        self._last = start
        self._count = 0

    def check(self, sequence: int) -> None:
        """Raise :class:`ReplayError` unless ``sequence`` is strictly newer."""
        if sequence <= self._last:
            raise ReplayError(f"replayed/duplicate sequence {sequence} (last={self._last})")
        self._last = sequence
        self._count += 1

    @property
    def last(self) -> int:
        return self._last

    @property
    def count(self) -> int:
        return self._count
