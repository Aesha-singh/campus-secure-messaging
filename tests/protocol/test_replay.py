"""Replay-protection tests for the sequence-number guard."""

from __future__ import annotations

import pytest

from protocol.replay import ReplayError, ReplayGuard


def test_accepts_strictly_increasing_sequences() -> None:
    guard = ReplayGuard()
    for seq in range(0, 100):
        guard.check(seq)
    assert guard.last == 99
    assert guard.count == 100


def test_rejects_duplicate_sequence() -> None:
    guard = ReplayGuard()
    guard.check(5)
    with pytest.raises(ReplayError):
        guard.check(5)


def test_rejects_older_sequence() -> None:
    guard = ReplayGuard()
    guard.check(10)
    with pytest.raises(ReplayError):
        guard.check(9)
    # ...and still accepts the next legitimate one.
    guard.check(11)


def test_replay_detection_accross_connections_is_independent() -> None:
    a, b = ReplayGuard(), ReplayGuard()
    a.check(7)
    b.check(1)  # fine: different connection, independent sequence space
    with pytest.raises(ReplayError):
        b.check(1)