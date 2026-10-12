"""Live server telemetry counters (single-threaded event loop -> no locks).

Networking concept demonstrated
-------------------------------
Performance monitoring: message rate, byte counters and RTT samples measure the
effect of the transport design.  The admin dashboard (WebSocket push) and the
Prometheus endpoint both read :meth:`ServerMetrics.snapshot`; the load generator
in `tests/load` asserts these numbers against expectations.
"""

from __future__ import annotations

import time


class ServerMetrics:
    """Simple, dependency-free counter bank.

    All mutations happen on the event loop thread, so plain attributes are safe.
    ``buckets`` keeps per-second message counts over the last ``window`` seconds
    for a smoothed messages/sec figure.
    """

    def __init__(self, window: int = 60) -> None:
        self.window = window
        self.connections_total = 0
        self.connections_active = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.messages_in = 0
        self.messages_out = 0
        self.messages_direct = 0
        self.messages_group = 0
        self.auth_success = 0
        self.auth_failure = 0
        self.malformed_frames = 0
        self.replay_rejected = 0
        self.rate_limited = 0
        self.transfers_active = 0
        self.transfers_completed = 0
        self.transfers_bytes = 0
        self.ping_rtt_last_ms = 0.0
        self.ping_rtt_ewma_ms = 0.0
        self.connections_evicted = 0

        self._start = time.monotonic()
        self._buckets: dict[int, int] = {}

    def _stamp(self) -> int:
        return int(time.monotonic()) % (1 << 63)

    def connect(self) -> None:
        self.connections_total += 1
        self.connections_active += 1

    def disconnect(self) -> None:
        self.connections_active = max(0, self.connections_active - 1)

    def record_bytes_in(self, n: int) -> None:
        self.bytes_in += n

    def record_bytes_out(self, n: int) -> None:
        self.bytes_out += n

    def record_message(self, *, direct: bool = False, group: bool = False) -> None:
        now = self._stamp()
        self._buckets[now] = self._buckets.get(now, 0) + 1
        self.messages_in += 1
        if direct:
            self.messages_direct += 1
        if group:
            self.messages_group += 1

    def record_auth(self, ok: bool) -> None:
        if ok:
            self.auth_success += 1
        else:
            self.auth_failure += 1

    def record_rtt(self, ms: float) -> None:
        self.ping_rtt_last_ms = ms
        if self.ping_rtt_ewma_ms <= 0:
            self.ping_rtt_ewma_ms = ms
        else:
            self.ping_rtt_ewma_ms = 0.875 * self.ping_rtt_ewma_ms + 0.125 * ms

    def messages_per_sec(self) -> float:
        """Smoothed over the sliding per-second window."""
        horizon = self._stamp() - self.window
        total = sum(v for k, v in self._buckets.items() if k >= horizon)
        return round(total / self.window, 2)

    def uptime(self) -> float:
        return time.monotonic() - self._start

    def snapshot(self) -> dict[str, int | float]:
        return {
            "uptime_s": round(self.uptime(), 2),
            "connections_total": self.connections_total,
            "connections_active": self.connections_active,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "messages_in": self.messages_in,
            "messages_out": self.messages_out,
            "messages_per_sec": self.messages_per_sec(),
            "messages_direct": self.messages_direct,
            "messages_group": self.messages_group,
            "auth_success": self.auth_success,
            "auth_failure": self.auth_failure,
            "malformed_frames": self.malformed_frames,
            "replay_rejected": self.replay_rejected,
            "rate_limited": self.rate_limited,
            "transfers_active": self.transfers_active,
            "transfers_completed": self.transfers_completed,
            "transfers_bytes": self.transfers_bytes,
            "ping_rtt_last_ms": self.ping_rtt_last_ms,
            "ping_rtt_ewma_ms": round(self.ping_rtt_ewma_ms, 3),
            "connections_evicted": self.connections_evicted,
        }

    def reset(self) -> None:
        self.__init__(window=self.window)  # type: ignore[misc]