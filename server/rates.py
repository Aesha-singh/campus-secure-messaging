"""Token-bucket rate limiting, per IP and per user.

Networking concept demonstrated
-------------------------------
**Traffic shaping / admission control (OSI L3/L7).**  A token bucket allows
*bursts* up to ``capacity`` while enforcing a long-term average of
``refill_per_sec`` -- the same model as a police-shaper in QoS.  Without it, a
flood of frames (or a wrong-password loop) would monopolise CPU, so rate limits
are the first line of **brute-force and DoS defence** (STRIDE table: DoS).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from server.config import BucketConfig, RateConfig


class TokenBucket:
    """Leaky-ish token bucket (burst tolerant, average-rate enforcing)."""

    __slots__ = ("capacity", "refill_per_sec", "_tokens", "_ts")

    def __init__(self, capacity: float, refill_per_sec: float) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._tokens = float(capacity)
        self._ts = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._ts
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_sec)
            self._ts = now

    def try_consume(self, n: float = 1.0) -> bool:
        self._refill()
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens


@dataclass(slots=True)
class _WindowCounter:
    window_start: float
    count: int


class RateLimiter:
    """Admission control for frames (per IP / per user) and auth attempts."""

    def __init__(self, cfg: RateConfig | None = None) -> None:
        self.cfg = cfg or RateConfig()
        self._ip_buckets: dict[str, TokenBucket] = {}
        self._user_buckets: dict[str, TokenBucket] = {}
        self._auth: dict[str, _WindowCounter] = {}
        self._buckets_created = 0

    def _bucket(self, table: dict[str, TokenBucket], key: str, bucket_cfg: BucketConfig) -> TokenBucket:
        bucket = table.get(key)
        if bucket is None:
            bucket = TokenBucket(bucket_cfg.capacity, bucket_cfg.refill_per_sec)
            table[key] = bucket
            self._buckets_created += 1
        return bucket

    def ip_allowed(self, ip: str, n: float = 1.0) -> bool:
        return self._bucket(self._ip_buckets, ip, self.cfg.per_ip).try_consume(n)

    def user_allowed(self, user_id: str, n: float = 1.0) -> bool:
        return self._bucket(self._user_buckets, user_id, self.cfg.per_user).try_consume(n)

    def auth_attempt_allowed(self, ip: str) -> bool:
        """Sliding-window limit on login attempts per source IP."""
        now = time.monotonic()
        rec = self._auth.get(ip)
        if rec is None or now - rec.window_start > self.cfg.auth_window_seconds:
            self._auth[ip] = _WindowCounter(now, 0)
            rec = self._auth[ip]
        if rec.count >= self.cfg.auth_max_per_window:
            return False
        rec.count += 1
        return True

    def auth_remaining(self, ip: str) -> int:
        now = time.monotonic()
        rec = self._auth.get(ip)
        if rec is None or now - rec.window_start > self.cfg.auth_window_seconds:
            return self.cfg.auth_max_per_window
        return max(0, self.cfg.auth_max_per_window - rec.count)

    def flush(self, max_idle_seconds: float = 3600.0) -> int:
        """Drop buckets that have not been touched recently (memory hygiene)."""
        now = time.monotonic()
        dropped = 0
        for table in (self._ip_buckets, self._user_buckets):
            stale = [k for k, b in table.items() if now - b._ts > max_idle_seconds]  # noqa: SLF001
            for k in stale:
                del table[k]
                dropped += 1
        return dropped

    def snapshot(self) -> dict[str, Any]:
        return {
            "ip_entries": len(self._ip_buckets),
            "user_entries": len(self._user_buckets),
            "auth_entries": len(self._auth),
            "buckets_created": self._buckets_created,
        }