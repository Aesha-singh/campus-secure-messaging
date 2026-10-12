"""Token-bucket rate limiter tests (burst tolerance, refill, per-key isolation)."""

from __future__ import annotations

import time

from server.config import BucketConfig, RateConfig
from server.rates import RateLimiter, TokenBucket


def test_bucket_allows_exactly_capacity_burst() -> None:
    b = TokenBucket(5, 1.0)
    assert sum(b.try_consume() for _ in range(5)) == 5
    assert not b.try_consume()


def test_bucket_refills_over_time() -> None:
    b = TokenBucket(5, 2.0)
    for _ in range(5):
        b.try_consume()
    time.sleep(0.11)  # ~0.2 tokens
    assert b.try_consume(0.2)
    assert not b.try_consume(0.3)


def test_bucket_never_exceeds_capacity() -> None:
    b = TokenBucket(4, 1000.0)
    time.sleep(0.05)
    assert b.available <= 4.0 + 1e-6


def test_limiter_per_ip_and_per_user_isolated() -> None:
    rc = RateConfig(
        per_ip=BucketConfig(capacity=3, refill_per_sec=0.0),
        per_user=BucketConfig(capacity=3, refill_per_sec=0.0),
    )
    limiter = RateLimiter(rc)
    assert limiter.ip_allowed("1.1.1.1")
    assert limiter.ip_allowed("1.1.1.2")  # different IP not affected
    for _ in range(2):
        limiter.ip_allowed("1.1.1.1")
    assert not limiter.ip_allowed("1.1.1.1")
    for _ in range(3):
        assert limiter.user_allowed("u1")
    assert not limiter.user_allowed("u1")
    assert limiter.user_allowed("u2")  # per-user isolation


def test_auth_window_limits_attempts_per_ip() -> None:
    rc = RateConfig(auth_max_per_window=3, auth_window_seconds=60)
    limiter = RateLimiter(rc)
    for _ in range(3):
        assert limiter.auth_attempt_allowed("10.0.0.7")
    assert not limiter.auth_attempt_allowed("10.0.0.7")
    assert limiter.auth_attempt_allowed("10.0.0.8")  # different source is fine
    assert limiter.auth_remaining("10.0.0.7") == 0


def test_flush_removes_stale_entries() -> None:
    limiter = RateLimiter()
    limiter.ip_allowed("9.9.9.9")
    assert "9.9.9.9" in limiter._ip_buckets  # noqa: SLF001
    limiter.flush(max_idle_seconds=-1.0)
    assert "9.9.9.9" not in limiter._ip_buckets  # noqa: SLF001