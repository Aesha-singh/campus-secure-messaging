"""HMAC token tests: issuance, verification, tampering, expiry."""

from __future__ import annotations

import time

from server.auth import (
    UserRecord,
    issue_session,
    issue_token,
    verify_token,
)

_SECRET = b"unit-test-secret-0123456789abcdef"


def test_token_roundtrip() -> None:
    token, exp = issue_token(
        _SECRET, subject="u1", claims={"username": "alice", "kind": "access"}, ttl_seconds=60
    )
    claims = verify_token(_SECRET, token)
    assert claims is not None
    assert claims["sub"] == "u1"
    assert claims["username"] == "alice"
    assert exp > time.time()


def test_tampered_token_rejected() -> None:
    token, _ = issue_token(_SECRET, subject="u1", claims={}, ttl_seconds=60)
    tampered = "A" + token[1:]
    assert verify_token(_SECRET, tampered) is None


def test_wrong_secret_rejected() -> None:
    token, _ = issue_token(_SECRET, subject="u1", claims={}, ttl_seconds=60)
    assert verify_token(b"different-secret", token) is None


def test_expired_token_rejected() -> None:
    token, _ = issue_token(_SECRET, subject="u1", claims={}, ttl_seconds=-10)
    assert verify_token(_SECRET, token) is None


def test_issue_session_produces_expiring_pair() -> None:
    user = UserRecord(user_id="u1", username="alice", totp_enabled=False)
    s = issue_session(
        _SECRET, user=user, device_id="laptop", access_ttl=60, session_ttl=86400
    )
    assert verify_token(_SECRET, s.access_token) is not None
    assert verify_token(_SECRET, s.session_token) is not None
    assert s.access_expires_at < s.session_expires_at
    assert verify_token(_SECRET, s.access_token)["kind"] == "access"  # type: ignore[index]