"""TOTP (RFC 6238) and backup-code tests -- clock skew tolerance included."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from security import totp


def test_generate_secret_is_base32() -> None:
    secret = totp.generate_secret()
    assert len(secret) >= 16
    assert set(secret.upper()) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_current_code_matches_verify() -> None:
    secret = totp.generate_secret()
    code = totp.current_code(secret)
    assert totp.verify_totp(secret, code)


def test_verify_rejects_bad_code() -> None:
    secret = totp.generate_secret()
    assert not totp.verify_totp(secret, "000000")


def test_window_tolerates_clock_skew() -> None:
    """A code computed for a neighbour window (NTP drift) still verifies."""
    secret = totp.generate_secret()
    now = datetime.now(UTC)
    future = pyotp_totp(secret).at(now + timedelta(seconds=totp.STEP_SECONDS))
    past = pyotp_totp(secret).at(now - timedelta(seconds=totp.STEP_SECONDS))
    assert totp.verify_totp(secret, future, window=1)
    assert totp.verify_totp(secret, past, window=1)
    # window=0 means no skew tolerance -> neighbour codes must be rejected
    assert not totp.verify_totp(secret, future, window=0)


def pyotp_totp(secret: str) -> Any:
    from pyotp import TOTP

    return TOTP(secret, interval=totp.STEP_SECONDS)


def test_provisioning_uri_shape() -> None:
    uri = totp.generate_uri("alice", totp.generate_secret())
    assert uri.startswith("otpauth://totp/")


def test_backup_codes_unique_and_verifiable() -> None:
    codes = totp.backup_codes(count=8)
    assert len(codes) == 8
    assert len(set(codes)) == 8
    digest = totp.hash_backup_code(codes[0])
    assert totp.verify_backup_code(codes[0], digest)
    assert not totp.verify_backup_code("AAAA-0000", digest)