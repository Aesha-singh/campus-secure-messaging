"""Time-based one-time passwords (RFC 6238) and backup codes -- second factor.

Networking concept demonstrated
-------------------------------
**Authentication factors over a distributed system.**  A TOTP code is derived
from ``HMAC-SHA1(secret, floor(now / 30))`` and is only valid for one 30-second
window: it defends against credential *replay* even if the shared secret is
harvested elsewhere, and it is the standard second factor for network logins.
Because both parties must agree on the current time, this module exercises the
**clock-skew tolerance** every distributed service needs -- ``verify_totp``
accepts codes from ``-window``..``+window`` steps so small NTP drift does not
lock users out.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

import pyotp

STEP_SECONDS: Final[int] = 30
DEFAULT_WINDOW: Final[int] = 1
BACKUP_CODE_LEN: Final[int] = 8
BACKUP_CODE_COUNT: Final[int] = 10


def generate_secret() -> str:
    """Generate a fresh base32 TOTP secret (as shown in the QR provisioning)."""
    return pyotp.random_base32()


def generate_uri(username: str, secret: str, issuer: str = "CSCP Campus") -> str:
    """Return the ``otpauth://`` URI for QR scanners (Google Auth / andOTP ...)."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def current_code(secret: str) -> str:
    """Return the 6-digit code valid right now."""
    return pyotp.TOTP(secret, interval=STEP_SECONDS).now()


def verify_totp(secret: str, code: str, *, window: int = DEFAULT_WINDOW) -> bool:
    """Constant-ish time check with ``±window`` tolerance for clock skew.

    Uses ``secrets.compare_digest`` on the computed codes: timing side-channels
    over the network cannot learn anything about individual digits.
    """
    totp = pyotp.TOTP(secret, interval=STEP_SECONDS)
    # pyotp's `at()` takes a wall-clock datetime; the counter is implied.
    for offset in range(-window, window + 1):
        moment = datetime.fromtimestamp(time.time(), tz=UTC) + timedelta(
            seconds=offset * STEP_SECONDS
        )
        candidate = totp.at(moment)
        if secrets.compare_digest(candidate, code or ""):
            return True
    return False


def backup_codes(count: int = BACKUP_CODE_COUNT, length: int = BACKUP_CODE_LEN) -> Sequence[str]:
    """Generate ``count`` offline recovery codes (''XXXX-XXXX'' style)."""
    codes = []
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(count):
        mid = length // 2
        raw = "".join(secrets.choice(alphabet) for _ in range(length))
        codes.append(f"{raw[:mid]}-{raw[mid:]}")
    return codes


def hash_backup_code(code: str) -> str:
    """Return a salted SHA-256 digest of a backup code for storage.

    Backup codes are one-time long-live secrets, so we store only their digest
    (server-side leak does not expose usable codes).
    """
    return hashlib.sha256(code.encode()).hexdigest()


def verify_backup_code(code: str, stored_digest: str) -> bool:
    """Compare a presented backup code against its stored digest."""
    return hashlib.sha256(code.encode()).hexdigest() == stored_digest.lower()