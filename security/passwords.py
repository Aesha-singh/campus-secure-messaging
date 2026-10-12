"""Argon2id password hashing and strength policy.

Networking concept demonstrated
-------------------------------
**Defence in depth for the credential store.**  A network service must never
keep plaintext passwords (server compromise would reveal every account).  We
store only the PHC string produced by :func:`hash_password`, so:

* a database leak yields *hashes*, not passwords (mitigates credential-theft);
* Argon2id is a **memory-hard** KDF -- it costs gigabytes of RAM per guess,
  which is precisely what makes *offline* brute-force over a network gap slow;
* Argon2id mixes in BLAKE2b via overpricing memory+CPU, the 2019 PHC winner
  and the default for ``libsodium``/``pynacl``.
"""

from __future__ import annotations

import re
import secrets
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# --------------------------------------------------------------------------- #
# Policy constants
# --------------------------------------------------------------------------- #
MIN_PASSWORD_LENGTH: Final[int] = 10

# A tiny denylist of the most common weak passwords (do not try this at home).
_COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password123",
        "12345678",
        "qwerty123",
        "letmein",
        "admin123",
        "welcome1",
        "campus123",
        "changeme",
        "password1",
    }
)

_HAS_DIGIT_RE = re.compile(r"[0-9]")
_HAS_ALPHA_RE = re.compile(r"[A-Za-z]")

# Parameter regime: tuned to ~ 30ms-100ms on a modern CPU with 64 MiB memory.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)


class PasswordPolicyError(ValueError):
    """Raised when a candidate password fails the strength policy."""


def validate_policy(password: str) -> None:
    """Enforce the minimum password policy; raise :class:`PasswordPolicyError`."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if not (_HAS_DIGIT_RE.search(password) and _HAS_ALPHA_RE.search(password)):
        raise PasswordPolicyError("password must contain letters and digits")
    if password.lower() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("password is too common; choose a unique one")


def hash_password(password: str) -> str:
    """Return the PHC-format Argon2id hash of ``password``.

    A fresh random salt is generated internally on every call, so identical
    inputs produce different hashes (no rainbow-table precomputation target).
    """
    validate_policy(password)
    return _hasher.hash(password)


def verify_password(password: str, stored: str) -> bool:
    """Verify ``password`` against a stored PHC hash; never raises on mismatch."""
    try:
        return _hasher.verify(stored, password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


def needs_rehash(stored: str) -> bool:
    """True if ``stored`` predates the current parameters (upgrade path)."""
    try:
        return _hasher.check_needs_rehash(stored)
    except InvalidHashError:
        return True


def new_salt() -> bytes:
    """Return a fresh 32-byte salt (used for TOTP backup-code hashing, etc.)."""
    return secrets.token_bytes(32)