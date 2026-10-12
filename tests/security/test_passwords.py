"""Unit tests for Argon2id password hashing and policy enforcement."""

from __future__ import annotations

import pytest

from security import passwords


@pytest.mark.parametrize(
    "candidate",
    [
        "short",
        "123456789012",
        "abcdefghij",
        "password",
        "password123",
        "changeme1",
    ],
)
def test_policy_rejects_weak(candidate: str) -> None:
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.validate_policy(candidate)


def test_policy_strength_policy_ok() -> None:
    passwords.validate_policy("Correct Horse 42")  # strong -> no raise


def test_hash_verify_roundtrip() -> None:
    stored = passwords.hash_password("S3cure!Passphrase-2026")
    assert stored.startswith("$argon2id$")
    assert passwords.verify_password("S3cure!Passphrase-2026", stored)


def test_wrong_password_rejected() -> None:
    stored = passwords.hash_password("S3cure!Passphrase-2026")
    assert not passwords.verify_password("nope-nope-nope", stored)


def test_same_password_different_salts() -> None:
    a = passwords.hash_password("S3cure!Passphrase-2026")
    b = passwords.hash_password("S3cure!Passphrase-2026")
    assert a != b  # unique per-call salt defeats rainbow tables


def test_malformed_hash_is_false_not_crash() -> None:
    assert not passwords.verify_password("x", "not-a-phc-hash")


def test_needs_rehash_flag() -> None:
    from argon2 import PasswordHasher

    old = PasswordHasher(time_cost=2, memory_cost=8 * 1024, parallelism=1).hash("S3cure!")
    assert passwords.needs_rehash(old) is True