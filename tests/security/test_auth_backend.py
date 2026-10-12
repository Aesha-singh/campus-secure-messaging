# ruff: noqa: S105, S106  -- deliberate test credentials
"""Argon2idAuthenticator integration tests: passwords, TOTP, lockout, session resumption."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from protocol.constants import AuthMethod
from protocol.messages import AuthReq
from security import totp as security_totp
from security.auth import Argon2idAuthenticator, UserDatabase, provision_default_db

SECRET = b"unit-test-secret-here"


def _req(username: str, *, method: AuthMethod = AuthMethod.PASSWORD, password: str | None = None, **kw) -> AuthReq:
    return AuthReq(
        username=username,
        method=method,
        device_id=kw.pop("device_id", "dev-1"),
        client_nonce=kw.pop("client_nonce", b"\x00" * 16),
        password=password,
        token=kw.pop("token", None),
        totp_code=kw.pop("totp_code", None),
    )


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "users.yaml"
    provision_default_db(
        path,
        {"alice": "Al1ce!Passphrase", "bob": "Bob!Passphrase2"},
        roles={"alice": "staff"},
    )
    return path


@pytest.fixture()
def auth(db_path: Path) -> Argon2idAuthenticator:
    db = UserDatabase.from_yaml(db_path)
    return Argon2idAuthenticator(db, SECRET)


@pytest.mark.asyncio
async def test_password_success(auth: Argon2idAuthenticator) -> None:
    result = await auth.authenticate(_req("alice", password="Al1ce!Passphrase"), ip="10.0.0.5")
    assert result.ok
    assert result.user is not None
    assert result.user.user_id == "u_alice"
    assert result.user.role == "staff"


@pytest.mark.asyncio
async def test_wrong_password_decrements_attempts(auth: Argon2idAuthenticator) -> None:
    result = await auth.authenticate(_req("alice", password="wrong-pass"), ip="10.0.0.5")
    assert not result.ok
    assert result.attempts_remaining == 4


@pytest.mark.asyncio
async def test_lockout_after_max_failures(auth: Argon2idAuthenticator) -> None:
    await auth.authenticate(_req("alice", password="x" * 9), ip="10.0.0.6")
    await auth.authenticate(_req("alice", password="x" * 9), ip="10.0.0.6")
    await auth.authenticate(_req("alice", password="x" * 9), ip="10.0.0.6")
    await auth.authenticate(_req("alice", password="x" * 9), ip="10.0.0.6")
    locked = await auth.authenticate(_req("alice", password="x" * 9), ip="10.0.0.6")
    assert not locked.ok
    assert locked.attempts_remaining == 0
    assert locked.locked_until is not None and locked.locked_until > time.time()
    # even with the correct password now, account is locked
    again = await auth.authenticate(_req("alice", password="Al1ce!Passphrase"), ip="10.0.0.6")
    assert not again.ok
    assert again.reason == "account temporarily locked; try again later"


@pytest.mark.asyncio
async def test_totp_second_factor_required(db_path: Path) -> None:
    db = UserDatabase.from_yaml(db_path)
    entry = db.get("alice")
    assert entry is not None
    secret = security_totp.generate_secret()
    entry.totp_secret = secret  # enable 2FA at runtime (provisioning)
    auth = Argon2idAuthenticator(db, SECRET)

    missing = await auth.authenticate(_req("alice", password="Al1ce!Passphrase"), ip="10.0.0.8")
    assert not missing.ok
    assert "TOTP" in missing.reason

    valid = await auth.authenticate(
        _req("alice", password="Al1ce!Passphrase", totp_code=security_totp.current_code(secret)), ip="10.0.0.8"
    )
    assert valid.ok


@pytest.mark.asyncio
async def test_session_resumption_no_password(auth: Argon2idAuthenticator) -> None:
    from server.auth import issue_token

    good_token, _ = issue_token(
        SECRET, subject="u_alice", claims={"username": "alice", "kind": "session"}, ttl_seconds=3600
    )
    bad_token = "forged.token"
    with_bad = await auth.authenticate(_req("alice", method=AuthMethod.TOKEN, token=bad_token), ip="10.0.0.9")
    assert not with_bad.ok
    with_good = await auth.authenticate(_req("alice", method=AuthMethod.TOKEN, token=good_token), ip="10.0.0.9")
    assert with_good.ok


@pytest.mark.asyncio
async def test_unknown_user_db_plaintext_refused(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("users:\n  - username: eve\n    password: 'a-plaintext-password'\n")
    with pytest.raises(ValueError, match="password_hash"):
        UserDatabase.from_yaml(path)


def test_from_yaml_allow_plaintext(tmp_path: Path) -> None:
    path = tmp_path / "bk.yaml"
    path.write_text("users:\n  - username: eve\n    password: 'a1-plaintext-password'\n")
    db = UserDatabase.from_yaml(path, allow_plaintext=True)
    assert db.get("eve") is not None


def test_provision_writes_hash_not_plaintext(db_path: Path) -> None:
    raw = db_path.read_text()
    assert "Al1ce!Passphrase" not in raw
    assert "$argon2id$" in raw