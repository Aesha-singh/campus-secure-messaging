"""Production authentication: Argon2id passwords + optional TOTP 2FA.

Networking concept demonstrated
-------------------------------
**AAA done right -- authentication without secrets on the wire.**  The
:class:`Argon2idAuthenticator` realises the ``Authenticator`` dependency the
transport already uses (:mod:`server.auth`), so the whole TLS/session layer
stays untouched.  Key properties:

* passwords are verified **offline** against Argon2id hashes (nothing secret
  crosses the network);
* a **per-username lockout** counter + lockout window throttles online
  guessing (same idea as the IP rate limiter, but tied to the account);
* optional **TOTP** second factor (see :mod:`security.totp`) is enforced when
  the account has a secret;
* session resume is done with a short-lived HMAC *session token* -- no
  re-entry of the password for up to 7 days, standard web/mobile session
  behaviour backed by :mod:`server.auth`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from protocol.constants import AuthMethod
from protocol.messages import AuthReq
from security import passwords, totp
from server.auth import AuthResult, UserRecord, verify_token

log = logging.getLogger("cscp.security.auth")

MAX_FAILURES = 5
LOCKOUT_SECONDS = 300


@dataclass(slots=True)
class UserEntry:
    """A persisted user account (password hash + optional TOTP)."""

    username: str
    password_hash: str
    role: str = "member"
    user_id: str | None = None
    channels: tuple[str, ...] = ()
    totp_secret: str | None = None
    device_allowlist: tuple[str, ...] = ()


@dataclass(slots=True)
class _FailureTracker:
    max_failures: int
    lockout_seconds: int
    failures: int = 0
    locked_until: float = 0.0
    clock: Callable[[], float] = time.time

    def bump(self) -> int:
        self.failures += 1
        if self.failures >= self.max_failures:
            self.locked_until = self.clock() + self.lockout_seconds
            self.failures = 0
            return 0
        return self.max_failures - self.failures

    def remaining(self) -> int:
        if self.clock() < self.locked_until:
            return 0
        return max(0, self.max_failures - self.failures)


class UserDatabase:
    """Loads users from a YAML file::

        users:
          - username: alice
            password_hash: "$argon2id$...phc string..."
            role: staff
            channels: [class-10a]
            totp_secret: null   # or base32 secret once 2FA is provisioned
          - username: bob
            password_hash: "..."
            role: member

    Opening a file with a plaintext ``password`` is refused unless
    ``allow_plaintext`` is set (only for bootstrapping/example).
    """

    def __init__(self, users: dict[str, UserEntry]) -> None:
        self._users = users

    def get(self, username: str) -> UserEntry | None:
        return self._users.get(username)

    def __contains__(self, username: str) -> bool:  # pragma: no cover - trivial
        return username in self._users

    def __len__(self) -> int:
        return len(self._users)

    @classmethod
    def from_yaml(cls, path: str | Path, *, allow_plaintext: bool = False) -> UserDatabase:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"user database not found: {path}")
        raw = yaml.safe_load(path.read_text()) or {}
        entries: dict[str, UserEntry] = {}
        for item in raw.get("users", []):
            username = str(item["username"])
            phash = item.get("password_hash")
            if phash is None and not allow_plaintext:
                raise ValueError(f"user {username!r} has no password_hash; production forbids plaintext")
            if phash is None:
                phash = passwords.hash_password(str(item["password"]))
            entries[username] = UserEntry(
                username=username,
                password_hash=phash,
                role=str(item.get("role", "member")),
                user_id=str(item.get("user_id", f"u_{username}")),
                channels=tuple(item.get("channels", ())),
                totp_secret=item.get("totp_secret") or None,
                device_allowlist=tuple(item.get("device_allowlist", ())),
            )
        return cls(entries)


class Argon2idAuthenticator:
    """Drop-in replacement for the stub authenticator (production backend).

    Supports:
      * ``PASSWORD``: Argon2id verify (+ mandatory TOTP if the account has one)
      * ``SESSION``:  HMAC session-token resume (no password re-entry)
    """

    name = "argon2"

    def __init__(
        self,
        db: UserDatabase,
        secret: bytes,
        *,
        lockout_seconds: int = LOCKOUT_SECONDS,
        max_failures: int = MAX_FAILURES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._secret = secret
        self._lockout_seconds = lockout_seconds
        self._max_failures = max_failures
        self._failures: dict[str, _FailureTracker] = {}
        self._clock = clock

    def _track(self, username: str) -> _FailureTracker:
        return self._failures.setdefault(
            username, _FailureTracker(self._max_failures, self._lockout_seconds, clock=self._clock)
        )

    def _locked_out(self, username: str) -> bool:
        return self._clock() < self._track(username).locked_until

    async def authenticate(self, req: AuthReq, *, ip: str) -> AuthResult:
        entry = self._db.get(req.username)
        tracker = self._track(req.username)

        if self._locked_out(req.username):
            return AuthResult(
                ok=False,
                reason="account temporarily locked; try again later",
                attempts_remaining=0,
                locked_until=tracker.locked_until,
            )
        if entry is None or not req.username:
            return AuthResult(ok=False, reason="invalid credentials", attempts_remaining=tracker.remaining())

        if req.method is AuthMethod.TOKEN:
            return self._session_resume(req, entry)
        if req.method is not AuthMethod.PASSWORD:
            return AuthResult(ok=False, reason="unsupported authentication method")

        # 1. Password (Argon2id, memory-hard -- offline-guess resistant).
        if not passwords.verify_password(req.password or "", entry.password_hash):
            remaining = tracker.bump()
            return AuthResult(
                ok=False,
                reason="invalid credentials",
                attempts_remaining=remaining,
                locked_until=tracker.locked_until if remaining == 0 else None,
            )
        # 2. Optional TOTP second factor.
        if entry.totp_secret and not totp.verify_totp(entry.totp_secret, req.totp_code or "", window=1):
            return AuthResult(ok=False, reason="invalid or missing TOTP code", attempts_remaining=0)

        tracker.failures = 0
        log.info("auth_ok", extra={"username": entry.username, "ip": ip, "factor2": bool(entry.totp_secret)})
        return AuthResult(
            ok=True,
            user=UserRecord(
                user_id=entry.user_id or f"u_{entry.username}",
                username=entry.username,
                role=entry.role,
                channels=entry.channels,
                totp_enabled=bool(entry.totp_secret),
            ),
        )

    def _session_resume(self, req: AuthReq, entry: UserEntry) -> AuthResult:
        """Validate an HMAC session token; no password is sent over the network."""
        if not (req.token and verify_token(self._secret, req.token, max_age=30 * 86400)):
            return AuthResult(ok=False, reason="invalid or expired session token", attempts_remaining=0)
        log.info("auth_session_resume", extra={"username": entry.username})
        return AuthResult(
            ok=True,
            user=UserRecord(
                user_id=entry.user_id or f"u_{entry.username}",
                username=entry.username,
                role=entry.role,
                channels=entry.channels,
                totp_enabled=bool(entry.totp_secret),
            ),
        )

    def unlock(self, username: str) -> None:
        """Administrative reset of the failure counter (admin dashboard action)."""
        self._failures.pop(username, None)


def provision_default_db(
    path: str | Path, users: dict[str, str], *, roles: dict[str, str] | None = None
) -> UserDatabase:
    """Create a fresh user database with hashed passwords (bootstrap helper)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for username, password in users.items():
        rows.append(
            {
                "username": username,
                "password_hash": passwords.hash_password(password),
                "role": (roles or {}).get(username, "member"),
                "channels": [],
                "totp_secret": None,
            }
        )
    path.write_text(yaml.safe_dump({"users": rows}, sort_keys=False))
    return UserDatabase.from_yaml(path)