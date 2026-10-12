"""Authentication interface and token issuance.

Networking concept demonstrated
-------------------------------
**AAA (Authentication, Authorisation, Accounting).**  The server treats
authentication as a *pluggable service* so the transport layer never hard-codes
how passwords are stored.  Phase 4 replaces the dev-only stub with an Argon2id
+ TOTP backend; the transport code is untouched.

Access tokens are issued as **short-lived HMAC-signed bearer tokens**, the
standard pattern for session management over a network.  The signature matrix
below says who verifies what:

    token = base64url(header) "." base64url(payload) "." HMAC_SHA256(secret, h.p)
    access token validity : `exp` (configurable, default 5 minutes)
    session token validity: `exp` (configurable, default 7 days) + `device_id`
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol

from protocol.constants import AuthMethod
from protocol.messages import AuthReq

log = logging.getLogger("cscp.auth")


# --------------------------------------------------------------------------- #
# User / auth result model
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class UserRecord:
    user_id: str
    username: str
    role: str = "member"
    channels: tuple[str, ...] = ()
    totp_enabled: bool = False


@dataclass(slots=True)
class AuthResult:
    ok: bool
    user: UserRecord | None = None
    reason: str = ""
    attempts_remaining: int | None = None
    locked_until: float | None = None


class Authenticator(Protocol):
    """Authenticates an :class:`AuthReq` and reports lockout state."""

    async def authenticate(self, req: AuthReq, *, ip: str) -> AuthResult: ...

    @property
    def name(self) -> str: ...


# --------------------------------------------------------------------------- #
# HMAC-signed tokens
# --------------------------------------------------------------------------- #
def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_token(secret: bytes, *, subject: str, claims: dict[str, Any], ttl_seconds: int) -> tuple[str, float]:
    """Mint ``alg:payload.sig``; returns (token, expires_at_epoch)."""
    now = int(time.time())
    exp = now + ttl_seconds
    payload = {"sub": subject, "iat": now, "exp": exp, **claims}
    payload_b64 = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, payload_b64.encode(), "sha256").digest()
    return f"{_b64e(sig)}.{payload_b64}", float(exp)


def verify_token(secret: bytes, token: str, *, max_age: float | None = None) -> dict[str, Any] | None:
    """Verify signature and expiry; returns decoded claims or ``None``."""
    try:
        sig_b64, payload_b64 = token.split(".", 1)
        expected = hmac.new(secret, payload_b64.encode(), "sha256").digest()
        if not hmac.compare_digest(_b64d(sig_b64), expected):
            return None
        payload = dict(json.loads(_b64d(payload_b64)))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    if max_age is not None and int(time.time()) - int(payload.get("iat", 0)) > max_age:
        return None
    return payload


@dataclass(slots=True)
class IssuedSession:
    access_token: str
    session_token: str
    access_expires_at: float
    session_expires_at: float


def issue_session(
    secret: bytes,
    *,
    user: UserRecord,
    device_id: str,
    access_ttl: int,
    session_ttl: int,
) -> IssuedSession:
    """Issue a fresh access token + a resumable session token."""
    session_token, session_expires = issue_token(
        secret,
        subject=user.user_id,
        claims={"username": user.username, "kind": "session", "device_id": device_id},
        ttl_seconds=session_ttl,
    )
    access_token, access_expires = issue_token(
        secret,
        subject=user.user_id,
        claims={"username": user.username, "kind": "access", "session": session_token},
        ttl_seconds=access_ttl,
    )
    return IssuedSession(
        access_token=access_token,
        session_token=session_token,
        access_expires_at=float(access_expires),
        session_expires_at=float(session_expires),
    )


# --------------------------------------------------------------------------- #
# Dev-only stub authenticator (never used in production)
# --------------------------------------------------------------------------- #
class StubAuthenticator:
    """DEVELOPMENT/TEST ONLY.

    Accepts a fixed dictionary of username -> password (or the env vars
    ``CSCP_DEV_USER`` / ``CSCP_DEV_PASS``).  Never used in production -- phase 4
    swaps in the Argon2id + TOTP backend behind the same interface.
    """

    name = "stub"

    def __init__(self, users: dict[str, str] | None = None) -> None:
        self.users = users or {
            os.environ.get("CSCP_DEV_USER", "dev"): os.environ.get("CSCP_DEV_PASS", "dev")
        }

    async def authenticate(self, req: AuthReq, *, ip: str) -> AuthResult:
        if req.method is not AuthMethod.PASSWORD:
            return AuthResult(ok=False, reason="stub backend only supports password")
        password = self.users.get(req.username)
        if password is not None and req.password == password:
            user = UserRecord(
                user_id=f"u_{req.username}",
                username=req.username,
                role="staff",
            )
            log.warning("STUB authenticator accepted login for %r", req.username)
            return AuthResult(ok=True, user=user)
        return AuthResult(ok=False, reason="invalid credentials", attempts_remaining=-1)


def make_authenticator(
    backend: str = "stub",
    *,
    secret: bytes | None = None,
    userdb: str | None = None,
    auth_cfg: Any | None = None,
) -> Authenticator:
    """Factory for auth backends.

    ``stub``   -- dev/test only (see :class:`StubAuthenticator`)
    ``argon2`` -- production backend from :mod:`security.auth`
                   (Argon2id + optional TOTP, per-username lockout)
    """
    if backend == "stub":
        return StubAuthenticator()
    if backend == "argon2":
        from security.auth import Argon2idAuthenticator, UserDatabase

        if not secret:
            raise ValueError("argon2 backend requires a server secret")
        if not userdb:
            raise ValueError("argon2 backend requires a user database path")
        db = UserDatabase.from_yaml(userdb)
        lockout = int(getattr(auth_cfg, "lockout_seconds", 300))
        max_attempts = int(getattr(auth_cfg, "max_attempts", 5))
        return Argon2idAuthenticator(db, secret, lockout_seconds=lockout, max_failures=max_attempts)
    raise ValueError(f"unknown auth backend {backend!r}")