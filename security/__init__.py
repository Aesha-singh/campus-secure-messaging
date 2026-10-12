"""Security subsystem: PKI, credentials, authentication, and E2EE.

Coverage
--------
* :mod:`security.passwords` -- Argon2id password hashing + policy checks.
* :mod:`security.totp`     -- RFC 6238 TOTP + backup codes (2FA).
* :mod:`security.auth`     -- ``Argon2idAuthenticator`` (plugs into the server's
  ``Authenticator`` Protocol), user database loading.
* :mod:`security.e2ee`     -- X25519 + HKDF + AES-256-GCM with a per-direction
  key-chain "ratchet-lite" for end-to-end encryption.
* :mod:`security.certs`    -- local CA / server / client X.509 generation and
  TLS context builders (trust, SANs, EKU).
"""

from __future__ import annotations

__all__ = ["auth", "certs", "e2ee", "passwords", "totp"]