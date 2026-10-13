"""TLS context construction for the server listener.

Regression coverage for the TLS 1.3 cipher policy: the config lists TLS 1.3
suite names, which ``SSLContext.set_ciphers`` rejects ("No cipher can be
selected") -- they must go through the TLS 1.3 API.  A failure here means the
server cannot start at all in TLS mode.
"""

from __future__ import annotations

import ssl
from pathlib import Path

from security.certs import main as generate_certs
from server.config import TlsConfig
from server.server import build_ssl_context

_TLS13_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"


def _tls_cfg(tmp_path: Path, *, require_client_cert: bool = True) -> TlsConfig:
    generate_certs(["--outdir", str(tmp_path)])
    return TlsConfig(
        certfile=str(tmp_path / "server.pem"),
        keyfile=str(tmp_path / "server.key"),
        ca_file=str(tmp_path / "ca.pem"),
        require_client_cert=require_client_cert,
        min_version="TLSv1_3",
        ciphers=_TLS13_CIPHERS,
    )


def test_build_ssl_context_accepts_tls13_cipher_policy(tmp_path: Path) -> None:
    ctx = build_ssl_context(_tls_cfg(tmp_path))
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_build_ssl_context_without_certs_is_plain_mode(tmp_path: Path) -> None:
    cfg = TlsConfig(
        certfile=str(tmp_path / "missing.pem"),
        keyfile=str(tmp_path / "missing.key"),
        ca_file=str(tmp_path / "missing-ca.pem"),
    )
    assert build_ssl_context(cfg) is None


def test_build_ssl_context_optional_client_cert(tmp_path: Path) -> None:
    ctx = build_ssl_context(_tls_cfg(tmp_path, require_client_cert=False))
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
