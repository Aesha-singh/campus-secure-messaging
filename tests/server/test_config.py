"""Config loading tests: YAML parsing, defaults, and the no-secrets policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from server.config import Config, NetConfig, RateConfig, TlsConfig

_REPO = Path(__file__).resolve().parent.parent.parent
_CONFIG_YAML = _REPO / "config" / "config.yaml"


def test_yaml_file_parses() -> None:
    cfg = Config.from_yaml(_CONFIG_YAML)
    assert cfg.net.port == 9443
    assert cfg.heartbeat.ping_interval > 0
    assert cfg.limits.max_connections == 2000


def test_config_contains_no_inline_secrets() -> None:
    text = Path(_CONFIG_YAML).read_text().lower()
    for needle in ("password:", "secret:", "passphrase:", " Cscp-admin-pass:", "hunter2"):
        assert needle not in text, f"secret-looking key {needle!r} found in config.yaml"


def test_admin_password_reads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSCP_ADMIN_PASSWORD", "s3cr3t")
    assert Config().admin_password() == "s3cr3t"


def test_defaults_are_sane() -> None:
    cfg = Config()
    assert cfg.net.enable_v4 and cfg.net.enable_v6  # dual stack by default
    assert cfg.limits.max_frame_size == 16 * 1024 * 1024
    assert cfg.auth.token_ttl_seconds <= cfg.auth.session_resume_ttl_seconds


def test_netconfig_dual_stack() -> None:
    net = NetConfig.from_mapping({"port": 9000})
    assert net.enable_v4 and net.enable_v6
    assert net.host_v6 == "::"


def test_ratelimit_config_defaults() -> None:
    rc = RateConfig()
    assert rc.per_ip.capacity == 120
    assert rc.auth_max_per_window == 20


def test_tls_config_requires_certs() -> None:
    tc = TlsConfig.from_mapping(
        {"certfile": "a.crt", "keyfile": "a.key", "ca_file": "a_ca.crt"}
    )
    assert tc.min_version == "TLSv1_3"