"""Startup configuration for the CSCP server.

Configuration is loaded from YAML and validated into typed dataclasses.  No
secrets are stored in the file -- only *paths* to secrets (private keys), and
any inline secret (e.g. a key password) must come from the environment.

Networking concept demonstrated
-------------------------------
Central, declarative tuning parameters for transport behaviour (TCP buffer and
queue sizes, heartbeat timers, rate budgets, limits) -- the "network tuning"
dimension of a network deployment.  Every knob maps to a measurable protocol
behaviour so the viva table in docs can cite the config as evidence.
"""

from __future__ import annotations

import copy
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from protocol.constants import FILE_CHUNK_SIZE, MAX_FRAME_SIZE
from server.admin import AdminHttpConfig

_BASE = Path(__file__).resolve().parent.parent


def _resolve(path: str) -> str:
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = _BASE / p
    return str(p)


@dataclass(slots=True)
class NetConfig:
    """Listener addresses (IPv4 and IPv6 may both be enabled = dual stack)."""

    enable_v4: bool = True
    host_v4: str = "0.0.0.0"  # noqa: S104 -- intentional: server binds all interfaces
    enable_v6: bool = True
    host_v6: str = "::"  # noqa: S104 -- intentional: server binds all interfaces
    port: int = 9443
    mdns_name: str = "cscp-campus.local"

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> NetConfig:
        return cls(
            enable_v4=bool(m.get("enable_v4", True)),
            host_v4=str(m.get("host_v4", "0.0.0.0")),  # noqa: S104 -- server binds all interfaces
            enable_v6=bool(m.get("enable_v6", True)),
            host_v6=str(m.get("host_v6", "::")),  # noqa: S104 -- server binds all interfaces
            port=int(m.get("port", 9443)),
            mdns_name=str(m.get("mdns_name", "cscp-campus.local")),
        )


@dataclass(slots=True)
class TlsConfig:
    certfile: str
    keyfile: str
    ca_file: str
    require_client_cert: bool = True
    min_version: str = "TLSv1_3"
    ciphers: str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> TlsConfig:
        return cls(
            certfile=_resolve(str(m["certfile"])),
            keyfile=_resolve(str(m["keyfile"])),
            ca_file=_resolve(str(m["ca_file"])),
            require_client_cert=bool(m.get("require_client_cert", True)),
            min_version=str(m.get("min_version", "TLSv1_3")),
            ciphers=str(
                m.get("ciphers", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
            ),
        )


@dataclass(slots=True)
class LimitsConfig:
    max_connections: int = 2000
    max_frame_size: int = MAX_FRAME_SIZE
    write_queue_size: int = 512  # frames queued per connection before backpressure
    close_timeout: float = 3.0
    max_username_len: int = 64
    max_message_bytes: int = 512 * 1024

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> LimitsConfig:
        return cls(
            max_connections=int(m.get("max_connections", 2000)),
            max_frame_size=int(m.get("max_frame_size", MAX_FRAME_SIZE)),
            write_queue_size=int(m.get("write_queue_size", 512)),
            close_timeout=float(m.get("close_timeout", 3.0)),
            max_username_len=int(m.get("max_username_len", 64)),
            max_message_bytes=int(m.get("max_message_bytes", 512 * 1024)),
        )


@dataclass(slots=True)
class HeartbeatConfig:
    ping_interval: float = 30.0
    idle_timeout: float = 90.0
    max_missed_pings: int = 3

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> HeartbeatConfig:
        return cls(
            ping_interval=float(m.get("ping_interval", 30.0)),
            idle_timeout=float(m.get("idle_timeout", 90.0)),
            max_missed_pings=int(m.get("max_missed_pings", 3)),
        )


@dataclass(slots=True)
class AuthConfig:
    backend: str = "argon2"          # "stub" (dev only) | "argon2"
    userdb: str = "security/users.example.yaml"
    max_attempts: int = 5
    lockout_seconds: int = 300
    token_ttl_seconds: int = 300          # short-lived access token
    session_resume_ttl_seconds: int = 604800  # 7 days
    totp_enabled: bool = True

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> AuthConfig:
        return cls(
            backend=str(m.get("backend", "argon2")),
            userdb=str(m.get("userdb", "security/users.example.yaml")),
            max_attempts=int(m.get("max_attempts", 5)),
            lockout_seconds=int(m.get("lockout_seconds", 300)),
            token_ttl_seconds=int(m.get("token_ttl_seconds", 300)),
            session_resume_ttl_seconds=int(m.get("session_resume_ttl_seconds", 604800)),
            totp_enabled=bool(m.get("totp_enabled", True)),
        )


@dataclass(slots=True)
class BucketConfig:
    capacity: float = 120.0
    refill_per_sec: float = 40.0

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> BucketConfig:
        return cls(
            capacity=float(m.get("capacity", 120.0)),
            refill_per_sec=float(m.get("refill_per_sec", 40.0)),
        )


@dataclass(slots=True)
class RateConfig:
    per_ip: BucketConfig = field(default_factory=lambda: BucketConfig(120.0, 40.0))
    per_user: BucketConfig = field(default_factory=lambda: BucketConfig(300.0, 100.0))
    auth_window_seconds: int = 300
    auth_max_per_window: int = 20

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> RateConfig:
        return cls(
            per_ip=BucketConfig.from_mapping(dict(m.get("per_ip", {}))),
            per_user=BucketConfig.from_mapping(dict(m.get("per_user", {}))),
            auth_window_seconds=int(m.get("auth_window_seconds", 300)),
            auth_max_per_window=int(m.get("auth_max_per_window", 20)),
        )


@dataclass(slots=True)
class StorageConfig:
    db_path: str = "data/campus.db"
    wal: bool = True
    history_limit: int = 200  # max messages returned for one SYNC_REQ

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> StorageConfig:
        return cls(
            db_path=_resolve(str(m.get("db_path", "data/campus.db"))),
            wal=bool(m.get("wal", True)),
            history_limit=max(1, int(m.get("history_limit", 200))),
        )


@dataclass(slots=True)
class FileConfig:
    enabled: bool = True
    max_size_bytes: int = 200 * 1024 * 1024
    quota_bytes: int = 2 * 1024 * 1024 * 1024
    ttl_seconds: int = 86400 * 7
    chunk_size: int = FILE_CHUNK_SIZE
    relay_encrypted_blobs_dir: str = "data/blobs"
    allowed_mime: tuple[str, ...] = (
        "application/pdf",
        "image/png",
        "image/jpeg",
        "text/plain",
        "application/zip",
    )

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> FileConfig:
        return cls(
            enabled=bool(m.get("enabled", True)),
            max_size_bytes=int(m.get("max_size_bytes", 200 * 1024 * 1024)),
            quota_bytes=int(m.get("quota_bytes", 2 * 1024 * 1024 * 1024)),
            ttl_seconds=int(m.get("ttl_seconds", 86400 * 7)),
            chunk_size=int(m.get("chunk_size", FILE_CHUNK_SIZE)),
            relay_encrypted_blobs_dir=str(m.get("relay_encrypted_blobs_dir", "data/blobs")),
            allowed_mime=tuple(m.get("allowed_mime", [])),
        )


@dataclass(slots=True)
class LogConfig:
    level: str = "INFO"
    json: bool = True
    file: str = "logs/server.log"
    stderr: bool = True

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> LogConfig:
        return cls(
            level=str(m.get("level", "INFO")).upper(),
            json=bool(m.get("json", True)),
            file=str(m.get("file", "logs/server.log")),
            stderr=bool(m.get("stderr", True)),
        )


@dataclass(slots=True)
class Config:
    server_name: str = "campus-cscp-1"
    net: NetConfig = field(default_factory=NetConfig)
    tls: TlsConfig = field(
        default_factory=lambda: TlsConfig(
            certfile="security/certs/server.crt",
            keyfile="security/certs/server.key",
            ca_file="security/certs/ca.crt",
        )
    )
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    rate: RateConfig = field(default_factory=RateConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    files: FileConfig = field(default_factory=FileConfig)
    logging: LogConfig = field(default_factory=LogConfig)
    admin: AdminHttpConfig = field(default_factory=AdminHttpConfig)
    #: Optional static admin password read from env (NOT from YAML).
    admin_password_env: str | None = "CSCP_ADMIN_PASSWORD"  # noqa: S105 -- env variable NAME, not a secret value

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        raw: Mapping[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> Config:
        return cls(
            server_name=str(m.get("server_name", "campus-cscp-1")),
            net=NetConfig.from_mapping(dict(m.get("net", {}))),
            tls=TlsConfig.from_mapping(dict(m.get("tls", {}))),
            limits=LimitsConfig.from_mapping(dict(m.get("limits", {}))),
            heartbeat=HeartbeatConfig.from_mapping(dict(m.get("heartbeat", {}))),
            auth=AuthConfig.from_mapping(dict(m.get("auth", {}))),
            rate=RateConfig.from_mapping(dict(m.get("rate", {}))),
            storage=StorageConfig.from_mapping(dict(m.get("storage", {}))),
            files=FileConfig.from_mapping(dict(m.get("files", {}))),
            logging=LogConfig.from_mapping(dict(m.get("logging", {}))),
            admin=AdminHttpConfig.from_mapping(dict(m.get("admin", {}))),
            admin_password_env=m.get("admin_password_env"),
        )

    def admin_password(self, default: str | None = None) -> str | None:
        """Resolve the admin password from the environment (never from YAML)."""
        if self.admin_password_env:
            return os.environ.get(self.admin_password_env, default)
        return default

    def as_dict(self) -> dict[str, Any]:
        """Deep copy used for logging; strips nothing (has no secrets)."""
        return copy.deepcopy(self.__dict__)