"""Client configuration: server endpoint, TLS identity, credentials.

Networking concept demonstrated
-------------------------------
**Client-side transport tuning.**  A real client needs asymmetric budgets to
the server: connect timeouts, heartbeat cadence, and an *application-level
keep-alive* so NAT/firewall idle timers (which silently drop the mapping) do
not kill the chat session.  Every knob maps to a server-side behaviour
(heartbeat idle, queue sizes) so the viva table can cite both halves.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_BASE = Path(__file__).resolve().parent.parent


def _resolve(path: str | None, base: Path = _BASE) -> str | None:
    if not path:
        return None
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = base / p
    return str(p)


@dataclass(slots=True)
class ClientConfig:
    host: str = "127.0.0.1"
    port: int = 9443
    prefer_ipv6: bool = False
    # TLS identity: ca.crt to verify the server; client cert/key for mTLS.
    ca_file: str | None = None
    certfile: str | None = None
    keyfile: str | None = None
    require_tls: bool = True  # refuse to talk PLAIN to a server without certs
    # Heartbeat / recovery.
    ping_interval: float = 20.0
    idle_timeout: float = 60.0
    connect_timeout: float = 8.0
    reconnect_backoff_base: float = 1.0
    reconnect_backoff_max: float = 30.0
    # Endpoint identity for HELLO / device binding.
    client_id: str = "cscp-py-client"
    capabilities: tuple[str, ...] = ("e2ee", "files", "channels", "sync")
    device_name: str = "cscp-py"
    # Credentials.  Password/totp come from the environment or the caller
    # (never stored in YAML); the *session token* may be cached on disk.
    username: str = ""
    password: str | None = None  # literal override wins over $CSCP_PASSWORD
    totp: str | None = None      # literal override wins over $CSCP_TOTP
    password_env: str | None = "CSCP_PASSWORD"  # noqa: S105 -- env variable NAME, not a secret
    totp_env: str | None = "CSCP_TOTP"
    data_dir: str = "data/client"

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> ClientConfig:

        return cls(
            host=str(m.get("host", "127.0.0.1")),
            port=int(m.get("port", 9443)),
            prefer_ipv6=bool(m.get("prefer_ipv6", False)),
            ca_file=_resolve(m.get("ca_file")),
            certfile=_resolve(m.get("certfile")),
            keyfile=_resolve(m.get("keyfile")),
            require_tls=bool(m.get("require_tls", True)),
            ping_interval=float(m.get("ping_interval", 20.0)),
            idle_timeout=float(m.get("idle_timeout", 60.0)),
            connect_timeout=float(m.get("connect_timeout", 8.0)),
            reconnect_backoff_base=float(m.get("reconnect_backoff_base", 1.0)),
            reconnect_backoff_max=float(m.get("reconnect_backoff_max", 30.0)),
            client_id=str(m.get("client_id", "cscp-py-client")),
            capabilities=tuple(m.get("capabilities", ["e2ee", "files", "channels", "sync"])),
            device_name=str(m.get("device_name", "cscp-py")),
            username=str(m.get("username", "")),
            password=m.get("password"),
            totp=m.get("totp"),
            password_env=m.get("password_env"),
            totp_env=m.get("totp_env"),
            data_dir=_resolve(m.get("data_dir", "data/client")) or "data/client",
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> ClientConfig:
        raw: Mapping[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
        return cls.from_mapping(raw)

    def password_from_env(self) -> str | None:
        if self.password is not None:
            return self.password
        import os

        return os.environ.get(self.password_env) if self.password_env else None

    def totp_from_env(self) -> str | None:
        if self.totp is not None:
            return self.totp
        import os

        return os.environ.get(self.totp_env) if self.totp_env else None

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = copy.deepcopy(self.__dict__)
        d.pop("password", None)  # never log the credential
        d.pop("totp", None)
        d.pop("password_env", None)
        d.pop("totp_env", None)
        return d