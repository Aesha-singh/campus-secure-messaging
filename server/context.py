"""Shared services bundle handed to every Session."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from server.auth import Authenticator
from server.config import Config
from server.manager import ConnectionManager
from server.metrics import ServerMetrics
from server.rates import RateLimiter
from server.storage import MessageStore
from server.transfer import FileTransferManager


@dataclass(slots=True)
class ServerContext:
    """Everything a session needs, injected (deduced from the server module)."""

    cfg: Config
    secret: bytes  # HMAC secret for tokens (phase 4 adds distributed secrets)
    manager: ConnectionManager
    auth: Authenticator
    store: MessageStore
    metrics: ServerMetrics
    rate: RateLimiter
    transfers: FileTransferManager
    log: logging.Logger