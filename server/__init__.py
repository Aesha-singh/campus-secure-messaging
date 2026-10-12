"""CSCP server package.

Modules:
    config        -- typed YAML config
    logging_setup -- structured JSON logging
    metrics       -- live telemetry counters
    rates         -- token-bucket rate limiter (per IP / per user)
    auth          -- authenticator interface + HMAC tokens (+ dev stub)
    storage       -- message store interface (+ in-memory reference)
    manager       -- user/channel registry + presence relay
    session       -- per-connection FSM, framing, heartbeat, backpressure
    server        -- TLS 1.3 dual-stack listener + graceful shutdown
    main          -- CLI entrypoint
"""

from server.context import ServerContext
from server.server import CSCPServer, build_ssl_context

__all__ = ["CSCPServer", "build_ssl_context", "ServerContext"]