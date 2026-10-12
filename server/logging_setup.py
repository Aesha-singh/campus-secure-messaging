"""Structured JSON logging (production requirement: no ``print`` anywhere).

Networking concept demonstrated
-------------------------------
Operability: a 2000-peer server can only be reasoned about if every event --
connect, disconnect, auth result, limit trip, heartbeat timeout -- is emitted
as a machine-readable record correlated by ``connection_id``/``user_id``/``ip``.
This is the same telemetry contract Prometheus/loki consume for ops dashboards.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_RESERVED = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
}


def _json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"__hex__": bytes(value).hex()}
    if isinstance(value, Exception):
        return f"{type(value).__name__}: {value}"
    if isinstance(value, (datetime,)):
        return value.isoformat()
    return str(value)


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line on stdout/stderr."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _RESERVED or key in payload:
                continue
            payload[key] = value
        return json.dumps(payload, default=_json_default, sort_keys=False)


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"[{datetime.now(UTC).isoformat()}] {record.levelname:<5} {record.name} — {record.getMessage()}"
        extras = []
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _RESERVED or key in ("ts", "level", "logger", "event"):
                continue
            extras.append(f"{key}={value}")
        if extras:
            base += "  " + " ".join(extras)
        if record.exc_info and record.exc_info[0] is not None:
            base += "\n" + self.formatException(record.exc_info)
        return base


def setup_logging(*, level: str = "INFO", json: bool = True, file: str | None = None, stderr: bool = True) -> None:
    """Install root handlers. Idempotent; safe to call from tests."""
    root = logging.getLogger("cscp")
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False

    formatter: logging.Formatter = JsonFormatter() if json else PlainFormatter()

    if stderr:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        root.addHandler(handler)
    if file:
        path = Path(file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(formatter)
        root.addHandler(fh)


def get_logger(name: str) -> logging.Logger:
    """Return the application logger (children of ``cscp`` root)."""
    return logging.getLogger(f"cscp.{name}")