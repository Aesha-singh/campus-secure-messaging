"""CLI entrypoint for the CSCP server.

Usage:
    CSCP_ADMIN_PASSWORD=... CSCP_SERVER_SECRET=... python -m server.main [--config ...]
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import signal
import sys
from pathlib import Path

from server.config import Config
from server.logging_setup import get_logger, setup_logging
from server.server import CSCPServer

log = get_logger("main")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cscp-server", description="Campus Secure Messaging Server")
    parser.add_argument(
        "--config",
        type=str,
        default=str(Path(__file__).resolve().parent.parent / "config" / "config.yaml"),
        help="path to config.yaml",
    )
    parser.add_argument(
        "--auth",
        type=str,
        default=None,
        choices=["stub", "argon2"],
        help="auth backend (stub=dev only; default = config auth.backend)",
    )
    parser.add_argument("--userdb", type=str, default=None, help="path to users.yaml (argon2 backend)")
    parser.add_argument(
        "--secret-env",
        type=str,
        default="CSCP_SERVER_SECRET",
        help="environment variable holding the HMAC token secret",
    )
    return parser


async def amain(args: argparse.Namespace) -> int:
    cfg = Config.from_yaml(args.config)
    setup_logging(level=cfg.logging.level, json=cfg.logging.json, file=cfg.logging.file, stderr=cfg.logging.stderr)

    secret = await asyncio.to_thread(lambda: _resolve_secret(args.secret_env))
    server = CSCPServer(
        cfg,
        auth_backend=args.auth if args.auth is not None else cfg.auth.backend,
        auth_userdb=args.userdb,
        secret=secret,
    )

    loop = asyncio.get_running_loop()
    shutdown_requested = asyncio.Event()

    def _request_shutdown() -> None:
        log.info("signal_received", extra={"signal": "SIGINT/SIGTERM"})
        shutdown_requested.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            log.warning("signal handler not supported on this platform")

    await server.start()
    log.info("server_ready", extra={"summary": server.summary()})

    await shutdown_requested.wait()
    await server.shutdown()
    log.info("exiting")
    return 0


def _resolve_secret(env_name: str) -> bytes:
    import os

    value = os.environ.get(env_name)
    if value:
        return value.encode("utf-8")
    ephemeral = secrets.token_hex(32)
    log.warning(
        "no %s env var set; using an EPHEMERAL secret (tokens invalidate on restart)", env_name
    )
    return ephemeral.encode("utf-8")


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())