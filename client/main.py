"""Headless console client for the CSCP system (CLI harness for the GUI later).

Networking concept demonstrated
-------------------------------
**Application-layer client demo.**  Reads config + credentials and drives the
full client stack (mTLS transport -> session FSM -> E2EE channel -> local
store) from a terminal, which is what a small script or a pyodide embed would
use.  The PyQt6 GUI wraps the exact same :class:`ClientSession` objects.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from client.config import ClientConfig
from client.crypto import ClientCrypto, load_or_create_identity
from client.session import ClientCallbacks, ClientSession
from client.store import ClientStore
from client.ui.app import run_gui
from server.storage import convo_key


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cscp-client", description="CSCP secure messaging client (console + GUI)")
    p.add_argument("--config", default="config/client.yaml", help="client YAML config")
    p.add_argument("--gui", action="store_true", help="launch the PyQt6 desktop client")
    p.add_argument("--username", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--totp", default=None)
    p.add_argument("--peer", default="bob", help="default conversation partner")
    p.add_argument("--send", default=None, help="one-shot: send this text and exit")
    p.add_argument("--peer-key", default=None, help="pin a peer X25519 public key hex (TOFU)")
    p.add_argument("--sync", action="store_true", help="after connect, replay history")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--json", action="store_true", help="log structured JSON (default true via config)")
    return p


async def run(args: argparse.Namespace) -> int:  # noqa: C901
    cfg = ClientConfig.from_yaml(args.config)
    if args.username:
        cfg.username = args.username
    if args.password:
        cfg.password = args.password
    if args.totp:
        cfg.totp = args.totp

    data_root = Path(cfg.data_dir) / args.username
    identity = load_or_create_identity(data_root / "identity.key")
    crypto = ClientCrypto(identity)

    store = ClientStore(data_root / "profile.db")
    await store.open()
    pinned = await store.load_peers()
    for pid, key in pinned.items():
        crypto.ring.load(pid, key)

    if args.peer_key:
        key = bytes.fromhex(args.peer_key)
        crypto.pin_peer(args.peer, key)
        await store.save_peer(args.peer, key.hex())

    my_pub = crypto.own_public()
    print(f"device_id={identity.device_id} public_key={my_pub.hex()}")

    async def on_ready(session: ClientSession) -> None:
        print(f"ready: {session.username} user_id={session.user_id}")

    async def on_message(msg) -> None:  # type: ignore[no-untyped-def]
        body = msg.text if msg.text is not None else f"[ciphertext {len(msg.raw)}B]"
        print(f"<< {msg.peer_id}: {body}")

    async def on_presence(presence) -> None:  # type: ignore[no-untyped-def]
        print(f"presence: {presence.user_id} -> {presence.state.name}")

    async def on_disconnected() -> None:
        print("! connection lost (will reconnect with backoff)")

    cbs = ClientCallbacks(
        on_ready=on_ready,
        on_message=on_message,
        on_presence=on_presence,
        on_disconnected=on_disconnected,
    )
    session = ClientSession(cfg=cfg, crypto=crypto, store=store, callbacks=cbs)
    session.set_credentials(args.username, args.password, args.totp)

    runner = asyncio.create_task(session.run())
    try:
        await asyncio.wait_for(_connected_flag(session), timeout=15)
    except TimeoutError:
        print("auth timeout; check credentials/TOTP")
        await session.stop()
        return 2

    if args.sync:
        peer = args.peer if args.peer else args.username
        await session.mark_read("dm", _convo(session.user_id, peer))
        await session.sync_history("dm", _convo(session.user_id, peer))
        await asyncio.sleep(0.5)
    if args.send:
        peer = _peer_for(session, args)
        msg_id = await session.send_text(peer_id=peer, text=args.send)
        try:
            ack = await session.await_ack(msg_id, ttl_seconds=5.0)
            print(f"ack: {session.delivery_status_text(ack)}")
        except TimeoutError:
            print("no ack yet (recipient or network pending)")
        await session.stop()
        return 0

    print("interactive demo: waiting; press Ctrl-C to exit")
    try:
        await runner
    except KeyboardInterrupt:
        await session.stop()
    return 0


def _peer_for(session: ClientSession, args: argparse.Namespace) -> str:
    if args.send and not args.peer:
        return session.user_id  # unreachable default safe fallback
    return args.peer or session.user_id


def _convo(a: str, b: str) -> str:
    return convo_key("dm", a, b)


async def _connected_flag(session: ClientSession) -> None:
    while not session.is_ready:  # noqa: ASYNC110 -- CLI bootstrap poller
        await asyncio.sleep(0.05)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.gui:
        base = dict(ClientConfig.from_yaml(args.config).as_dict()) if args.config else {}
        if args.username:
            base["username"] = args.username
        if args.password:
            base["password"] = args.password
        if args.totp:
            base["totp"] = args.totp
        return run_gui(base)
    if not args.username:
        build_parser().error("--username is required unless --gui is given")
    assert args.username is not None
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())