#!/usr/bin/env python3
"""Generate capturable CSCP traffic for the three Wireshark scenarios.

Run this while Wireshark/tcpdump is sniffing loopback, then follow
``docs/captures.md`` to record the evidence:

    # 1) PLAIN mode, no E2EE  -> marker visible in the capture
    sudo tcpdump -i lo0 -w captures/plain.pcap 'tcp port 9443'
    python scripts/traffic_demo.py --mode plain

    # 2) PLAIN transport, E2EE on -> ciphertext, marker NOT visible
    python scripts/traffic_demo.py --mode e2ee

    # 3) TLS 1.3 (needs generated certs) -> everything is one opaque stream
    python scripts/traffic_demo.py --mode tls

The script prints the exact bytes it hands to the transport so the analyst can
cross-check the capture against ground truth.  Networking lesson: E2EE hides
the *payload* even on a cleartext transport; TLS hides the *whole protocol*.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.config import ClientConfig
from client.crypto import ClientCrypto
from client.session import ClientCallbacks, ClientSession
from client.store import ClientStore
from server.auth import StubAuthenticator
from server.config import Config
from server.server import CSCPServer

MARKER = "CAMPUS-E2EE-DEMO-MARKER"


async def _run(
    mode: str,
    host: str,
    port: int,
    *,
    tap: Callable[[str, int], Awaitable[tuple[int, Callable[[], Awaitable[None]]]]] | None = None,
) -> None:
    cfg = Config()
    cfg.net.enable_v4 = True
    cfg.net.host_v4 = host
    cfg.net.enable_v6 = False
    cfg.net.port = port

    if mode == "tls":
        cfg.tls.certfile = "security/certs/server.pem"
        cfg.tls.keyfile = "security/certs/server.key"
        cfg.tls.ca_file = "security/certs/ca.pem"
        cfg.tls.require_client_cert = False

    server = CSCPServer(cfg, auth=StubAuthenticator({"alice": "sa", "bob": "sb"}), secret=b"k" * 32)
    await server.start()
    bound = server.listeners[0].server.sockets[0].getsockname()[1]
    print(f"[server] {'TLS 1.3' if server.is_tls else 'PLAIN'} on {host}:{bound}")

    # Optionally insert a userspace tap (recording proxy) between client and
    # server so the traffic can be captured into a pcap without root.
    connect_port = bound
    stop_tap: Callable[[], Awaitable[None]] | None = None
    if tap is not None:
        connect_port, stop_tap = await tap(host, bound)
        print(f"[tap] client will connect via {host}:{connect_port}")

    try:
        with tempfile.TemporaryDirectory() as tmp:
            ccfg = ClientConfig(
                host=host,
                port=connect_port,
                username="alice",
                password="sa",  # noqa: S106 -- stub demo credential
                require_tls=(mode == "tls"),
                ca_file="security/certs/ca.pem" if mode == "tls" else None,
                data_dir=tmp,
            )
            crypto = ClientCrypto.create("demo-device")
            store = ClientStore(Path(tmp) / "profile.db")
            await store.open()
            received: list[bytes] = []

            async def on_message(msg) -> None:  # type: ignore[no-untyped-def]
                received.append(msg.raw)

            session = ClientSession(
                cfg=ccfg, crypto=crypto, store=store, callbacks=ClientCallbacks(on_message=on_message)
            )
            session.set_credentials("alice", "sa")

            # Pin Bob's key only in E2EE mode so the envelope is encrypted.
            if mode == "e2ee":
                bob = ClientCrypto.create("bob-device")
                crypto.pin_peer("u_bob", bob.own_public())

            task = asyncio.create_task(session.run())
            try:
                await asyncio.wait_for(session._connected.wait(), timeout=5)
                msg_id = await session.send_text("u_bob", MARKER)
                payload = (
                    crypto.channel_for("u_bob").send("probe", MARKER.encode())
                    if mode == "e2ee"
                    else MARKER.encode()
                )
                print(f"[client] sent {len(MARKER)}B plaintext; wire envelope {len(payload)}B")
                print(f"[client] marker visible on wire: {MARKER.encode() in payload}")
                try:
                    await asyncio.wait_for(session.await_ack(msg_id), timeout=3)
                    print("[client] ack received")
                except TimeoutError:
                    print("[client] no ack (bob offline; store-and-forward holds it)")
            finally:
                await session.stop()
                await task
                await store.close()
    finally:
        if stop_tap is not None:
            await stop_tap()
        await server.shutdown()

    print("\nExpected Wireshark observation:")
    if mode == "plain":
        print("  follow TCP stream -> you can read the marker in ASCII.")
    elif mode == "e2ee":
        print("  the marker is absent; only base64/binary ciphertext is visible.")
    else:
        print("  the whole record is a TLS Application Data blob (content type 0x17).")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("plain", "e2ee", "tls"), default="plain")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    args = ap.parse_args()
    asyncio.run(_run(args.mode, args.host, args.port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())