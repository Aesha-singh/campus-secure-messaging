#!/usr/bin/env python3
"""Configurable load benchmark -> the numbers for the report.

    python scripts/bench.py --clients 200 --messages 10

Reports connection setup rate, auth rate, message throughput and RTT
percentiles (p50/p90/p99), plus the server's own metrics snapshot, so the
client-side and server-side views can be compared.  Runs entirely on loopback;
increase ``--clients`` to stress the single event loop (C10k direction).
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from protocol.constants import ErrorCode, FrameFlags, MessageType  # noqa: E402
from protocol.messages import Error, MsgDirect, decode_message  # noqa: E402
from server.auth import StubAuthenticator  # noqa: E402
from server.config import Config  # noqa: E402
from server.server import CSCPServer  # noqa: E402
from tests.server.conftest import connect  # noqa: E402


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(len(ordered) * pct))
    return ordered[idx]


async def bench(clients: int, per_client: int) -> int:
    cfg = Config()
    cfg.net.enable_v4 = True
    cfg.net.host_v4 = "127.0.0.1"
    cfg.net.enable_v6 = False
    cfg.net.port = 0
    for bucket in (cfg.rate.per_ip, cfg.rate.per_user):
        bucket.capacity = 10_000_000
        bucket.refill_per_sec = 10_000_000
    cfg.rate.auth_max_per_window = 10_000_000

    users = {f"c{i}": "pw" for i in range(clients + 1)}
    sink_idx = clients
    server = CSCPServer(cfg, auth=StubAuthenticator(users), secret=b"k" * 32, store=None)
    await server.start()
    port = server.listeners[0].server.sockets[0].getsockname()[1]
    print(f"[bench] server on 127.0.0.1:{port}, {clients} clients x {per_client} msgs")

    conns = []
    try:
        t0 = time.perf_counter()
        conns = await asyncio.gather(*(connect(port) for _ in range(clients + 1)))
        connect_elapsed = time.perf_counter() - t0

        t1 = time.perf_counter()
        await asyncio.gather(*(c.handshake(f"c{i}", "pw") for i, c in enumerate(conns)))
        auth_elapsed = time.perf_counter() - t1

        latencies: list[float] = []
        sink = f"u_c{sink_idx}"

        async def _run_one(i: int) -> int:
            c = conns[i]
            ok = 0
            for k in range(per_client):
                start = time.perf_counter()
                await c.send(
                    MsgDirect(
                        msg_id=f"b-{i}-{k}",
                        sender_id=f"u_c{i}",
                        recipient_id=sink,
                        ciphertext=b"z" * 256,
                        ts=0.0,
                        reply_to=None,
                        ratchet_header=None,
                    ),
                    flags=FrameFlags.ACK_REQUESTED,
                )
                frame = await c.read_until(MessageType.ACK, timeout=10.0)
                msg = decode_message(frame)
                if isinstance(msg, Error) and msg.code == ErrorCode.RATE_LIMITED:
                    continue
                latencies.append(time.perf_counter() - start)
                ok += 1
            return ok

        t2 = time.perf_counter()
        results = await asyncio.gather(*(_run_one(i) for i in range(clients)))
        send_elapsed = time.perf_counter() - t2
        total = sum(results)
    finally:
        await asyncio.gather(*(c.close() for c in conns), return_exceptions=True)
        await server.shutdown()

    snap = server.metrics.snapshot()
    print("\n=== results ===")
    print(f"connections        : {clients + 1} in {connect_elapsed * 1000:.1f} ms "
          f"({(clients + 1) / connect_elapsed:,.0f}/s)")
    print(f"auth (HELLO+AUTH)  : {clients + 1} in {auth_elapsed * 1000:.1f} ms "
          f"({(clients + 1) / auth_elapsed:,.0f}/s)")
    print(f"messages           : {total} in {send_elapsed * 1000:.1f} ms "
          f"({total / send_elapsed:,.0f}/s)")
    if latencies:
        print(f"rtt                : p50={_percentile(latencies, .50) * 1000:.2f} ms "
              f"p90={_percentile(latencies, .90) * 1000:.2f} ms "
              f"p99={_percentile(latencies, .99) * 1000:.2f} ms "
              f"mean={statistics.mean(latencies) * 1000:.2f} ms")
    print(f"bytes in/out       : {snap['bytes_in']:,} / {snap['bytes_out']:,}")
    print(f"rate-limited       : {snap['rate_limited']}  malformed: {snap['malformed_frames']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=100)
    ap.add_argument("--messages", type=int, default=10, help="messages per client")
    args = ap.parse_args()
    return asyncio.run(bench(args.clients, args.messages))


if __name__ == "__main__":
    raise SystemExit(main())