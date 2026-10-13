#!/usr/bin/env python3
"""Turn the load benchmark into report-ready charts (docs/charts/*.png).

    python scripts/bench_charts.py            # default sweep -> docs/charts/
    python scripts/bench_charts.py --clients 1,10,50,100,200

It drives the same loopback server + wire client as ``scripts/bench.py`` across a
sweep of client counts and plots two figures:

* **throughput** -- acknowledged messages/sec vs concurrent clients, and
* **latency** -- RTT p50/p90/p99 vs concurrent clients.

Networking lesson: a single asyncio event loop scales message throughput nearly
linearly until the per-message RTT tail (p99) starts to bend -- the classic
open-queueing shape -- without any thread pool.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from protocol.constants import ErrorCode, FrameFlags, MessageType  # noqa: E402
from protocol.messages import Error, MsgDirect, decode_message  # noqa: E402
from server.auth import StubAuthenticator  # noqa: E402
from server.config import Config  # noqa: E402
from server.server import CSCPServer  # noqa: E402
from tests.server.conftest import connect  # noqa: E402


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * pct))]


async def _run_point(clients: int, per_client: int) -> dict[str, float]:
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
    sink = f"u_c{clients}"
    server = CSCPServer(cfg, auth=StubAuthenticator(users), secret=b"k" * 32, store=None)
    await server.start()
    port = server.listeners[0].server.sockets[0].getsockname()[1]

    conns = []
    try:
        conns = list(await asyncio.gather(*(connect(port) for _ in range(clients + 1))))
        await asyncio.gather(*(c.handshake(f"c{i}", "pw") for i, c in enumerate(conns)))

        latencies: list[float] = []

        async def _one(i: int) -> int:
            c = conns[i]
            ok = 0
            for k in range(per_client):
                start = time.perf_counter()
                await c.send(
                    MsgDirect(
                        msg_id=f"b-{i}-{k}", sender_id=f"u_c{i}", recipient_id=sink,
                        ciphertext=b"z" * 256, ts=0.0, reply_to=None, ratchet_header=None,
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

        t0 = time.perf_counter()
        results = await asyncio.gather(*(_one(i) for i in range(clients)))
        elapsed = time.perf_counter() - t0
        total = sum(results)
    finally:
        await asyncio.gather(*(c.close() for c in conns), return_exceptions=True)
        await server.shutdown()

    return {
        "clients": clients,
        "throughput": total / elapsed if elapsed else 0.0,
        "p50": _pct(latencies, 0.50) * 1000,
        "p90": _pct(latencies, 0.90) * 1000,
        "p99": _pct(latencies, 0.99) * 1000,
        "mean": statistics.mean(latencies) * 1000 if latencies else 0.0,
    }


def _plot(points: list[dict[str, float]], out_dir: Path) -> list[Path]:
    xs = [int(p["clients"]) for p in points]
    written: list[Path] = []

    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(xs, [p["throughput"] for p in points], "o-", color="#1f77b4", lw=2, label="acked msgs/sec")
    ax.set_xlabel("concurrent clients")
    ax.set_ylabel("messages / second")
    ax.set_title("CSCP message throughput vs. clients (loopback, single event loop)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    path = out_dir / "throughput.png"
    fig.savefig(path, dpi=120)
    plt.close(fig)
    written.append(path)

    fig, ax = plt.subplots(figsize=(7, 4.2))
    for key, color in (("p50", "#2ca02c"), ("p90", "#ff7f0e"), ("p99", "#d62728")):
        ax.plot(xs, [p[key] for p in points], "o-", color=color, lw=2, label=f"RTT {key}")
    ax.set_xlabel("concurrent clients")
    ax.set_ylabel("round-trip latency (ms)")
    ax.set_title("CSCP request/response latency percentiles (loopback)")
    ax.set_yscale("log")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    fig.tight_layout()
    path = out_dir / "latency.png"
    fig.savefig(path, dpi=120)
    plt.close(fig)
    written.append(path)

    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", default="1,10,25,50,100", help="comma-separated client counts")
    ap.add_argument("--messages", type=int, default=20, help="messages per client per point")
    ap.add_argument("--out-dir", default="docs/charts")
    args = ap.parse_args()

    counts = [int(x) for x in args.clients.split(",") if x.strip()]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    points: list[dict[str, float]] = []
    for n in counts:
        point = asyncio.run(_run_point(n, args.messages))
        print(
            f"[chart] clients={n:>4}  throughput={point['throughput']:>9,.0f}/s  "
            f"p50={point['p50']:.2f}ms  p90={point['p90']:.2f}ms  p99={point['p99']:.2f}ms"
        )
        points.append(point)

    for path in _plot(points, out_dir):
        print(f"[chart] wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
