"""Load test: many concurrent connections, auth fan-in, message throughput.

Networking concept demonstrated
-------------------------------
**C10k-style multiplexing on a single event loop.**  Dozens of sockets are
opened, handshaked and driven *concurrently* on one thread; there is no thread
per connection.  The test measures the three numbers a network engineer cares
about under load -- connection setup rate, message round-trip latency
(p50/p95), and sustained throughput -- and cross-checks them against the
server's own metrics counters so the client side and the server side agree.

The heavier, configurable version lives in ``tests/load/bench.py``; this test
is bounded so it stays in the normal suite.
"""

from __future__ import annotations

import asyncio
import statistics
import time

import pytest

from protocol.constants import FrameFlags, MessageType
from protocol.messages import MsgDirect, decode_message
from server.config import Config
from tests.server.conftest import connect

CLIENTS = 30
PER_CLIENT = 4
AUTH_BUDGET_S = 10.0
RTT_BUDGET_S = 5.0


@pytest.mark.asyncio
async def test_concurrent_clients_auth_and_message_throughput(running_server) -> None:  # type: ignore[no-untyped-def]
    n = CLIENTS
    users = {f"user{i}": "pw" for i in range(n + 1)}  # last one is the sink
    sink_user_id = f"u_user{n}"
    # The rate limiter is the *subject* of a different test; here we raise the
    # budgets so all loopback traffic (one IP) is admitted during the load run.
    cfg = Config()
    cfg.rate.per_ip.capacity = 1_000_000
    cfg.rate.per_ip.refill_per_sec = 1_000_000
    cfg.rate.per_user.capacity = 1_000_000
    cfg.rate.per_user.refill_per_sec = 1_000_000
    cfg.rate.auth_max_per_window = 1_000_000
    server, port = await running_server(cfg, users=users)

    clients = [await connect(port) for _ in range(n + 1)]
    try:
        # -- connection setup + auth fan-in --------------------------------
        t0 = time.perf_counter()
        await asyncio.gather(*(c.handshake(f"user{i}", "pw") for i, c in enumerate(clients)))
        auth_elapsed = time.perf_counter() - t0
        assert auth_elapsed < AUTH_BUDGET_S, f"auth of {n + 1} clients took {auth_elapsed:.2f}s"
        auth_rate = (n + 1) / auth_elapsed

        # -- message throughput + RTT --------------------------------------
        latencies: list[float] = []

        async def _sender(i: int) -> None:
            c = clients[i]
            for k in range(PER_CLIENT):
                start = time.perf_counter()
                await c.send(
                    MsgDirect(
                        msg_id=f"load-{i}-{k}",
                        sender_id=f"u_user{i}",
                        recipient_id=sink_user_id,
                        ciphertext=b"x" * 128,
                        ts=0.0,
                        reply_to=None,
                        ratchet_header=None,
                    ),
                    flags=FrameFlags.ACK_REQUESTED,
                )
                frame = await c.read_until(MessageType.ACK, timeout=RTT_BUDGET_S)
                ack = decode_message(frame)
                assert ack.msg_id == f"load-{i}-{k}"
                latencies.append(time.perf_counter() - start)

        t1 = time.perf_counter()
        await asyncio.gather(*(_sender(i) for i in range(n)))
        send_elapsed = time.perf_counter() - t1
        total_msgs = n * PER_CLIENT
        throughput = total_msgs / send_elapsed

        # -- cross-check client observations vs server metrics -------------
        snap = server.metrics.snapshot()
        assert snap["connections_total"] >= n + 1
        assert snap["auth_success"] >= n + 1
        assert snap["messages_direct"] >= total_msgs

        p50 = statistics.median(latencies) * 1000
        p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1] * 1000
        print(
            f"\n[load] clients={n + 1} auth={auth_elapsed:.3f}s ({auth_rate:,.0f}/s) "
            f"msgs={total_msgs} throughput={throughput:,.0f}/s "
            f"rtt p50={p50:.1f}ms p95={p95:.1f}ms active={snap['connections_active']}"
        )
        assert throughput > 0
    finally:
        await asyncio.gather(*(c.close() for c in clients), return_exceptions=True)