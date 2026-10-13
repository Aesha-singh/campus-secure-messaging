# Load benchmarks and charts

Two scripts drive the same loopback server + wire client:

- `scripts/bench.py` — a single configurable run, prints a table.
- `scripts/bench_charts.py` — a sweep across client counts, writes PNGs for the
  report (`make charts`).

Both run entirely on loopback against one `asyncio` event loop with rate limits
lifted, so the numbers measure the *protocol and the loop*, not the NIC.

## Reproducing

```bash
# one run
make bench CLIENTS=200 MSGS=10

# full sweep -> docs/charts/{throughput,latency}.png
make charts
# or: python scripts/bench_charts.py --clients 1,10,25,50,100 --messages 20
```

## Sweep results (macOS 14, Apple silicon, loopback, Python 3.12)

| clients | throughput (acked msgs/s) | RTT p50 | RTT p90 | RTT p99 |
|--------:|--------------------------:|--------:|--------:|--------:|
| 1       | 7,950                     | 0.12 ms | 0.14 ms | 0.15 ms |
| 10      | 18,074                    | 0.53 ms | 0.58 ms | 0.65 ms |
| 25      | 19,166                    | 1.27 ms | 1.39 ms | 1.54 ms |
| 50      | 22,460                    | 2.11 ms | 2.48 ms | 2.66 ms |
| 100     | 21,909                    | 4.47 ms | 4.65 ms | 4.72 ms |

Charts: [`charts/throughput.png`](charts/throughput.png),
[`charts/latency.png`](charts/latency.png).

## Reading the shape (for the viva)

- **Throughput scales, then saturates.**  Going from 1 → 10 clients lifts
  throughput ~2.3x (one round-trip at a time cannot fill the pipe), but past
  ~25-50 clients it plateaus near ~20k msgs/s: a single event loop has a fixed
  per-message cost (frame decode, CRC32, dispatch, one `write` syscall).
- **Latency is linear in concurrency.**  p50 climbs 0.12 → 4.47 ms as clients
  go 1 → 100.  This is **Little's law** (L = λW) at work: with roughly constant
  in-flight work W and rising concurrency, per-request wait grows proportionally.
- **The tail (p99) tracks p50** because there is no queue thrash yet; there is
  no lock contention (single-threaded), so no lock-convoy p99 blow-up.
- **No thread pool.**  All of this is one `epoll`/`kqueue` loop multiplexing
  every socket -- the whole point of the asyncio design.

## What the numbers validate

- `tests/load` asserts the server's own `ServerMetrics` against the client-side
  view, so the dashboard (`/metrics`), the store-and-forward path, and these
  charts all describe the same events.
- E2EE adds a constant **28 bytes/message** (12-byte nonce + 16-byte GCM tag);
  the size -- not the throughput shape -- is what changes when E2EE is on.
