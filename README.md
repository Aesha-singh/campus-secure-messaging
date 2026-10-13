# Campus Secure Messaging & File Sharing System

A secure, real-time messaging and file-sharing system for a university campus
(~thousands of users, LAN/WAN), built around **CSCP** — Campus Secure Comm
Protocol — a custom binary application-layer protocol over TLS 1.3.

> Computer Networks course project. Every design decision is documented with
> the networking concept it demonstrates, for the viva defence.

## Highlights

- **CSCP over TLS 1.3 + mutual TLS** — length-delimited binary frames (CRC32 +
  MessagePack) on a single-threaded `asyncio` server (epoll/kqueue).
- **End-to-end encryption** — X25519 → HKDF-SHA256 → AES-256-GCM with a
  per-message ratchet; the server relays ciphertext-only. Keys are pinned
  out-of-band (TOFU), so there is no key directory to attack.
- **Store-and-forward** — offline messages and files are persisted (SQLite/WAL)
  and replayed byte-identically on reconnect; unread badges and history sync.
- **File transfer** — chunked relay with a sliding-window cumulative ACK,
  resume from a byte offset, per-user quotas and TTL cleanup; peer-to-peer
  transfers can be sealed end-to-end with a per-file AES-256-GCM key wrapped to
  the recipient's pinned X25519 identity.
- **Channel rooms** — server-mediated public/private/course/club channels with
  membership, `create/join/leave/list` and live fan-out, persisted like DMs.
- **mDNS/DNS-SD discovery** — the server advertises `_cscp._tcp.local.` so a
  client can find the campus server on the LAN with no manual host/port.
- **Desktop client** — PyQt6 + `qasync` (one event loop owns the socket and the
  widgets): sign-in, chat, transcript, unread badges, E2EE contact pinning,
  channel rooms, file send/accept with progress, a live RTT/jitter/loss
  diagnostics panel, and a discovery dialog.
- **Admin dashboard** — a hand-rolled HTTP/1.1 listener exposing `/metrics`
  (JSON telemetry) and `/health`, on a separate TCP port from the CSCP service;
  the served page is a live, dependency-free dashboard (canvas charts + online
  user/channel tables) that polls `/metrics`.
- **Auth** — Argon2id passwords, TOTP 2FA, rate limiting, replay/DoS guards.

## Stack

| Layer         | Technology                                                   |
|---------------|--------------------------------------------------------------|
| Language      | Python 3.11+ (developed on 3.12)                             |
| Concurrency   | `asyncio` (single-threaded event loop; epoll/kqueue)         |
| Transport     | TLS 1.3 over TCP (mutual auth, certificate pinning)          |
| App protocol  | CSCP — length-delimited binary frames + CRC32 (MessagePack)  |
| Storage       | SQLite (WAL)                                                 |
| Crypto        | X25519, HKDF-SHA256, AES-256-GCM, Argon2id, TOTP             |
| Desktop UI    | PyQt6 + qasync                                               |
| Admin         | stdlib `asyncio` HTTP/1.1 dashboard (JSON metrics + health)  |
| Deploy        | Docker, docker-compose, systemd                              |

## Repository layout

```
protocol/   CSCP spec, codec (FrameDecoder), message types, replay guard
server/     asyncio + TLS server, sessions, connection manager, heartbeat,
            rate limiting, metrics, channel rooms, file relay, mDNS advert,
            live HTTP dashboard (dashboard.html)
client/     transport, session FSM, E2EE device identity, local store,
            mDNS discovery (discovery.py), diagnostics,
            PyQt6 desktop UI (client/ui/), console harness
messaging/  SQLite message store (offline queue, history, unread)
security/   CA/cert generation, Argon2id auth, TOTP, E2EE primitives
tests/      protocol, server, client, security, scripts, load
scripts/    traffic_demo.py (Wireshark), pcap_capture.py (root-free capture),
            bench.py (load), bench_charts.py (report charts)
docs/       captures.md (Wireshark), benchmarks.md + charts/, threat_model.md
deploy/     Dockerfile, docker-compose.yml, systemd unit, prod config
config/     server + client YAML
captures/   saved pcaps for the report (root-free, see docs/captures.md)
```

## Quick start

Fastest path — one command runs the whole stack in Docker (generates its own
certs + demo accounts on first boot, then serves TLS 1.3 + mTLS):

```bash
make up              # build + start (needs Docker); CSCP on :9443, admin on :9444
make client-stack    # launch the PyQt6 desktop client against it
make down            # stop
```

Demo logins: `alice` / `bob`, password `campus-demo1`.

Or run everything directly on the host:

```bash
make venv            # create virtualenv + install dev+client deps
make certs           # generate the local CA + server + client certs
make test            # run the full test suite
make server          # run the server  (stub auth; PLAIN if no certs)
make client          # launch the PyQt6 desktop client
make check           # lint + strict type-check + tests
```

Console client (no GUI):

```bash
make cli USER=alice PEER=u_bob SEND="hello"
```

## Verifying the network behaviour

| What to demonstrate | How |
|---|---|
| Cleartext vs E2EE vs TLS | `make pcap` (root-free, writes `captures/*.pcap`) or `make capture MODE=plain`; see `docs/captures.md` |
| Live telemetry | `CSCP_ADMIN_TOKEN=dev python -m server.main --auth stub`, then open `http://127.0.0.1:9444/` (dashboard) or `curl -H "Authorization: Bearer dev" localhost:9444/metrics` |
| Load / latency / throughput | `make bench CLIENTS=200 MSGS=10`, or `make charts` for report PNGs (`docs/benchmarks.md`) |
| LAN service discovery | `python -m server.main --config deploy/server.local.yaml` (mDNS on) then the client's "Discover..." dialog |
| Offline store-and-forward | unit test `tests/client/test_session.py::test_offline_queue_delivered_after_reconnect` |

Sample load result (loopback, one event loop): **101 connections in 8 ms,
auth ≈3,000/s, ≈21,700 msgs/s, RTT p50 4.2 / p99 4.6 ms, 0 rate-limited.**

## Networking concepts demonstrated

| Feature | Concept |
|---|---|
| Dual-stack listeners, `start_server` | IPv4/IPv6, socket multiplexing on one loop |
| CSCP framing (length prefix + CRC32) | message vs stream boundaries, integrity |
| TLS 1.3 + mTLS, pins | confidentiality, authentication, certificate pinning |
| Heartbeat PING/PONG + idle timeout | keep-alive across NAT/firewalls, liveness |
| Reconnect with exponential backoff | resilience to transient failures |
| ACK correlation + msg_id de-dup | at-least-once delivery → effectively-once |
| Sliding-window chunk ACK + resume | flow control, retransmission, resume |
| Server-side persistence + replay | store-and-forward, offline delivery |
| Channel membership + server fan-out | application-layer multicast (group messaging) |
| mDNS/DNS-SD `_cscp._tcp.local.` | zero-config service discovery on the LAN |
| HTTP/1.1 admin on a second port | two application protocols, one process |
| Userspace TCP tap + pcap writer | packet capture without raw-socket privileges |
| RTT/jitter/loss sampling (PING/PONG) | active network-quality measurement |
| Rate limiting (token bucket) | DoS mitigation, QoS |

See `protocol/spec.md` for the full protocol and `docs/threat_model.md` for the
STRIDE analysis.

## Deployment

See `deploy/README.md` — Docker Compose or a hardened systemd unit, with the
production TLS/mTLS config (`deploy/server.prod.yaml`) and secret handling via
environment files.

## Security disclaimer

Attack-lab material (ARP spoof / MITM / replay / brute-force) is documented
**for execution on your own isolated lab machine only**. Never run it against
networks or hosts you do not own.
