# Campus Secure Messaging & File Sharing System

A production-quality, secure, real-time messaging and file-sharing system for a
university campus (~thousands of users, LAN/WAN), built around **CSCP** (Campus
Secure Comm Protocol), a custom binary application-layer protocol over TLS 1.3.

> Computer Networks course project. Every design decision is documented with the
> networking concept it demonstrates, for viva defence.

## Stack

| Layer        | Technology                                        |
|--------------|---------------------------------------------------|
| Language     | Python 3.11+ (developed on 3.12)                  |
| Concurrency  | `asyncio` (single-threaded event loop, epoll/kqueue) |
| Transport    | TLS 1.3 over TCP (mutual auth, cert pinning)      |
| App protocol | CSCP — length-delimited binary frames + CRC32     |
| Serialization| MessagePack                                       |
| Storage      | SQLite (WAL) + schema migrations                  |
| Crypto       | X25519, HKDF-SHA256, AES-256-GCM, Argon2id, TOTP  |
| Desktop UI   | PyQt6 + qasync (dark theme)                       |
| Admin        | FastAPI + WebSocket + Chart.js + Prometheus       |
| Deploy       | Docker, docker-compose, Mininet / Packet Tracer   |

## Repository layout

```
protocol/   CSCP spec, codec (FrameDecoder), message types
server/     asyncio + TLS server, sessions, manager, heartbeat, rate limiting
client/     PyQt6 desktop client + headless client API
admin/      FastAPI web dashboard, Prometheus metrics, CSRF
security/   CA + cert generation, auth, E2EE, threat model
tests/      Unit, fuzz, integration, and load tests
captures/   Wireshark walkthrough material
docs/       Protocol spec, analysis, threat model, viva notes
deploy/     Dockerfiles, compose, Makefile, network topology
```

## Quick start

```bash
make venv        # create virtualenv + install
make test        # run the full test suite
make certs       # generate CA + server + client certificates
make server      # run the server
make client      # run the PyQt6 client
make demo        # one-command end-to-end demo
```

See `docs/` for the report-ready explanations and `deploy/` for topology.

## Security disclaimer

Attack-lab material (ARP spoof / MITM / replay / brute-force / SYN-flood) is
documented **for execution on your own isolated lab machine only**. Never run it
against networks or hosts you do not own.
