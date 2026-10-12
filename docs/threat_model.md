# Threat Model — Campus Secure Messaging and File Sharing System (CSCP)

This document analyses the system using the **STRIDE** mnemonic and maps each
identified threat to the exact control already implemented (or intentionally
deferred). It is a living document: every phase re-runs this table.

```
                        ┌──────────────────────────────────────────┐
  Attacker (active)     │            CSCP SERVER (asyncio)          │
  ─────────────────►    │  TLS 1.3 (mTLS) ◄── ALICE / BOB clients    │
                        │         │                                 │
                        │  ┌──────┴────────┐                        │
                        │  │ Auth (Argon2) │  rate limiter, lockout │
                        │  └──────┬────────┘                        │
                        │  ┌──────┴────────┐  E2EE (X25519/GCM) is   │
                        │  │ Relays cipher │  opaque to the server   │
                        │  └───────────────┘  (defence in depth)     │
                        └──────────────────────────────────────────┘
```

## Assets
| Asset | Sensitivity |
|---|---|
| User identities, roles, group membership | Medium |
| Message content, file contents | High (student data) |
| Access / session tokens | High |
| Password hashes (Argon2id), TOTP seeds | High |
| TLS private keys (server, CA) | Critical |

## Assumptions / trust boundaries
* The server operator is **semi-trusted**: TLS protects transport, but the
  server *could* read anything unencrypted at the application layer. E2EE
  makes message/file content opaque to the server (new boundary).
* Clients are fully-trusted endpoints (no code sandbox).
* The campus LAN is **untrusted**, including other students on the same
  switch; hence mTLS, E2E, and rate limits are mandatory, not optional.

## STRIDE analysis

### 1. Spoofing (pretending to be someone else)
| Threat | Vector | Control |
|---|---|---|
| Attacker impersonates a user | Forge username in login | Server authenticates via Argon2id password + optional TOTP (`security/auth.py`); identity derived from the *hashed* credential, never from client-declared fields. |
| Attacker impersonates the server | DNS rebinding / MitM on LAN | Server presents a CA-signed certificate and clients **pin the CA** (`load_tls_client_context`); hostname verification against SANs. |
| Attacker impersonates a peer device | Unauthorised client on the LAN | **Mutual TLS**: server demands `CERT_REQUIRED` client cert; a peer with no cert is refused (`PEER_DID_NOT_RETURN_A_CERTIFICATE`). |
| Forged session | Token theft / replay | Tokens are HMAC-SHA256-signed with the server secret (`server/auth.py`), short `exp` (5 min access / 7 day session), bound to `sub` + `device_id`. |
| E2E identity spoof | Swap public keys in a chat | Ratchet-lite keys pinned per conversation; GCM tag authenticates *every* packet (`security/e2ee.py`). A wrong key ⇒ `InvalidTag`. |

### 2. Tampering (modifying data)
| Threat | Vector | Control |
|---|---|---|
| Flip bytes in a frame mid-flight | Active MitM | TLS 1.3 AEAD (AES-256-GCM / CHACHA20-POLY1305) authenticates transport. |
| Modify frame payload inside relay | Server tampering while relaying | E2EE layer: AES-256-GCM tag + **AAD binding** to `channel_id|message_id|dir|seq`; any alteration fails `open_seal`. |
| Re-order / splice frames | MITM reordering at transport | ReplayGuard enforces strictly increasing per-connection sequence (`protocol/replay.py`), plus logoff + ack bookkeeping. |
| Corrupt stored user db / logs | Compromised disk | Logs are append-only files with `chmod 0o600` on private keys; user db validated on load (rejects plaintext). |
| Weak TLS | Downgrade to TLS 1.2 | `minimum_version = TLSv1_3` on both server and client contexts. |

### 3. Repudiation (denying actions)
| Threat | Vector | Control |
|---|---|---|
| User denies sending a message | No receipts | `msg_id` + `Ack` on delivery; server records send/receive logs (structured JSON, `logging_setup.py`). |
| Server denies processing | No audit trail | Every frame type is logged with `connection_id`, `user`, `ip`; metrics counters exposed for the admin dashboard. |

### 4. Information Disclosure
| Threat | Vector | Control |
|---|---|---|
| Eavesdrop on wire | Passive sniffing on shared LAN | TLS 1.3 encrypts traffic; capture-lab documents handshake (see `docs/captures/`). |
| Read message content via server | Server operator with DB dump | **E2EE**: server only ever relays ciphertext; keys never leave the clients. Content column stores the sealed packet. |
| Offline password cracking | Database leak | Argon2id memory-hard KDF (64 MiB, t=3); unique per-user salted hashes. |
| Token / secret disclosure | Log injection | Secrets never logged; JSON logs redact; private key files `0o600`. |
| Timing side-channel on auth | Measure password check latency | TOTP compare uses `secrets.compare_digest`; Argon2 is inherently constant-ish. |

### 5. Denial of Service
| Threat | Vector | Control |
|---|---|---|
| Connect flood | Many TCP connections | `max_connections` semaphore; inbound excess `writer.close()` on hand-raise. |
| Auth brute-force | Scripted login attempts | Per-IP rate limiter (`rates.py`) **and** per-username lockout (5 fails → 5 min) in `Argon2idAuthenticator`. |
| Frame flood / slow loris | Send partial frames | Bounded read with `max_frame_size`; idle heartbeat (`ping_interval`) evicts dead peers; frame decoder rejects oversized frames. |
| Message-rate flood | Spam from user | Token-bucket per IP + per user (`rates.py`), capacity/refill from config. |
| Outbound queue blow-up | Server can't keep up | Bounded `asyncio.Queue`; producer awaits `put` (backpressure via TCP flow control, Nagle documented in load-lab). |
| TLS renegotiation flood | CPU burn | TLS 1.3 forbids renegotiation; clients pinned to a single version. |

### 6. Elevation of Privilege
| Threat | Vector | Control |
|---|---|---|
| Client pushes a fabricated user_id | Claim another user's identity | Auth derives `user_id` server-side (e.g. `u_<username>` from db); never accepted from the client. |
| Unknown user joins a channel | Access-control bypass | Channel membership is server-side (`ConnectionManager`); only registered peers in `channels` get the message. |
| Client claims admin role | — | Role comes from the backend (`users.yaml`), not from the wire. |
| Memory corruption in protocol parser | Crafted frames | Inputs are decoded via strict-MessagePack with schema validation, `limit=None` off; only known message types dispatch (`messages.py`). |

## Controls not implemented yet (tracked)
| Phase | Control |
|---|---|
| Messaging | Server-side SQLite store + persistence, unread/sync, message size limits enforced |
| Files | Chunked transfer + quarantine (ClamAV), per-user quota |
| Admin | Role-based admin login, token revocation list (allow `unlock`) |
| E2EE | Proper double ratchet incl. DH re-key + out-of-order buffers; signature keys per device |

## Data-flow with controls annotated
```
client ── TCP ──► TLS 1.3 (mTLS, GCM) ──► CSCP frame (seq + CRC32) ──► Session FSM
        auth: AUTH_REQ ──► Argon2id verify + TOTP ──► HMAC session token
        message: E2E sealed(payload, aad(channel, id, dir, seq)) ──► server relays opaque blob
        ──► rate limiter (token bucket per ip/user) ──► bounded queue ──► drain() ──► wire
```

Each bullet in the table is backed by a passing test under `tests/security/`
and `tests/server/` (framing fuzz, replay, tamper, wrong CA, lockout, TOTP).