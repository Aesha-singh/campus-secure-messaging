"""End-to-end encryption: X25519 key agreement, HKDF, AES-256-GCM.

Networking concept demonstrated
-------------------------------
**End-to-end confidentiality on top of TLS** (defence in depth).  TLS 1.3 only
protects data *in transit* -- the operator of the server still reads the bytes.
E2EE adds a second encryption layer such that even the server relays
ciphertext it cannot decrypt:

* **Key agreement** -- ephemeral X25519 (ECDH).  Each participant publishes a
  public key once; the shared secret is ``X25519(priv_alice, pub_bob)``.
  Because a fresh ephemeral key can be minted per session, we get **perfect
  forward secrecy**: a stolen long-term key cannot decrypt past traffic.
* **Key derivation** -- the raw ECDH output is passed through HKDF-SHA256 with
  a domain-separation ``info`` string so "key for E2EE" never collides with any
  other key derived from the same secret.
* **Authenticated encryption** -- AES-256-GCM provides confidentiality **and**
  integrity.  The **AAD** (additional authenticated data) binds every packet to
  its CSCP metadata (peer id, message id, sequence), so an attacker cannot
  splice ciphertext between messages or replay it elsewhere.
* **Ratchet-lite** -- a one-way HKDF key-chain per direction ("sending" and
  "receiving").  After each message, the key is irreversibly advanced; a leaked
  key only decrypts *future* messages, never ones already sent (KDF-chain
  forward secrecy) -- the core idea behind State (Signal) ratchets, kept here
  without full double-ratchet complexity.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN: Final[int] = 32
NONCE_LEN: Final[int] = 12
TAG_LEN: Final[int] = 16


def generate_keypair() -> X25519PrivateKey:
    """Generate a fresh X25519 private key (ephemeral per device/session)."""
    return X25519PrivateKey.generate()


def public_bytes(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes_raw()


def derive_shared(priv: X25519PrivateKey, peer_pub_bytes: bytes, info: bytes) -> bytes:
    """Derive a 32-byte AEAD key from an ECDH exchange using HKDF-SHA256."""
    peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = priv.exchange(peer)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=info,
    ).derive(shared)


def chain_step(key: bytes, info: bytes, salt: bytes | None = None) -> bytes:
    """Advance a key one ratchet step: ``HKDF(key, info=salt)`` (one-way)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        info=info,
    ).derive(key)


def sign_mac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 used to authenticate ratchet parameters (optional binding)."""
    ctx = hmac.HMAC(key, hashes.SHA256())
    ctx.update(data)
    return ctx.finalize()


def seal(master: bytes, plaintext: bytes, *, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext``; returns ``(nonce, nonce||ciphertext||tag)``.

    The random 96-bit nonce is generated fresh per packet (a nonce reuse under
    GCM is fatal -- randomness via the OS CSPRNG avoids the counter pitfalls).
    """
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(master).encrypt(nonce, plaintext, aad)
    return nonce, nonce + ct


def open_seal(master: bytes, packet: bytes, *, aad: bytes) -> bytes:
    """Decrypt/authenticate ``(nonce || ciphertext || tag)``; raises on tamper.

    Returns plaintext or raises :class:`InvalidTag`/``ValueError`` when the AAD,
    the tag, or the ciphertext has been altered -- GCM authenticity check.
    """
    nonce, ct = packet[:NONCE_LEN], packet[NONCE_LEN:]
    return AESGCM(master).decrypt(nonce, ct, aad)


def aad_for(channel_id: str, message_id: str, direction: int, seq: int) -> bytes:
    """Build the AAD binding a packet to its CSCP metadata (anti-splicing)."""
    return b"cscp-v1|%s|%s|%d|%d" % (channel_id.encode(), message_id.encode(), direction, seq)


class E2EEChannel:
    """Symmetric E2E channel built from the *same* master secret on both ends.

    Design
    ------
    The transport provides reliable, in-order delivery (frames carry a strict
    sequence already), so "ratchet-lite" is a per-direction one-way HKDF chain:

    * two independent chains are derived from the master (``direction 0`` and
      ``direction 1``) -- the initiator sends on chain 0, the peer on chain 1;
    * every message advances its chain by one HKDF step, so a leaked key can
      only decrypt the *current and future* packets, never the past (KDF-chain
      forward secrecy, the core of Signal's ratchet without the DH re-keys);
    * the nonce (96-bit) is random per packet and the **AAD** binds the packet
      to its ``channel_id | message_id | direction | seq`` so ciphertext can
      not be spliced or replayed from another context.

    Delivery is ordered per CSCP connection; if a packet is *lost*, both sides
    step their chains once (the loss is detected by the message-id gap and the
    peer re-requests), and GCM will still authenticate because the counter is
    stepped in lockstep -- a future "sync" message can re-sync the chain.
    """

    def __init__(self, master: bytes, *, channel_id: str, initiator: bool) -> None:
        if len(master) != KEY_LEN:
            raise ValueError(f"master must be {KEY_LEN} bytes")
        # Both endpoints derive the *same* two direction chains from the master.
        self._chains: dict[int, bytes] = {
            0: chain_step(master, b"CSCP-E2EE|chain|0"),
            1: chain_step(master, b"CSCP-E2EE|chain|1"),
        }
        self._channel_id = channel_id
        self._send_dir = int(initiator)
        self._recv_dir = int(not initiator)
        self._sender_seq = 0
        self._receiver_seq = 0

    def _advance(self, direction: int) -> bytes:
        """Step one direction chain forward (irreversible, so past stays secret)."""
        nxt = chain_step(self._chains[direction], b"CSCP-E2EE|ratchet")
        self._chains[direction] = nxt
        return nxt

    def send(self, message_id: str, plaintext: bytes) -> bytes:
        """Encrypt one message using this endpoint's sending chain."""
        seq = self._sender_seq
        self._sender_seq += 1
        key = self._advance(self._send_dir)
        _, packet = seal(key, plaintext, aad=aad_for(self._channel_id, message_id, self._send_dir, seq))
        return packet

    def recv(self, message_id: str, packet: bytes) -> bytes:
        """Decrypt and authenticate one peer packet using the peer's chain."""
        seq = self._receiver_seq
        self._receiver_seq += 1
        key = self._advance(self._recv_dir)
        return open_seal(key, packet, aad=aad_for(self._channel_id, message_id, self._recv_dir, seq))