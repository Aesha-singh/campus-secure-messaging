"""Client-side end-to-end encryption: device identity, TOFU key pinning.

Networking concept demonstrated
-------------------------------
**End-to-end confidentiality, client half.**  The server relays ciphertext it
cannot decrypt (defence in depth on top of TLS).  This module owns *our*
half of the wire keys:

* **Device identity** -- a persistent X25519 keypair per install (the
  "hello" device in HELLO/device binding).  Only the public half leaves the
  device, and it is what a peer pins to start a conversation.
* **Trust On First Use (TOFU) pinning** -- public keys are exchanged
  *outside* the app (printed / QR / typed by the users, the same model as
  Signal's safety numbers or Tox's tox-id).  The first key seen for a peer is
  remembered; future messages must decrypt with the **same** pinned key or
  GCM authentication fails (``InvalidTag``).  This makes an attacker who
  swaps keys mid-thread undetectably-infeasible: the swap is *visible* on one
  of the two devices.
* **Per-conversation HKDF master** -- ``X25519(our_priv, their_pub)`` is
  folded through HKDF-SHA256 with a conversation-scoped ``info`` string, so
  every chat is cryptographically separate even if both derive from the same
  long-term keys (deniability-by-separation).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from security.e2ee import (
    E2EEChannel,
    derive_shared,
    generate_keypair,
    public_bytes,
)

log = logging.getLogger("cscp.client.crypto")


@dataclass(slots=True)
class DeviceIdentity:
    """The client's long-lived X25519 identity (persisted as one SQLite row)."""

    device_id: str
    private_key: X25519PrivateKey

    @property
    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()

    def public_bytes(self) -> bytes:
        return public_bytes(self.public_key)


class PeerKeyRing:
    """TOFU pinning of peer public keys for direct conversations."""

    def __init__(self) -> None:
        self._pinned: dict[str, bytes] = {}

    def load(self, peer_id: str, public_key: bytes) -> None:
        self._pinned[peer_id] = public_key

    def pin(self, peer_id: str, public_key: bytes) -> bool:
        """Pin ``public_key`` for ``peer_id``; returns ``False`` on conflict."""
        existing = self._pinned.get(peer_id)
        if existing is not None and existing != public_key:
            return False  # key change mid-thread -> refuse (visible swap)
        self._pinned[peer_id] = public_key
        return True

    def get(self, peer_id: str) -> bytes | None:
        return self._pinned.get(peer_id)

    def keys(self) -> dict[str, bytes]:
        return dict(self._pinned)


class ClientCrypto:
    """Glue between the device identity, the key ring, and the ratchet.

    A :class:`E2EEChannel` (per-conversation, per-direction one-way HKDF
    chains) is cached in memory -- the two sides step their chains in the
    order frames arrive over the reliable TCP pipe, which is exactly the
    order CSCP preserves.
    """

    def __init__(self, identity: DeviceIdentity, local_user_id: str = "") -> None:
        self.identity = identity
        self.local_user_id = local_user_id
        self.ring = PeerKeyRing()
        self._channels: dict[str, E2EEChannel] = {}

    @classmethod
    def create(cls, device_id: str, keypair: X25519PrivateKey | None = None) -> ClientCrypto:
        return cls(DeviceIdentity(device_id=device_id, private_key=keypair or generate_keypair()))

    def set_local_id(self, user_id: str) -> None:
        """Bind the authenticated user id (message ids on the wire) to this entity.

        Both ends of a conversation must agree on the *same* ordering input for
        the channel id and the initiator flag; the user id is the only string
        both sides see (device ids would differ per install).
        """
        self.local_user_id = user_id
        if user_id:
            self._channels = {k: v for k, v in self._channels.items() if k.startswith(f"dm:{user_id}:")}

    def own_public(self) -> bytes:
        return self.identity.public_bytes()

    def peer_pinned(self, peer_id: str) -> bytes | None:
        return self.ring.get(peer_id)

    def pin_peer(self, peer_id: str, public_key: bytes) -> bool:
        return self.ring.pin(peer_id, public_key)

    def start_with_seed(self, peer_id: str, seed: str) -> E2EEChannel:
        """Peers can bootstrap a conversation from a shared one-time seed.

        Both sides hash ``seed``; the first message rides on a simple PBKDF
        instead of requiring the DH exchange, giving a demo-friendly "type the
        same passphrase" flow.  Once a real X25519 key is pinned (out-of-band),
        normal derivation takes over.
        """
        master = hashlib.sha256(seed.encode()).digest()
        channel_id = self._convo_id(peer_id)
        ch = E2EEChannel(master, channel_id=channel_id, initiator=self._is_initiator(peer_id))
        self._channels[channel_id] = ch
        return ch

    def channel_for(self, peer_id: str) -> E2EEChannel:
        """Return (creating if needed) a per-conversation ratchet for ``peer_id``.

        Derives the conversation master from the pinned public key:
        ``HKDF(X25519(our_priv, peer_pub), info='CSCP-E2EE|<convo>')``.
        """
        channel_id = self._convo_id(peer_id)
        cached = self._channels.get(channel_id)
        if cached is not None:
            return cached
        pub = self.ring.get(peer_id)
        if pub is None:
            raise ValueError(f"no pinned public key for peer '{peer_id}'")
        master = derive_shared(
            self.identity.private_key,
            pub,
            info=f"CSCP-E2EE|{channel_id}".encode(),
        )
        ch = E2EEChannel(master, channel_id=channel_id, initiator=self._is_initiator(peer_id))
        self._channels[channel_id] = ch
        return ch

    def reset_thread(self, peer_id: str) -> None:
        """Drop the ratchet state for a peer (e.g. after a key re-pin)."""
        self._channels.pop(self._convo_id(peer_id), None)

    def _convo_id(self, peer_id: str) -> str:
        a, b = self.local_user_id, peer_id
        if not a:
            a = self.identity.device_id
        return "dm:" + ":".join(sorted((a, b)))

    def _is_initiator(self, peer_id: str) -> bool:
        """True iff OUR side is the lexicographically-smaller user id.

        Both endpoints compute this from the *same* sorted (mine, theirs) pair,
        so exactly one of the two is the initiator -- the ratchet direction
        keys then line up on both ends.
        """
        mine = self.local_user_id or self.identity.device_id
        return mine == min(mine, peer_id)


def new_device_id() -> str:
    """A stable random device id (envelope/Finger connected sessions)."""
    return "dev-" + uuid.uuid4().hex[:16]


def _read_private_key_bytes(path: Path) -> bytes:
    """Read a stored X25519 private key, accepting raw or legacy hex encoding."""
    data = path.read_bytes()
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return data
    if len(text) == 64:  # legacy hex-encoded form (32 bytes -> 64 hex chars)
        try:
            return bytes.fromhex(text)
        except ValueError:
            return data
    return data


def load_or_create_identity(path: Path) -> DeviceIdentity:
    """Load the device identity from ``path``, or mint a fresh one.

    The private key is stored alongside the SQLite db with 0600 permissions --
    stealing it lets an attacker impersonate the device, so this file is the
    client-side secret (documented in the viva threat table).
    """
    raw = _read_private_key_bytes(path) if path.exists() else b""
    if len(raw) == 32:
        try:
            pk = X25519PrivateKey.from_private_bytes(raw)
            return DeviceIdentity(device_id=path.parent.name, private_key=pk)
        except ValueError:  # corrupt file -> mint a new identity
            log.warning("corrupt identity file '%s' -> generating new", path)
    pk = generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pk.private_bytes_raw())
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return DeviceIdentity(device_id=path.parent.name, private_key=pk)