"""E2EE attack tests: tampering, wrong keys, wrong AAD, HMAC binding.

These mirror real network attacks: an active MITM *can* flip or re-route
bytes inside the CSCP payload, so we verify the GCM tag and ratchet really
catch it.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from security import e2ee

INF = b"CSCP/E2EE-v1|session-live"


def _pair() -> tuple[e2ee.E2EEChannel, e2ee.E2EEChannel]:
    alice_priv = e2ee.generate_keypair()
    bob_priv = e2ee.generate_keypair()
    alice_shared = e2ee.derive_shared(alice_priv, e2ee.public_bytes(bob_priv.public_key()), INF)
    bob_shared = e2ee.derive_shared(bob_priv, e2ee.public_bytes(alice_priv.public_key()), INF)
    assert alice_shared == bob_shared  # ECDH agreement
    alice = e2ee.E2EEChannel(alice_shared, channel_id="c1", initiator=True)
    bob = e2ee.E2EEChannel(bob_shared, channel_id="c1", initiator=False)
    return alice, bob


def test_key_exchange_agrees() -> None:
    alice, bob = _pair()
    packet = alice.send("m1", b"hello bob")
    assert bob.recv("m1", packet) == b"hello bob"


def test_tampered_ciphertext_fails_auth() -> None:
    alice, bob = _pair()
    packet = bytearray(alice.send("m1", b"secret"))
    packet[len(packet) // 2] ^= 0xFF  # flip a byte -- MITM corruption
    with pytest.raises((InvalidTag, ValueError)):
        bob.recv("m1", bytes(packet))


def test_wrong_aad_rejected() -> None:
    alice, bob = _pair()
    packet = alice.send("m1", b"secret")
    # splice into a different message id => different AAD => tag mismatch
    with pytest.raises((InvalidTag, ValueError)):
        bob.recv("m2", packet)


def test_wrong_peer_key_rejected() -> None:
    """A participant must use the *true* peer public key; a mismatched key fails."""
    alice_priv = e2ee.generate_keypair()
    bob_priv = e2ee.generate_keypair()
    eves_priv = e2ee.generate_keypair()

    bob_shared = e2ee.derive_shared(bob_priv, e2ee.public_bytes(alice_priv.public_key()), INF)
    # MITM substitutes Eve's public key into Alice's key store:
    wrong_shared = e2ee.derive_shared(alice_priv, e2ee.public_bytes(eves_priv.public_key()), INF)
    alice = e2ee.E2EEChannel(wrong_shared, channel_id="c1", initiator=True)
    bob = e2ee.E2EEChannel(bob_shared, channel_id="c1", initiator=False)

    packet = alice.send("m1", b"real secret")
    with pytest.raises((InvalidTag, ValueError)):
        bob.recv("m1", packet)


def test_replay_stale_packet_rejected() -> None:
    """Re-encrypting under the wrong chain position (replay) must fail.

    Because the receiver ratchets its key after each packet, replaying an old
    packet is decrypted with the *next* chain key => tag check fails.
    """
    alice, bob = _pair()
    p1 = alice.send("m1", b"first")
    bob.recv("m1", p1)
    with pytest.raises((InvalidTag, ValueError)):
        bob.recv("m1", p1)


def test_ratchet_advances_each_packet() -> None:
    """Each message uses a distinct key; a prior ciphertext is unreadable once
    the chain has moved forward, even to the legitimate receiver."""
    alice, bob = _pair()
    p1 = alice.send("m1", b"msg-one")
    p2 = alice.send("m2", b"msg-two")
    bob.recv("m1", p1)
    bob.recv("m2", p2)  # both authenticate fine in order
    with pytest.raises((InvalidTag, ValueError)):
        bob.recv("m1", p1)  # already one step past m1 -> replay fails again


def test_seal_open_roundtrip_wrong_nonce() -> None:
    master = b"k" * 32
    nonce, packet = e2ee.seal(master, b"payload", aad=b"a")
    wrong = nonce + b"x" + packet[len(nonce) + 1 :]  # corrupt nonce region
    with pytest.raises(InvalidTag):
        e2ee.open_seal(master, wrong, aad=b"a")


def test_hmac_mac_deterministic() -> None:
    assert e2ee.sign_mac(b"key", b"data") == e2ee.sign_mac(b"key", b"data")
    assert e2ee.sign_mac(b"key", b"data") != e2ee.sign_mac(b"key2", b"data")