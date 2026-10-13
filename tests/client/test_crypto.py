"""Tests for the client E2EE device identity / TOFU pinning and ratchet glue."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from client.crypto import ClientCrypto, load_or_create_identity
from security.e2ee import E2EEChannel


class ClientCryptoHarness:
    """Two {crypto, key-ring} halves with mutually pinned keys."""

    def __init__(self, alice_id: str = "u_alice", bob_id: str = "u_bob") -> None:
        self.alice = ClientCrypto.create("dev-alice", keypair=None)
        self.bob = ClientCrypto.create("dev-bob", keypair=None)
        self.alice.set_local_id(alice_id)
        self.bob.set_local_id(bob_id)
        # Out-of-band key exchange: each pins the other's *public* key.
        assert self.alice.pin_peer(bob_id, self.bob.own_public())
        assert self.bob.pin_peer(alice_id, self.alice.own_public())


class TestClientCrypto:
    def test_keypair_and_pin_roundtrip(self) -> None:
        h = ClientCryptoHarness()
        assert h.alice.own_public() != h.bob.own_public()
        assert h.alice.peer_pinned("u_bob") == h.bob.own_public()

    def test_pin_conflict_rejected(self) -> None:
        h = ClientCryptoHarness()
        other = ClientCrypto.create("dev-mallory")
        assert not h.alice.pin_peer("u_bob", other.own_public())

    def test_channel_ids_agree_from_both_sides(self) -> None:
        h = ClientCryptoHarness()
        # shared master via X25519(privA, pubB) == X25519(privB, pubA)
        ch_a = h.alice.channel_for("u_bob")
        ch_b = h.bob.channel_for("u_alice")
        assert isinstance(ch_a, E2EEChannel) and isinstance(ch_b, E2EEChannel)
        # Exactagreet: exactly one side must be the ratchet initiator.
        init_a = h.alice._is_initiator("u_bob")
        init_b = h.bob._is_initiator("u_alice")
        assert init_a != init_b

    def test_encrypted_roundtrip_alice_to_bob(self) -> None:
        h = ClientCryptoHarness()
        ch_a = h.alice.channel_for("u_bob")
        for i in range(3):
            packet = ch_a.send(f"m{i}", f"hello #{i}".encode())
            plain = h.bob.channel_for("u_alice").recv(f"m{i}", packet)
            assert plain == f"hello #{i}".encode()

    def test_opposite_direction_independent_chain(self) -> None:
        h = ClientCryptoHarness()
        # Bob replies before Alice sends again: direction chains are separate.
        packet = h.bob.channel_for("u_alice").send("r0", b"reply")
        assert h.alice.channel_for("u_bob").recv("r0", packet) == b"reply"

    def test_tampered_ciphertext_rejected(self) -> None:
        h = ClientCryptoHarness()
        packet = bytearray(h.alice.channel_for("u_bob").send("m0", b"secret"))
        packet[30] ^= 0x01  # flip one bit inside the GCM ciphertext
        with pytest.raises((ValueError, InvalidTag)):
            h.bob.channel_for("u_alice").recv("m0", bytes(packet))

    def test_key_swap_breaks_decryption(self) -> None:
        # A middle swap: Alice *starts* the thread against Mallory's key while
        # Bob still knows Alice's real public key -> the two ECDH masters
        # diverge and GCM rejects every packet.
        alice = ClientCrypto.create("dev-alice")
        bob = ClientCrypto.create("dev-bob")
        mallory = ClientCrypto.create("dev-mallory")
        alice.set_local_id("u_alice")
        bob.set_local_id("u_bob")
        assert alice.pin_peer("u_bob", mallory.own_public())
        assert bob.pin_peer("u_alice", alice.own_public())
        packet = alice.channel_for("u_bob").send("m0", b"secret")
        with pytest.raises((ValueError, InvalidTag)):
            bob.channel_for("u_alice").recv("m0", packet)


def test_load_or_create_identity_is_idempotent(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # Regression: the file was written as raw key bytes but read back as hex
    # text, so the *second* load of the same path crashed with UnicodeDecodeError.
    path = tmp_path / "u_alice" / "identity.key"
    first = load_or_create_identity(path)
    second = load_or_create_identity(path)
    assert first.device_id == "u_alice"
    assert first.private_key.private_bytes_raw() == second.private_key.private_bytes_raw()


def test_load_or_create_identity_reads_legacy_hex(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "u_bob" / "identity.key"
    seeded = load_or_create_identity(path)
    path.write_text(seeded.private_key.private_bytes_raw().hex())  # legacy encoding
    reloaded = load_or_create_identity(path)
    assert reloaded.private_key.private_bytes_raw() == seeded.private_key.private_bytes_raw()