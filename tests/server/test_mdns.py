"""Tests for the mDNS/DNS-SD advertiser (server side)."""

from __future__ import annotations

import socket

from server.mdns import MdnsAdvertiser, local_addresses


def test_local_addresses_prefers_concrete_ipv4() -> None:
    packed = local_addresses("192.168.1.50", None)
    assert packed == [socket.inet_aton("192.168.1.50")]


def test_local_addresses_wildcard_falls_back_to_host() -> None:
    packed = local_addresses("0.0.0.0", None)  # noqa: S104 -- testing wildcard translation
    assert packed  # never empty: at least the loopback fallback
    for addr in packed:
        assert len(addr) == 4


def test_advertiser_service_name_and_txt() -> None:
    adv = MdnsAdvertiser(
        instance_name="Campus CSCP",
        port=9443,
        addresses=[socket.inet_aton("127.0.0.1")],
        host_name="cscp-campus.local",
        properties={"proto": "1", "tls": "1"},
    )
    assert adv.service_name == "Campus CSCP._cscp._tcp.local."
    assert adv.txt() == {"proto": "1", "tls": "1"}


def test_advertiser_builds_service_info() -> None:
    adv = MdnsAdvertiser(
        instance_name="Campus CSCP",
        port=9443,
        addresses=[socket.inet_aton("127.0.0.1")],
        host_name="cscp-campus.local",
    )
    info = adv._build_info()
    assert info.port == 9443
    assert info.type == "_cscp._tcp.local."
    assert info.server == "cscp-campus.local."
    assert isinstance(info.properties, dict)
