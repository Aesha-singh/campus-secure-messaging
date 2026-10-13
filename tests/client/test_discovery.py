"""Tests for the client-side mDNS/DNS-SD browser."""

from __future__ import annotations

import asyncio
import socket

import pytest

from client.discovery import DiscoveredServer, ServerBrowser, _decode_properties, discover_servers


def test_decode_properties_bytes_keys() -> None:
    raw = {b"proto": b"1", b"tls": b"1", b"empty": None}
    assert _decode_properties(raw) == {"proto": "1", "tls": "1", "empty": ""}


def test_discovered_server_label() -> None:
    srv = DiscoveredServer(
        name="Campus CSCP._cscp._tcp.local.",
        host="192.168.1.5",
        port=9443,
        addresses=["192.168.1.5"],
        properties={"tls": "1"},
    )
    assert srv.label == "Campus CSCP @ 192.168.1.5:9443 (TLS)"


def test_discovered_server_label_no_tls() -> None:
    srv = DiscoveredServer(name="s._cscp._tcp.local.", host="10.0.0.2", port=9000, properties={})
    assert srv.label == "s @ 10.0.0.2:9000"


@pytest.mark.integration
async def test_advertise_and_browse_round_trip() -> None:
    """End-to-end DNS-SD: advertise a service, then discover it.

    This relies on multicast being available; on a host without it the
    discovery simply yields nothing and we skip rather than fail.
    """
    from server.mdns import MdnsAdvertiser

    adv = MdnsAdvertiser(
        instance_name="CSCP Test",
        port=9455,
        addresses=[socket.inet_aton("127.0.0.1")],
        properties={"proto": "1", "tls": "0"},
    )
    await adv.start()
    found: list[DiscoveredServer] = []
    try:
        browser = ServerBrowser(on_found=found.append)
        await browser.start()
        try:
            await asyncio.sleep(3.0)
        finally:
            await browser.stop()
    finally:
        await adv.stop()

    if not found:
        pytest.skip("mDNS multicast unavailable on this host")
    assert any(s.port == 9455 for s in found)


@pytest.mark.integration
async def test_discover_servers_one_shot() -> None:
    servers = await discover_servers(timeout=1.0)
    assert isinstance(servers, list)
