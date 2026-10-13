"""The userspace capture tap: synthesized packets + a real recording round-trip.

Networking concept demonstrated
-------------------------------
**You can produce a real capture without raw sockets.**  These tests pin down the
hand-forged IPv4/TCP framing (valid header checksums, correct linktype) and then
push bytes through the :class:`RecordingProxy` to prove the pcap it writes
contains the exact bytes that crossed the wire.
"""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pcap_capture
import pytest
from pcap_capture import PcapWriter, RecordingProxy, _checksum, _segment


def _ip_checksum_valid(ip: bytes) -> bool:
    return _checksum(ip) == 0


def _tcp_checksum_valid(ip: bytes) -> bool:
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    src, dst = ip[12:16], ip[16:20]
    tcp = ip[ihl:total]
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    return _checksum(pseudo + tcp) == 0


def test_checksum_zero_input_is_all_ones() -> None:
    assert _checksum(b"\x00\x00") == 0xFFFF


def test_segment_has_valid_ip_and_tcp_headers() -> None:
    pkt = _segment(40000, 9443, 100, 200, 0x18, b"payload!", 7)
    assert pkt[0] >> 4 == 4, "IP version must be 4"
    assert (pkt[0] & 0x0F) * 4 == 20, "no IP options"
    assert pkt[9] == 6, "protocol must be TCP"
    assert struct.unpack("!H", pkt[2:4])[0] == 20 + 20 + len(b"payload!")
    assert _ip_checksum_valid(pkt[:20])
    assert _tcp_checksum_valid(pkt)
    ihl = 20
    sport, dport = struct.unpack("!HH", pkt[ihl : ihl + 4])
    assert (sport, dport) == (40000, 9443)
    assert pkt[ihl + 12] >> 4 == 5, "TCP data offset must be 5 (20 bytes)"
    assert pkt[ihl + 20 :] == b"payload!"


def test_pcap_writer_emits_valid_global_header_and_records(tmp_path: Path) -> None:
    path = tmp_path / "t.pcap"
    writer = PcapWriter(path)
    pkt = _segment(1, 2, 3, 4, 0x18, b"hi", 1)
    writer.write(pkt, 1_700_000_000.5)
    writer.write(pkt, 1_700_000_001.25)
    assert writer.packets == 2
    writer.close()

    raw = path.read_bytes()
    magic, vmaj, vmin, _tz, _sig, snap, net = struct.unpack("!IHHiIII", raw[:24])
    assert magic == 0xA1B2C3D4
    assert (vmaj, vmin) == (2, 4)
    assert snap == 65535
    assert net == pcap_capture._LINKTYPE_IPV4 == 228

    sec, usec, inc, orig = struct.unpack("!IIII", raw[24:40])
    assert (sec, usec) == (1_700_000_000, 500_000)
    assert inc == orig == len(pkt)
    assert raw[40 : 40 + len(pkt)] == pkt


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while (data := await reader.read(65536)):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


@pytest.mark.asyncio
async def test_recording_proxy_captures_relayed_bytes(tmp_path: Path) -> None:
    echo = await asyncio.start_server(_echo, "127.0.0.1", 0)
    echo_port = echo.sockets[0].getsockname()[1]

    path = tmp_path / "roundtrip.pcap"
    pcap = PcapWriter(path)
    proxy = RecordingProxy(pcap, "127.0.0.1", echo_port)
    listen_port = await proxy.start("127.0.0.1")
    assert listen_port > 0

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        payload = b"the-marker-crosses-the-tap"
        writer.write(payload)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(payload)), timeout=3) == payload
        writer.close()
        await writer.wait_closed()
    finally:
        await proxy.stop()
        pcap.close()
        echo.close()
        await echo.wait_closed()

    assert pcap.packets >= 4, "handshake + at least one data segment each way"
    assert payload in path.read_bytes(), "the relayed payload must survive into the pcap"
