#!/usr/bin/env python3
"""Record the CSCP demo traffic into real pcap files -- without root.

Why this exists
---------------
The usual way to capture is ``tcpdump``/``dumpcap``, but both need raw-socket
privileges (root).  This tool instead inserts a **userspace TCP tap** between the
client and the server: a plain asyncio relay that copies every byte in both
directions and re-frames them into synthesized IPv4/TCP packets, then writes a
standard ``libpcap`` file.  The result opens in Wireshark exactly like a
``tcpdump`` capture -- because it *is* one; we just forged the link-layer-free
IP packets ourselves.

    # all three scenarios -> captures/{A-plain,B-e2ee,C-tls}.pcap
    python scripts/pcap_capture.py --all

    # just one
    python scripts/pcap_capture.py --mode plain

Then open the pcap in Wireshark and follow the TCP stream (see docs/captures.md).
Networking lesson: a relay proves the bytes on the wire are the bytes the
application sent -- the tap is just another TCP endpoint.

pcap format (linktype 228 = LINKTYPE_IPV4): a 24-byte global header followed by
16-byte per-record headers (``ts_sec ts_usec incl_len orig_len``) and the packet.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import struct
import sys
import time
from contextlib import suppress
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import traffic_demo  # noqa: E402  -- same directory as this script

# LINKTYPE_IPV4 -- each record begins at the IPv4 header.
_LINKTYPE_IPV4 = 228
_PCAP_MAGIC = 0xA1B2C3D4  # microsecond resolution, little-endian
_SNAPLEN = 65535

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
_LOCAL = b"\x7f\x00\x00\x01"  # 127.0.0.1

_SCENARIOS = {"plain": "A-plain", "e2ee": "B-e2ee", "tls": "C-tls"}


def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) -- 16-bit one's complement sum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(src: bytes, dst: bytes, payload_len: int, ident: int) -> bytes:
    total = 20 + payload_len
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0x4000, 64, 6, 0, src, dst
    )
    return hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]


def _tcp_header(
    src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes
) -> bytes:
    offset_flags = (5 << 12) | flags
    hdr = struct.pack(
        "!HHIIHHHH", sport & 0xFFFF, dport & 0xFFFF, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        offset_flags, 65535, 0, 0,
    )
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    return hdr[:16] + struct.pack("!H", _checksum(pseudo + hdr + payload)) + hdr[18:]


def _segment(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes, ident: int) -> bytes:
    ip = _ipv4_header(_LOCAL, _LOCAL, 20 + len(payload), ident)
    tcp = _tcp_header(_LOCAL, _LOCAL, sport, dport, seq, ack, flags, payload)
    return ip + tcp + payload


class PcapWriter:
    """Minimal little-endian libpcap writer for LINKTYPE_IPV4 packets."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("wb")
        self._fh.write(
            struct.pack("!IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, _SNAPLEN, _LINKTYPE_IPV4)
        )
        self._packets = 0

    def write(self, packet: bytes, ts: float) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("!IIII", sec, usec, len(packet), len(packet)))
        self._fh.write(packet)
        self._packets += 1

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()

    @property
    def packets(self) -> int:
        return self._packets


class _Flow:
    """Per-connection TCP sequence state, one counter per direction."""

    __slots__ = ("cseq", "sseq")

    def __init__(self) -> None:
        self.cseq = secrets.randbelow(1 << 30) + 1
        self.sseq = secrets.randbelow(1 << 30) + 1


class RecordingProxy:
    """A TAP: any TCP client connects here, bytes are relayed upstream and logged."""

    def __init__(self, writer: PcapWriter, upstream_host: str, upstream_port: int) -> None:
        self._writer = writer
        self._up_host = upstream_host
        self._up_port = upstream_port
        self._server: asyncio.AbstractServer | None = None
        self._conns: set[asyncio.StreamWriter] = set()
        self._ident = 0
        self.listen_port = 0

    async def start(self, host: str = "127.0.0.1") -> int:
        self._server = await asyncio.start_server(self._handle, host=host)
        self.listen_port = self._server.sockets[0].getsockname()[1]
        return self.listen_port

    async def stop(self) -> None:
        for w in list(self._conns):
            with suppress(Exception):
                w.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def _emit(self, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
        self._ident = (self._ident + 1) & 0xFFFF
        self._writer.write(_segment(sport, dport, seq, ack, flags, payload, self._ident), time.time())

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        cport = peer[1] if peer else 0
        sport = self.listen_port
        up_reader, up_writer = await asyncio.open_connection(self._up_host, self._up_port)
        self._conns.update((writer, up_writer))
        flow = _Flow()

        # Synthetic three-way handshake so Wireshark labels the stream cleanly.
        self._emit(cport, sport, flow.cseq, 0, SYN)
        self._emit(sport, cport, flow.sseq, flow.cseq + 1, SYN | ACK)
        self._emit(cport, sport, flow.cseq + 1, flow.sseq + 1, ACK)
        flow.cseq += 1
        flow.sseq += 1

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, *, from_client: bool) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
                    if from_client:
                        self._emit(cport, sport, flow.cseq, flow.sseq, PSH | ACK, data)
                        flow.cseq += len(data)
                    else:
                        self._emit(sport, cport, flow.sseq, flow.cseq, PSH | ACK, data)
                        flow.sseq += len(data)
            except (ConnectionError, OSError, asyncio.CancelledError):
                pass
            finally:
                # Closing one transport unblocks the peer pump's read too.
                with suppress(Exception):
                    dst.close()

        try:
            await asyncio.gather(
                pump(reader, up_writer, from_client=True),
                pump(up_reader, writer, from_client=False),
            )
        finally:
            self._emit(cport, sport, flow.cseq, flow.sseq, FIN | ACK)
            self._emit(sport, cport, flow.sseq, flow.cseq, FIN | ACK)
            for w in (writer, up_writer):
                self._conns.discard(w)
                with suppress(Exception):
                    w.close()
                with suppress(Exception):
                    await w.wait_closed()


def _make_tap(writer: PcapWriter):
    async def tap(host: str, upstream_port: int):
        proxy = RecordingProxy(writer, host, upstream_port)
        listen_port = await proxy.start(host)
        return listen_port, proxy.stop

    return tap


async def _capture_mode(mode: str, host: str, out_dir: Path) -> Path:
    path = out_dir / f"{_SCENARIOS[mode]}.pcap"
    writer = PcapWriter(path)
    try:
        await traffic_demo._run(mode, host, 0, tap=_make_tap(writer))
    finally:
        writer.close()
    print(f"[capture] wrote {path} ({writer.packets} packets)\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=tuple(_SCENARIOS), help="single scenario to capture")
    ap.add_argument("--all", action="store_true", help="capture all three scenarios")
    ap.add_argument("--out-dir", default="captures", help="directory for the .pcap files")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    modes = list(_SCENARIOS) if args.all or not args.mode else [args.mode]
    out_dir = Path(args.out_dir)

    if "tls" in modes and not Path("security/certs/server.pem").exists():
        print("[capture] TLS certs missing -- run `make certs` first; skipping tls", file=sys.stderr)
        modes = [m for m in modes if m != "tls"]
        if not modes:
            return 1

    for mode in modes:
        asyncio.run(_capture_mode(mode, args.host, out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
