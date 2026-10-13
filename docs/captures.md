# Network captures: proving PLAIN vs E2EE vs TLS

This is the evidence pack for the networking half of the viva.  It shows, at
the packet level, exactly what each layer hides.  Run the demo script while
capturing on the loopback interface, then answer the three questions below
with your own screenshots.

## What to capture and why

| Scenario | Transport | E2EE | Wireshark sees |
|----------|-----------|------|----------------|
| A. `--mode plain` | cleartext TCP | off | full protocol **and the plaintext marker** |
| B. `--mode e2ee`  | cleartext TCP | on  | full protocol, **marker is gone** (GCM ciphertext) |
| C. `--mode tls`   | TLS 1.3   | (n/a) | one opaque encrypted stream; no CSCP fields at all |

The marker sent in every run is `CAMPUS-E2EE-DEMO-MARKER`.  The whole point:
in A it is readable, in B it is not even though the TCP is still cleartext,
and in C the entire protocol header disappears behind TLS.

## Root-free capture (default in this repo)

`tcpdump`/`dumpcap` need raw-socket privileges, which often means a `sudo`
password we may not have.  Instead, `scripts/pcap_capture.py` inserts a
**userspace TCP tap** between the client and the server: a plain `asyncio` relay
that copies every byte both ways and re-frames them into synthesized IPv4/TCP
packets (valid header checksums) written as a standard **libpcap** file with
`linktype 228` (`LINKTYPE_IPV4`).  Wireshark opens it exactly like a `tcpdump`
capture -- because it is one; we only forged the IP layer ourselves.

```bash
make pcap                     # -> captures/{A-plain,B-e2ee,C-tls}.pcap
# or one scenario:
python scripts/pcap_capture.py --mode e2ee
```

The committed `captures/*.pcap` files are produced this way, so the evidence is
reproducible without root.  The tap is the *same* bytes the application sends --
it is just another TCP endpoint, which is itself the lesson: TLS/E2EE operate
end-to-end, so a relay in the middle cannot read them.

The `sudo tcpdump` recipes below are the classic alternative if you *do* have
root (and preferable when you want to capture real NIC traffic, not loopback).

## Setup

```bash
# from the repo root, in the venv
python -m pip install -e ".[dev]"
mkdir -p captures
```

### Scenario A -- cleartext, no E2EE

```bash
sudo tcpdump -i lo0 -s 0 -w captures/A-plain.pcap 'tcp port 9443'
python scripts/traffic_demo.py --mode plain      # in a second terminal
# Ctrl-C tcpdump
```

In Wireshark: `File > Open -> captures/A-plain.pcap`, then
`Analyze > Follow > TCP Stream`.  You should be able to read:

```
{"msg_id":"m-...","sender_id":"u_alice",...}CAMPUS-E2EE-DEMO-MARKER...
```

Display filter that isolates the interesting bytes:

```
tcp.port == 9443 and tcp contains "CAMPUS-E2EE-DEMO-MARKER"
```

### Scenario B -- cleartext transport, E2EE enabled

```bash
sudo tcpdump -i lo0 -s 0 -w captures/B-e2ee.pcap 'tcp port 9443'
python scripts/traffic_demo.py --mode e2ee
```

Now repeat the stream-follow.  The marker is **absent**; the `ciphertext`
field holds `nonce(12) || ciphertext || tag(16)`.  This is the killer frame for
the demo: the transport is still plain TCP, yet the payload is unreadable.

```
tcp.port == 9443 and tcp contains "CAMPUS-E2EE-DEMO-MARKER"   # -> no matches
```

The script also prints `marker visible on wire: False` and the envelope size
(`len(marker)+28`), which you can compare against the byte count in Wireshark.

### Scenario C -- TLS 1.3

TLS needs certificates.  Generate the local dev CA + server cert first (see
`security/certs.py` / the `make certs` target), then:

```bash
sudo tcpdump -i lo0 -s 0 -w captures/C-tls.pcap 'tcp port 9443'
python scripts/traffic_demo.py --mode tls
```

In Wireshark, open the pcap and apply `tls`.  You will see:

1. a **ClientHello / ServerHello** handshake with `TLSv1.3` and the negotiated
   cipher suite (`TLS_AES_256_GCM_SHA384`);
2. after the handshake, every record is `Content Type: Application Data
   (23)` -- a uniform encrypted blob.

There is no way to read the CSCP header or the marker: TLS protects the whole
protocol, not just the payload.  Display filter:

```
tcp.port == 9443 and tls.handshake.type == 1     # ClientHello
tcp.port == 9443 and tls.record.content_type == 23
```

## Screenshot checklist (paste into the report)

- [ ] A: Follow-TCP-Stream showing the readable marker.
- [ ] B: same stream, marker absent; `tcp contains "CAMPUS-..."` filter matches
      0 packets.
- [ ] C: TLS ClientHello with `TLSv1.3` + the GCM suite, followed by
      Application Data records.
- [ ] One packet-detail pane showing the CSCP framing
      (msg_type / length / sequence) in A or B, and its absence in C.

## Cross-checking with the live metrics

While the capture runs, the server's admin dashboard reports the same events
as numbers (`bytes_in` / `bytes_out` / `messages_direct`):

```bash
CSCP_ADMIN_TOKEN=devtoken python -m server.main --auth stub &
curl -s -H "Authorization: Bearer devtoken" http://127.0.0.1:9444/metrics
```

## Bandwidth / overhead notes

- E2EE adds a **constant 28 bytes per message** (12-byte nonce + 16-byte GCM
  tag); this is asserted in `tests/security/test_e2ee.py`.
- Every CSCP frame adds a fixed header on top (see `protocol/spec.md`), and the
  length is independent of payload entropy -- so the overhead is predictable.
- TLS adds its own record/handshake overhead but authenticates the channel;
  measure both with `tests/load` (phase 10) if you want numbers for the report.

## Benchmark charts

The load sweep is charted for the report by `scripts/bench_charts.py`
(`make charts`), which writes `docs/charts/throughput.png` and
`docs/charts/latency.png`.  See `docs/benchmarks.md` for the numbers and the
networking reading of the shape (throughput rises then plateaus; the RTT tail
bends up as concurrency grows -- Little's law on a single event loop).
