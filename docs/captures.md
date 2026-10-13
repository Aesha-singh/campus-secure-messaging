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
