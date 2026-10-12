"""Hypothesis fuzzing: frame decoder correctness under arbitrary segmentation.

These properties encode the two TCP-stream guarantees we must not break:

1. **Arbitrary segmentation** -- however the kernel splits the byte stream, the
   decoder reconstructs exactly the original frames (this is what
   `FrameDecoder` exists for).
2. **Garbage never crashes the decoder** -- fuzzed input may raise only defined
   :class:`CscpError` exceptions; anything else is a bug.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from protocol.codec import Frame, FrameDecoder, encode_frame
from protocol.constants import MessageType
from protocol.errors import CscpError

_MESSAGE_TYPES = list(MessageType)


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(
    payloads=st.lists(
        st.binary(max_size=512), min_size=1, max_size=8,
    ),
    split=st.integers(min_value=1, max_value=31),
)
def test_arbitrary_segmentation_reconstructs_frames(
    payloads: list[bytes], split: int
) -> None:
    frames = [
        Frame(MessageType.PING, i, payload=p, flags=0) for i, p in enumerate(payloads)
    ]
    blob = b"".join(encode_frame(f) for f in frames)
    dec = FrameDecoder(max_frame_size=1 << 20)
    out: list[Frame] = []
    for i in range(0, len(blob), split):
        dec.feed(blob[i : i + split])
        out.extend(dec.frames())
    assert out == frames
    assert dec.next_frame() is None
    assert dec.buffered == 0


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(
    trailing=st.binary(max_size=256),
    payload=st.binary(max_size=128),
    seq=st.integers(min_value=0, max_value=1 << 32),
)
def test_valid_frame_then_garbage_keeps_defined_behavior(
    trailing: bytes, payload: bytes, seq: int
) -> None:
    blob = encode_frame(Frame(MessageType.PING, seq, payload)) + trailing
    dec = FrameDecoder(max_frame_size=1 << 20)
    try:
        dec.feed(blob)
        dec.frames()
    except CscpError:
        # Garbage after a valid frame is allowed to raise a FrameError; the
        # connection owner decides whether to resync or close.
        return


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(data=st.binary(max_size=512))
def test_arbitrary_bytes_only_raise_cscp_errors(data: bytes) -> None:
    dec = FrameDecoder(max_frame_size=1024)
    dec.feed(data)
    try:
        dec.frames()
    except CscpError:
        # Defined protocol error (magic / CRC / oversized): acceptable.
        return
    # No unexpected exception raised: parser state stayed consistent.