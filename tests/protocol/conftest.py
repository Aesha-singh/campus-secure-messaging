"""Shared fixtures/helpers for protocol tests."""

from __future__ import annotations

import struct
from collections.abc import Callable

import pytest

from protocol.codec import compute_crc
from protocol.constants import MAGIC, PROTOCOL_VERSION, MessageType

RawFrameBuilder = Callable[..., bytes]


@pytest.fixture
def raw_frame() -> RawFrameBuilder:
    """Build an arbitrary (possibly malformed) frame for negative tests."""

    def _build(
        *,
        magic: bytes = MAGIC,
        version: int = PROTOCOL_VERSION,
        mtype: int = int(MessageType.PING),
        flags: int = 0,
        payload: bytes = b"",
        seq: int = 0,
        crc: int | None = None,
        payload_len: int | None = None,
    ) -> bytes:
        length = len(payload) if payload_len is None else payload_len
        header = struct.pack(">4sBBHIQ", magic, version, mtype, flags, length, seq)
        trailer = compute_crc(header, payload) if crc is None else crc
        return header + payload + struct.pack(">I", trailer)

    return _build
