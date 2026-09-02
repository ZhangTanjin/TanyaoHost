"""Frame codec implementing PROTOCOL.md section 2 (20-byte binary header + JSON payload)."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass

from .constants import (
    FLAG_ERROR,
    FLAG_RESPONSE,
    FRAME_MAGIC,
    HEADER_SIZE,
    MAX_PAYLOAD,
    PROTOCOL_VERSION,
    ProtocolError,
)

_HEADER = struct.Struct(">IBBHIII")  # magic, version, flags, reserved, seq, cmd, length = 20 bytes
assert _HEADER.size == HEADER_SIZE


@dataclass(slots=True)
class Frame:
    flags: int
    seq: int
    cmd: int
    payload: dict

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def is_error(self) -> bool:
        return bool(self.flags & FLAG_ERROR)


def encode_frame(frame: Frame) -> bytes:
    payload = json.dumps(frame.payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"payload too large: {len(payload)} > {MAX_PAYLOAD}")
    header = _HEADER.pack(
        FRAME_MAGIC,
        PROTOCOL_VERSION,
        frame.flags,
        0,  # reserved
        frame.seq & 0xFFFFFFFF,
        frame.cmd & 0xFFFFFFFF,
        len(payload),
    )
    return header + payload


class FrameDecoder:
    """Incremental decoder: feed() arbitrary byte chunks, pop() complete frames."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)
        if len(self._buffer) > HEADER_SIZE + MAX_PAYLOAD:
            raise ProtocolError(f"frame exceeds MAX_PAYLOAD ({MAX_PAYLOAD})")

    def pop(self) -> Frame | None:
        if len(self._buffer) < HEADER_SIZE:
            return None
        magic, version, flags, _reserved, seq, cmd, length = _HEADER.unpack_from(self._buffer, 0)
        if magic != FRAME_MAGIC:
            raise ProtocolError(f"bad frame magic 0x{magic:08x}")
        if version != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version {version}")
        if length > MAX_PAYLOAD:
            raise ProtocolError(f"payload length {length} exceeds MAX_PAYLOAD")
        if len(self._buffer) < HEADER_SIZE + length:
            return None
        payload_bytes = bytes(self._buffer[HEADER_SIZE : HEADER_SIZE + length])
        del self._buffer[: HEADER_SIZE + length]
        try:
            payload = json.loads(payload_bytes.decode("utf-8")) if length else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"payload is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProtocolError("payload must be a JSON object")
        return Frame(flags=flags, seq=seq, cmd=cmd, payload=payload)
