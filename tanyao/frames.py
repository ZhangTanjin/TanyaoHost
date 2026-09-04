"""Frame codec implementing PROTOCOL.md section 2 (20-byte binary header + JSON
payload) plus the v1.2 draft §2/§3 extensions: PAYLOAD_BINARY response frames,
the dump_pull 24-byte chunk sub-header, and the packed symbol-table layout.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass

from .constants import (
    FLAG_ERROR,
    FLAG_PAYLOAD_BINARY,
    FLAG_RESPONSE,
    FRAME_MAGIC,
    HEADER_SIZE,
    MAX_PAYLOAD,
    PROTOCOL_VERSION,
    ProtocolError,
)

_HEADER = struct.Struct(">IBBHIII")  # magic, version, flags, reserved, seq, cmd, length = 20 bytes
assert _HEADER.size == HEADER_SIZE

# v1.2 draft §3.5: dump_pull chunk sub-header (24B, big-endian):
# offset u64 | data_len u32 | raw_len u32 | flags u8 | reserved 3x0 | crc32 u32
DUMP_CHUNK_HEADER = struct.Struct(">QIIB3xI")
DUMP_CHUNK_HEADER_SIZE = 24
assert DUMP_CHUNK_HEADER.size == DUMP_CHUNK_HEADER_SIZE

DUMP_CHUNK_DEFLATE = 0x01
DUMP_CHUNK_LAST = 0x02

# v1.2 draft §3.1: packed symbol table (big-endian).
# header: count u32 | module_count u32 | name_blob_size u32 | module_blob_size u32
# entry (20B x count): addr u64 | size u32 | name_off u32 | module_idx u32
# then name_blob, then module_blob (NUL-terminated strings, offsets relative
# to their own blob start; module_idx is a byte offset into module_blob).
PACKED_SYMBOL_HEADER = struct.Struct(">IIII")
PACKED_SYMBOL_ENTRY = struct.Struct(">QIII")
PACKED_SYMBOL_ENTRY_SIZE = 20
assert PACKED_SYMBOL_ENTRY.size == PACKED_SYMBOL_ENTRY_SIZE


@dataclass(slots=True)
class Frame:
    flags: int
    seq: int
    cmd: int
    payload: dict | bytes  # bytes when the response carries PAYLOAD_BINARY

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def is_error(self) -> bool:
        return bool(self.flags & FLAG_ERROR)

    @property
    def is_binary(self) -> bool:
        return bool(self.flags & FLAG_PAYLOAD_BINARY)


def encode_frame(frame: Frame) -> bytes:
    if isinstance(frame.payload, (bytes, bytearray)):
        # Host requests are JSON-only per draft §2; binary payloads are only
        # ever encoded by tests/reference tooling, flagged explicitly.
        payload = bytes(frame.payload)
        flags = frame.flags | FLAG_PAYLOAD_BINARY
    else:
        payload = json.dumps(frame.payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        flags = frame.flags
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"payload too large: {len(payload)} > {MAX_PAYLOAD}")
    header = _HEADER.pack(
        FRAME_MAGIC,
        PROTOCOL_VERSION,
        flags,
        0,  # reserved
        frame.seq & 0xFFFFFFFF,
        frame.cmd & 0xFFFFFFFF,
        len(payload),
    )
    return header + payload


class FrameDecoder:
    """Incremental decoder: feed() arbitrary byte chunks, pop() complete frames.

    feed() only rejects runaway garbage streams (buffer > 2× the max frame);
    the authoritative MAX_PAYLOAD check happens per-frame in pop(), so a
    single recv coalescing several legal frames is not falsely rejected.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)
        if len(self._buffer) > 2 * MAX_PAYLOAD + HEADER_SIZE:
            raise ProtocolError(f"stream exceeds framing limits ({MAX_PAYLOAD})")

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
        if flags & FLAG_PAYLOAD_BINARY:
            return Frame(flags=flags, seq=seq, cmd=cmd, payload=payload_bytes)
        try:
            payload = json.loads(payload_bytes.decode("utf-8")) if length else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"payload is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProtocolError("payload must be a JSON object")
        return Frame(flags=flags, seq=seq, cmd=cmd, payload=payload)


# -- dump_pull chunk sub-header (v1.2 draft §3.5) --------------------------------


@dataclass(slots=True)
class DumpChunk:
    offset: int
    data: bytes          # as-received (still compressed when flags & DEFLATE)
    raw_len: int         # decompressed length
    flags: int           # bit0 deflate, bit1 last

    @property
    def is_deflated(self) -> bool:
        return bool(self.flags & DUMP_CHUNK_DEFLATE)

    @property
    def is_last(self) -> bool:
        return bool(self.flags & DUMP_CHUNK_LAST)


def encode_dump_chunk(offset: int, data: bytes, raw_len: int, flags: int) -> bytes:
    import zlib

    head = DUMP_CHUNK_HEADER.pack(offset, len(data), raw_len, flags, zlib.crc32(data) & 0xFFFFFFFF)
    return head + data


def decode_dump_chunk(payload: bytes) -> DumpChunk:
    if len(payload) < DUMP_CHUNK_HEADER_SIZE:
        raise ProtocolError(f"dump chunk shorter than {DUMP_CHUNK_HEADER_SIZE}B sub-header")
    offset, data_len, raw_len, flags, crc = DUMP_CHUNK_HEADER.unpack_from(payload, 0)
    data = payload[DUMP_CHUNK_HEADER_SIZE:]
    if len(data) != data_len:
        raise ProtocolError(f"dump chunk data_len {data_len} != payload {len(data)}")
    import zlib

    if (zlib.crc32(data) & 0xFFFFFFFF) != crc:
        raise ProtocolError(f"dump chunk crc mismatch at offset 0x{offset:x}")
    return DumpChunk(offset=offset, data=data, raw_len=raw_len, flags=flags)


# -- packed symbol table (v1.2 draft §3.1) ----------------------------------------


def decode_packed_symbols(payload: bytes) -> dict:
    """Decode the packed symbol_batch response into column arrays.

    Raises ProtocolError on any structural violation (short buffer, offsets
    outside their blob, unterminated names) — malformed frames must never
    surface as partially-populated results.
    """
    if len(payload) < PACKED_SYMBOL_HEADER.size:
        raise ProtocolError("packed symbol table shorter than 16B header")
    count, module_count, name_blob_size, module_blob_size = PACKED_SYMBOL_HEADER.unpack_from(payload, 0)
    entries_off = PACKED_SYMBOL_HEADER.size
    name_blob_off = entries_off + PACKED_SYMBOL_ENTRY_SIZE * count
    module_blob_off = name_blob_off + name_blob_size
    expected = module_blob_off + module_blob_size
    if len(payload) != expected:
        raise ProtocolError(
            f"packed symbol table size mismatch: got {len(payload)}, header says {expected}"
        )

    def cstr(blob: bytes, off: int) -> str:
        if not 0 <= off < len(blob):
            raise ProtocolError(f"packed symbol string offset {off} outside blob ({len(blob)}B)")
        end = blob.find(b"\x00", off)
        if end < 0:
            raise ProtocolError(f"unterminated string at blob offset {off}")
        return blob[off:end].decode("utf-8", "replace")

    names: list[str] = []
    addresses: list[str] = []
    sizes: list[int] = []
    module_indexes: list[int] = []
    module_blob = payload[module_blob_off:module_blob_off + module_blob_size]
    name_blob = payload[name_blob_off:name_blob_off + name_blob_size]
    for i in range(count):
        addr, size, name_off, module_idx = PACKED_SYMBOL_ENTRY.unpack_from(payload, entries_off + i * PACKED_SYMBOL_ENTRY_SIZE)
        names.append(cstr(name_blob, name_off))
        addresses.append(f"0x{addr:x}")
        sizes.append(size)
        module_indexes.append(module_idx)
    # module_idx is a BYTE OFFSET into module_blob (draft §3.1), not an index
    for idx in module_indexes:
        if not 0 <= idx < len(module_blob):
            raise ProtocolError(f"module_idx {idx} outside module_blob ({len(module_blob)}B)")
    # rebuild the module name table by walking the concatenated blob
    modules: list[str] = []
    pos = 0
    while pos < len(module_blob):
        end = module_blob.find(b"\x00", pos)
        if end < 0:
            raise ProtocolError("unterminated module name in module_blob")
        modules.append(module_blob[pos:end].decode("utf-8", "replace"))
        pos = end + 1
    return {
        "count": count,
        "truncated": False,  # packed carries no truncated flag; bounded by max_symbols
        "modules": modules,
        "module_indexes": module_indexes,
        "names": names,
        "addresses": addresses,
        "sizes": sizes,
        "types": [""] * count,  # not represented in packed layout
    }
