"""v1.2 wire-format regression: PAYLOAD_BINARY frames, the 24B dump_pull chunk
sub-header, and the packed symbol table (PROTOCOL_V1.2_DRAFT §2/§3.1/§3.5).

Golden bytes here pin the new layouts the same way test_frames.py pins the
20B header (the 16/18B header-variant incident, architecture doc §10).
Run: python3 -m unittest tests.test_frames_v12 -v
"""

from __future__ import annotations

import os
import struct
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tanyao.constants import (  # noqa: E402
    FLAG_PAYLOAD_BINARY,
    FLAG_RESPONSE,
    FRAME_MAGIC,
    HEADER_SIZE,
    PROTOCOL_VERSION,
    ProtocolError,
)
from tanyao.frames import (  # noqa: E402
    DUMP_CHUNK_HEADER,
    DUMP_CHUNK_HEADER_SIZE,
    PACKED_SYMBOL_ENTRY,
    PACKED_SYMBOL_HEADER,
    Frame,
    FrameDecoder,
    decode_dump_chunk,
    decode_packed_symbols,
    encode_dump_chunk,
    encode_frame,
)


def _frame_with_binary_payload(seq: int, cmd: int, body: bytes) -> bytes:
    header = struct.pack(
        ">IBBHIII", FRAME_MAGIC, PROTOCOL_VERSION,
        FLAG_RESPONSE | FLAG_PAYLOAD_BINARY, 0, seq, cmd, len(body),
    )
    return header + body


class TestBinaryFrames(unittest.TestCase):
    def test_binary_frame_roundtrip(self):
        body = bytes(range(256))
        decoder = FrameDecoder()
        decoder.feed(_frame_with_binary_payload(9, 65, body))
        frame = decoder.pop()
        self.assertIsNotNone(frame)
        self.assertTrue(frame.is_binary)
        self.assertTrue(frame.is_response)
        self.assertEqual(frame.payload, body)
        self.assertEqual(frame.seq, 9)
        self.assertEqual(frame.cmd, 65)

    def test_binary_frame_golden_bytes(self):
        """Hand-computed golden: magic|ver|RESPONSE|BINARY|res|seq|cmd|len."""
        wire = _frame_with_binary_payload(1, 65, b"\xde\xad")
        self.assertEqual(
            wire.hex(),
            "54594f31" "01" "05" "0000" "00000001" "00000041" "00000002" "dead",
        )

    def test_json_frame_unaffected(self):
        decoder = FrameDecoder()
        decoder.feed(encode_frame(Frame(flags=FLAG_RESPONSE, seq=2, cmd=10, payload={"ok": True})))
        frame = decoder.pop()
        self.assertFalse(frame.is_binary)
        self.assertEqual(frame.payload, {"ok": True})

    def test_coalesced_frames_do_not_falsely_reject(self):
        """Two legal frames coalesced in one feed must both pop (regression: the
        old feed() sized its MAX_PAYLOAD check against the whole buffer)."""
        a = encode_frame(Frame(flags=FLAG_RESPONSE, seq=1, cmd=2, payload={"n": 1}))
        b = encode_frame(Frame(flags=FLAG_RESPONSE, seq=2, cmd=2, payload={"n": 2}))
        decoder = FrameDecoder()
        decoder.feed(a + b)
        first, second = decoder.pop(), decoder.pop()
        self.assertEqual((first.payload["n"], second.payload["n"]), (1, 2))
        self.assertIsNone(decoder.pop())

    def test_oversized_binary_length_rejected(self):
        bad = struct.pack(">IBBHIII", FRAME_MAGIC, PROTOCOL_VERSION,
                          FLAG_RESPONSE | FLAG_PAYLOAD_BINARY, 0, 1, 65,
                          (16 * 1024 * 1024) + 1)
        decoder = FrameDecoder()
        decoder.feed(bad + b"\x00" * 64)
        with self.assertRaises(ProtocolError):
            decoder.pop()


class TestDumpChunkSubHeader(unittest.TestCase):
    def test_subheader_is_24_bytes(self):
        self.assertEqual(DUMP_CHUNK_HEADER.size, DUMP_CHUNK_HEADER_SIZE)
        self.assertEqual(DUMP_CHUNK_HEADER_SIZE, 24)

    def test_encode_golden_bytes(self):
        """offset=0x10, data='ab', raw_len=2, flags=1(deflate), crc32('ab')."""
        wire = encode_dump_chunk(0x10, b"ab", 2, 1)
        crc = zlib.crc32(b"ab") & 0xFFFFFFFF
        self.assertEqual(
            wire.hex(),
            f"{0x10:016x}" f"{2:08x}" f"{2:08x}" "01" "000000" f"{crc:08x}" "6162",
        )

    def test_roundtrip_and_flags(self):
        chunk = decode_dump_chunk(encode_dump_chunk(0x1234, b"\x01\x02\x03", 3, 0x02))
        self.assertEqual(chunk.offset, 0x1234)
        self.assertEqual(chunk.data, b"\x01\x02\x03")
        self.assertEqual(chunk.raw_len, 3)
        self.assertTrue(chunk.is_last)
        self.assertFalse(chunk.is_deflated)

    def test_crc_mismatch_rejected(self):
        payload = bytearray(encode_dump_chunk(0, b"abcd", 4, 0))
        payload[-1] ^= 0xFF  # corrupt data byte -> crc mismatch
        with self.assertRaises(ProtocolError):
            decode_dump_chunk(bytes(payload))

    def test_short_payload_rejected(self):
        with self.assertRaises(ProtocolError):
            decode_dump_chunk(b"\x00" * 10)

    def test_data_len_mismatch_rejected(self):
        header = DUMP_CHUNK_HEADER.pack(0, 4, 4, 0, zlib.crc32(b"abc") & 0xFFFFFFFF)
        with self.assertRaises(ProtocolError):
            decode_dump_chunk(header + b"abc")  # claims 4, carries 3


def _build_packed(rows, modules):
    name_blob = bytearray()
    name_offs = []
    for name, _addr, _size in rows:
        name_offs.append(len(name_blob))
        name_blob += name.encode() + b"\x00"
    module_blob = bytearray()
    module_offs = {}
    for m in modules:
        module_offs[m] = len(module_blob)
        module_blob += m.encode() + b"\x00"
    out = bytearray(PACKED_SYMBOL_HEADER.pack(len(rows), len(modules),
                                              len(name_blob), len(module_blob)))
    for (name, addr, size), noff in zip(rows, name_offs):
        out += PACKED_SYMBOL_ENTRY.pack(addr, size, noff, module_offs["libc.so"])
    return bytes(out + name_blob + module_blob)


class TestPackedSymbols(unittest.TestCase):
    ROWS = [("pthread_create", 0x7DD2EF1160, 64), ("memcpy", 0x7DD2EF0A40, 32)]
    MODULES = ["libc.so"]

    def test_decode_roundtrip(self):
        decoded = decode_packed_symbols(_build_packed(self.ROWS, self.MODULES))
        self.assertEqual(decoded["count"], 2)
        self.assertEqual(decoded["names"], ["pthread_create", "memcpy"])
        self.assertEqual(decoded["addresses"], ["0x7dd2ef1160", "0x7dd2ef0a40"])
        self.assertEqual(decoded["sizes"], [64, 32])
        self.assertEqual(decoded["modules"], ["libc.so"])

    def test_name_offset_outside_blob_rejected(self):
        payload = bytearray(_build_packed(self.ROWS, self.MODULES))
        # first entry's name_off (at 16+8+4=byte 28) -> far beyond the blob
        struct.pack_into("<I", payload, 28, 0xFFFF)
        with self.assertRaises(ProtocolError):
            decode_packed_symbols(bytes(payload))

    def test_module_idx_outside_blob_rejected(self):
        payload = bytearray(_build_packed(self.ROWS, self.MODULES))
        struct.pack_into("<I", payload, 16 + PACKED_SYMBOL_ENTRY.size - 4, 0xFFFF)
        with self.assertRaises(ProtocolError):
            decode_packed_symbols(bytes(payload))

    def test_truncated_payload_rejected(self):
        payload = _build_packed(self.ROWS, self.MODULES)
        with self.assertRaises(ProtocolError):
            decode_packed_symbols(payload[:-4])

    def test_unterminated_name_rejected(self):
        payload = bytearray(_build_packed(self.ROWS, self.MODULES))
        payload[payload.index(b"\x00", 0) :]  # noqa: B018 — keep reference obvious
        # strip ALL NULs from the name blob region (bytes after the 16B header
        # + entries): decode must fail rather than return partial names
        header_size = 16 + PACKED_SYMBOL_ENTRY.size * len(self.ROWS)
        body = bytes(payload[:header_size]) + bytes(payload[header_size:]).replace(b"\x00", b"")
        with self.assertRaises(ProtocolError):
            decode_packed_symbols(body)


if __name__ == "__main__":
    unittest.main()
