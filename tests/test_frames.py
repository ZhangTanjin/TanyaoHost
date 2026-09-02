"""Wire-format regression tests: pin the 20-byte header layout (PROTOCOL.md section 2).

These exist because the header struct once diverged across files
(>IBBHII 16B / >IBBHIHI 18B vs the canonical >IBBHIII 20B), which produced the
"agent sendall succeeds, host recv times out forever" failure mode. Golden bytes
here make any future format drift fail loudly and immediately.
"""

from __future__ import annotations

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import HEADER as MOCK_HEADER  # noqa: E402
from tanyao.constants import FLAG_RESPONSE, HEADER_SIZE, PROTOCOL_VERSION  # noqa: E402
from tanyao.frames import Frame, FrameDecoder, encode_frame  # noqa: E402


class TestGoldenHeader(unittest.TestCase):
    MAGIC = 0x54594F31

    def test_header_struct_is_20_bytes(self):
        self.assertEqual(HEADER_SIZE, 20)

    def test_encode_frame_golden_bytes(self):
        """Hand-computed golden: magic|ver|flags|res|seq|cmd|len."""
        frame = Frame(flags=FLAG_RESPONSE, seq=7, cmd=30, payload={"a": 1})
        wire = encode_frame(frame)
        # 54594f31 | 01 | 01 | 0000 | 00000007 | 0000001e | 00000007 + b'{"a":1}'
        self.assertEqual(
            wire.hex(),
            "54594f31" "01" "01" "0000" "00000007" "0000001e" "00000007" + b'{"a":1}'.hex(),
        )
        self.assertEqual(len(wire), 20 + 7)

    def test_roundtrip_all_fields(self):
        frame = Frame(flags=0, seq=0xDEADBEEF, cmd=0x1234, payload={"x": "0xff", "n": 3})
        decoder = FrameDecoder()
        decoder.feed(encode_frame(frame))
        out = decoder.pop()
        self.assertIsNotNone(out)
        self.assertEqual(out.flags, 0)
        self.assertEqual(out.seq, 0xDEADBEEF)
        self.assertEqual(out.cmd, 0x1234)
        self.assertEqual(out.payload, {"x": "0xff", "n": 3})
        self.assertIsNone(decoder.pop())  # buffer fully consumed

    def test_cross_implementation_with_mock_agent_header(self):
        """The mock agent (device reference) and the host codec must agree byte-for-byte."""
        payload = b'{"ok":true}'
        wire = MOCK_HEADER.pack(self.MAGIC, PROTOCOL_VERSION, FLAG_RESPONSE, 0, 41, 10, len(payload)) + payload
        self.assertEqual(MOCK_HEADER.size, 20)
        self.assertEqual(len(wire), 20 + len(payload))

        decoder = FrameDecoder()
        decoder.feed(wire)
        out = decoder.pop()
        self.assertEqual(out.cmd, 10)
        self.assertEqual(out.seq, 41)
        self.assertEqual(out.payload, {"ok": True})
        self.assertTrue(out.is_response)

        # and the reverse direction: host encode -> mock unpack
        host_wire = encode_frame(Frame(flags=0, seq=1, cmd=30, payload={"addr": "0x0"}))
        magic, version, flags, _r, seq, cmd, length = MOCK_HEADER.unpack(host_wire[:20])
        self.assertEqual(magic, self.MAGIC)
        self.assertEqual(version, PROTOCOL_VERSION)
        self.assertEqual(seq, 1)
        self.assertEqual(cmd, 30)
        self.assertEqual(length, len(host_wire) - 20)

    def test_partial_feed_then_complete(self):
        wire = encode_frame(Frame(flags=FLAG_RESPONSE, seq=1, cmd=2, payload={"ok": True}))
        decoder = FrameDecoder()
        decoder.feed(wire[:9])
        self.assertIsNone(decoder.pop())
        decoder.feed(wire[9:])
        frame = decoder.pop()
        self.assertIsNotNone(frame)
        self.assertEqual(frame.cmd, 2)

    def test_bad_magic_rejected(self):
        bad = b"\x00" * 20
        decoder = FrameDecoder()
        decoder.feed(bad)
        with self.assertRaises(Exception):
            decoder.pop()


if __name__ == "__main__":
    unittest.main()
