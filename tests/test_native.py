"""Toolchain regression: disassemble / strings / apk tools (native analysis).

All against MockAgent (no device). Complements test_field.py (P1/P2 fixes) and
test_e2e.py. Run: python3 -m unittest tests.test_native -v
"""

from __future__ import annotations

import os
import struct
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import BASE, DEMO_PID, HEAP_START, MockAgent  # noqa: E402
from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.native import disassemble_a64, extract_strings, parse_axml  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

TOKEN = "tanyao-dev-token"


def hx(v: int) -> str:
    return f"0x{v:x}"


class TestNativeUnit(unittest.TestCase):
    """Pure decoder tests, no agent needed."""

    def test_decode_prologue(self):
        data = struct.pack("<5I",
                           0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                           0xD280A720,  # mov x0, #0x539
                           0x94000100,  # bl +0x400
                           0xB4000040,  # cbz x0, +8
                           0xD65F03C0)  # ret
        insns = disassemble_a64(data, 0x1000)
        self.assertEqual(len(insns), 5)
        self.assertEqual(insns[0]["text"], "stp x29, x30, [sp, #-16]!")
        self.assertEqual(insns[1]["text"], "mov x0, #0x539")
        self.assertEqual(insns[2]["text"], "bl 0x1408")   # 0x1008 + 0x400
        self.assertEqual(insns[3]["text"], "cbz x0, 0x1014")  # 0x100c + 8
        self.assertEqual(insns[4]["text"], "ret")

    def test_decode_adrp_bcond(self):
        data = struct.pack("<2I",
                           0xB00000A0,  # adrp x0, <page>
                           0x54000040)  # b.eq +8
        insns = disassemble_a64(data, 0x2000)
        self.assertTrue(insns[0]["text"].startswith("adrp x0,"))
        self.assertEqual(insns[1]["text"], "b.eq 0x200c")

    def test_every_instruction_is_four_bytes(self):
        import random
        rng = random.Random(1234)
        blob = bytes(rng.getrandbits(8) for _ in range(1024))
        insns = disassemble_a64(blob, 0x0)
        self.assertEqual(len(insns), 256)
        for i, ins in enumerate(insns):
            self.assertEqual(ins["addr"], hx(i * 4))
        # never raises on random input

    def test_extract_strings_basic(self):
        data = b"ab\x00defgh\x00\x01\x02xyz\x00\x01\x02\xff\xfe"
        out = extract_strings(data, min_length=3)
        vals = [s["value"] for s in out]
        self.assertIn("defgh", vals)
        self.assertIn("xyz", vals)
        self.assertNotIn("ab", vals)  # below min_length

    def test_extract_strings_filter_offset(self):
        data = b"AAAA\x00ro.debuggable=1\x00"
        out = extract_strings(data, offset=0x1000, min_length=4, filter="ro\\.")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["value"], "ro.debuggable=1")
        self.assertEqual(out[0]["offset"], 0x1005)


class TestNativeFacade(unittest.TestCase):
    """Facade paths against MockAgent."""

    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN)
        cls.agent.start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def setUp(self):
        os.environ["TANYAO_ALLOW_WRITE"] = "1"
        self.service = TanyaoService("127.0.0.1", self.agent.port, TOKEN)
        self.facade = AnalysisFacade(self.service)
        self.service.connect()

    def tearDown(self):
        self.service.close()

    def test_disassemble_live_window(self):
        out = self.facade.disassemble(DEMO_PID, BASE + 0x800, count=5)
        self.assertEqual(out["module"], "libdemo.so")
        self.assertEqual(out["rva"], hx(0x800))
        texts = [i["text"] for i in out["instructions"]]
        # engine-aware: capstone prints "#-0x10" and "movz"; subset prints "#-16"/"mov"
        if out["engine"] == "capstone":
            self.assertEqual(texts[0], "stp x29, x30, [sp, #-0x10]!")
            self.assertEqual(texts[1], "movz x0, #0x539")
            self.assertEqual(texts[2], "bl #" + hx(BASE + 0x808 + 0x400))
            self.assertEqual(texts[4], "ret")
        else:
            self.assertEqual(texts[0], "stp x29, x30, [sp, #-16]!")
            self.assertEqual(texts[1], "mov x0, #0x539")
            self.assertEqual(texts[2], "bl " + hx(BASE + 0x808 + 0x400))
            self.assertEqual(texts[4], "ret")

    def test_disassemble_module_not_found(self):
        from tanyao.connection import AgentError
        with self.assertRaises(AgentError):
            self.facade.disassemble(DEMO_PID, BASE + 0x800, module="nosuch.so")

    def test_strings_module_mode(self):
        out = self.facade.strings(DEMO_PID, module="libdemo.so", min_length=6)
        vals = [s["value"] for s in out["strings"]]
        self.assertIn("tanyao_mock_engine", vals)
        self.assertIn("Java_icu_nullptr_test", vals)

    def test_strings_window_mode(self):
        out = self.facade.strings(DEMO_PID, address=HEAP_START + 0xAFF0, size=0x40, min_length=8)
        vals = [s["value"] for s in out["strings"]]
        self.assertIn("TANYAO_STRINGS_WINDOW_MARKER", vals)

    def test_strings_requires_module_or_address(self):
        from tanyao.connection import AgentError
        with self.assertRaises(AgentError):
            self.facade.strings(DEMO_PID)

    def test_apk_info_end_to_end(self):
        tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native-test.apk")
        TestAxmlParse._write_apk(tmp)
        try:
            info = self.facade.apk_info(tmp)
            self.assertEqual(info["package"], "com.example.re")
            self.assertEqual(info["launcher_activities"], ["com.example.re.MainActivity"])
        finally:
            os.unlink(tmp)


class TestAxmlParse(unittest.TestCase):
    """Binary AXML parse: hand-built minimal manifest with string pool."""

    @classmethod
    def setUpClass(cls):
        cls.strings = [
            "manifest", "package", "com.example.re", "versionName", "1.2.3",
            "uses-permission", "name", "android.permission.INTERNET",
            "activity", "com.example.re.MainActivity", "intent-filter",
            "action", "android.intent.action.MAIN",
            "category", "android.intent.category.LAUNCHER",
        ]
        cls.xml = cls._build_axml()

    @staticmethod
    def _build_string_pool(strings: list[str]) -> bytes:
        utf16 = b"".join(
            struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
            for s in strings
        )
        count = len(strings)
        header = 28
        offsets = []
        cur = 0
        for s in strings:
            offsets.append(cur)
            cur += 2 + len(s) * 2 + 2
        strings_start = header + 4 * count
        pool_size = strings_start + len(utf16)
        # type, headerSize, chunkSize, stringCount, styleCount, flags,
        # stringsStart, stylesStart — 28-byte header, fields in spec order
        return struct.pack("<HHIIIIII", 0x0001, header, pool_size, count, 0, 0,
                           strings_start, 0) \
            + b"".join(struct.pack("<I", o) for o in offsets) + utf16

    @classmethod
    def _build_axml(cls) -> bytes:
        pool = cls._build_string_pool(cls.strings)
        S = {name: i for i, name in enumerate(cls.strings)}
        chunks = [pool]

        def start(name_idx, attrs):
            attr_bytes = b""
            for aname, avalue, atype in attrs:
                # ns(4) name(4) raw_value(4) + typed_value{size(2) res0(1) type(1) data(4)} = 20
                attr_bytes += struct.pack("<iiIHBBI", -1, S[aname], 0xFFFFFFFF, 8, 0, atype, avalue)
            # 8 chunk hdr + 8 line/comment + 8 ns/name + 12 attrExt + attrs
            csize = 36 + len(attr_bytes)
            node = (struct.pack("<HHI", 0x0102, 16, csize)
                    + struct.pack("<ii", 0, -1)                     # lineNumber, comment
                    + struct.pack("<ii", -1, name_idx)              # attrExt: ns, name
                    + struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
                    + attr_bytes)
            return node

        def end(name_idx):
            return (struct.pack("<HHI", 0x0103, 16, 24)
                    + struct.pack("<ii", 0, -1)                     # lineNumber, comment
                    + struct.pack("<ii", -1, name_idx))             # ns, name

        chunks.append(start(S["manifest"], [
            ("package", S["com.example.re"], 0x03),
            ("versionName", S["1.2.3"], 0x03),
        ]))
        chunks.append(start(S["uses-permission"], [("name", S["android.permission.INTERNET"], 0x03)]))
        chunks.append(end(S["uses-permission"]))
        chunks.append(start(S["activity"], [("name", S["com.example.re.MainActivity"], 0x03)]))
        chunks.append(start(S["intent-filter"], []))
        chunks.append(start(S["action"], [("name", S["android.intent.action.MAIN"], 0x03)]))
        chunks.append(end(S["action"]))
        chunks.append(start(S["category"], [("name", S["android.intent.category.LAUNCHER"], 0x03)]))
        chunks.append(end(S["category"]))
        chunks.append(end(S["intent-filter"]))
        chunks.append(end(S["activity"]))
        chunks.append(end(S["manifest"]))

        body = b"".join(chunks)
        # RES_XML_TYPE header is exactly 8 bytes: type(2) headerSize(2) size(4)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body

    @staticmethod
    def _write_apk(path: str):
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("AndroidManifest.xml", TestAxmlParse.xml)
            zf.writestr("classes.dex", b"dex\n")

    def test_parse_axml_fields(self):
        info = parse_axml(self.xml)
        self.assertEqual(info["package"], "com.example.re")
        self.assertEqual(info["version_name"], "1.2.3")
        self.assertEqual(info["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(info["activities"], ["com.example.re.MainActivity"])
        self.assertEqual(info["launcher_activities"], ["com.example.re.MainActivity"])


if __name__ == "__main__":
    unittest.main()
