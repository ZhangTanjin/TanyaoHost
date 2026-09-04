"""Field-test regression (P1/P2 from TANYAO_FIELD_TEST_REPORT.md).

P1: full-anon scan must survive unreadable special pages ([vvar] PFNMAP) —
    bisect-skip, preserve hits, report skipped ranges.
P2-1: read_batch span isolation — a bad span must not pollute later spans
    (kernel readv prefix-cancellation semantics are emulated by the mock).
P2-2: dump_module file-layout reconstruction — file-backed mappings written at
    their FILE OFFSET (vaddr drifts), -w-p tail mappings included.

Run: python3 -m unittest tests.test_field -v
"""

from __future__ import annotations

import json
import time
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import BASE, DEMO_PID, HEAP_START, MockAgent  # noqa: E402
from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

TOKEN = "tanyao-dev-token"


def hx(v: int) -> str:
    return f"0x{v:x}"


class TestFieldRegression(unittest.TestCase):
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

    # -- P1: scan resilience -------------------------------------------------

    def test_scan_survives_poison_hole(self):
        """Heap contains a poisoned 4KB hole ([vvar] analogue) at +0x8000.
        Scan must complete (not raise), keep hits before AND after the hole,
        and report the skipped range."""
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        out = self.facade.scan_value(DEMO_PID, "u32", 1337)
        self.assertEqual(out["count"], 4)  # 0x1000, 0x2000, 0x3004, 0xA000 (after hole)
        self.assertGreaterEqual(out["skipped_ranges"], 1)
        addrs = {int(x["address"], 16) for x in out["results"]}
        self.assertIn(HEAP_START + 0xA000, addrs)  # hit AFTER the hole survived

    def test_scan_hex_survives_hole(self):
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        out = self.facade.scan_hex(DEMO_PID, "EF BE AD DE")
        self.assertEqual(out["found"], 1)
        self.assertEqual(out["results"][0]["address"], hx(HEAP_START + 0x488))

    def test_scan_skipped_accounting(self):
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        self.facade.scan_value(DEMO_PID, "u32", 1337)
        st = self.facade.scan_results(DEMO_PID)
        # escalation may round skipped regions up to probe granularity; the
        # invariant is: hole detected, at least the 4KB hole accounted
        self.assertGreaterEqual(st["skipped_ranges"], 1)
        self.assertGreaterEqual(st["skipped_bytes"], 0x1000)

    # -- P2-1: read_batch span isolation ---------------------------------------

    def test_read_batch_bad_span_no_pollution(self):
        """Mock emulates kernel prefix-cancellation: spans after the first
        failure report ECANCELED. Host must recover them individually."""
        out = self.facade.read_batch(DEMO_PID, [
            {"address": hx(BASE), "size": 4},            # good
            {"address": hx(0xDEAD0000), "size": 4},      # bad (unmapped)
            {"address": hx(BASE + 0x2000), "size": 4},   # good, AFTER the bad span
        ])
        spans = out["spans"]
        self.assertEqual(spans[0]["data_hex"], "7f454c46")     # before failure: ok
        self.assertIn("error", spans[1])                        # the bad span: error
        self.assertEqual(spans[2]["data_hex"], "e8030000")      # AFTER: recovered, not polluted

    # -- P2-2: dump file-layout reconstruction ---------------------------------

    def test_dump_includes_write_only_tail_and_file_layout(self):
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "field-libdemo.dump")
        out = self.facade.dump_module(DEMO_PID, "libdemo.so", out_path)
        try:
            data = open(out_path, "rb").read()
            # file extent = 0x4000 (r-xp 0..0x2000 @0, rw-p/-w-p @0x2000..0x3000,
            # -w-p tail span to 0x3000)
            self.assertEqual(len(data), 0x3000)
            self.assertEqual(data[:4], b"\x7fELF")
            # -w-p tail mapping content written at its FILE offset 0x2000
            self.assertEqual(data[0x2000:0x2010], bytes(range(16)))
            manifest = json.load(open(out_path + ".manifest.json"))
            wtail = [e for e in manifest["mappings"] if e.get("flags_str", "").startswith("-w")]
            self.assertEqual(len(wtail), 1)
            self.assertEqual(wtail[0]["out_offset"], 0x2000)  # file offset, not vaddr
        finally:
            os.remove(out_path)
            if os.path.exists(out_path + ".manifest.json"):
                os.remove(out_path + ".manifest.json")

    def test_dump_manifest_matches_original_layout(self):
        """PT_DYNAMIC-style validation: the -w-p tail (file 0x2000..) is present,
        so a dynamic segment living past the r-xp end is no longer truncated."""
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "field2.dump")
        out = self.facade.dump_module(DEMO_PID, "libdemo.so", out_path)
        try:
            self.assertEqual(out["size"], 0x3000)
            self.assertEqual(out["mappings"], 3)  # r-xp + rw-p + -w-p (fileless excluded)
        finally:
            os.remove(out_path)
            if os.path.exists(out_path + ".manifest.json"):
                os.remove(out_path + ".manifest.json")

    # -- P3: scan_value inline results & scan_clear keeps ranges -----------------

    def test_scan_value_results_inline(self):
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        out = self.facade.scan_value(DEMO_PID, "u32", 424242)
        self.assertEqual(out["results"][0]["address"], hx(HEAP_START + 0x4000))

    def test_scan_clear_keeps_ranges(self):
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        self.facade.scan_value(DEMO_PID, "u32", 424242)
        self.facade.scan_clear(DEMO_PID)
        # after clear: ranges must survive — no re-set needed for a new scan
        out = self.facade.scan_value(DEMO_PID, "u32", 424242)
        self.assertEqual(out["found"], 1)


class TestAobStraddle(unittest.TestCase):
    """scan_hex carry semantics: straddling matches found exactly once.

    Regression: a working-tree variant scanned each chunk starting AFTER the
    carry prefix (i = len(carry)), which silently dropped every AOB match
    crossing a chunk boundary. Correct behavior: scan from the carry start and
    skip only matches that END within already-scanned bytes."""

    @staticmethod
    def _engine(data: bytes, base: int) -> "ScanEngine":
        from tanyao.scan import ScanEngine

        buf = bytearray(data)

        def read(pid, addr, size):
            off = addr - base
            if off < 0 or off + size > len(buf):
                raise MemoryError("out of range")
            return bytes(buf[off : off + size])

        eng = ScanEngine(read)  # no readv: deterministic chunking path
        eng.set_ranges(1, [(base, base + len(buf))])
        return eng

    def test_straddling_match_found_across_chunk_boundary(self):
        base = 0x100000
        data = bytearray(b"\xcc" * 0x100)
        marker = bytes.fromhex("EFBEADDE")
        data[0x1E:0x22] = marker  # straddles a 0x20-byte boundary
        eng = self._engine(bytes(data), base)
        for chunk in (0x10, 0x20, 0x21, 0x40):
            eng.scan_hex(1, marker, b"\xff" * 4, chunk=chunk)
            self.assertEqual(
                eng.state.hits[0].address,
                base + 0x1E,
                f"straddle missed with chunk=0x{chunk:x}",
            )
            self.assertEqual(len(eng.state.hits), 1)

    def test_no_duplicates_across_many_chunks(self):
        base = 0x200000
        data = bytearray(b"\x00" * 0x200)
        marker = bytes.fromhex("CAFEF00D")
        data[0x40:0x44] = marker
        data[0x140:0x144] = marker
        eng = self._engine(bytes(data), base)
        found = eng.scan_hex(1, marker, b"\xff" * 4, chunk=0x18)
        self.assertEqual(found, 2)
        self.assertEqual({h.address for h in eng.state.hits}, {base + 0x40, base + 0x140})

    def test_wildcard_straddle(self):
        base = 0x300000
        data = bytearray(b"\x11" * 0x80)
        data[0x3F:0x43] = bytes.fromhex("7F450000")  # ?? ?? wildcard tail crosses 0x40
        eng = self._engine(bytes(data), base)
        eng.scan_hex(1, bytes.fromhex("7F450000"), bytes.fromhex("FFFF0000"), chunk=0x20)
        self.assertEqual([h.address for h in eng.state.hits], [base + 0x3F])


if __name__ == "__main__":
    unittest.main()


class TestScanCancel(unittest.TestCase):
    """scan_cancel: running hex job stops between chunks; state becomes cancelled."""

    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN)
        cls.agent.start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def test_cancel_running_hex_job(self):
        os.environ["TANYAO_ALLOW_WRITE"] = "1"
        svc = TanyaoService("127.0.0.1", self.agent.port, TOKEN)
        facade = AnalysisFacade(svc)
        svc.connect()
        try:
            facade.scan_set_range(DEMO_PID, HEAP_START, HEAP_START + 0x10000)
            out = facade.scan_hex(DEMO_PID, "EF BE AD DE", async_run=True)
            job_id = out["job_id"]
            self.assertTrue(facade.scan_cancel(DEMO_PID, job_id)["cancel_requested"])
            deadline = time.time() + 5
            while time.time() < deadline:
                st = facade.scan_status(DEMO_PID, job_id)
                if st["state"] != "running":
                    break
                time.sleep(0.05)
            self.assertEqual(st["state"], "cancelled")
            # cancel on finished job -> error
            with self.assertRaises(Exception):
                facade.scan_cancel(DEMO_PID, job_id)
        finally:
            svc.close()
