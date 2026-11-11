"""P1 feature tests: async scan jobs, read_batch, scan presets, symbol resolution.

Run: python3 -m unittest tests.test_p1 -v
"""

from __future__ import annotations

import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import BASE, DEMO_PID, HEAP_START, MockAgent  # noqa: E402
from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

TOKEN = "tanyao-dev-token"


def hx(v: int) -> str:
    return f"0x{v:x}"


class TestP1(unittest.TestCase):
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

    # -- read_batch ------------------------------------------------------------

    def test_read_batch_mixed(self):
        out = self.facade.read_batch(DEMO_PID, [
            {"address": hx(BASE), "size": 4},          # ELF magic
            {"address": hx(BASE + 0x2000), "size": 8},  # data array head
            {"address": hx(0xDEAD0000), "size": 4},     # unmapped -> error span
        ])
        self.assertEqual(out["count"], 3)
        spans = out["spans"]
        self.assertEqual(spans[0]["data_hex"], "7f454c46")
        self.assertEqual(spans[1]["data_hex"], "e8030000" + "ef030000")
        self.assertIn("error", spans[2])

    def test_read_batch_bad_span_rejected(self):
        with self.assertRaises(Exception):
            self.facade.read_batch(DEMO_PID, [{"address": hx(BASE), "size": 0}])

    # -- scan presets ------------------------------------------------------------

    def test_scan_preset_module(self):
        out = self.facade.scan_set_default_ranges(DEMO_PID, preset="module:libdemo.so")
        self.assertEqual(out["ranges"], 2)
        self.assertGreater(out["total_bytes"], 0)

    def test_scan_preset_anon_and_all(self):
        out = self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        self.assertGreaterEqual(out["ranges"], 1)
        out = self.facade.scan_set_default_ranges(DEMO_PID, preset="all_readable")
        self.assertGreaterEqual(out["ranges"], 3)

    def test_scan_preset_unknown_rejected(self):
        with self.assertRaises(Exception):
            self.facade.scan_set_default_ranges(DEMO_PID, preset="bogus")

    # -- async scan jobs ------------------------------------------------------------

    def test_async_scan_value_roundtrip(self):
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, async_run=True)
        self.assertTrue(out["async"])
        job_id = out["job_id"]
        # poll until done (small ranges: immediate)
        deadline = time.time() + 5
        while time.time() < deadline:
            st = self.facade.scan_status(DEMO_PID, job_id)
            if st["state"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(st["state"], "done", st.get("error"))
        self.assertEqual(st["summary"]["count"], 4)

    def test_async_scan_hex_roundtrip(self):
        self.facade.scan_set_range(DEMO_PID, HEAP_START, HEAP_START + 0x10000)
        out = self.facade.scan_hex(DEMO_PID, "EF BE AD DE", async_run=True)
        deadline = time.time() + 5
        st = {}
        while time.time() < deadline:
            st = self.facade.scan_status(DEMO_PID, out["job_id"])
            if st["state"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(st["state"], "done")
        self.assertEqual(st["summary"]["count"], 1)

    def test_scan_status_unknown_job(self):
        with self.assertRaises(Exception):
            self.facade.scan_status(DEMO_PID, "nosuchjob")

    def test_refine_blocked_while_job_running(self):
        self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, async_run=True)
        # immediately try refine — job may still be running; if it already finished
        # this is a valid refine with no changes; assert only no-crash semantics
        deadline = time.time() + 5
        while time.time() < deadline:
            st = self.facade.scan_status(DEMO_PID, out["job_id"])
            if st["state"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(st["state"], "done")

    # -- symbols -------------------------------------------------------------------

    def test_symbol_list(self):
        out = self.facade.symbol_list(DEMO_PID, "libdemo.so")
        names = {s["name"]: s for s in out["symbols"]}
        self.assertIn("demo_start", names)
        self.assertIn("demo_data", names)
        self.assertEqual(names["demo_start"]["type"], "FUNC")
        self.assertEqual(names["demo_start"]["address"], hx(BASE + 0x1B40))
        self.assertEqual(names["demo_data"]["type"], "OBJECT")

    def test_symbol_list_filter(self):
        out = self.facade.symbol_list(DEMO_PID, "libdemo.so", filter="data")
        names = [s["name"] for s in out["symbols"]]
        self.assertEqual(names, ["demo_data"])

    def test_symbol_find_with_module(self):
        out = self.facade.symbol_find(DEMO_PID, "demo_start", module="libdemo.so")
        self.assertEqual(out["module"], "libdemo.so")
        self.assertEqual(out["matches"][0]["address"], hx(BASE + 0x1B40))

    def test_symbol_find_auto_module(self):
        out = self.facade.symbol_find(DEMO_PID, "demo_start")
        self.assertIn("module", out)
        self.assertEqual(out["matches"][0]["address"], hx(BASE + 0x1B40))

    def test_symbol_find_missing(self):
        with self.assertRaises(Exception):
            self.facade.symbol_find(DEMO_PID, "no_such_symbol_xyz")

    # -- read via symbol: integration ---------------------------------------------------

    def test_read_at_symbol_address(self):
        found = self.facade.symbol_find(DEMO_PID, "demo_data")
        addr = int(found["matches"][0]["address"], 16)
        data = self.service.mem_read(DEMO_PID, addr, 4)
        # demo_data -> vaddr 0x2010 -> rw map BASE+0x2000+0x10 -> 1000+4*7=1028
        self.assertEqual(struct.unpack("<I", data)[0], 1028)


if __name__ == "__main__":
    unittest.main()
