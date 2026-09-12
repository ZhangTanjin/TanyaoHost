"""R5 D13/D14: the single MapsView parser — list_modules / address_resolve /
resolve_module must agree, and nothing may fabricate ranges.

Cross-assertions (prompt §任务1.4): for the same pid, address_resolve(module
base) attribution == list_modules' module; addresses outside the snapshot are
`unknown`; the lolm six-segment fixture extends to the per-segment
list_modules shape.

Run: python3 -m unittest tests.test_r5_maps -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import DEMO_PID, HEAP_START, MockAgent  # noqa: E402
from tests.test_d9_address_meta import (  # noqa: E402
    MODULE,
    SEGMENTS,
    _MetaService,
)
from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

PID = 1
TOKEN = "tanyao-dev-token"


class _MetaServiceWithSource(_MetaService):
    def maps_source(self):
        return "target_maps"


class TestMapsViewOnMockWorld(unittest.TestCase):
    """Cross-assertions over the real mock-agent world."""

    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN)
        cls.agent.start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def setUp(self):
        self.service = TanyaoService("127.0.0.1", self.agent.port, TOKEN)
        self.facade = AnalysisFacade(self.service)
        self.service.connect()

    def tearDown(self):
        self.service.close()

    def test_list_modules_per_segment_shape(self):
        out = self.facade.list_modules(DEMO_PID)
        lib = next(m for m in out["modules"] if m["name"] == "libdemo.so")
        # D13: per-segment view — no cross-segment end merge, base == first map
        self.assertEqual(lib["base"], "0x7000000000")
        self.assertNotIn("end", lib)
        self.assertGreaterEqual(len(lib["segments"]), 2)
        for seg in lib["segments"]:
            self.assertIn("start", seg)
            self.assertIn("end", seg)
            self.assertIn("file_offset", seg)
        # segments keep their gap (no 311MB-style runaway end)
        starts = [int(s["start"], 16) for s in lib["segments"]]
        self.assertEqual(starts, sorted(starts))

    def test_address_resolve_matches_list_modules_at_every_base(self):
        mods = self.facade.list_modules(DEMO_PID)["modules"]
        self.assertGreater(len(mods), 0)
        for m in mods:
            got = self.facade.address_resolve(DEMO_PID, int(m["base"], 16))
            self.assertFalse(got.get("unknown"), f"{m['name']}: {got}")
            self.assertEqual(got["module"], m["name"],
                             f"base of {m['name']} attributed to {got.get('module')}")

    def test_outside_snapshot_is_unknown(self):
        got = self.facade.address_resolve(DEMO_PID, 0x6D00000000)
        self.assertTrue(got.get("unknown"))
        self.assertNotIn("start", got)  # no fabricated range
        self.assertNotIn("end", got)

    def test_anonymous_hit_is_not_a_module(self):
        got = self.facade.address_resolve(DEMO_PID, HEAP_START + 0x100)
        self.assertFalse(got.get("unknown"))
        self.assertTrue(got.get("anonymous"))
        self.assertIsNone(got["module"])


class TestWatchManyAndPointersTo(unittest.TestCase):
    """F1/F2 on the mock world (host route)."""

    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN)
        cls.agent.start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def setUp(self):
        self.service = TanyaoService("127.0.0.1", self.agent.port, TOKEN)
        self.facade = AnalysisFacade(self.service)
        self.service.connect()

    def tearDown(self):
        self.service.close()

    def test_watch_many_per_span_samples(self):
        out = self.facade.watch_many(DEMO_PID, [
            {"address": hex(HEAP_START + 0x4000), "size": 8},
            {"address": hex(HEAP_START + 0x1000), "size": 8},
        ], interval_ms=10, count=3)
        self.assertEqual(len(out["spans"]), 2)
        for span in out["spans"]:
            self.assertEqual(len(span["samples"]), 3)
            self.assertTrue(all(s["data_hex"] for s in span["samples"]))

    def test_watch_many_bad_span_rejected(self):
        from tanyao.connection import AgentError
        with self.assertRaises(AgentError):
            self.facade.watch_many(DEMO_PID, [{"address": hex(HEAP_START), "size": 0}])

    def test_pointers_to_finds_known_pointer(self):
        # mock world: HEAP+0x100 holds a pointer to HEAP+0x400
        out = self.facade.pointers_to(
            DEMO_PID, [HEAP_START + 0x400],
            ranges=[{"start": hex(HEAP_START), "end": hex(HEAP_START + 0x8000)}])
        self.assertEqual(out["engine"], "host-scan")
        target = out["targets"][0]
        self.assertEqual(target["address"], hex(HEAP_START + 0x400))
        self.assertEqual(target["found"], 1)
        self.assertEqual(target["pointers"][0]["address"], hex(HEAP_START + 0x100))

    def test_pointers_to_pac_strip_wildcards_top_bytes(self):
        # write a PAC-tagged variant of the pointer (top bits set), exact scan
        # must miss it, strip_pac must find it
        import struct as _struct
        tagged = (HEAP_START + 0x400) | (0x007F << 56)
        self.service.mem_write(DEMO_PID, HEAP_START + 0x200, _struct.pack("<Q", tagged))
        try:
            region = [{"start": hex(HEAP_START), "end": hex(HEAP_START + 0x8000)}]
            exact = self.facade.pointers_to(DEMO_PID, [HEAP_START + 0x400],
                                            ranges=region, strip_pac=False)
            found_exact = [p["address"] for t in exact["targets"] for p in t["pointers"]]
            stripped = self.facade.pointers_to(DEMO_PID, [HEAP_START + 0x400], ranges=region)
            found_strip = [p["address"] for t in stripped["targets"] for p in t["pointers"]]
            self.assertNotIn(hex(HEAP_START + 0x200), found_exact)
            self.assertIn(hex(HEAP_START + 0x200), found_strip)
        finally:
            self.service.mem_write(DEMO_PID, HEAP_START + 0x200, b"\x00" * 8)


class TestMapsViewOnSixSegmentFixture(unittest.TestCase):
    """lolm-shaped world: list_modules per-segment output and cross
    attribution against address_resolve."""

    def setUp(self):
        self.facade = AnalysisFacade(_MetaServiceWithSource())  # type: ignore[arg-type]

    def test_list_modules_six_segments_no_merge(self):
        out = self.facade.list_modules(PID)
        lib = next(m for m in out["modules"] if m["name"] == MODULE)
        self.assertEqual(len(lib["segments"]), len(SEGMENTS))
        self.assertEqual(lib["base"], hex(SEGMENTS[0][0]))
        # gap preserved: each segment end < next segment start
        for a, b in zip(lib["segments"], lib["segments"][1:]):
            self.assertLess(int(a["end"], 16), int(b["start"], 16))
        # unity is a separate module, never swallowed
        self.assertIn(UNITY := "libunity.so", [m["name"] for m in out["modules"]])

    def test_cross_attribution_all_segment_starts(self):
        mods = {m["name"]: m for m in self.facade.list_modules(PID)["modules"]}
        for name, m in mods.items():
            got = self.facade.address_resolve(PID, int(m["base"], 16))
            self.assertEqual(got.get("module"), name, f"{name}: {got}")
        # and a hit in each later libil2cpp segment still attributes correctly
        for start, _size, _off in SEGMENTS[1:]:
            got = self.facade.address_resolve(PID, start)
            self.assertEqual(got.get("module"), MODULE, f"seg@{hex(start)}: {got}")
            self.assertEqual(got.get("segment_index"), SEGMENTS.index((start, _size, _off)))

    def test_resolve_module_uses_same_grouping(self):
        out = self.facade.resolve_module(PID, MODULE)
        self.assertNotIn("error", out)
        mods = {m["name"]: m for m in self.facade.list_modules(PID)["modules"]}
        self.assertEqual(out["first_map"], mods[MODULE]["base"])


if __name__ == "__main__":
    unittest.main()
