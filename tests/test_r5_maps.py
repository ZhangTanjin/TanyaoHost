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
    INIT_FILE_OFFSET,
    MODULE,
    SEGMENTS,
    _MetaService,
)
from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

PID = 1
TOKEN = "tanyao-dev-token"


def hx(v: int) -> str:
    return f"0x{v:x}"


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


class _AliasService(_MetaServiceWithSource):
    """lolm R10 tail shape: two non-mirror segments sharing file offset
    0xc620000 plus a drifted r-xp segment."""

    def __init__(self):
        super().__init__()
        from tanyao.service import MapEntry

        self.maps = [
            MapEntry(start=0x7299_DBE000, end=0x7299_DC1000, file_offset=0xC62000,
                     flags=1 | 2 | 8, path="/data/app/libil2cpp.so"),
            MapEntry(start=0x7299_DC2000, end=0x7299_DC2800, file_offset=0x56F5000,
                     flags=1 | 4 | 8, path="/data/app/libil2cpp.so"),
            MapEntry(start=0x7299_DC3000, end=0x7299_DD5000, file_offset=0xC62000,
                     flags=1 | 2 | 8, path="/data/app/libil2cpp.so"),
        ]
        self.mem = {m.start: bytearray(min(m.size, 0x1000)) for m in self.maps}

    def mem_read(self, _pid, addr, size):
        for start, buf in self.mem.items():
            if start <= addr and addr + size <= start + len(buf):
                return bytes(buf[addr - start: addr - start + size])
        return b"\x00" * size


class TestResolveRva(unittest.TestCase):
    """R8/D20: resolve_rva — vaddr vs file_offset entries over the lolm
    six-segment multi-bias fixture; mirrors never bear translations."""

    def setUp(self):
        self.facade = AnalysisFacade(_MetaServiceWithSource())  # type: ignore[arg-type]

    def test_file_offset_entry(self):
        out = self.facade.resolve_rva(PID, MODULE, file_offset=INIT_FILE_OFFSET)
        self.assertEqual(out["used"], "file_offset")
        # bearing segment m4: start 0x1000_0300_0000, file_offset 0x200000
        tb = 0x1000_0300_0000 - 0x200000
        self.assertEqual(out["segment"]["translation_base"], hex(tb))
        self.assertEqual(out["runtime"], hex(tb + INIT_FILE_OFFSET))

    def test_vaddr_entry_converted_via_phdr(self):
        """The 0x4000-diff scenario: segment 2 carries vaddr = F + 0x4000
        (R4-era offline records use vaddr-RVA); live phdrs must convert."""
        import struct as _struct

        class DriftService(_MetaServiceWithSource):
            def __init__(self):
                super().__init__()
                e = bytearray(64 + 2 * 56)
                e[0:4] = b"\x7fELF"
                e[4], e[5], e[6] = 2, 1, 1
                _struct.pack_into("<HHIQQQIHHHHHH", e, 16,
                                  3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
                _struct.pack_into("<IIQQQQQQ", e, 64, 1, 5, 0x0, 0x0, 0, 0x2000, 0x2000, 0x1000)
                _struct.pack_into("<IIQQQQQQ", e, 64 + 56, 1, 6,
                                  0x10000, 0x14000, 0, 0x4000, 0x4000, 0x1000)
                self.mem[SEGMENTS[0][0]][: len(e)] = bytearray(e)

        facade = AnalysisFacade(DriftService())  # type: ignore[arg-type]
        fo, vaddr = 0x10010, 0x14010
        out = facade.resolve_rva(PID, MODULE, rva=vaddr)
        self.assertEqual(out["used"], "vaddr")
        self.assertEqual(out["file_offset"], hex(fo))
        self.assertEqual(out["runtime"], hex(0x1000_0100_0000 + 0x10))
        self.assertEqual(out["vaddr"], hex(vaddr))

    def test_exactly_one_of_rva_or_file_offset(self):
        from tanyao.connection import AgentError
        with self.assertRaises(AgentError):
            self.facade.resolve_rva(PID, MODULE)
        with self.assertRaises(AgentError):
            self.facade.resolve_rva(PID, MODULE, rva=0x10, file_offset=0x10)

    def test_mirrorless_coverage_miss_lists_segments(self):
        from tanyao.connection import AgentError
        # beyond every segment's file window (fixture max F ≈ 0x606000)
        with self.assertRaises(AgentError) as ctx:
            self.facade.resolve_rva(PID, MODULE, file_offset=0x10000000)
        self.assertIn("non-mirror segments", str(ctx.exception))


class TestD21FileAliases(unittest.TestCase):
    """D21: same-module non-mirror segments with overlapping file windows —
    file-offset→runtime is non-injective; resolve_rva returns candidates."""

    def setUp(self):
        from tanyao.service import MapEntry

        self.maps = [
            # lolm R10 tail: two rw-p segments BOTH bearing off 0xc620000
            MapEntry(start=0x7299_DBE000, end=0x7299_DC1000, file_offset=0xC62000,
                     flags=1 | 2 | 8, path="/data/app/libil2cpp.so"),
            MapEntry(start=0x7299_DC3000, end=0x7299_DD5000, file_offset=0xC62000,
                     flags=1 | 2 | 8, path="/data/app/libil2cpp.so"),
            # drifted r-xp between them (different file window, non-overlapping)
            MapEntry(start=0x7299_DC2000, end=0x7299_DC2800, file_offset=0x56F5000,
                     flags=1 | 4 | 8, path="/data/app/libil2cpp.so"),
        ]
        self.facade = AnalysisFacade(_AliasService())  # type: ignore[arg-type]

    def test_alias_group_detected(self):
        from tanyao.mapsview import MapsView

        view = MapsView.from_maps(self.maps)
        v = view.modules["libil2cpp.so"]
        alias = [s for s in v.segments if s.alias_group]
        self.assertEqual(len(alias), 2)
        self.assertTrue(all(s.file_overlap for s in alias))
        self.assertEqual(alias[0].alias_group, alias[1].alias_group)
        drifted = next(s for s in v.segments if s.file_offset == 0x56F5000)
        self.assertFalse(drifted.file_overlap)  # non-overlapping: untouched

    def test_resolve_rva_returns_both_candidates(self):
        facade = self.facade
        out = facade.resolve_rva(PID, MODULE, file_offset=0xC62010)
        self.assertTrue(out.get("alias"))
        runtimes = [c["runtime"] for c in out["candidates"]]
        self.assertEqual(runtimes, [hx(0x7299_DBE010), hx(0x7299_DC3010)])
        groups = [c["segment"]["alias_group"] for c in out["candidates"]]
        self.assertEqual(groups[0], groups[1])

    def test_non_alias_keeps_single_value_shape(self):
        facade = self.facade
        out = facade.resolve_rva(PID, MODULE, file_offset=0x56F5010)
        self.assertNotIn("candidates", out)
        self.assertNotIn("alias", out)
        self.assertEqual(out["runtime"], hex(0x7299_DC2010))
        self.assertIn("segment", out)

    def test_list_modules_carries_alias_flags(self):
        mods = {m["name"]: m for m in self.facade.list_modules(PID)["modules"]}
        segs = mods[MODULE]["segments"]
        flagged = [x for x in segs if x.get("file_overlap")]
        self.assertEqual(len(flagged), 2)
        self.assertEqual(flagged[0]["alias_group"], flagged[1]["alias_group"])


if __name__ == "__main__":
    unittest.main()
    """F4 symbol_list fields=names_only; F6 preset category summary."""

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

    def test_symbol_list_names_only(self):
        full = self.facade.symbol_list(DEMO_PID, "libdemo.so")
        self.assertIn("bind", full["symbols"][0])
        slim = self.facade.symbol_list(DEMO_PID, "libdemo.so", fields="names_only")
        self.assertTrue(all(set(r) == {"name", "address"} for r in slim["symbols"]))
        self.assertEqual(len(slim["symbols"]), full["shown"])

    def test_preset_categories_summary(self):
        out = self.facade.scan_set_default_ranges(DEMO_PID, preset="module:libdemo.so")
        self.assertEqual(out["categories"]["module"], 2)
        self.assertEqual(out["categories"]["anon"], 0)
        self.assertGreater(out["total_bytes"], 0)
        anon = self.facade.scan_set_default_ranges(DEMO_PID, preset="anon")
        self.assertGreaterEqual(anon["categories"]["anon"], 1)


class TestF5Entropy(unittest.TestCase):
    """F5: page entropy math + the force gate on a >64MB high-entropy module."""

    def test_page_entropy_values(self):
        facade = AnalysisFacade(TanyaoService("127.0.0.1", 1, "x"))  # no connect needed
        import random
        self.assertAlmostEqual(facade._page_entropy(b"\x00" * 4096), 0.0, places=6)
        rng = random.Random(7)
        blob = bytes(rng.getrandbits(8) for _ in range(4096))
        self.assertGreater(facade._page_entropy(blob), 7.9)
        text = (b"the quick brown fox jumps over the lazy dog\n" * 90)
        self.assertLess(facade._page_entropy(text), 5.0)

    def test_force_gate_on_big_high_entropy_module(self):
        import random

        class BigHighEntropyService(_MetaServiceWithSource):
            def __init__(self):
                super().__init__()
                from tanyao.service import MapEntry
                rng = random.Random(11)
                big = MapEntry(start=0x3000_0000_0000, end=0x3000_5000_0000,
                               file_offset=0, flags=1 | 4,
                               path="/data/app/libbig.so")
                self.maps.append(big)
                self._big = (big.start, big.end,
                             bytes(rng.getrandbits(8) for _ in range(0x1000)))

            def mem_read(self, _pid, addr, size):
                lo, hi, page = self._big
                if lo <= addr and addr + size <= hi:
                    off = (addr - lo) % 0x1000
                    tile = (page * ((size // 0x1000) + 2))[off: off + size]
                    return tile
                return super().mem_read(_pid, addr, size)

        facade = AnalysisFacade(BigHighEntropyService())  # type: ignore[arg-type]
        with self.assertRaises(Exception) as ctx:
            facade.decompile_start(PID, "libbig.so")
        self.assertIn("force=true", str(ctx.exception))
        note = facade._entropy_guard(
            PID, facade.service.target_maps(PID)[-1:], force=True)
        self.assertIn("forced", note)


if __name__ == "__main__":
    unittest.main()


class TestMirrorAnnotation(unittest.TestCase):
    """R5 residual: whole-file mirror segments are flagged and excluded from
    the load_base anchor (field: lolm libil2cpp seg0 — 207MB r--p offset-0
    whole-file image far from the real loader segments)."""

    def test_mirror_flag_and_load_base(self):
        from tanyao.mapsview import MapsView
        from collections import namedtuple
        Map = namedtuple("Map", "start end file_offset flags path")
        P = "/data/app/~~x/com.tencent.lolm/lib/arm64/libil2cpp.so"
        R, X, RW, PRIV = 1, 4, 3, 8
        maps = [
            Map(0x70F39CD000, 0x7100000000, 0x0, R | PRIV, P),
            Map(0x728D53B000, 0x72990BC000, 0x0, X | PRIV, P),
            Map(0x72990BF000, 0x729943E000, 0xBB80000, R | PRIV, P),
            Map(0x7299441000, 0x7299B5C000, 0xBEFE000, RW | PRIV, P),
        ]
        view = MapsView.from_maps(maps)
        v = view.modules["libil2cpp.so"]
        self.assertTrue(v.segments[0].mirror, "offset-0 r--p duplicate of the exec mapping is a mirror")
        self.assertFalse(v.segments[1].mirror)
        self.assertFalse(v.segments[2].mirror)
        self.assertEqual(v.load_base, 0x728D53B000, "load_base skips the mirror")
        self.assertEqual(v.first_map, 0x70F39CD000, "first_map keeps the absolute first")

    def test_no_mirror_without_exec_duplicate(self):
        from tanyao.mapsview import MapsView
        from collections import namedtuple
        Map = namedtuple("Map", "start end file_offset flags path")
        P = "/system/lib64/libdemo.so"
        R, X, PRIV = 1, 4, 8
        maps = [
            Map(0x700000, 0x701000, 0x0, R | PRIV, P),
            Map(0x701000, 0x708000, 0x1000, X | PRIV, P),
        ]
        view = MapsView.from_maps(maps)
        v = view.modules["libdemo.so"]
        self.assertFalse(any(s.mirror for s in v.segments))
        self.assertEqual(v.load_base, 0x700000)
