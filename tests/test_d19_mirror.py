"""D19 (P0): mirror heuristic v2 + load_bias semantic downgrade.

Tester three-way base inconsistency on lolm libil2cpp: the v1 mirror rule
flagged the REAL ~58MB r--p loader segment as a mirror (it shares offset 0
with the 192MB exec image), moving the load anchor 39.5MB away —
resolve_module/address_resolve reported 0x728d53b000 while the truth
(symbol_find − RVA and byte-exact disassembly) is 0x728af3b000.

Fixtures pin the three layouts:
  A (dominant mirror — stays a mirror): 202MB r--p off-0 + 192MB exec off-0
  B (co-resident real loader — must NOT be a mirror): ~58MB r--p off-0 +
     192MB exec off-0 → translation_base == 0x728af3b000
  C (no off-0 duplicate — unchanged behaviour)

Run: python3 -m unittest tests.test_d19_mirror -v
"""

from __future__ import annotations

import os
import struct
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.mapsview import MapsView  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

Map = namedtuple("Map", "start end file_offset flags path")
P = "/data/app/~~x/com.tencent.lolm/lib/arm64/libil2cpp.so"
R, W, X, RW, PRIV = 1, 2, 4, 3, 8

TRUE_ANCHOR = 0x728AF3B000
MISLABELLED_ANCHOR = 0x728D53B000
INIT_RVA = 0x3A3609C


def _elf_header_bytes() -> bytes:
    e = bytearray(64 + 2 * 56)
    e[0:4] = b"\x7fELF"
    e[4], e[5], e[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", e, 16,
                     3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", e, 64, 1, 5, 0x0, 0x0, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<IIQQQQQQ", e, 64 + 56, 1, 6, 0x604000, 0x86C000, 0, 0x2000, 0x200000, 0x1000)
    return bytes(e)


class _LayoutService:
    """Facade double over hand-built layout maps; ELF header lives in the
    off-0 r--p member; reads outside overlays return zeros."""

    def __init__(self, maps, header_addr):
        self.maps = maps
        self._header = _elf_header_bytes()
        self._header_addr = header_addr

    def target_maps(self, _pid):
        return self.maps

    def maps_source(self):
        return "target_maps"

    def mem_read(self, _pid, addr, size):
        if self._header_addr <= addr < self._header_addr + len(self._header):
            off = addr - self._header_addr
            return bytes(self._header[off: off + size])
        return b"\x00" * size

    def has_agent_cap(self, _bit):
        return False


def _layout_b_maps():
    """Case B (real lolm R7 shape): small real r--p off-0 (58MB class) +
    big exec off-0 (192MB) + drifted rw segments — the exec anchor would be
    the mislabelled 0x728d53b000."""
    r_size = 0x3A9C000  # ~58MB class, covers F=0x3a3609c
    return [
        Map(TRUE_ANCHOR, TRUE_ANCHOR + r_size, 0x0, R | PRIV, P),
        Map(MISLABELLED_ANCHOR, MISLABELLED_ANCHOR + 0xC181000, 0x0, X | PRIV, P),
        Map(0x72990BF000, 0x729943E000, 0xBB80000, R | PRIV, P),
        Map(0x7299441000, 0x7299B5C000, 0xBEFE000, RW | PRIV, P),
    ]


def _layout_a_maps():
    """Case A (dominant mirror): 202MB r--p off-0 + 192MB exec off-0."""
    return [
        Map(0x70F39CD000, 0x7100000000, 0x0, R | PRIV, P),   # ~202MB mirror
        Map(0x728D53B000, 0x72990BC000, 0x0, X | PRIV, P),   # 192MB exec
        Map(0x72990BF000, 0x729943E000, 0xBB80000, R | PRIV, P),
    ]


class TestMirrorHeuristicV2(unittest.TestCase):
    def test_case_b_real_loader_segment_not_mirrored(self):
        view = MapsView.from_maps(_layout_b_maps())
        v = view.modules["libil2cpp.so"]
        self.assertFalse(v.segments[0].mirror,
                         "the smaller real r--p loader segment must keep loader status")
        self.assertEqual(v.load_base, TRUE_ANCHOR,
                         "load anchor must stay on the true loader segment")

    def test_case_a_dominant_mirror_still_flagged(self):
        view = MapsView.from_maps(_layout_a_maps())
        v = view.modules["libil2cpp.so"]
        self.assertTrue(v.segments[0].mirror, "dominant off-0 r--p stays a mirror")
        self.assertEqual(v.load_base, 0x728D53B000)

    def test_case_c_no_off0_duplicate_unchanged(self):
        maps = [
            Map(0x700000, 0x701000, 0x0, R | PRIV, "/system/lib64/libdemo.so"),
            Map(0x701000, 0x708000, 0x1000, X | PRIV, "/system/lib64/libdemo.so"),
        ]
        v = MapsView.from_maps(maps).modules["libdemo.so"]
        self.assertFalse(any(s.mirror for s in v.segments))
        self.assertEqual(v.load_base, 0x700000)


class TestD19LoadBiasSemantics(unittest.TestCase):
    def _facade(self, maps):
        return AnalysisFacade(_LayoutService(maps, TRUE_ANCHOR))  # type: ignore[arg-type]

    def test_case_b_resolve_module_ambiguous_with_segment_table(self):
        facade = self._facade(_layout_b_maps())
        out = facade.resolve_module(1, "libil2cpp.so")
        self.assertEqual(out["load_bias"], None)
        self.assertTrue(out.get("load_bias_ambiguous"))
        self.assertIn("translation_base", out.get("hint", ""))
        segs = out["segments"]
        self.assertGreaterEqual(len(segs), 4)
        first = segs[0]
        self.assertFalse(first["mirror"])
        # the true loader segment carries the truth anchor as translation_base
        self.assertEqual(int(first["translation_base"], 16), TRUE_ANCHOR)

    def test_case_b_address_resolve_self_consistent(self):
        facade = self._facade(_layout_b_maps())
        addr = TRUE_ANCHOR + INIT_RVA
        out = facade.address_resolve(1, addr)
        self.assertEqual(out["module"], "libil2cpp.so")
        self.assertEqual(out["rva"], hex(INIT_RVA))
        # no self-contradiction: ambiguous → load_bias omitted, flagged instead
        self.assertNotIn("load_bias", out)
        self.assertTrue(out.get("load_bias_ambiguous"))
        # and the rva is self-consistent with the TRUE anchor
        self.assertEqual(TRUE_ANCHOR + INIT_RVA, addr)

    def test_standard_layout_keeps_load_bias_self_consistent(self):
        from tests.mock_agent import DEMO_PID, MockAgent

        TOKEN = "tanyao-dev-token"
        agent = MockAgent(port=0, token=TOKEN)
        agent.start()
        try:
            svc = TanyaoService("127.0.0.1", agent.port, TOKEN)
            facade = AnalysisFacade(svc)
            svc.connect()
            from tests.mock_agent import BASE

            out = facade.resolve_module(DEMO_PID, "libdemo.so")
            self.assertEqual(out["load_bias"], hex(BASE))
            self.assertNotIn("load_bias_ambiguous", out)
            resolved = facade.address_resolve(DEMO_PID, BASE + 0x1234)
            self.assertEqual(resolved.get("load_bias"), hex(BASE))
            # self-consistency identity: load_bias + rva == address
            self.assertEqual(
                int(resolved["load_bias"], 16) + int(resolved["rva"], 16),
                BASE + 0x1234)
        finally:
            agent.stop()


if __name__ == "__main__":
    unittest.main()
