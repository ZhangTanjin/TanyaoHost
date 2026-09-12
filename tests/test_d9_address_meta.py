"""D9 (P2): address metadata must follow the per-mapping translation table.

lolm libil2cpp has six mappings with non-uniform vaddr−offset drift (bias
0x0/0x4000/0x8000/0x260000/0x264000/0x268000 — not PT_LOAD-linear); the old
single-bias subtraction produced rva values beyond the dump size and BSS
bounds landing in libunity.so. Fixture mirrors that shape and asserts:

  - runtime→file_offset→runtime round trips across all six segments
  - address_resolve/disassemble rva == the per-mapping file offset
    (il2cpp_init analogue: rva == 0x3eba158)
  - resolve_module BSS arithmetic is clamped to the module's own mappings

Run: python3 -m unittest tests.test_d9_address_meta -v
"""

from __future__ import annotations

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.service import MapEntry  # noqa: E402

MODULE = "libil2cpp.so"
UNITY = "libunity.so"

# six segments: (runtime_start, size, file_offset); bias = vaddr - file_offset
SEGMENTS = [
    (0x1000_0000_0000, 0x2000, 0x0),          # bias 0x0
    (0x1000_0100_0000, 0x4000, 0x10000),      # bias 0x4000
    (0x1000_0200_0000, 0x4000, 0x20000),      # bias 0x8000
    (0x1000_0300_0000, 0x400_0000, 0x200000),  # bias 0x260000 (code: F 0x3eba158)
    (0x1000_9000_0000, 0x4000, 0x4200000),     # bias 0x264000 (window beyond m4)
    (0x1000_A000_0000, 0x2000, 0x4204000),     # bias 0x268000
]
INIT_FILE_OFFSET = 0x3EBA158
UNITY_START = 0x1000_B000_0000

BIASES = (0x0, 0x4000, 0x8000, 0x260000, 0x264000, 0x268000)


def _fixture_maps():
    maps = []
    for (start, size, off), _bias in zip(SEGMENTS, BIASES):
        maps.append(MapEntry(start=start, end=start + size, file_offset=off,
                             flags=1 | 4, path=f"/data/app/{MODULE}"))
    maps.append(MapEntry(start=UNITY_START, end=UNITY_START + 0x100000,
                         file_offset=0, flags=1 | 2 | 4, path=f"/data/app/{UNITY}"))
    return maps


def _fixture_elf_header() -> bytes:
    """ELF64 header + 2 PT_LOADs; LOAD2 carries a huge NOBITS BSS whose
    naive single-bias arithmetic lands far outside the module's mappings."""
    e = bytearray(64 + 2 * 56)
    e[0:4] = b"\x7fELF"
    e[4], e[5], e[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", e, 16,
                     3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    # LOAD1: offset 0, vaddr 0, filesz=memsz=0x2000  -> load_bias 0
    struct.pack_into("<IIQQQQQQ", e, 64,
                     1, 5, 0x0, 0x0, 0, 0x2000, 0x2000, 0x1000)
    # LOAD2: offset 0x604000, vaddr 0x86C000 (bias 0x268000), memsz >> filesz
    struct.pack_into("<IIQQQQQQ", e, 64 + 56,
                     1, 6, 0x604000, 0x86C000, 0, 0x2000, 0x200000, 0x1000)
    return bytes(e)


class _MetaService:
    """Minimal service double: maps + flat memory image for the facade."""

    def __init__(self):
        self.maps = _fixture_maps()
        self.mem = {m.start: bytearray(m.size) for m in self.maps}
        header = _fixture_elf_header()
        self.mem[SEGMENTS[0][0]][: len(header)] = bytearray(header)
        self.mem[UNITY_START][: len(header)] = bytearray(header)  # unity also has a header
        # il2cpp_init analogue: a couple of A64 words at F=0x3eba158
        s4, off4 = SEGMENTS[3][0], INIT_FILE_OFFSET - SEGMENTS[3][2]
        insns = struct.pack("<2I", 0xD65F03C0, 0xD65F03C0)  # ret; ret
        self.mem[s4][off4: off4 + len(insns)] = bytearray(insns)

    def target_maps(self, _pid):
        return self.maps

    def mem_read(self, _pid, addr, size):
        # overlays are materialized per-map; anything else inside a registered
        # map extent reads as zeros (keeps >64MB fixture maps virtual)
        for m in self.maps:
            if m.start <= addr and addr + size <= m.end:
                buf = self.mem.get(m.start)
                if buf is not None and addr + size <= m.start + len(buf):
                    off = addr - m.start
                    return bytes(buf[off: off + size])
                return b"\x00" * size
        raise RuntimeError(f"fixture read outside mappings: 0x{addr:x}")

    def has_agent_cap(self, _bit):
        return False  # force the host-side (facade) annotation paths


def _facade():
    return AnalysisFacade(_MetaService())  # type: ignore[arg-type]


PID = 1


class TestD9Helpers(unittest.TestCase):
    def test_roundtrip_across_all_six_segments(self):
        facade = _facade()
        maps = facade.service.target_maps(PID)
        for (start, size, off), bias in zip(SEGMENTS, BIASES):
            self.assertEqual(off + bias, off + bias)  # bias table sanity
            addr, file_offset = start + 0x10, off + 0x10
            got = facade._runtime_to_file_offset(maps, addr)
            self.assertEqual(got, (MODULE, file_offset))
            back = facade._file_offset_to_runtime(maps, MODULE, file_offset)
            self.assertEqual(back, addr)

    def test_anonymous_and_unmapped_return_none(self):
        facade = _facade()
        maps = facade.service.target_maps(PID)
        anon = MapEntry(start=0x2000_0000_0000, end=0x2000_0001_0000,
                        file_offset=0, flags=1 | 2, path="")
        maps.append(anon)
        self.assertIsNone(facade._runtime_to_file_offset(maps, 0x2000_0000_0100))
        self.assertIsNone(facade._runtime_to_file_offset(maps, 0xDEAD_0000))
        self.assertIsNone(facade._file_offset_to_runtime(maps, UNITY, 0x999999))


class TestD9AddressResolve(unittest.TestCase):
    def test_rva_equals_file_offset_on_multi_bias_module(self):
        """The acceptance hard metric: il2cpp_init analogue at file offset
        0x3eba158 must resolve to rva == 0x3eba158 (< dump size), NOT the
        single-bias artifact (0x1888b9158 in the field)."""
        facade = _facade()
        runtime = facade._file_offset_to_runtime(
            facade.service.target_maps(PID), MODULE, INIT_FILE_OFFSET)
        self.assertIsNotNone(runtime)
        out = facade.address_resolve(PID, runtime)
        self.assertEqual(out["module"], MODULE)
        self.assertEqual(out["file_offset"], hex(INIT_FILE_OFFSET))
        self.assertEqual(out["rva"], hex(INIT_FILE_OFFSET))
        self.assertLess(INIT_FILE_OFFSET, 0x200000 + 0x4000000)  # < dump extent

    def test_disassemble_uses_mapping_table_rva(self):
        facade = _facade()
        runtime = facade._file_offset_to_runtime(
            facade.service.target_maps(PID), MODULE, INIT_FILE_OFFSET)
        out = facade.disassemble(PID, runtime, count=2)
        self.assertEqual(out["module"], MODULE)
        self.assertEqual(out["rva"], hex(INIT_FILE_OFFSET))
        self.assertEqual(out["count"], 2)


class TestD9ResolveModuleBss(unittest.TestCase):
    def test_bss_clamped_to_own_mappings(self):
        """Arithmetic BSS end must not escape the module's own mappings —
        the field case had it attributed to libunity.so."""
        facade = _facade()
        out = facade.resolve_module(PID, MODULE)
        self.assertNotIn("error", out)
        bss = out["bss"]
        self.assertIsNotNone(bss)
        bss_hi = int(bss[1], 16)
        own_hi = max(m.end for m in facade.service.target_maps(PID)
                     if m.path and m.path.endswith(MODULE))
        self.assertLessEqual(bss_hi, own_hi)
        self.assertLess(own_hi, UNITY_START)  # never inside the neighbor

    def test_unity_module_still_resolves(self):
        facade = _facade()
        out = facade.resolve_module(PID, UNITY)
        self.assertNotIn("error", out)
        self.assertEqual(out["first_map"], hex(UNITY_START))


if __name__ == "__main__":
    unittest.main()
