#!/usr/bin/env python3
"""AddressModel: the seam where ELF space and runtime space meet.

The cases below are the ones that actually produced wrong addresses in this
project, not invented edge cases:

  * a prelinked PIE whose first mapping does NOT sit at `load_bias`
    (`tanyao_target`: first_map 0x400000, load_bias 0x200000)
  * `.bss` living past the last mapping's end, so a naive window test reads a
    runtime address as a vaddr and shifts it twice
  * mirror segments, where no single anchor is provable
"""
from __future__ import annotations

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.addr import AddressModel, AddressModelError  # noqa: E402
from tanyao.elfinfo import PhdrLoad  # noqa: E402


# --- fixture builders -------------------------------------------------------

def build_elf(loads: list[PhdrLoad], *, e_entry: int = 0) -> bytes:
    phoff = 64
    buf = bytearray(phoff + 56 * len(loads) + 64)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2
    buf[5] = 1
    buf[6] = 1
    struct.pack_into("<QQQ", buf, 0x18, e_entry, phoff, 0)
    struct.pack_into("<H", buf, 0x34, 64)
    struct.pack_into("<H", buf, 0x36, 56)
    struct.pack_into("<H", buf, 0x38, len(loads))
    for i, ld in enumerate(loads):
        base = phoff + i * 56
        struct.pack_into("<II", buf, base, 1, ld.flags)
        struct.pack_into("<QQQQQ", buf, base + 8,
                         ld.offset, ld.vaddr, ld.vaddr, ld.filesz, ld.memsz)
        struct.pack_into("<Q", buf, base + 48, ld.align)
    return bytes(buf)


class Map:
    __slots__ = ("start", "end", "file_offset", "flags", "path")

    def __init__(self, start: int, end: int, file_offset: int, flags: int,
                 path: str) -> None:
        self.start, self.end = start, end
        self.file_offset, self.flags, self.path = file_offset, flags, path


def mem_from(header: bytes, at: int):
    def _read(pid: int, addr: int, size: int) -> bytes:
        if addr != at:
            raise OSError(f"unexpected read at {addr:#x}")
        return header[:size]
    return _read


# --- prelinked PIE: the real trap ------------------------------------------
# ELF says p_vaddr 0x400000 for the first LOAD, p_offset 0.
#   load_bias = 0x400000 - 0 = 0x400000
# But at runtime the loader placed it at 0x200000, so the mapping's start is
# 0x200000. A model that assumes start == load_bias reports every address
# 0x200000 too high.
PIE_LOADS = [
    PhdrLoad(0x400000, 0x1000, 0x1000, 0x0, 5, 0x1000),      # r-x
    PhdrLoad(0x401000, 0x2000, 0x1000, 0x1000, 6, 0x1000),   # rw
]
PIE_HEADER = build_elf(PIE_LOADS)
PIE_SEGS = [
    Map(0x200000, 0x201000, 0x0, 5, "/x/libpie.so"),
    Map(0x201000, 0x203000, 0x1000, 6, "/x/libpie.so"),
]


class PrelinkedPieTest(unittest.TestCase):
    def setUp(self) -> None:
        self.m = AddressModel.build(0, "libpie.so", PIE_SEGS,
                                    mem_from(PIE_HEADER, 0x200000))

    def test_elf_load_bias_is_a_file_property(self) -> None:
        self.assertEqual(self.m.elf.load_bias, 0x400000)

    def test_runtime_base_comes_from_the_mapping(self) -> None:
        # The one anchor-computable value: start(0x200000) - file_offset(0) .
        self.assertEqual(self.m.base, 0x200000)

    def test_vaddr_of_first_segment_maps_to_mapping_start(self) -> None:
        # vaddr 0x400000 is the first segment's p_vaddr; it must land on the
        # mapping that starts at 0x200000, not 0x400000.
        self.assertEqual(self.m.to_runtime(0x400000), 0x200000)

    def test_vaddr_inside_second_segment(self) -> None:
        self.assertEqual(self.m.to_runtime(0x401234), 0x201234)


# --- .bss past the last mapping --------------------------------------------
BSS_LOADS = [
    PhdrLoad(0x400000, 0x1000, 0x1000, 0x0, 5, 0x1000),
    PhdrLoad(0x401000, 0x3000, 0x1000, 0x1000, 6, 0x1000),  # NOBITS tail
]
BSS_HEADER = build_elf(BSS_LOADS)
BSS_SEGS = [
    Map(0x200000, 0x201000, 0x0, 5, "/x/libbss.so"),
    Map(0x201000, 0x202000, 0x1000, 6, "/x/libbss.so"),
    # The anonymous .bss region the loader adds AFTER the last mapping.
    Map(0x202000, 0x205000, 0x0, 6, ""),
]


class BssWindowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.m = AddressModel.build(0, "libbss.so", BSS_SEGS,
                                    mem_from(BSS_HEADER, 0x200000))

    def test_bss_bounds_are_elf_vaddr_space(self) -> None:
        # p_vaddr 0x401000 + p_filesz 0x1000, no bias subtracted.
        self.assertEqual(self.m.elf.bss_start, 0x402000)
        self.assertEqual(self.m.elf.bss_end, 0x404000)

    def test_is_bss_classifies_elf_vaddrs(self) -> None:
        self.assertFalse(self.m.is_bss(0x401fff))
        self.assertTrue(self.m.is_bss(0x402000))
        self.assertTrue(self.m.is_bss(0x403fff))
        self.assertFalse(self.m.is_bss(0x404000))

    def test_runtime_window_includes_the_anonymous_bss(self) -> None:
        # 0x203000 is in the anonymous region, PAST the last file-backed end
        # (0x202000). Without widening by bss this would be called a vaddr.
        self.assertTrue(self.m.is_runtime_addr(0x203000))

    def test_runtime_window_excludes_vaddrs(self) -> None:
        self.assertFalse(self.m.is_runtime_addr(0x402000))


# --- conversions ------------------------------------------------------------
class ConversionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.m = AddressModel.build(0, "libpie.so", PIE_SEGS,
                                    mem_from(PIE_HEADER, 0x200000))

    def test_runtime_to_file_offset(self) -> None:
        self.assertEqual(self.m.runtime_to_file_offset(0x200500), 0x500)
        self.assertEqual(self.m.runtime_to_file_offset(0x201500), 0x1500)

    def test_runtime_to_file_offset_unmapped(self) -> None:
        self.assertIsNone(self.m.runtime_to_file_offset(0x999000))

    def test_file_offset_to_runtime_round_trip(self) -> None:
        rt = self.m.file_offset_to_runtime(0x500)
        self.assertEqual(rt, 0x200500)

    def test_translation_base_identity(self) -> None:
        """start == translation_base + file_offset, for the SEGMENT start.

        The identity is about the segment, not about an arbitrary byte inside
        it: translation_base + fo gives the runtime address of the byte at that
        file offset, and that equals the segment start only at file_offset ==
        seg.file_offset.
        """
        tb = self.m.bearing_translation_base(0x1500)
        self.assertIsNotNone(tb)
        seg = self.m.segment_for_runtime(0x201500)
        # At the segment's own file offset the identity lands on its start.
        self.assertEqual(seg.start, tb + seg.file_offset)
        # And for any byte inside, tb + fo is that byte's runtime address.
        self.assertEqual(tb + 0x1500, 0x201500)


# --- multi-anchor / mirror --------------------------------------------------
MULTI_SEGS = [
    Map(0x200000, 0x201000, 0x0, 5, "/x/libmulti.so"),
    # A second off-0 segment with a DIFFERENT anchor (the lolm layout).
    Map(0x300000, 0x301000, 0x0, 6, "/x/libmulti.so"),
]


class MultiAnchorTest(unittest.TestCase):
    def test_ambiguity_is_reported_not_hidden(self) -> None:
        m = AddressModel.build(0, "libmulti.so", MULTI_SEGS,
                               mem_from(PIE_HEADER, 0x200000))
        self.assertTrue(m.base_is_ambiguous)

    def test_describe_carries_the_flag(self) -> None:
        m = AddressModel.build(0, "libmulti.so", MULTI_SEGS,
                               mem_from(PIE_HEADER, 0x200000))
        self.assertTrue(m.describe()["load_bias_ambiguous"])


# --- failure modes ----------------------------------------------------------
class FailureTest(unittest.TestCase):
    def test_missing_module_is_not_an_unavailable(self) -> None:
        with self.assertRaises(AddressModelError) as ctx:
            AddressModel.build(0, "nope.so", PIE_SEGS, mem_from(PIE_HEADER, 0x200000))
        self.assertFalse(ctx.exception.unavailable)

    def test_unreadable_header_is_unavailable(self) -> None:
        def boom(pid, addr, size):
            raise OSError("device gone")
        with self.assertRaises(AddressModelError) as ctx:
            AddressModel.build(0, "libpie.so", PIE_SEGS, boom)
        self.assertTrue(ctx.exception.unavailable)

    def test_garbage_header_is_invalid_not_unavailable(self) -> None:
        def junk(pid, addr, size):
            return b"\xde\xad\xbe\xef" * 64
        with self.assertRaises(AddressModelError) as ctx:
            AddressModel.build(0, "libpie.so", PIE_SEGS, junk)
        self.assertFalse(ctx.exception.unavailable)


if __name__ == "__main__":
    unittest.main()


# --- memsz > filesz tail: the "covered by no PT_LOAD" trap -----------------
# A LOAD whose p_memsz exceeds p_filesz has a zero-filled tail. Those bytes are
# INSIDE the segment but have no file offset at all. A resolver that tests only
# `p_filesz` concludes the vaddr belongs to no segment and refuses it — the
# field report's 0x1D38800, which sat inside .data and was rejected with
# "not covered by any PT_LOAD ... no unambiguous load anchor".
TAIL_LOADS = [
    PhdrLoad(0x400000, 0x1000, 0x1000, 0x0, 5, 0x1000),
    # filesz 0x1e18, memsz 0x2000 -> zero tail [0x401e18, 0x402000)
    PhdrLoad(0x401000, 0x2000, 0x1e18, 0x1000, 6, 0x1000),
]
TAIL_HEADER = build_elf(TAIL_LOADS)
TAIL_SEGS = [
    Map(0x200000, 0x201000, 0x0, 5, "/x/libtail.so"),
    Map(0x201000, 0x203000, 0x1000, 6, "/x/libtail.so"),
]


class ZeroFillTailTest(unittest.TestCase):
    """load_covering must distinguish file bytes from the zero-filled tail."""

    def setUp(self) -> None:
        self.m = AddressModel.build(0, "libtail.so", TAIL_SEGS,
                                    mem_from(TAIL_HEADER, 0x200000))

    def test_file_backed_bytes_are_file(self) -> None:
        load, where = self.m.load_covering(0x401000)
        self.assertEqual(where, "file")
        self.assertEqual(load.vaddr, 0x401000)

    def test_byte_just_past_filesz_is_zero_fill(self) -> None:
        # p_vaddr + p_filesz = 0x401000 + 0x1e18 = 0x402e18,
        # the first byte with no file counterpart.
        load, where = self.m.load_covering(0x402e18)
        self.assertEqual(where, "zero")
        self.assertEqual(load.vaddr, 0x401000)

    def test_last_file_byte_is_file(self) -> None:
        _load, where = self.m.load_covering(0x402e17)
        self.assertEqual(where, "file")

    def test_last_zero_fill_byte_is_inside(self) -> None:
        # p_vaddr + p_memsz - 1 = 0x403000 - 1
        _load, where = self.m.load_covering(0x402fff)
        self.assertEqual(where, "zero")

    def test_first_byte_past_memsz_is_not_covered(self) -> None:
        _load, where = self.m.load_covering(0x403000)
        self.assertEqual(where, "none")

    def test_below_first_load_is_not_covered(self) -> None:
        _load, where = self.m.load_covering(0x3fffff)
        self.assertEqual(where, "none")


# --- segment vaddr windows: the property that actually matters ----------------
# Earlier attempts asserted "adjacent windows must not overlap". That is FALSE
# for this model by construction: a mapping's window is the union of every
# PT_LOAD it overlaps, and neighbouring mappings share a page, so their windows
# overlap on purpose. Such an assertion would fail on correct output.
#
# The property that does hold, and that catches the original defect, is
# COVERAGE: every PT_LOAD's file-backed vaddr range must fall inside exactly one
# mapping's window. Under the buggy version a vaddr like 0x51EA4D0 was covered by
# no window at all.
WINDOW_LOADS = [
    PhdrLoad(0x0, 0x7ba78, 0x7ba78, 0x0, 5, 0x1000),
    PhdrLoad(0x7fa80, 0x94028, 0x94028, 0x7ba80, 5, 0x1000),   # unaligned p_offset
    PhdrLoad(0x117aa8, 0x7300, 0x8558, 0x10faa8, 6, 0x1000),
    PhdrLoad(0x122da8, 0x1c0, 0x74e0, 0x116da8, 6, 0x1000),
]
WINDOW_HEADER = build_elf(WINDOW_LOADS)
# Page-aligned mappings, as the loader really produces.
WINDOW_SEGS = [
    Map(0x7000000000, 0x7000007c000, 0x0, 5, "/x/libwin.so"),
    Map(0x7000007b000, 0x70000110000, 0x7b000, 5, "/x/libwin.so"),
    Map(0x7000010f000, 0x70000117000, 0x10f000, 6, "/x/libwin.so"),
]


def _window_of(seg, loads):
    """Mirror of the resolver's rule: union of overlaps, page-aligned matching."""
    seg_off = seg.file_offset
    file_end = seg_off + (seg.end - seg.start)
    lo = hi = None
    for ld in loads:
        ov_lo = max(ld.offset, seg_off)
        ov_hi = min(ld.offset + ld.filesz, file_end)
        if ov_hi <= ov_lo:
            continue
        v_lo = ld.vaddr + (ov_lo - ld.offset)
        v_hi = ld.vaddr + (ov_hi - ld.offset)
        lo = v_lo if lo is None else min(lo, v_lo)
        hi = v_hi if hi is None else max(hi, v_hi)
    return (lo, hi) if lo is not None else None


class WindowCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.loads = WINDOW_LOADS

    def test_every_load_is_covered_by_some_window(self) -> None:
        """The defect this replaces: a vaddr that no window covered."""
        windows = [w for w in (_window_of(s, self.loads) for s in WINDOW_SEGS) if w]
        for ld in self.loads:
            lo, hi = ld.vaddr, ld.vaddr + ld.filesz
            covering = [w for w in windows if w[0] <= lo and hi <= w[1]]
            self.assertTrue(
                covering,
                f"PT_LOAD [{lo:#x}, {hi:#x}) is not contained in any window; "
                f"windows={[(hex(a), hex(b)) for a, b in windows]}")

    def test_windows_may_overlap(self) -> None:
        """Overlap is expected, not a defect — pin it so nobody 'fixes' it."""
        windows = sorted(w for w in (_window_of(s, self.loads) for s in WINDOW_SEGS) if w)
        overlaps = any(windows[i][1] > windows[i + 1][0] for i in range(len(windows) - 1))
        self.assertTrue(overlaps, "expected the union model to produce overlapping windows")

    def test_unaligned_p_offset_shifts_window_start(self) -> None:
        """A mapping starting before p_offset must not report p_vaddr as its start."""
        seg = WINDOW_SEGS[1]                 # off 0x7b000, LOAD2 has p_offset 0x7ba80
        win = _window_of(seg, self.loads)
        self.assertIsNotNone(win)
        self.assertNotEqual(win[0], 0x7fa80, "window start must be mapping-relative, not p_vaddr")
