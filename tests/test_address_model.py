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
