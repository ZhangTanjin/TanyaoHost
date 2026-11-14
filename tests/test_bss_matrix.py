#!/usr/bin/env python3
"""BSS resolution matrix: the four scenarios that distinguish "we measured it"
from "we guessed it".

The `[anon:.bss]` mapping is not always available (some kernels emit no label,
some emit an empty path, and a module can be queried when its trailing mapping
is owned by a neighbour). Arithmetic is then the ONLY route left, so it must be
correct on its own — and must say so, rather than silently pretending to be
measured.

Cases (all host-side, no device required):
  1. labelled [anon:.bss]        -> method=anon_bss_mapping
  2. no label, correct segments  -> method=arithmetic, note flags it as such
  3. 16 KiB PIE + no label       -> arithmetic must still land exactly
  4. intermediate NOBITS padding -> must NOT be mistaken for the real .bss
"""
from __future__ import annotations

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.elfinfo import PhdrLoad, _align_up  # noqa: E402

PAGE = 0x1000


def build_elf(loads: list[PhdrLoad], *, e_entry: int = 0) -> bytes:
    """Minimal ELF64 little-endian header + phdr table, enough for parse_elf64."""
    phoff = 64
    bufsize = phoff + 56 * len(loads) + 64
    buf = bytearray(bufsize)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2          # ELFCLASS64
    buf[5] = 1          # ELFDATA2LSB
    buf[6] = 1          # EV_CURRENT
    struct.pack_into("<QQQ", buf, 0x18, e_entry, phoff, 0)  # entry, phoff, shoff
    struct.pack_into("<H", buf, 0x34, 64)   # e_ehsize
    struct.pack_into("<H", buf, 0x36, 56)   # e_phentsize
    struct.pack_into("<H", buf, 0x38, len(loads))  # e_phnum
    for i, ld in enumerate(loads):
        base = phoff + i * 56
        struct.pack_into("<II", buf, base, 1, ld.flags)  # PT_LOAD
        struct.pack_into("<QQQQQ", buf, base + 8,
                         ld.offset, ld.vaddr, ld.vaddr, ld.filesz, ld.memsz)
        struct.pack_into("<Q", buf, base + 48, ld.align)
    return bytes(buf)


# Real MapEntry, so the fixtures exercise the same shape the service produces.
from tanyao.service import MapEntry


class FakeMap(MapEntry):
    """A MapEntry with a zero file_offset, convenient for anonymous regions."""

    def __init__(self, start: int, end: int, path: str, file_offset: int = 0,
                 flags: int = 6) -> None:
        super().__init__(start=start, end=end, file_offset=file_offset,
                         flags=flags, path=path)


class FakeService:
    """Just enough of TanyaoService for AnalysisFacade's bss helpers."""

    def __init__(self, maps, header: bytes, bias_base: int):
        self._maps = maps
        self._header = header
        self._bias_base = bias_base

    def target_maps(self, pid, *, expected_cookie=None):
        return self._maps

    def mem_read(self, pid, addr, size):
        # serve the ELF header from wherever the module starts
        return self._header[:size]


def resolve_bss(header: bytes, maps, bias_base: int, segs,
                module: str | None = None) -> tuple:
    """Build a real AddressModel and ask it for the BSS range.

    This used to poke a private AnalysisFacade method with five hand-assembled
    arguments (and `__new__` to skip its constructor). The model is constructible
    directly from a maps list plus a header reader, which is the whole point of
    having it.
    """
    from tanyao.addr import AddressModel

    # MapsView keys modules by BASENAME, so take the name from the segments
    # rather than making the caller pass it correctly.
    if module is None:
        module = next((m.path.rstrip("/").split("/")[-1]
                       for m in segs if m.path), "libsample.so")
    all_maps = list(maps) if maps else []
    if not any(m.path and m.path.rstrip("/").split("/")[-1] == module
               for m in all_maps):
        all_maps.extend(segs)
    reader = FakeService(all_maps, header, bias_base)
    model = AddressModel.build(0, module, all_maps, reader.mem_read)
    bounds, note = model.bss_bounds()
    if bounds is None:
        return None, note
    lo, hi = bounds
    return [f"0x{lo:x}", f"0x{hi:x}"], note


# --- fixtures ---------------------------------------------------------------

# 16 KiB-aligned static PIE: the alignment trap.
# last LOAD: vaddr 0x270f00 filesz 0xb9c memsz 0x21828 align 0x4000
LOADS_16K = [
    PhdrLoad(0x200000, 0x170f4, 0x170f4, 0x0, 4, 0x4000),
    PhdrLoad(0x21b100, 0x4d100, 0x4d100, 0x17100, 5, 0x4000),
    PhdrLoad(0x26c200, 0xe00, 0xcf0, 0x64200, 6, 0x4000),    # padding gap
    PhdrLoad(0x270f00, 0x21828, 0xb9c, 0x64f00, 6, 0x4000),  # real .bss tail
]
HDR_16K = build_elf(LOADS_16K)
BIAS_16K = LOADS_16K[0].vaddr - LOADS_16K[0].offset            # 0x200000
# Only the FIRST segment is file-offset-0; the rest carry real offsets, as a
# normal loader layout does. Giving them all offset 0 would look like the
# multi-anchor (lolm) layout and make the base ambiguous by construction.
MOD_16K = "/x/libsixteen.so"
SEGS_16K = [
    FakeMap(0x200000, 0x218000, MOD_16K, 0x0),
    FakeMap(0x21b000, 0x269000, MOD_16K, 0x17100),
    FakeMap(0x26c000, 0x26d000, MOD_16K, 0x64200),
    FakeMap(0x270000, 0x272000, MOD_16K, 0x64f00),
]

# 4 KiB shared library (the libGameCore shape): arithmetic path exact.
LOADS_4K = [
    PhdrLoad(0x0, 0x218476c, 0x218476c, 0x0, 4, 0x1000),
    PhdrLoad(0x2185770, 0x29bcbc0, 0x29bcbc0, 0x2184770, 5, 0x1000),
    PhdrLoad(0x4b43330, 0x4b4560, 0x4b4560, 0x4b41330, 6, 0x1000),
    PhdrLoad(0x4ff8890, 0x454be8, 0x276308, 0x4ff5890, 6, 0x1000),
]
HDR_4K = build_elf(LOADS_4K)
MOD_4K = "/x/libfourk.so"
SEGS_4K = [
    FakeMap(0x74b763e000, 0x74b97c3000, MOD_4K, 0x0),
    FakeMap(0x74b97c3000, 0x74bb3a3000, MOD_4K, 0x2184000),
    FakeMap(0x74bc181000, 0x74bc636000, MOD_4K, 0x4b41000),
    FakeMap(0x74bc636000, 0x74bc8ad000, MOD_4K, 0x4ff5000),
]
BIAS_4K = SEGS_4K[0].start - 0x0                                # 0x74b763e000


class ArithmeticFallbackTest(unittest.TestCase):
    """Case 3a: no trailing anon mapping, so arithmetic is the only route.

    bss_start is the CONSERVATIVE lower bound (p_vaddr+p_filesz = 0x271a9c),
    because the true section start depends on sh_addralign which the program
    headers do not carry. Any real .bss byte is inside [start, end).
    """

    def setUp(self) -> None:
        self.bss, self.note = resolve_bss(HDR_16K, [], BIAS_16K, SEGS_16K)

    def test_lower_bound(self) -> None:
        self.assertEqual(self.bss[0], "0x271a9c")

    def test_bound_is_below_true_start(self) -> None:
        self.assertLessEqual(int(self.bss[0], 16), 0x274000)

    def test_note_flags_arithmetic(self) -> None:
        self.assertIn("arithmetic", self.note or "")


class LiveMappingTest(unittest.TestCase):
    """Cases 1 and 3b: a live mapping snaps the answer up to its start."""

    def test_unlabelled_mapping(self) -> None:
        maps = list(SEGS_16K) + [FakeMap(0x272000, 0x27c000, "")]
        bss, _note = resolve_bss(HDR_16K, maps, BIAS_16K, SEGS_16K)
        self.assertEqual(bss[0], "0x272000")

    def test_labelled_mapping(self) -> None:
        maps = list(SEGS_16K) + [FakeMap(0x272000, 0x27c000, "[anon:.bss]")]
        bss, note = resolve_bss(HDR_16K, maps, BIAS_16K, SEGS_16K)
        self.assertEqual(bss[0], "0x272000")
        self.assertIn("live", note or "")


class NobitsTailSelectionTest(unittest.TestCase):
    """Case 4: intermediate NOBITS padding must never win.

    The 0x26c200 segment also has memsz > filesz, but that gap is page padding
    between segments; using min() would report 0x70000 here.
    """

    def setUp(self) -> None:
        self.bss, _note = resolve_bss(HDR_16K, [], BIAS_16K, SEGS_16K)

    def test_padding_segment_not_chosen(self) -> None:
        self.assertNotEqual(self.bss[0], "0x70000")

    def test_last_tail_chosen(self) -> None:
        self.assertEqual(self.bss[0], "0x271a9c")


class SharedLibraryTest(unittest.TestCase):
    """Case 2: the libGameCore 4 KiB shape, arithmetic path."""

    def setUp(self) -> None:
        self.bss, _note = resolve_bss(HDR_4K, SEGS_4K, BIAS_4K, SEGS_4K)

    def test_lower_bound(self) -> None:
        self.assertEqual(self.bss[0], "0x74bc8acb98")

    def test_bound_is_below_true_start(self) -> None:
        self.assertLessEqual(int(self.bss[0], 16), 0x74bc8ad000)


class AmbiguousAnchorTest(unittest.TestCase):
    """Case 5: several CONFLICTING off-0 anchors -> refuse rather than pick one.

    Note the two cases are different, and the model treats them differently:

      * NO off-0 segment at all  -> derive the base from ELF arithmetic
        (`first_map - load_bias`); solvable, so it is the fallback path.
      * SEVERAL off-0 segments with DIFFERENT `start - file_offset` -> no single
        base is provable (the lolm co-resident layout). Refuse.
    """

    def test_ambiguous_anchors_return_none(self) -> None:
        # Two file-offset-0 segments placed so their anchors disagree.
        conflict = [
            FakeMap(0x200000, 0x218000, MOD_16K, 0x0),
            FakeMap(0x300000, 0x301000, MOD_16K, 0x0),
        ]
        bss, note = resolve_bss(HDR_16K, [], None, conflict)
        self.assertIsNone(bss)
        self.assertIn("anchor", note)


if __name__ == "__main__":
    unittest.main()
