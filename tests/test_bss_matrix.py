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


class FakeMap:
    def __init__(self, start: int, end: int, path: str):
        self.start, self.end, self.path = start, end, path


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


def resolve_bss(header: bytes, maps, bias_base: int, segs) -> tuple:
    """Drive the real AnalysisFacade helper with fakes."""
    from tanyao.analysis import AnalysisFacade

    svc = FakeService(maps, header, bias_base)
    facade = AnalysisFacade.__new__(AnalysisFacade)   # no __init__ side effects
    facade.service = svc  # type: ignore[attr-defined]
    from tanyao.elfinfo import parse_elf64
    info = parse_elf64(header, allow_zero_magic=True)
    return facade._resolve_bss_bounds(0, info, None, segs, bias_base)


def main() -> int:
    failures = 0

    def check(name: str, got, want, extra: str = "") -> None:
        nonlocal failures
        ok = got == want
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<46} got={got} want={want} {extra}")

    # ------------------------------------------------------------------ case 3
    # 16 KiB-aligned static PIE: the alignment trap.
    # last LOAD: vaddr 0x270f00 filesz 0xb9c memsz 0x21828 align 0x4000
    loads16 = [
        PhdrLoad(0x200000, 0x170f4, 0x170f4, 0x0, 4, 0x4000),
        PhdrLoad(0x21b100, 0x4d100, 0x4d100, 0x17100, 5, 0x4000),
        PhdrLoad(0x26c200, 0xe00, 0xcf0, 0x64200, 6, 0x4000),   # padding gap
        PhdrLoad(0x270f00, 0x21828, 0xb9c, 0x64f00, 6, 0x4000),  # real .bss tail
    ]
    hdr16 = build_elf(loads16)
    bias = loads16[0].vaddr - loads16[0].offset  # 0x200000
    segs16 = [
        FakeMap(0x200000, 0x218000, "f"), FakeMap(0x21b000, 0x269000, "f"),
        FakeMap(0x26c000, 0x26d000, "f"), FakeMap(0x270000, 0x272000, "f"),
    ]

    # case 3a: arithmetic only (no trailing anon mapping at all).
    # bss_start is now the CONSERVATIVE lower bound p_vaddr+p_filesz (=0x271a9c),
    # because the true section start depends on sh_addralign which the program
    # headers do not carry. Any real .bss byte is inside [start, end).
    bss, note = resolve_bss(hdr16, [], bias, segs16)
    check("case3 16K PIE, no mapping -> bss lower bound",
          bss[0] if bss else None, "0x271a9c", f"(note: {note[:40]})")
    check("case3 lower bound <= true .bss start (0x274000)",
          int(bss[0], 16) <= 0x274000, True)
    check("case3 note marked arithmetic",
          "arithmetic" in (note or ""), True)

    # case 3b: mapping present but unlabelled (empty path) — the field case
    maps16 = list(segs16) + [FakeMap(0x272000, 0x27c000, "")]
    bss_l, note_l = resolve_bss(hdr16, maps16, bias, segs16)
    # With a live mapping the answer snaps up to the mapping start (0x272000),
    # which is the page the loader actually allocated for the NOBITS tail.
    check("case3 16K PIE, unlabelled mapping -> snapped start",
          bss_l[0] if bss_l else None, "0x272000", f"(note: {note_l[:50]})")

    # ------------------------------------------------------------------ case 1
    # Same layout, but the kernel labels the mapping.
    maps16_labelled = list(segs16) + [FakeMap(0x272000, 0x27c000, "[anon:.bss]")]
    bss_lab, note_lab = resolve_bss(hdr16, maps16_labelled, bias, segs16)
    check("case1 labelled [anon:.bss] -> snapped start",
          bss_lab[0] if bss_lab else None, "0x272000")
    check("case1 note mentions the live mapping",
          "live" in (note_lab or ""), True)

    # ------------------------------------------------------------------ case 4
    # Intermediate NOBITS padding must never become the reported .bss.
    # If min() were used, 0x70000 (from the 0x26c200 segment) would win.
    check("case4 padding segment not chosen",
          (bss[0] if bss else None) != "0x70000", True)
    check("case4 chose the LAST nobits tail (0x271a9c)",
          bss[0] if bss else None, "0x271a9c")

    # ------------------------------------------------------------------ case 2
    # 4 KiB shared library (the libGameCore shape): arithmetic path exact.
    loads4 = [
        PhdrLoad(0x0, 0x218476c, 0x218476c, 0x0, 4, 0x1000),
        PhdrLoad(0x2185770, 0x29bcbc0, 0x29bcbc0, 0x2184770, 5, 0x1000),
        PhdrLoad(0x4b43330, 0x4b4560, 0x4b4560, 0x4b41330, 6, 0x1000),
        PhdrLoad(0x4ff8890, 0x454be8, 0x276308, 0x4ff5890, 6, 0x1000),
    ]
    hdr4 = build_elf(loads4)
    segs4 = [
        FakeMap(0x74b763e000, 0x74b97c3000, "f"),
        FakeMap(0x74b97c3000, 0x74bb3a3000, "f"),
        FakeMap(0x74bc181000, 0x74bc636000, "f"),
        FakeMap(0x74bc636000, 0x74bc8ad000, "f"),
    ]
    bias4 = segs4[0].start - 0x0          # 0x74b763e000
    bss4, note4 = resolve_bss(hdr4, segs4, bias4, segs4)
    # .bss vaddr = align_up(0x4ff8890+0x276308, 4K) = 0x526f000
    # Arithmetic path: lower bound = bias + p_vaddr + p_filesz = 0x74bc8acb98.
    check("case2 4K lib, arithmetic -> lower bound",
          bss4[0] if bss4 else None, "0x74bc8acb98", f"(note: {note4[:40]})")
    check("case2 lower bound <= true .bss start (0x74bc8ad000)",
          int(bss4[0], 16) <= 0x74bc8ad000, True)

    # ------------------------------------------------------------------ case 5
    # No load anchor at all -> must refuse rather than invent numbers.
    bss5, note5 = resolve_bss(hdr16, [], None, segs16)
    check("case5 no anchor -> returns None", bss5, None)

    print()
    if failures:
        print(f"{failures} case(s) FAILED")
        return 1
    print("all bss resolution cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
