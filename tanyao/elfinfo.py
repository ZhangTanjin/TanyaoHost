"""Pure-Python ELF64 (little-endian) parsing for mapped-module semantics.

Deliberately dependency-free: we only need what the CLI's `module resolve` /
`address resolve` already established — first mapping, load bias from PT_LOAD,
BSS bounds, mirror detection. pyelftools is an optional accelerator, not required.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

PT_LOAD = 1
PT_DYNAMIC = 2


@dataclass(slots=True)
class PhdrLoad:
    vaddr: int
    memsz: int
    filesz: int
    offset: int
    flags: int
    align: int = 0x1000


PAGE_SIZE = 0x1000


def _align_up(value: int, align: int) -> int:
    """Round `value` up to a multiple of `align` (identity when aligned).

    The alignment must come from the segment's own p_align: static binaries are
    routinely linked with p_align = 0x4000 (16 KiB) on a 4 KiB-page kernel, and
    rounding with a hard-coded 0x1000 lands two pages short of the real .bss
    (measured: computed 0x272000 vs actual 0x274000 on a 16 KiB-aligned PIE).
    """
    if align <= 1:
        return value
    return (value + align - 1) & ~(align - 1)


def _page_align_up(value: int) -> int:
    """Round up to the next 4 KiB page (kept for callers that assume pages)."""
    return _align_up(value, PAGE_SIZE)


@dataclass(slots=True)
class ElfInfo:
    """What an ELF file says about itself. EVERY field is in ELF vaddr space
    (the numbers `readelf -l` prints), never adjusted by any runtime mapping.

    There used to be two coordinate spaces in here: `load_bias` was
    `first.vaddr - first.offset` (an ELF-only quantity, unrelated to any
    mapping) while `bss_start`/`bss_end` were `p_vaddr + p_filesz - load_bias`
    (a module-base-relative quantity). Mixing them meant a caller could not tell
    which space a value was in without reading the code that produced it, and
    whenever the first mapping's start differed from `load_bias` — which happens
    on prelinked PIEs — the two silently disagreed. Every consumer then had to
    re-derive the base by hand, 39 lines of it spread over 11 functions.

    Conversions to runtime addresses belong to `tanyao.addr.AddressModel`, which
    is the only thing that knows about both spaces.
    """
    entry: int
    phoff: int
    phentsize: int
    phnum: int
    loads: list[PhdrLoad]
    load_bias: int          # first.vaddr - first.offset; a property of the FILE
    bss_start: int          # merged NOBITS tail lower bound, ELF vaddr space
    bss_end: int            # merged NOBITS tail upper bound, ELF vaddr space
    dynamic_vaddr: int | None = None  # PT_DYNAMIC vaddr, ELF vaddr space

    def to_runtime(self, vaddr: int, first_map: int) -> int:
        """Translate an ELF vaddr to a runtime address given the module's base.

        `first_map` is the runtime address of the module's first mapping, which
        is NOT always `load_bias` (a prelinked PIE has load_bias 0x200000 while
        its first mapping sits at 0x400000). Callers that guessed got it wrong.
        """
        return first_map + (vaddr - self.load_bias)


class ElfParseError(Exception):
    pass


def parse_elf64(data: bytes, *, allow_zero_magic: bool = False) -> ElfInfo:
    """Parse the minimum ELF64 header + program headers needed for load bias.

    `data` should start at the module's file-offset-0 mapping (the ELF header).
    allow_zero_magic: in-memory parsing must tolerate bionic's anti-dump
    hardening, which zeroes the 4 magic bytes after load while leaving
    class/data/version/e_type/phdrs intact (field finding, Android 16 device).
    Zero-magic headers are accepted when the remaining identity fields are sane.
    Raises ElfParseError on malformed input.
    """
    if len(data) < 64:
        raise ElfParseError(f"too short for ELF header: {len(data)}")
    if data[:4] == b"\x7fELF":
        pass
    elif allow_zero_magic and data[:4] == b"\x00\x00\x00\x00":
        pass  # bionic anti-dump: magic zeroed in memory, rest of header intact
    else:
        raise ElfParseError(f"bad ELF magic: {data[:4].hex()}")
    ei_class, ei_data = data[4], data[5]
    if ei_class != 2:
        raise ElfParseError("not ELF64")
    if ei_data != 1:
        raise ElfParseError("not little-endian")

    e_entry, e_phoff, e_shoff = struct.unpack_from("<QQQ", data, 0x18)
    (e_phentsize,) = struct.unpack_from("<H", data, 0x36)
    (e_phnum,) = struct.unpack_from("<H", data, 0x38)
    if e_phentsize < 56 or e_phnum == 0 or e_phnum > 512:
        raise ElfParseError(f"bad phnum/phentsize: {e_phnum}/{e_phentsize}")
    if e_phoff + e_phentsize * e_phnum > len(data):
        raise ElfParseError("program header table truncated")

    loads: list[PhdrLoad] = []
    dynamic_vaddr: int | None = None
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, base)
        if p_type == PT_DYNAMIC:
            _p_offset, p_vaddr, _p_paddr, _p_filesz, _p_memsz = struct.unpack_from("<QQQQQ", data, base + 8)
            dynamic_vaddr = p_vaddr
            continue
        if p_type != PT_LOAD:
            continue
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack_from(
            "<QQQQQ", data, base + 8)
        (p_align,) = struct.unpack_from("<Q", data, base + 48)
        loads.append(PhdrLoad(vaddr=p_vaddr, memsz=p_memsz, filesz=p_filesz,
                              offset=p_offset, flags=p_flags,
                              align=p_align or 0x1000))

    if not loads:
        raise ElfParseError("no PT_LOAD segments")

    first = min(loads, key=lambda s: s.vaddr)
    load_bias = first.vaddr - first.offset  # matches the documented CLI semantics

    # Merged BSS = the NOBITS tail of each PT_LOAD (where memsz > filesz).
    #
    # Page alignment matters here. The loader maps an anonymous region covering
    # the page-aligned tail, so the runtime BSS starts at
    #   page_align_up(vaddr + filesz)
    # and NOT at vaddr + filesz. Using the unaligned value put every .bss
    # translation a sub-page amount too low (field-measured: exactly 0x468 on
    # libGameCore.so, which is `file_end & 0xfff`). Section headers agree with
    # the aligned value: .bss has sh_addr 0x526f000 while vaddr+filesz is
    # 0x526eb98.
    # Only the LAST PT_LOAD can carry the real .bss. Earlier segments may also
    # have memsz > filesz, but that gap is just page padding between segments
    # (the linker aligns the next segment up to p_align), not zero-initialised
    # storage. Taking min() over every NOBITS tail therefore reported a bogus
    # start at the padding boundary: on a 16 KiB-aligned static PIE it produced
    # 0x70000 while the actual .bss sits at 0x74000 (section header agrees with
    # the latter).
    # The exact .bss start depends on the SECTION's sh_addralign, which is not
    # present in the program headers — and it varies per binary:
    #   tanyao_target  : .bss @ 0x491950 = align16(p_vaddr+p_filesz)
    #   libGameCore.so : .bss @ 0x526f000 = align4K(p_vaddr+p_filesz)
    # Guessing one alignment breaks the other. So report the CONSERVATIVE
    # window: [p_vaddr + p_filesz, p_vaddr + p_memsz). Any real .bss byte is
    # inside it, and the start is a lower bound (at most sh_addralign-1 below
    # the true section start).
    bss_start, bss_end = 0, 0
    for seg in loads:
        if seg.memsz <= seg.filesz:
            continue
        start = seg.vaddr + seg.filesz      # ELF vaddr space, no bias applied
        end = seg.vaddr + seg.memsz
        # Keep the highest start: only the final NOBITS tail is real .bss.
        if start > bss_start:
            bss_start = start
        bss_end = max(bss_end, end)

    return ElfInfo(
        entry=e_entry,
        phoff=e_phoff,
        phentsize=e_phentsize,
        phnum=e_phnum,
        loads=loads,
        load_bias=load_bias,
        bss_start=bss_start,
        bss_end=bss_end,
        dynamic_vaddr=dynamic_vaddr,
    )


def vaddr_to_offset(info: ElfInfo, vaddr: int) -> int:
    """Translate an ELF vaddr (bias-relative) to a file offset in a flat dump."""
    for seg in info.loads:
        if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
            return seg.offset + (vaddr - seg.vaddr)
    raise ElfParseError(f"vaddr 0x{vaddr:x} not in any PT_LOAD filesz range")


def detect_mirror(maps: list[tuple[int, int, int, str]], module_path: str) -> bool:
    """Detect full-file mirror: a same-module offset-0 mapping at least 2x larger
    than another same-module offset-0 mapping (the CLI's documented heuristic,
    without assuming a fixed permission string).

    maps: list of (start, end, file_offset, pathname).
    """
    candidates = [
        (end - start, file_offset)
        for start, end, file_offset, path in maps
        if path == module_path and file_offset == 0
    ]
    if len(candidates) < 2:
        return False
    sizes = sorted((size for size, _ in candidates), reverse=True)
    return sizes[0] >= sizes[-1] * 2
