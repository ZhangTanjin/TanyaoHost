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


@dataclass(slots=True)
class ElfInfo:
    entry: int
    phoff: int
    phentsize: int
    phnum: int
    loads: list[PhdrLoad]
    load_bias: int  # vaddr of first PT_LOAD minus its file offset (the "load bias")
    bss_start: int  # absolute (bias-relative) merged BSS bounds
    bss_end: int
    dynamic_vaddr: int | None = None  # PT_DYNAMIC segment vaddr (bias-relative), if present


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
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, base + 8)
        loads.append(PhdrLoad(vaddr=p_vaddr, memsz=p_memsz, filesz=p_filesz, offset=p_offset, flags=p_flags))

    if not loads:
        raise ElfParseError("no PT_LOAD segments")

    first = min(loads, key=lambda s: s.vaddr)
    load_bias = first.vaddr - first.offset  # matches the documented CLI semantics

    # merged BSS = parts of PT_LOAD where memsz > filesz
    bss_start, bss_end = 0, 0
    for seg in loads:
        if seg.memsz > seg.filesz:
            start = seg.vaddr + seg.filesz - load_bias
            end = seg.vaddr + seg.memsz - load_bias
            if bss_end == 0 or start < bss_start:
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
