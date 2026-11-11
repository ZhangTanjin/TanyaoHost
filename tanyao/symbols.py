"""In-memory symbol table resolution for mapped ELF modules (MiniMem symbol_find/list).

Parses DT_SYMTAB/DT_STRTAB/DT_HASH|DT_GNU_HASH from the module's memory image
via TARGET_MAPS reads — no host dump file required. Works on the live process:
bias-relative dynamic-table pointers are relocated by the loader at runtime
(glibc/bionic rewrite them to absolute), so both raw and absolute pointer
forms are handled.

Entry kinds returned as 4-char type + 4-char bind strings (e.g. "FUNC", "GLOBAL").
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .elfinfo import ElfInfo, ElfParseError, parse_elf64

DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_SYMENT = 11
DT_GNU_HASH = 0x6FFFFEF5

STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE = 0, 1, 2, 3, 4
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2

_SYM_FMT = struct.Struct("<IBBHQQ")  # st_name, st_info, st_other, st_shndx, st_value, st_size
_SYM_SIZE = _SYM_FMT.size  # 24

_KINDS = {STT_NOTYPE: "NOTYPE", STT_OBJECT: "OBJECT", STT_FUNC: "FUNC", STT_SECTION: "SECTION", STT_FILE: "FILE"}
_BINDS = {STB_LOCAL: "LOCAL", STB_GLOBAL: "GLOBAL", STB_WEAK: "WEAK"}


@dataclass(slots=True)
class Symbol:
    name: str
    address: int  # absolute in-process address (bias + st_value)
    size: int
    kind: str     # FUNC / OBJECT / NOTYPE / ...
    bind: str     # LOCAL / GLOBAL / WEAK

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": f"0x{self.address:x}",
            "size": self.size,
            "type": self.kind,
            "bind": self.bind,
        }


class SymbolError(Exception):
    pass


def _read_dynamic_entries(read_u64, dyn_vaddr_abs: int, limit: int = 256) -> dict:
    """Walk Elf64_Dyn array ({u64 tag, u64 val} pairs) until DT_NULL."""
    tags: dict[int, int] = {}
    for i in range(limit):
        raw = read_u64(dyn_vaddr_abs + i * 16, 16)
        tag, val = struct.unpack("<QQ", raw)
        if tag == DT_NULL:
            break
        tags.setdefault(tag, val)
    return tags


def _count_via_hash(hash_addr: int, read_u32) -> int:
    """SysV hash table: nchain at offset 4 equals the symbol count."""
    raw = read_u32(hash_addr, 8)
    nbucket, nchain = struct.unpack("<II", raw)
    return nchain


def _count_via_gnu_hash(gh_addr: int, read_u32) -> int | None:
    """GNU hash: no direct count. Walk buckets for the highest symbol index,
    then follow the chain from that bucket's start index until terminator."""
    raw = read_u32(gh_addr, 16)
    nbuckets, symoffset, bloom_size, _bloom_shift = struct.unpack("<IIII", raw)
    buckets_off = gh_addr + 16 + bloom_size * 8
    buckets_raw = read_u32(buckets_off, nbuckets * 4)
    buckets = struct.unpack(f"<{nbuckets}I", buckets_raw)
    if not any(buckets):
        return symoffset
    last = max(buckets)
    if last < symoffset:
        return symoffset
    # walk chain for `last`
    chain_off = buckets_off + nbuckets * 4
    idx = last
    for _ in range(1_000_000):  # hard safety bound
        val = struct.unpack("<I", read_u32(chain_off + (idx - symoffset) * 4, 4))[0]
        if val & 1:
            return idx + 1
        idx += 1
    raise SymbolError("gnu hash chain walk did not terminate")


def _maybe_abs(pointer: int, bias_abs: int, region_lo: int, region_hi: int) -> int:
    """Bionic/glibc rewrite DT_* pointers to absolute at load time; older/odd
    linkers keep bias-relative values. Decide by which interpretation lands
    inside the module's mapping range."""
    if region_lo <= pointer < region_hi:
        return pointer  # already absolute
    cand = bias_abs + pointer
    if region_lo <= cand < region_hi:
        return cand
    return pointer  # caller's range check will reject with a clear error


def load_symbols(
    read_fn,
    first_map: int,
    mem_size: int,
    header_bytes: bytes,
) -> list[Symbol]:
    """Read the dynamic symbol table of a mapped module.

    read_fn(addr, size) -> bytes (raises on fault)
    first_map: absolute address of the module's file-offset-0 mapping
    header_bytes: bytes read at first_map (>= ELF header + phdrs)
    Returns symbols sorted by address (skips index-0 null symbol).
    """
    info: ElfInfo = parse_elf64(header_bytes, allow_zero_magic=True)
    bias_abs = first_map - info.load_bias  # absolute address where vaddr 0 lands
    region_lo, region_hi = first_map, first_map + mem_size

    if info.dynamic_vaddr is None:
        raise SymbolError("module has no PT_DYNAMIC segment")

    def read_u64(addr: int, size: int) -> bytes:
        return read_fn(addr, size)

    def read_u32(addr: int, size: int) -> bytes:
        return read_fn(addr, size)

    dyn_abs = bias_abs + info.dynamic_vaddr
    tags = _read_dynamic_entries(read_u64, dyn_abs)

    if DT_SYMTAB not in tags or DT_STRTAB not in tags:
        raise SymbolError("dynamic table lacks SYMTAB/STRTAB (stripped or static?)")

    symtab_abs = _maybe_abs(tags[DT_SYMTAB], bias_abs, region_lo, region_hi)
    strtab_abs = _maybe_abs(tags[DT_STRTAB], bias_abs, region_lo, region_hi)

    # symbol count: prefer DT_HASH nchain, else GNU hash walk, else cap between symtab and strtab
    count: int | None = None
    if DT_HASH in tags:
        try:
            hash_abs = _maybe_abs(tags[DT_HASH], bias_abs, region_lo, region_hi)
            count = _count_via_hash(hash_abs, read_u32)
        except Exception:
            count = None
    if count is None and DT_GNU_HASH in tags:
        try:
            gh_abs = _maybe_abs(tags[DT_GNU_HASH], bias_abs, region_lo, region_hi)
            count = _count_via_gnu_hash(gh_abs, read_u32)
        except Exception:
            count = None
    if count is None:
        # last resort: symtab traditionally precedes strtab
        if symtab_abs < strtab_abs:
            count = (strtab_abs - symtab_abs) // _SYM_SIZE
        else:
            raise SymbolError("cannot determine symbol count (no hash tables, symtab after strtab)")
    count = min(count, 1_000_000)

    syms: list[Symbol] = []
    for i in range(1, count):  # skip null symbol 0
        try:
            raw = read_fn(symtab_abs + i * _SYM_SIZE, _SYM_SIZE)
        except Exception:
            break  # unreadable tail: keep what we have
        st_name, st_info, _other, st_shndx, st_value, st_size = _SYM_FMT.unpack(raw)
        if st_shndx == 0:
            continue  # SHN_UNDEF: imported symbol, st_value=0 — no RE value (field feedback)
        if not st_name and not st_value:
            continue
        name = b""
        try:
            chunk = read_fn(strtab_abs + st_name, min(256, 4096))
            name = chunk.split(b"\x00", 1)[0]
        except Exception:
            pass
        syms.append(
            Symbol(
                name=name.decode("utf-8", "replace"),
                address=bias_abs + st_value,
                size=st_size,
                kind=_KINDS.get(st_info & 0xF, "NOTYPE"),
                bind=_BINDS.get(st_info >> 4, "LOCAL"),
            )
        )
    syms.sort(key=lambda s: (s.address, s.name))
    return syms
