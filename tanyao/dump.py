"""Module dump and memory watch, host-side.

dump_module reconstructs file-backed module mappings into a sparse image plus
manifest (CLI semantics, minus the device-side temp file dance).
watch samples a range repeatedly and reports diffs.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from .constants import MAP_READ


@dataclass(slots=True)
class DumpManifest:
    pid: int
    module: str
    entries: list[dict]
    total_size: int
    skipped: list[dict]
    maps_source: str = "target_maps"
    sanitized: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "module": self.module,
            "total_size": self.total_size,
            "maps_source": self.maps_source,
            "mappings": self.entries,
            "skipped": self.skipped,
            "sanitized": self.sanitized,
        }


def dump_module(
    pid: int,
    module: str,
    maps,
    read_fn,
    *,
    chunk: int = 1 << 20,
    include_anonymous: bool = False,
) -> tuple[bytes, DumpManifest]:
    """Reconstruct a mapped module.

    maps: list[MapEntry] from service.target_maps()
    read_fn(addr, size) -> bytes
    Returns (image_bytes, manifest). Layout mirrors the CLI: file-backed mappings
    written at their original file offset; optional anonymous appended in VMA order.
    Special fileless VMAs whose first read faults ([vvar]/[vdso]) are skipped.
    """
    module_maps = [m for m in maps if module and m.path.rstrip("/").split("/")[-1] == module]
    if not module_maps:
        raise ValueError(f"no mappings matched module {module!r}")

    mirror_path = _detect_mirror_path(module_maps)
    selected = [m for m in module_maps if not (mirror_path and m.file_offset == 0 and m.size >= _min_mirror_size(module_maps))]
    # Include ALL file-backed mappings of the module, even -w-p (no READ perm):
    # the kernel backend reads via access_process_vm(FOLL_FORCE), so write-only
    # mappings are readable in practice — field test showed PT_DYNAMIC lives in
    # a -w-p tail mapping (P2-2). Unreadable ones are skipped per-mapping with
    # a manifest record instead of failing the whole dump.
    if not selected:
        raise ValueError(f"no file-backed mappings for {module!r}")

    # File-backed mappings are written at their FILE OFFSET in the image (not
    # vaddr-derived): the loader's page-aligned vaddrs drift from file offsets
    # (field test P2-2: -w-p at vaddr 0x1FA000 = file 0x1F9000). Writing at
    # file offsets reproduces the original file layout so readelf/PT_DYNAMIC
    # validate. Image extent = max(file_offset + span) over file-backed maps.
    file_extent = max(m.file_offset + (m.end - m.start) for m in selected if m.path)
    image = bytearray(file_extent)
    covered = bytearray(file_extent)  # 1 = written
    entries: list[dict] = []
    skipped: list[dict] = []

    for m in selected:
        if not m.path:
            continue  # fileless mappings have no file-offset anchor
        out_off = m.file_offset
        pos = m.start
        mapping_failed = False
        while pos < m.end:
            take = min(chunk, m.end - pos)
            try:
                data = read_fn(pos, take)
            except Exception as exc:
                # per-mapping skip: any unreadable mapping (PFNMAP special page,
                # truly unreadable -w segment) is recorded, not fatal (P1/P2-2)
                skipped.append(
                    {"start": f"0x{m.start:x}", "end": f"0x{m.end:x}",
                     "at": f"0x{pos:x}", "path": m.path, "reason": str(exc)}
                )
                mapping_failed = True
                break
            off = out_off + (pos - m.start)
            image[off : off + len(data)] = data
            covered[off : off + len(data)] = b"\x01" * len(data)
            pos += len(data)
        if not mapping_failed:
            entries.append(
                {
                    "start": f"0x{m.start:x}",
                    "end": f"0x{m.end:x}",
                    "file_offset": f"0x{m.file_offset:x}",
                    "flags": m.flags,
                    "flags_str": m.flags_str(),
                    "path": m.path,
                    "out_offset": out_off,
                    "rva": m.file_offset,
                    "rva_note": "out_offset in image == file offset (file-layout reconstruction)",
                }
            )

    manifest = DumpManifest(
        pid=pid,
        module=module,
        entries=entries,
        total_size=file_extent,
        skipped=skipped,
    )

    if include_anonymous:
        anon = [m for m in maps if not m.path and (m.flags & MAP_READ) and m.end > m.start]
        appended = []
        for m in anon:
            try:
                data = read_fn(m.start, m.end - m.start)
            except Exception as exc:
                skipped.append({"start": f"0x{m.start:x}", "reason": str(exc)})
                continue
            appended.append(
                {
                    "start": f"0x{m.start:x}",
                    "end": f"0x{m.end:x}",
                    "size": len(data),
                    "append_offset": len(image),
                }
            )
            image.extend(data)
        manifest.entries.extend(appended)

    # Sanitize dangling section-header fields. The ELF header is copied from
    # memory, where e_shoff still points at the on-disk section table we do NOT
    # capture (only file-backed PT_LOAD ranges are written). A dangling e_shoff
    # made Ghidra's ELF importer silently skip dynsym symbol loading (field:
    # exported names like Java_* absent from the program). Zero the fields so
    # downstream tools (Ghidra/IDA/readelf) take the clean program-header path.
    if len(image) >= 0x40 and bytes(image[0:4]) == b"\x7fELF" and struct.unpack_from("<Q", image, 0x28)[0]:
        struct.pack_into("<Q", image, 0x28, 0)   # e_shoff
        struct.pack_into("<H", image, 0x3A, 0)   # e_shentsize
        struct.pack_into("<H", image, 0x3C, 0)   # e_shnum
        struct.pack_into("<H", image, 0x3E, 0)   # e_shstrndx
        manifest.sanitized = [
            "e_shoff", "e_shentsize", "e_shnum", "e_shstrndx",
        ]

    return bytes(image), manifest


def _min_mirror_size(maps) -> int:
    sizes = [m.size for m in maps if m.file_offset == 0]
    return min(sizes) * 2 if len(sizes) >= 2 else (max(sizes) if sizes else 1 << 62)


def _detect_mirror_path(maps) -> str | None:
    by_path: dict[str, list[int]] = {}
    for m in maps:
        if m.file_offset == 0:
            by_path.setdefault(m.path, []).append(m.size)
    for path, sizes in by_path.items():
        if len(sizes) >= 2:
            sizes_sorted = sorted(sizes, reverse=True)
            if sizes_sorted[0] >= sizes_sorted[-1] * 2:
                return path
    return None


def watch(
    read_fn,
    pid: int,
    address: int,
    size: int,
    *,
    interval_ms: int = 200,
    count: int = 10,
    changes_only: bool = False,
) -> list[dict]:
    """Sample a bounded range repeatedly. Returns sample dicts (hex data + changed flag)."""
    samples: list[dict] = []
    previous: bytes | None = None
    for i in range(max(1, count)):
        data = read_fn(address, size)
        changed = None if previous is None else data != previous
        sample = {
            "index": i,
            "timestamp": time.time(),
            "data_hex": data.hex(),
            "changed": changed,
        }
        if not changes_only or changed is not False:
            samples.append(sample)
        previous = data
        if i + 1 < count:
            time.sleep(interval_ms / 1000.0)
    return samples
