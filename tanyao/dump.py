"""Module dump and memory watch, host-side.

dump_module reconstructs file-backed module mappings into a sparse image plus
manifest (CLI semantics, minus the device-side temp file dance).
watch samples a range repeatedly and reports diffs.
pull_dump_with_resume is the v3 dump-pipeline client (cmd 63/64/65/68): chunked
pull with per-chunk crc32, one same-offset retry on corrupted chunks, and
offset-based resume (in-memory + sidecar state).
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
import zlib
from dataclasses import dataclass, field

from .constants import MAP_READ
from .frames import decode_dump_chunk


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


# -- v3 dump pipeline client (cmd 63/64/65/68; DESIGN_V3_HOST §3.2) ---------------


class PullResumeError(Exception):
    pass


def _pull_chunk_bytes(service, dump_id: str | None, path: str | None, offset: int,
                      chunk: int, compress: bool) -> tuple[bytes, bool]:
    """One dump_pull round trip → (plain bytes, is_last). Corruption, wrong
    offsets, and decode failures surface as AgentError('internal') so the retry
    policy can distinguish them from terminal errors (not_found etc.)."""
    from .connection import AgentError

    chk = service.dump_pull(dump_id=dump_id, path=path, offset=offset, chunk=chunk,
                            compress=compress)
    if chk.offset != offset:
        raise AgentError("internal", detail=f"dump_pull offset drift: got 0x{chk.offset:x}, want 0x{offset:x}")
    data = chk.data
    if chk.is_deflated:
        try:
            data = zlib.decompress(data)
        except zlib.error as exc:
            raise AgentError("internal", detail=f"dump chunk deflate failed at 0x{offset:x}: {exc}") from exc
    if len(data) != chk.raw_len:
        raise AgentError("internal", detail=f"dump chunk raw_len mismatch at 0x{offset:x}: {len(data)} != {chk.raw_len}")
    return data, chk.is_last


def _terminal_pull_error(exc) -> bool:
    from .connection import AgentError

    return isinstance(exc, AgentError) and exc.error in ("not_found", "bad_request", "disk_budget")


def pull_dump_with_resume(
    service,
    out_path: str,
    *,
    dump_id: str | None = None,
    path: str | None = None,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
    chunk: int = 256 * 1024,
    compress: bool = True,
    state_store: dict | None = None,
    progress=None,
) -> dict:
    """Pull a device dump (or an explicit device file via `path`) to out_path.

    Per-chunk crc32 is verified by decode; corrupted chunks retry once at the
    same offset, then fail with AgentError('internal') KEEPING already-received
    data so a later call can resume. Resume state lives in `state_store`
    (facade-owned dict) plus a `<out>.part`/`<out>.part.state` sidecar pair so
    a serve restart can pick up where it left off (draft §3.2).
    """
    from .connection import AgentError

    if dump_id is None and path is None:
        raise AgentError("bad_request", detail="pull needs dump_id or path")
    out_path = os.path.abspath(out_path)
    part_path = out_path + ".part"
    sidecar = out_path + ".part.state"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    offset = 0
    store = state_store if state_store is not None else {}
    st = store.get(dump_id or path) if (dump_id or path) else None
    if st is None and os.path.exists(sidecar):
        try:
            with open(sidecar, encoding="utf-8") as fh:
                st = json.load(fh)
        except (OSError, ValueError):
            st = None
    if st is not None and os.path.exists(part_path) and st.get("offset"):
        resume_ok = os.path.getsize(part_path) == st["offset"]
        if resume_ok and dump_id is not None:
            # reconcile with the device before trusting a stale checkpoint
            try:
                status = service.dump_status(dump_id)
                resume_ok = bool(status.get("exists")) and (
                    not expected_sha256 or status.get("sha256") == expected_sha256
                )
            except AgentError:
                resume_ok = False
        if resume_ok:
            offset = int(st["offset"])

    mode = "ab" if offset else "wb"
    try:
        with open(part_path, mode) as fh:
            while True:
                try:
                    data, last = _pull_chunk_bytes(service, dump_id, path, offset, chunk, compress)
                except AgentError as exc:
                    if _terminal_pull_error(exc):
                        raise
                    # one retry at the SAME offset (draft §3.2), then give up
                    # with the partial data intact (resume-able, no auto-wipe)
                    try:
                        data, last = _pull_chunk_bytes(service, dump_id, path, offset, chunk, compress)
                    except AgentError as exc2:
                        if _terminal_pull_error(exc2):
                            raise
                        store[dump_id or path] = {"offset": offset, "sha256": expected_sha256 or ""}
                        with open(sidecar, "w", encoding="utf-8") as fh2:
                            json.dump({"dump_id": dump_id, "path": path,
                                       "offset": offset, "sha256": expected_sha256 or ""}, fh2)
                        raise AgentError(
                            "internal",
                            detail=f"dump_pull failed twice at 0x{offset:x}: {exc2}; "
                                   f"{offset} bytes kept at {part_path}",
                        ) from exc2
                fh.write(data)
                fh.flush()
                offset += len(data)
                if progress is not None:
                    progress(offset)
                if last:
                    break
    except AgentError:
        raise

    if expected_size is not None and offset != expected_size:
        raise AgentError("internal", detail=f"dump size mismatch: got {offset}, want {expected_size}")

    hasher = hashlib.sha256()
    with open(part_path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(block)
    if expected_sha256 and hasher.hexdigest() != expected_sha256:
        raise AgentError("internal", detail=f"dump sha256 mismatch: got {hasher.hexdigest()}")
    os.replace(part_path, out_path)
    for cleanup in (sidecar,):
        try:
            if os.path.exists(cleanup):
                os.remove(cleanup)
        except OSError:
            pass
    if dump_id is not None:
        store.pop(dump_id, None)
    return {"path": out_path, "size": offset, "sha256": hasher.hexdigest()}
