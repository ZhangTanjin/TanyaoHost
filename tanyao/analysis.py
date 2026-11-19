"""Analysis facade: binds scan/elf/pointer/dump engines to a TanyaoService.

This is what IPC and MCP call. One facade per agent connection.
"""

from __future__ import annotations

import json
import os
import re as _re
import shutil
import struct
import subprocess
import threading
import time
import uuid
import zipfile
from typing import Any

from .connection import AgentError
from .constants import (
    AGENT_CAP_APK_INFO,
    AGENT_CAP_CALL_EXPORT,
    AGENT_CAP_FUZZY_FIND,
    AGENT_CAP_SCAN_VALUES,
    b64_decode,
    AGENT_CAP_DISASSEMBLE,
    AGENT_CAP_DUMP_PIPELINE,
    AGENT_CAP_SCAN,
    AGENT_CAP_SCAN_EXPLICIT_RANGES,
    AGENT_CAP_STRINGS,
    AGENT_CAP_SYMBOL_BATCH,
    AGENT_CAP_WRITE_TXN,
    MAP_EXEC,
    MAP_WRITE,
    hex_u64,
    parse_u64,
)
from . import ida_backend
from .dump import dump_module as _dump_module
from .dump import pull_dump_with_resume
from .dump import watch as _watch
from .addr import AddressModel, AddressModelError

# Above this estimated range size a scan always runs as a background job, so the
# request does not block a caller for minutes. Named once: it used to be spelled
# out as a literal at four sites in the scan paths.
INLINE_LIMIT = 64 * 1024 * 1024

# Above this, a scan must be confirmed explicitly.
#
# The number is not about performance — it is about blast radius. A field report
# describes a preset left at `all_readable` (11.7 GB) being silently reused by a
# later `scan_hex`: the scan read 5.88 GB and the target process died. Nothing in
# the response had said what was about to be read.
#
# Deliberately ABOVE INLINE_LIMIT: crossing INLINE_LIMIT only forces a scan to
# run as a background job, which is a scheduling decision and still automatic.
# Crossing this one means "this will touch gigabytes of someone else's memory",
# which deserves a human saying yes.
SCAN_CONFIRM_LIMIT = 256 * 1024 * 1024
from .mapsview import MAP_ANONYMOUS, MAP_READ, MapsView
from .jobs import JobManager, ScanCancelled
from .native import ApkParseError, disassemble_a64_ex, extract_strings, parse_apk_manifest
from .pointer import PointerChainError, resolve_chain
from .scan import PAC_MASK_DEFAULT, TYPES, ScanEngine
from .service import AgentUnavailable, TanyaoService
from .symbols import SymbolError, load_symbols


class WriteDisabled(Exception):
    pass




def _parse_aob(pattern: str) -> tuple[bytes, bytes]:
    """Parse an AOB pattern ("7F 45 ?? 46") into (bytes, mask). 0x00 mask = wildcard.

    Single source for scan_hex and scan_start hex jobs — the A1 blocker was
    scan_start passing only the pattern while the job runner expected
    (pattern, mask) and crashed with IndexError."""
    pattern_bytes = bytearray()
    mask_bytes = bytearray()
    for tok in pattern.split():
        if tok in ("?", "??"):
            pattern_bytes.append(0)
            mask_bytes.append(0)
        else:
            pattern_bytes.append(int(tok, 16))
            mask_bytes.append(0xFF)
    return bytes(pattern_bytes), bytes(mask_bytes)


def _looks_like_pointer(value: int) -> bool:
    """Heuristic: does this 64-bit word plausibly hold a (possibly PAC-signed)
    user-space pointer?

    Deliberately conservative. Blindly masking the top 16 bits turns arbitrary
    data into a plausible-looking address — a magic constant
    `0x54414e59414f0001` becomes `0x4e59414f0001`, which "is an address" but
    means nothing. Requiring the 48-bit payload to sit in the usual user VA
    window (and to be 8-byte aligned or page-aligned) filters that out while
    still accepting genuine signed pointers such as `0xb40000782510e410`.
    """
    low = value & PAC_MASK_DEFAULT
    if low == 0:
        return False
    # User-space VAs on Android/arm64 live well below 2^40; kernel or MMIO
    # addresses never reach these primitives through a PAC-signed pointer.
    if low >= (1 << 40):
        return False
    # Code/data pointers are at least 4-byte aligned.
    if low & 0x3:
        return False
    return True


class AnalysisFacade:
    def __init__(self, service: TanyaoService) -> None:
        self.service = service
        self._scans: dict[int, ScanEngine] = {}
        self._jobs = JobManager()
        # IDA decompile jobs live outside JobManager: they are plain objects
        # polled by the caller, and must survive independent of scan jobs.
        self._ida_jobs: dict[str, object] = {}
        self._write_enabled = os.environ.get("TANYAO_ALLOW_WRITE") == "1"
        # v1.4 §3.2: call gate mirrors the write gate — serve must be started
        # with TANYAO_ALLOW_CALL=1 for the call_export tool to exist
        self._call_enabled = os.environ.get("TANYAO_ALLOW_CALL") == "1"
        self._call_allowlist: set[tuple[str, str]] | None = None
        allowlist_path = os.environ.get("TANYAO_CALL_ALLOWLIST")
        if allowlist_path:
            self._call_allowlist = self._load_call_allowlist(allowlist_path)
        # v3 engine dispatch state (agent-scan path): last preset per pid for
        # cmd 50 passthrough, per-pid device-job metadata, and a map of host
        # job ids to device job ids so scan_cancel reaches the agent.
        self._scan_presets: dict[int, str] = {}
        # Which presets were set for the scan about to run, vs left over from an
        # earlier one. See _scan_scope: the difference is the accident shape.
        self._preset_fresh: dict[int, bool] = {}
        self._agent_scan_meta: dict[int, dict] = {}
        self._agent_job_map: dict[str, int] = {}
        # user-set explicit ranges (scan_set_range); carried onto cmd 50
        # `ranges` when the agent declares bit9, else forces the host engine
        # (D1: a v1.1 agent would silently ignore ranges and fall back to preset)
        self._explicit_ranges: dict[int, list[tuple[int, int]]] = {}
        # dump pipeline resume checkpoints (pull_dump_with_resume store)
        self._pull_states: dict[str, dict] = {}

    # -- helpers ----------------------------------------------------------------

    @staticmethod
    def _module_of(path: str) -> str | None:
        """Module attribution = basename of the mapping path (containment:
        an address belongs to whoever's mapping it falls in — D9)."""
        return path.rstrip("/").split("/")[-1] if path else None

    @classmethod
    def _runtime_to_file_offset(cls, maps, addr: int):
        """D9 per-mapping translation: runtime → (module basename, file offset)
        with runtime = m.start + (F − m.file_offset) — same semantics as the
        device dump/symbol engines. None for anonymous mappings / unmapped."""
        for m in maps:
            if m.start <= addr < m.end:
                if not m.path:
                    return None
                return cls._module_of(m.path), addr - m.start + m.file_offset
        return None

    @staticmethod
    def _file_offset_to_runtime(maps, module: str, file_offset: int):
        """D9 per-mapping translation: file offset → runtime address within the
        named module's mapping whose file window covers it; None if uncovered."""
        for m in maps:
            if (m.path and AnalysisFacade._module_of(m.path) == module
                    and m.file_offset <= file_offset < m.file_offset + m.size):
                return m.start + (file_offset - m.file_offset)
        return None

    def _read_for(self, pid: int):
        def read_fn(addr: int, size: int) -> bytes:
            return self.service.mem_read(pid, addr, size)

        return read_fn

    def _scan_for(self, pid: int) -> ScanEngine:
        engine = self._scans.get(pid)
        if engine is None:
            backend = self.service.backend_info()
            engine = ScanEngine(
                self.service.mem_read,
                max_transfer=backend.max_transfer_size,
                readv_fn=self.service.mem_readv,
                max_iov=backend.max_iov,
            )
            self._scans[pid] = engine
        return engine

    # -- process / module ----------------------------------------------------------

    def find_process(self, name: str, *, mode: str = "exact") -> dict:
        if mode not in ("exact", "substring"):
            raise AgentError("bad_request", detail=f"unknown find mode {mode!r}")
        if mode == "substring" and not self.service.has_agent_cap(AGENT_CAP_FUZZY_FIND):
            # no silent degrade to exact: the caller asked for fuzzy semantics
            raise AgentError(
                "bad_request",
                detail="agent does not declare FUZZY_FIND (bit10); use the full "
                       "package/process name or list_processes instead")
        try:
            # V1.3 §2.1: multi-match carries matches=N — surfaced so the AI
            # can narrow the term instead of guessing on the first hit
            out = self.service.process_find_full(name, mode=mode)
            if mode == "substring":
                out["mode"] = "substring"
            # Attach the start_cookie so callers can pin the pid against reuse.
            # It is captured by opening the target once; the kernel's
            # start_cookie is the task's start_time, which is exactly what
            # expected_start_cookie verifies later. A failure here must not
            # fail find_process (target may be transiently unopenable), so the
            # cookie is best-effort and reported as absent when unavailable.
            pid = out.get("pid")
            if isinstance(pid, int) and pid > 0:
                try:
                    session = self.service.ensure_target(pid)
                    out["start_cookie"] = hex_u64(session.start_cookie)
                except AgentError:
                    pass
            return out
        except AgentError as exc:
            if exc.error == "not_found":
                # O4 lineage: exact match needs the FULL cmdline name; substring
                # is available when the agent declares bit10 (V1.3 §2.1)
                hint = ("use the FULL package/process name as in /proc/<pid>/cmdline "
                        "(e.g. com.tencent.lolm); short names (lolm) are not matched")
                if self.service.has_agent_cap(AGENT_CAP_FUZZY_FIND):
                    hint += " — or retry with mode='substring' for short names"
                hint += " — or call list_processes to enumerate pids"
                return {"pid": None, "found": False, "hint": hint}
            raise

    def list_modules(self, pid: int, name_filter: str | None = None) -> dict:
        """D13: per-segment module view from the single MapsView parser — no
        cross-segment end merging (a module's segments keep their gaps), no
        fabricated module names for anonymous mappings. base == first_map,
        same anchor resolve_module uses."""
        view = MapsView.from_maps(self.service.target_maps(pid))
        modules = []
        for v in sorted(view.modules.values(), key=lambda m: m.first_map):
            if name_filter and name_filter.lower() not in v.name.lower():
                continue
            modules.append({
                "name": v.name,
                "path": v.path,
                "base": f"0x{v.load_base:x}",
                "first_map": f"0x{v.first_map:x}",
                "mirror_present": any(s.mirror for s in v.segments),
                "segments": [
                    {
                        "start": f"0x{s.start:x}",
                        "end": f"0x{s.end:x}",
                        "size": s.size,
                        "file_offset": f"0x{s.file_offset:x}",
                        "permissions": s.flags_str(),
                        "mirror": s.mirror,
                        "file_overlap": s.file_overlap,
                        "alias_group": s.alias_group,
                    }
                    for s in v.segments
                ],
            })
        # Anonymous EXECUTABLE mappings are where injected code lives: JIT
        # stubs, inline-hook trampolines, and loader-generated islands all sit
        # in r-xp regions with no backing file. They deliberately do not appear
        # in `modules` (we refuse to invent names for them), but omitting them
        # entirely hid a live trampoline page from a field investigation — the
        # hook was found only by reading /proc/<pid>/maps by hand. Expose them
        # in their own list so the same mistake cannot repeat.
        anon_exec = []
        for seg in view.anonymous:
            if "x" not in seg.flags_str():
                continue
            anon_exec.append({
                "start": f"0x{seg.start:x}",
                "end": f"0x{seg.end:x}",
                "size": seg.size,
                "permissions": seg.flags_str(),
                "path": seg.path,
                # A short signature helps triage without a full disassembly:
                # executable-but-anonymous is the interesting set.
                "note": "anonymous executable mapping (JIT / trampoline / injected code)",
            })
        return {
            "pid": pid,
            "count": len(modules),
            "maps_source": self.service.maps_source(),
            "modules": modules,
            "anonymous_executable": anon_exec,
            "anonymous_executable_count": len(anon_exec),
        }

    def _resolve_bss_bounds(self, model: AddressModel) -> tuple[list[str] | None, str]:
        """Runtime BSS range for a module, as string bounds plus its evidence.

        The search now lives on AddressModel.bss_bounds — it needs the ELF BSS
        window, the module's segments AND the whole maps snapshot (the anonymous
        region sits outside this module's own segments), which is exactly what
        the model holds. This wrapper only adapts the shape for the tool layer.
        """
        bounds, note = model.bss_bounds()
        if bounds is None:
            return None, note
        lo, hi = bounds
        return [f"0x{lo:x}", f"0x{hi:x}"], note


    def resolve_module(self, pid: int, name: str) -> dict:
        view = MapsView.from_maps(self.service.target_maps(pid))
        v = view.modules.get(name)
        if v is None:
            raise AgentError("not_found", detail=f"module {name!r} not mapped in pid {pid}")
        # Mirror segments carry a valid ELF header too (whole-file image), but
        # PT_LOAD arithmetic describes the loader layout — anchor on the first
        # non-mirror segment when one exists.
        segs = [s for s in v.segments if not s.mirror] or v.segments
        first = segs[0]
        # The header read, the anchor derivation and the multi-anchor policy all
        # live in AddressModel now; this method only shapes the response.
        try:
            model = AddressModel.build(pid, name, self.service.target_maps(pid),
                                       self.service.mem_read)
        except AddressModelError as exc:
            if exc.unavailable:
                raise AgentError("unavailable", detail=exc.detail) from exc
            return {"pid": pid, "module": name, "first_map": f"0x{first.start:x}",
                    "error": exc.detail}
        info = model.elf
        base = first.start
        mirror = any(s.mirror for s in v.segments)
        load_bias_abs: int | None = None if model.base_is_ambiguous else model.base
        ambiguous = model.base_is_ambiguous
        bss, bss_note = self._resolve_bss_bounds(model)
        out = {
            "pid": pid,
            "module": name,
            "first_map": f"0x{base:x}",
            "load_bias": f"0x{load_bias_abs:x}" if load_bias_abs is not None else None,
            "bss": bss,
            "bss_note": bss_note,
            "mirror_detected": mirror,
            # D19: full segment table — translation_base is each segment's own
            # (start − file_offset) anchor; mirror flags the whole-file copies.
            #
            # vaddr_start/vaddr_end let a caller do segment attribution itself
            # instead of re-deriving it from load_bias, which cannot work on a
            # multi-anchor module and silently drifts on layouts whose first
            # mapping is not at load_bias.
            "segments": [
                {
                    "start": f"0x{s.start:x}",
                    "end": f"0x{s.end:x}",
                    "file_offset": f"0x{s.file_offset:x}",
                    "permissions": s.flags_str(),
                    "translation_base": f"0x{s.start - s.file_offset:x}",
                    "mirror": s.mirror,
                    "file_overlap": s.file_overlap,
                    "alias_group": s.alias_group,
                }
                for s in v.segments
            ],
        }
        # Attach each mapping's ELF vaddr window.
        #
        # Two facts make this subtle, and getting either wrong produces windows
        # that look plausible while being shifted by a page:
        #
        #   1. A mapping's file_offset is PAGE-ALIGNED, but p_offset need not be.
        #      When p_offset is not aligned, the mapping starts a few bytes
        #      BEFORE the segment's vaddr, so the mapping's first byte corresponds
        #      to `p_vaddr - (p_offset - map.file_offset)`, not to p_vaddr.
        #   2. Match on the page-aligned p_offset, not raw p_offset. Using the
        #      raw value fails to match at all and silently drops the window.
        #
        # A wrong window is worse than a missing one: the caller computes a
        # runtime address that is off by a page and everything downstream follows.
        _loads = sorted(model.elf.loads, key=lambda l: l.offset)
        for seg_out in out["segments"]:
            seg_off = int(seg_out["file_offset"], 16)
            seg_len = int(seg_out["end"], 16) - int(seg_out["start"], 16)
            file_end = seg_off + seg_len

            # A single mapping can span TWO PT_LOADs: the loader aligns the start
            # down to a page, so the tail of one segment and the head of the next
            # share a page and therefore a mapping. libc++.so is the textbook
            # case — its p_offsets are not page-aligned at all, so every mapping
            # after the first straddles a boundary.
            #
            # So the window is the union of the overlap with EACH LOAD, not the
            # range of whichever LOAD matched first.
            lo_v, hi_v = None, None
            spanned = []
            for load in _loads:
                ov_lo = max(load.offset, seg_off)
                ov_hi = min(load.offset + load.filesz, file_end)
                if ov_hi <= ov_lo:
                    continue
                v_lo = load.vaddr + (ov_lo - load.offset)
                v_hi = load.vaddr + (ov_hi - load.offset)
                lo_v = v_lo if lo_v is None else min(lo_v, v_lo)
                hi_v = v_hi if hi_v is None else max(hi_v, v_hi)
                spanned.append(load.vaddr)
            if lo_v is None:
                # This mapping's file range lies outside every PT_LOAD of the
                # ELF header we read. That is not an arithmetic failure: it
                # means the loaded image is not the file we think it is (an
                # upgraded library still mapped at its old offsets, or a module
                # whose on-disk copy was replaced after load).
                seg_out["vaddr_start"] = None
                seg_out["vaddr_end"] = None
                seg_out["vaddr_unmapped_reason"] = (
                    f"file range [0x{seg_off:x}, 0x{file_end:x}) matches no PT_LOAD "
                    f"of the ELF header at 0x{first.start:x}; the mapped image "
                    f"differs from the file on disk")
                continue
            seg_out["vaddr_start"] = f"0x{lo_v:x}"
            seg_out["vaddr_end"] = f"0x{hi_v:x}"
            if len(spanned) > 1:
                # Say so explicitly: a caller assuming one LOAD per mapping would
                # otherwise mis-attribute the boundary bytes.
                seg_out["spans_loads"] = len(spanned)

        # A single call that answers "where does this vaddr live" for callers who
        # would otherwise reach for load_bias + vaddr. This is the identity the
        # tool docs state but never exposed.
        out["vaddr_to_runtime_hint"] = (
            "resolve_vaddr(pid, module, vaddr) — handles .bss, zero-filled tails "
            "and multi-anchor layouts; do not do load_bias + vaddr arithmetic")
        if ambiguous:
            out["load_bias_ambiguous"] = True
            out["hint"] = ("load_bias is ambiguous on this multi-anchor layout — use "
                           "per-segment translation_base or derive the base from "
                           "disassemble self-reported rva")
        return out

    def _bss_owner(self, pid: int, view, anon_seg, address: int) -> tuple[str, int] | None:
        """Attribute an `[anon:.bss]`-style mapping to the module that owns it.

        This is the INVERSE of the address model: given a runtime address inside
        an anonymous region, which module put it there, and what is its ELF
        vaddr? Returns (module, elf_vaddr) or None.

        Two pieces of evidence, in order:

          1. adjacency — the anonymous region starts exactly where some module's
             last non-mirror segment ends. The loader maps a module's NOBITS
             immediately after its file-backed tail, so this usually narrows the
             candidate set to one module before any ELF is read.
          2. the module's ELF BSS window — the offset into the region must fall
             inside [bss_start, bss_end).

        Only the adjacent candidate gets an ELF read; scanning every module would
        cost one mem_read each.
        """
        target = anon_seg.start
        for name, mod in view.modules.items():
            segs = [x for x in mod.segments if not x.mirror] or mod.segments
            if not segs:
                continue
            if max(x.end for x in segs) != target:
                continue
            try:
                model = AddressModel.build(pid, name,
                                           self.service.target_maps(pid),
                                           self.service.mem_read)
            except AddressModelError:
                continue
            elf = model.elf
            if not elf.bss_end or elf.bss_start is None:
                continue
            offset = address - target
            if offset < 0 or offset >= (elf.bss_end - elf.bss_start):
                continue
            return name, elf.bss_start + offset
        return None

    def address_resolve(self, pid: int, address: int) -> dict:
        """D14: containment via the shared MapsView — an address outside the
        snapshot is reported as unknown; ranges are never fabricated."""
        view = MapsView.from_maps(self.service.target_maps(pid))
        mod, idx = view.find(address)
        if mod is None and idx is None:
            return {
                "pid": pid,
                "address": f"0x{address:x}",
                "unknown": True,
                "detail": "address is not inside any mapping of this pid",
            }
        if mod is not None:
            seg = mod.segments[idx]
            path, module = mod.path, mod.name
            out_extra: dict[str, Any] = {"segment_index": idx}
        else:
            seg = view.anonymous[idx]
            path, module = seg.path, None
            out_extra = {"segment_index": idx, "anonymous": True}
        out: dict[str, Any] = {
            "pid": pid,
            "address": f"0x{address:x}",
            "start": f"0x{seg.start:x}",
            "end": f"0x{seg.end:x}",
            "permissions": seg.flags_str(),
            "path": path,
            "module": module,
            "module_offset": f"0x{address - seg.start + seg.file_offset:x}"
            if path else None,
            "module_offset_space": "file_offset",
        }
        out.update(out_extra)

        # `[anon:.bss]` carries no module name in the kernel snapshot, so a
        # lookup there used to answer module=null and left the caller unable to
        # attribute the address. Infer ownership from adjacency + the owner's
        # ELF BSS window: the loader always maps a module's NOBITS right after
        # its last file-backed segment.
        # Anonymous mappings are not always labelled: the kernel may report
        # "[anon:.bss]", plain "[anon]", or an EMPTY path (verified on a 16 KiB
        # static PIE). Accept all three, but never a real file path.
        if module is None and (not seg.path or seg.path.startswith("[anon")):
            owner = self._bss_owner(pid, view, seg, address)
            if owner is not None:
                name_owner, elf_vaddr = owner
                out["module"] = name_owner
                out["module_inferred"] = "anon_bss_adjacency"
                out["module_offset"] = f"0x{elf_vaddr:x}"
                # Anonymous regions have no file offset at all, so here the
                # offset IS an ELF vaddr. Labelled explicitly because
                # module_offset is a file offset for every file-backed mapping.
                out["module_offset_space"] = "elf_vaddr"
                out["path"] = f"{seg.path} (of {name_owner})"
        if path:
            # D19 self-consistency: load_bias is reported ONLY when it agrees
            # with the containing segment — load_bias + rva == address must
            # hold inside one response (the field case had both fields true
            # simultaneously, pointing 39.5MB apart)
            try:
                resolved = self.resolve_module(pid, module)
                lb = resolved.get("load_bias")
                if isinstance(lb, str):
                    rva = address - seg.start + seg.file_offset
                    if int(lb, 16) + rva == address:
                        out["load_bias"] = lb
                    else:
                        out["load_bias_ambiguous"] = True
                elif resolved.get("load_bias_ambiguous"):
                    out["load_bias_ambiguous"] = True
            except AgentError:
                pass
        if path:
            # D9: file-layout rva straight from the per-mapping translation —
            # the authoritative runtime↔file-offset reference (R7)
            file_offset = address - seg.start + seg.file_offset
            out["file_offset"] = f"0x{file_offset:x}"
            out["rva"] = out["file_offset"]
        return out

    @staticmethod
    def _load_call_allowlist(path: str) -> set[tuple[str, str]]:
        """Host-side mirror of the device allowlist (v1.4 §3.1 line format:
        'group:module_basename:symbol' or 'module_basename:symbol'). Used for
        pre-validation and the get_status entries count — the agent-side list
        remains authoritative."""
        entries: set[tuple[str, str]] = set()
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) == 3:
                    entries.add((parts[1], parts[2]))
                elif len(parts) == 2:
                    entries.add((parts[0], parts[1]))
        return entries

    def call_export(self, pid: int, module: str, symbol: str, *, args: list | None = None,
                    ret_type: str = "u64", probe_ret: bool = False) -> dict:
        """V1.4 cmd 80: controlled in-process call of an allowlisted export.
        Double gate (host TANYAO_ALLOW_CALL=1 + agent allowlist); this is an
        EXPLICITLY AUTHORISED operation on the target — every attempt is
        audited device-side, and TP anti-cheat may observe the attach."""
        if not self._call_enabled:
            raise AgentError(
                "call_disabled",
                detail="call_export is disabled; start serve with TANYAO_ALLOW_CALL=1 "
                       "(explicit authorisation for live-target calls)")
        args = list(args or [])
        if len(args) > 8:
            raise AgentError("bad_request", detail="at most 8 args (x0-x7)")
        if not self.service.has_agent_cap(AGENT_CAP_CALL_EXPORT):
            raise AgentError(
                "unsupported",
                detail="agent does not declare CALL_EXPORT (bit13); it either predates "
                       "v1.4 or runs without a call allowlist")
        if self._call_allowlist is not None:
            key = (module.rsplit("/", 1)[-1], symbol)
            if key not in self._call_allowlist:
                raise AgentError("not_in_allowlist",
                                 detail=f"{module}:{symbol} is not in the host allowlist")
        return self.service.call_export(pid, module, symbol, args=args,
                                        ret_type=ret_type, probe_ret=probe_ret)

    # -- memory ----------------------------------------------------------------------

    def read_memory(self, pid: int, address: int, size: int, *, as_type: str | None = None,
                    count: int = 1, pid_cookie: int | None = None,
                    strip_pac: bool = False) -> dict:
        """Raw/typed read. pid_cookie (from find_process.start_cookie) pins the
        pid: if the process restarted and the pid was recycled, the kernel
        answers -ESTALE instead of silently reading the wrong process.

        strip_pac (default OFF) masks the top 16 bits of each returned pointer,
        matching the convention already used by resolve_offset_chain and
        pointers_to. Off by default because this is the raw-memory primitive:
        silently altering bytes would make it useless for binary diffing,
        checksumming and disassembly. Turn it on when walking pointer chains,
        where signed pointers otherwise poison the address arithmetic.

        Only the *interpreted* values are masked; data_hex always carries the
        untouched bytes, so both views are available in one response.
        """
        if as_type:
            fmt, width, kind = TYPES[as_type]
            total = width * max(1, count)
            data = self.service.mem_read(pid, address, total, expected_cookie=pid_cookie)
            values = [struct.unpack_from(fmt, data, i * width)[0] for i in range(max(1, count))]
            out = {
                "pid": pid,
                "address": f"0x{address:x}",
                "type": as_type,
                "count": count,
                "values": values,
                # The same numbers as hex STRINGS.
                #
                # JSON has no integer type: a parser that yields IEEE doubles
                # silently rounds anything above 2^53. A pointer like
                # 0xB4007BE0774880 (12970367458873919616) comes back wrong in the
                # last digits while data_hex stays correct — so the response
                # contradicts itself and the more convenient field is the lying
                # one. Hex strings have no such cliff, for any width.
                "values_hex": [f"0x{v:x}" for v in values],
                "data_hex": data.hex(),
            }
            if strip_pac and kind == "int" and width == 8:
                # PAC lives in the top byte(s); mask to the 48-bit VA space.
                # Guard: stripping is only meaningful for values that LOOK like
                # signed pointers (48-bit payload non-zero + high bits set).
                # Applying the mask blindly turns arbitrary data into a
                # plausible-looking but meaningless address — a 64-bit magic
                # constant 0x54414e59414f0001 becomes 0x4e59414f0001.
                stripped, noted = [], []
                for v in values:
                    low = v & PAC_MASK_DEFAULT
                    if _looks_like_pointer(v):
                        stripped.append(low)
                        noted.append(True)
                    else:
                        stripped.append(v)
                        noted.append(False)
                out["values_stripped"] = stripped
                out["pac_stripped"] = True
                out["pac_applied"] = noted
            return out
        data = self.service.mem_read(pid, address, size, expected_cookie=pid_cookie)
        out = {"pid": pid, "address": f"0x{address:x}", "size": size,
               "data_hex": data.hex()}
        if strip_pac:
            # Interpret the buffer as a sequence of 8-byte pointers. Non-pointer
            # words are returned unchanged (see the typed branch above for why
            # blind masking is dangerous).
            n = size // 8
            if n:
                ptrs = [struct.unpack_from("<Q", data, i * 8)[0] for i in range(n)]
                stripped, applied = [], []
                for v in ptrs:
                    low = v & PAC_MASK_DEFAULT
                    if _looks_like_pointer(v):
                        stripped.append(f"0x{low:x}")
                        applied.append(True)
                    else:
                        stripped.append(f"0x{v:x}")
                        applied.append(False)
                out["pointers_stripped"] = stripped
                out["pac_stripped"] = True
                out["pac_applied"] = applied
        return out

    def write_bytes(self, pid: int, address: int, data: bytes, *, expect_old: bytes | None = None) -> dict:
        if not self._write_enabled:
            raise WriteDisabled(
                "memory write is disabled; set TANYAO_ALLOW_WRITE=1 on the host to enable"
            )
        if self.service.has_agent_cap(AGENT_CAP_WRITE_TXN):
            # bit1: the gate stays here, the expect→write→verify round trip
            # collapses into cmd 60 (PROTOCOL.md §7.5, DESIGN_V3_HOST §3.5)
            try:
                resp = self.service.write_txn(pid, address, data, expect_old=expect_old, verify=True)
            except AgentError as exc:
                if exc.error == "expect_old_mismatch" and exc.payload.get("old_b64"):
                    # D5: decode the device-attached old bytes into the detail
                    old_hex = b64_decode(exc.payload["old_b64"]).hex()
                    exc.detail = f"expect_old mismatch: device has {old_hex} (old_b64 preserved)"
                raise
            return {
                "pid": pid,
                "address": f"0x{address:x}",
                "bytes_written": parse_u64(resp.get("result_size", "0x0"), field="result_size"),
                "verified": bool(resp.get("verified", False)),
                "rolled_back": bool(resp.get("rolled_back", False)),
                "engine": "agent-write-txn",
            }
        if expect_old is not None:
            old = self.service.mem_read(pid, address, len(expect_old))
            if old != expect_old:
                raise AgentError(
                    "backend_error",
                    detail=f"expect_old mismatch: have {old.hex()}, expected {expect_old.hex()}",
                )
        written = self.service.mem_write(pid, address, data)
        verify = self.service.mem_read(pid, address, len(data))
        return {
            "pid": pid,
            "address": f"0x{address:x}",
            "bytes_written": written,
            "verified": verify == data,
            "engine": "host-write",
        }

    def resolve_offset_chain(
        self,
        pid: int,
        start: int,
        offsets: list[int],
        *,
        vtype: str = "u64",
        strip_pac: bool = True,
        pointer_mask: int | None = None,
    ) -> dict:
        read_fn = self._read_for(pid)
        try:
            return resolve_chain(
                read_fn, start, offsets, vtype=vtype, strip_pac=strip_pac, pointer_mask=pointer_mask
            )
        except PointerChainError as exc:
            raise AgentError("backend_error", detail=str(exc)) from exc

    def watch(self, pid: int, address: int, size: int, *, interval_ms: int = 200, count: int = 10, changes_only: bool = False) -> dict:
        read_fn = self._read_for(pid)
        samples = _watch(
            read_fn, pid, address, size,
            interval_ms=interval_ms, count=count, changes_only=changes_only,
        )
        return {"pid": pid, "address": f"0x{address:x}", "size": size, "samples": samples}

    # -- scan ----------------------------------------------------------------------------

    def _agent_scan_enabled(self, pid: int) -> bool:
        """Engine dispatch (DESIGN_V3_HOST §3.1): bit0 in hello.capabilities →
        scan_* goes to the device (cmd 50-55); otherwise the frozen host engine."""
        return self.service.has_agent_cap(AGENT_CAP_SCAN)

    def _scan_route(self, pid: int) -> str:
        """Engine choice for the next scan on pid: 'agent' or 'host'.

        D1 rule (PROTOCOL.md §7.2 v1.2.1 附录): with user-set explicit ranges
        the device engine only qualifies when the agent declared bit9
        SCAN_EXPLICIT_RANGES — an agent without bit9 would silently ignore
        `ranges` and fall back to the preset, scanning the WRONG ranges.
        Fallback must never surface as an error to the user."""
        if not self.service.has_agent_cap(AGENT_CAP_SCAN):
            return "host"
        explicit = self._explicit_ranges.get(pid)
        if explicit and not self.service.has_agent_cap(AGENT_CAP_SCAN_EXPLICIT_RANGES):
            return "host"
        return "agent"

    def _scan_scope(self, pid: int, *, allow_large: bool = False) -> dict:
        """Describe the scope the NEXT scan will use, and gate the dangerous sizes.

        This exists because of a real accident: a preset left at `all_readable`
        (11.7 GB) was silently reused by a later scan, which read 5.88 GB and
        killed the target. The caller had no way to see what was coming.

        Returns the fields every scan response now carries:

          range_source      "explicit" | "preset" | "inherited" | "default"
          scan_bytes        total bytes about to be read
          scan_segments     how many ranges that is
          effective_ranges  the actual [start, end] pairs

        `inherited` is the accident shape and is called out separately: it means
        this call did not choose the scope, it merely failed to change it.
        """
        engine = self._scan_for(pid)
        ranges = list(engine.state.ranges)
        total = sum(e - s for s, e in ranges)

        if self._explicit_ranges.get(pid):
            source = "explicit"
        elif pid in self._scan_presets:
            # Fresh means the caller set it for this scan; stale means it is a
            # leftover. Reporting them the same would hide exactly the case that
            # caused the incident.
            source = "preset" if self._preset_fresh.pop(pid, False) else "inherited"
        else:
            source = "default"

        if total > SCAN_CONFIRM_LIMIT and not allow_large:
            raise AgentError(
                "bad_request",
                detail=(f"this scan would read {total:,} bytes across "
                        f"{len(ranges)} range(s) (source: {source}), above the "
                        f"{SCAN_CONFIRM_LIMIT:,}-byte confirmation limit. Pass "
                        f"allow_large=true to proceed, or narrow the scope with "
                        f"scan_set_default_ranges first."),
            )

        out = {
            "range_source": source,
            "scan_bytes": total,
            "scan_segments": len(ranges),
            "effective_ranges": [[f"0x{s:x}", f"0x{e:x}"] for s, e in ranges],
        }
        if total > SCAN_CONFIRM_LIMIT:
            out["large_scope"] = True
        return out

    def _run_agent_scan(self, pid: int, kind: str, *, dev_job: int, meta: dict,
                        async_run: bool, limit: int) -> dict:
        """Run a device-side scan job to completion, or hand it to the job manager.

        Both scan entry points spelled this sequence out separately: start the
        device job, estimate the range size, go async past 64 MiB, otherwise
        block and shape the summary. Only `kind` and the result page size ever
        differed.
        """
        engine = self._scans.get(pid)
        est = sum(e - s for s, e in engine.state.ranges) if engine else 0
        if async_run or est > INLINE_LIMIT:
            return self._start_agent_scan_job(pid, kind, dev_job, meta)
        st = self._agent_wait(dev_job)
        summary = self._agent_summary(pid, st, meta)
        return summary | {"found": summary["count"],
                          "results": self._agent_results_page(dev_job, 0, limit),
                          "async": False}

    def _explicit_ranges_payload(self, pid: int) -> list[dict] | None:
        ranges = self._explicit_ranges.get(pid)
        if not ranges or len(ranges) > 4096:
            return None
        return [{"addr": f"0x{start:x}", "size": f"0x{end - start:x}"} for start, end in ranges]

    def _agent_summary(self, pid: int, st: dict, meta: dict) -> dict:
        """Map device scan_status fields onto the host ScanEngine.summary() shape.

        Note: the v1.1 wire carries skipped_bytes but no skipped-range count, so
        skipped_ranges is 0 unless the agent sends the additive field."""
        return {
            "pid": pid,
            "type": meta.get("type_label") or str(st.get("type") or "u32"),
            "round": int(st.get("round", 1)),
            "count": int(st.get("matches", 0)),
            "ranges": int(meta.get("ranges", 0)),
            "truncated": bool(st.get("truncated", False)),
            "skipped_ranges": int(st.get("skipped_ranges", 0)),
            "skipped_bytes": parse_u64(st.get("skipped_bytes", "0x0"), field="skipped_bytes"),
            # Why bytes were skipped. Without this a large skipped total is
            # unexplainable, which is exactly what hid a 1.6 GB protected
            # region during a field investigation.
            "skipped_events": int(st.get("skipped_events", 0)),
            "skipped_errno": int(st.get("skipped_errno", 0)),
            "skipped_reason": st.get("skipped_reason"),
            "engine": "agent-scan",
        }

    def _agent_scan_start(self, pid: int, *, kind: str, vtype: str | None = None,
                          value=None, pattern: str | None = None,
                          epsilon: float = 0.0, alignment: int = 0,
                          ranges: list[dict] | None = None) -> tuple[int, dict]:
        resp = self.service.agent_scan_start(
            pid, kind=kind, type=vtype, value=value, pattern=pattern,
            epsilon=epsilon, alignment=alignment,
            preset=None if ranges else self._scan_presets.get(pid, "anon"),
            ranges=ranges,
        )
        dev_job = int(resp["job_id"])
        meta = {
            "type_label": vtype if kind == "value" else "bytes",
            "ranges": int(resp.get("ranges", 0)),
            "dev_job": dev_job,
        }
        self._agent_scan_meta[pid] = meta
        return dev_job, meta

    def _agent_wait(self, dev_job: int, progress=None, cancel_event=None,
                    timeout: float = 600.0, *, label: str = "agent scan",
                    poll_interval: float = 0.05) -> dict:
        """Poll a device job until it finishes, mapping device states to host ones.

        One implementation for every device-side job. There used to be two
        (scan and strings) whose bodies differed only in three message strings
        and a sleep interval, so a fix to the cancel path had to be made twice.

        `label` names the job kind in error messages; `poll_interval` lets the
        long-running kinds poll less often.
        """
        deadline = time.monotonic() + timeout
        while True:
            if cancel_event is not None and cancel_event.is_set():
                try:
                    self.service.agent_scan_cancel(dev_job)
                except AgentError:
                    pass
                raise ScanCancelled()
            st = self.service.agent_scan_status(dev_job)
            if progress is not None:
                progress(
                    parse_u64(st.get("scanned_bytes", "0x0"), field="scanned_bytes"),
                    parse_u64(st.get("total_bytes", "0x0"), field="total_bytes"),
                )
            state = st.get("state")
            if state == "done":
                return st
            if state == "cancelled":
                raise ScanCancelled()
            if state == "error":
                raise AgentError("backend_error",
                                 detail=str(st.get("error") or f"{label} failed"))
            if time.monotonic() > deadline:
                raise AgentError("backend_error",
                                 detail=f"{label} {dev_job} timed out")
            time.sleep(poll_interval)

    def _agent_results_page(self, dev_job: int, offset: int, limit: int) -> list[dict]:
        resp = self.service.agent_scan_results(offset, limit)
        out: list[dict] = []
        for h in resp.get("hits", []):
            item: dict = {"address": str(h["address"])}
            for key in ("value", "value_hex", "length"):
                if key in h:
                    item[key] = h[key]
            out.append(item)
        return out

    def _start_agent_scan_job(self, pid: int, kind: str, dev_job: int, meta: dict) -> dict:
        """Wrap a device job in a host JobManager job (progress passthrough)."""
        cancel_event = threading.Event()

        def run(progress) -> dict:
            st = self._agent_wait(dev_job, progress=progress, cancel_event=cancel_event)
            summary = self._agent_summary(pid, st, meta)
            return summary | {"results": self._agent_results_page(dev_job, 0, 32)}

        job_id = self._jobs.start(pid, kind, run, cancel_event=cancel_event)
        self._agent_job_map[job_id] = dev_job
        out = {"job_id": job_id, "pid": pid, "kind": kind, "state": "running",
               "async": True, "poll": "scan_status"}
        engine = self._scans.get(pid)
        if engine and engine.state.ranges:
            # D18: volume estimate — all_readable-class scans announce their
            # size up front (device total_bytes arrives via scan_status)
            out["ranges"] = len(engine.state.ranges)
            out["total_bytes_estimate"] = sum(e - s for s, e in engine.state.ranges)
        return out

    def compute_preset_ranges(self, pid: int, preset: str) -> tuple[list[tuple[int, int]], dict]:
        """Single truth for preset → range selection (D13/D14: every consumer
        — scan_set_default_ranges, pointers_to, scan_start estimates — derives
        from the MapsView, never from ad-hoc map filtering).

        Returns (ranges, categories) with categories counting selected
        segments by class: module / anon (heap & anonymous) / stack."""
        view = MapsView.from_maps(self.service.target_maps(pid))
        categories = {"module": 0, "anon": 0, "stack": 0}
        ranges: list[tuple[int, int]] = []

        def take(seg, kind: str) -> None:
            ranges.append((seg.start, seg.end))
            categories[kind] += 1

        if preset == "anon":
            for s in view.anonymous:
                if (s.flags & MAP_READ) and (s.flags & MAP_ANONYMOUS or (s.flags & 2 and not s.path)):
                    take(s, "anon")
        elif preset == "stack":
            for s in view.anonymous:
                if "[stack" in s.path and (s.flags & 2):
                    take(s, "stack")
        elif preset == "all_readable":
            for v in view.modules.values():
                for seg in v.segments:
                    if seg.flags & MAP_READ:
                        take(seg, "module")
            for s in view.anonymous:
                if s.flags & MAP_READ:
                    take(s, "anon")
        elif preset.startswith("module:"):
            name = preset.split(":", 1)[1]
            v = view.modules.get(name)
            if v is None:
                raise AgentError("not_found", detail=f"module {name!r} not mapped")
            for seg in v.segments:
                if seg.flags & MAP_READ:
                    take(seg, "module")
        else:
            raise AgentError("bad_request", detail=f"unknown preset {preset!r}")
        return ranges, categories

    def scan_set_default_ranges(self, pid: int, *, preset: str = "anon") -> dict:
        """preset: anon (default, readable anonymous/heap), stack, module:<name>,
        all_readable (NOTE: includes ART boot images and every other readable
        file mapping — scope scans deliberately, F6). Host-side accounting
        only: the device engine derives its own ranges from the same preset at
        scan_start time; we keep a host snapshot for the est-based inline/async
        decision and error parity."""
        ranges, categories = self.compute_preset_ranges(pid, preset)
        if not ranges:
            if preset == "stack":
                raise AgentError("bad_request", detail="no [stack] mapping found")
            raise AgentError("not_found", detail=f"preset {preset!r} matched no readable ranges")
        engine = self._scan_for(pid)
        engine.set_ranges(pid, ranges)
        self._scan_presets[pid] = preset
        self._preset_fresh[pid] = True
        self._explicit_ranges.pop(pid, None)  # preset supersedes explicit ranges
        total = sum(e - s for s, e in engine.state.ranges)
        # F6: transparent preset summary (segments / total bytes / classes)
        return {
            "pid": pid,
            "preset": preset,
            "ranges": len(engine.state.ranges),
            "total_bytes": total,
            "categories": categories,
        }

    def scan_set_range(self, pid: int, start: int, end: int) -> dict:
        engine = self._scan_for(pid)
        engine.set_ranges(pid, [(start, end)])
        # D1: explicit ranges must survive the engine dispatch — carried onto
        # cmd 50 `ranges` under bit9, host engine otherwise
        self._explicit_ranges[pid] = [(start, end)]
        self._scan_presets.pop(pid, None)
        self._preset_fresh.pop(pid, None)
        return {"pid": pid, "ranges": 1, "span": end - start}

    def scan_value(
        self,
        pid: int,
        vtype: str,
        value: float,
        *,
        epsilon: float = 0.0,
        alignment: int | None = None,
        async_run: bool = False,
        allow_large: bool = False,
    ) -> dict:
        """First scan. With async_run=True (or estimated bytes > threshold) this runs
        as a background job: returns {'job_id','state':'running'} — poll scan_status.

        Every response states what was scanned and where that scope came from;
        see `_scan_scope`. A scope above SCAN_CONFIRM_LIMIT is refused unless
        `allow_large` is set.
        """
        scope = self._scan_scope(pid, allow_large=allow_large)
        if self._scan_route(pid) == "agent":
            dev_job, meta = self._agent_scan_start(
                pid, kind="value", vtype=vtype, value=value,
                epsilon=epsilon, alignment=alignment or 0,
                ranges=self._explicit_ranges_payload(pid),
            )
            return scope | self._run_agent_scan(pid, "value", dev_job=dev_job,
                                                meta=meta, async_run=async_run,
                                                limit=32)
        engine = self._scan_for(pid)
        est = sum(e - s for s, e in engine.state.ranges)
        if async_run or est > INLINE_LIMIT:
            return scope | self._start_scan_job(pid, "value", vtype, value,
                                                epsilon=epsilon, alignment=alignment)
        found = engine.scan_value(pid, vtype, value, epsilon=epsilon, alignment=alignment)
        return scope | engine.summary() | {"found": found,
                                           "results": engine.results(limit=32),
                                           "async": False, "engine": "host-scan"}

    def scan_hex(self, pid: int, pattern: str, *, async_run: bool = False,
                 allow_large: bool = False) -> dict:
        scope = self._scan_scope(pid, allow_large=allow_large)
        if self._scan_route(pid) == "agent":
            dev_job, meta = self._agent_scan_start(pid, kind="hex", pattern=pattern,
                                                   ranges=self._explicit_ranges_payload(pid))
            return scope | self._run_agent_scan(pid, "hex", dev_job=dev_job,
                                                meta=meta, async_run=async_run,
                                                limit=256)
        pattern_bytes, mask_bytes = _parse_aob(pattern)
        engine = self._scan_for(pid)
        est = sum(e - s for s, e in engine.state.ranges)
        if async_run or est > INLINE_LIMIT:
            return scope | self._start_scan_job(pid, "hex", bytes(pattern_bytes),
                                                bytes(mask_bytes))
        found = engine.scan_hex(pid, bytes(pattern_bytes), bytes(mask_bytes))
        return scope | engine.summary() | {"found": found,
                                           "results": engine.results(),
                                           "async": False, "engine": "host-scan"}

    def scan_start(self, pid: int, kind: str, *, type: str | None = None, value=None,
                   pattern: str | None = None, epsilon: float = 0.0,
                   alignment: int | None = None) -> dict:
        """Public async-scan entry (MCP scan_start). Validates kind/params then
        hands off to the background job runner."""
        if kind == "value":
            if type is None or value is None:
                raise AgentError("bad_request", detail="value scan requires 'type' and 'value'")
            if self._scan_route(pid) == "agent":
                dev_job, meta = self._agent_scan_start(
                    pid, kind="value", vtype=type, value=value,
                    epsilon=epsilon, alignment=alignment or 0,
                    ranges=self._explicit_ranges_payload(pid),
                )
                return self._start_agent_scan_job(pid, "value", dev_job, meta)
            return self._start_scan_job(pid, "value", type, value, epsilon=epsilon, alignment=alignment)
        if kind == "hex":
            if not pattern:
                raise AgentError("bad_request", detail="hex scan requires 'pattern'")
            if self._scan_route(pid) == "agent":
                dev_job, meta = self._agent_scan_start(pid, kind="hex", pattern=pattern,
                                                       ranges=self._explicit_ranges_payload(pid))
                return self._start_agent_scan_job(pid, "hex", dev_job, meta)
            pattern_bytes, mask_bytes = _parse_aob(pattern)
            return self._start_scan_job(pid, "hex", pattern_bytes, mask_bytes)
        raise AgentError("bad_request", detail=f"unknown scan kind {kind!r}")

    def _start_scan_job(self, pid: int, kind: str, *args, **kwargs) -> dict:
        engine = self._scan_for(pid)
        cancel_event = threading.Event()

        def run(progress) -> dict:
            if kind == "value":
                engine.scan_value(pid, args[0], args[1], epsilon=kwargs.get("epsilon", 0.0),
                                  alignment=kwargs.get("alignment"), progress=progress,
                                  cancel_event=cancel_event)
            else:
                engine.scan_hex(pid, args[0], args[1], progress=progress,
                                cancel_event=cancel_event)
            return engine.summary() | {"results": engine.results(limit=32), "engine": "host-scan"}

        job_id = self._jobs.start(pid, kind, run, cancel_event=cancel_event)
        out = {"job_id": job_id, "pid": pid, "kind": kind, "state": "running",
               "async": True, "poll": "scan_status"}
        if engine.state.ranges:
            # D18: volume estimate — all_readable-class scans announce size up front
            out["ranges"] = len(engine.state.ranges)
            out["total_bytes_estimate"] = sum(e - s for s, e in engine.state.ranges)
        return out

    def scan_cancel(self, pid: int, job_id: str) -> dict:
        """Request cancellation of a running scan job. The engine checks the
        cancel event between chunks and raises ScanCancelled (job → cancelled)."""
        if self._jobs.cancel(job_id):
            dev_job = self._agent_job_map.get(job_id)
            if dev_job is not None:
                try:
                    self.service.agent_scan_cancel(dev_job)
                except AgentError:
                    pass  # device job may have finished between poll cycles
            return {"job_id": job_id, "cancel_requested": True}
        raise AgentError("not_found", detail=f"job {job_id!r} unknown or already finished")

    def scan_status(self, pid: int, job_id: str | None = None) -> dict:
        if job_id:
            job = self._jobs.get(job_id)
            if job is None:
                raise AgentError("not_found", detail=f"job {job_id!r} unknown (or expired)")
            return job.to_dict()
        jobs = self._jobs.list_for(pid)
        if not jobs:
            return {"pid": pid, "jobs": []}
        return {"pid": pid, "jobs": [j.to_dict(include_summary=(j.state == "done")) for j in jobs[-8:]]}

    def _require_idle_scan(self, pid: int) -> None:
        """Refinement needs a completed scan: one must exist, and no job may run.

        Both engine branches of scan_next repeated these two checks, so a change
        to the ordering rule had to be made twice.
        """
        if any(j.state == "running" for j in self._jobs.list_for(pid)):
            raise AgentError("bad_request",
                             detail="a scan job is still running; poll scan_status first")

    def scan_next(self, pid: int, mode: str, value: float | None = None, *, epsilon: float = 0.0) -> dict:
        if self._agent_scan_enabled(pid):
            meta = self._agent_scan_meta.get(pid)
            if meta is None:
                raise AgentError("bad_request", detail="no scan in progress for this pid")
            self._require_idle_scan(pid)
            resp = self.service.agent_scan_refine(mode, value, epsilon=epsilon)
            st = self.service.agent_scan_status(meta["dev_job"])
            summary = self._agent_summary(pid, st, meta)
            return summary | {"found": int(resp.get("matches", 0))}
        engine = self._scans.get(pid)
        if engine is None or engine.state.scan_round == 0:
            raise AgentError("bad_request", detail="no scan in progress for this pid")
        self._require_idle_scan(pid)
        found = engine.refine(pid, mode, value, epsilon=epsilon)
        return engine.summary() | {"found": found, "engine": "host-scan"}

    def scan_results(self, pid: int, *, offset: int = 0, limit: int = 256) -> dict:
        """D18: truncation must be explicit — when more hits exist beyond this
        page the response carries next_offset; truncated stays at top level.
        Silent tail-drops are never OK."""
        if self._agent_scan_enabled(pid):
            meta = self._agent_scan_meta.get(pid)
            if meta is None:
                raise AgentError("bad_request", detail="no scan for this pid")
            st = self.service.agent_scan_status(meta["dev_job"])
            summary = self._agent_summary(pid, st, meta)
            results = self._agent_results_page(meta["dev_job"], offset, limit)
            out = summary | {"results": results}
            if offset + len(results) < int(summary.get("count", 0)):
                out["next_offset"] = offset + len(results)
            return out
        engine = self._scans.get(pid)
        if engine is None:
            raise AgentError("bad_request", detail="no scan for this pid")
        results = engine.results(offset, limit)
        out = engine.summary() | {"results": results, "engine": "host-scan"}
        if offset + len(results) < engine.state.count:
            out["next_offset"] = offset + len(results)
        return out

    def scan_clear(self, pid: int) -> dict:
        if self._agent_scan_enabled(pid):
            self.service.agent_scan_clear()
            return {"cleared": True, "engine": "agent-scan"}
        engine = self._scans.get(pid)
        if engine:
            engine.clear()
        return {"cleared": True, "engine": "host-scan"}

    # -- reverse rva resolution (R8/D20) --------------------------------------------

    # -- reference scanning (ADRP / ADR decode) --------------------------------

    @staticmethod
    def _sext(value: int, bits: int) -> int:
        sign = 1 << (bits - 1)
        return (value & (sign - 1)) - (value & sign)

    @classmethod
    def _decode_adrp(cls, word: int, pc: int) -> tuple[int, int] | None:
        """ADRP: 1xx1 0000 immlo[30:29] 10000 immhi[23:5] Rd[4:0]."""
        if (word & 0x9F000000) != 0x90000000:
            return None
        rd = word & 0x1F
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = cls._sext((immhi << 2) | immlo, 21)
        return rd, (pc & ~0xFFF) + (imm << 12)

    @classmethod
    def _decode_adr(cls, word: int, pc: int) -> int | None:
        """ADR: pc-relative +/-1 MiB."""
        if (word & 0x9F000000) != 0x10000000:
            return None
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        return pc + cls._sext((immhi << 2) | immlo, 21)

    @classmethod
    def _decode_ldr_literal(cls, word: int, pc: int) -> int | None:
        """LDR (literal, 64-bit): 0101 1000 imm19 Rt  -> address of the literal."""
        if (word & 0xFF000000) != 0x58000000:
            return None
        imm19 = (word >> 5) & 0x7FFFF
        return pc + (cls._sext(imm19, 19) << 2)

    @staticmethod
    def _decode_ldr_imm(word: int) -> tuple[int, int, int] | None:
        """LDR (immediate, unsigned offset, 64-bit): returns (rn, rt, byte_offset).

        Encoding: 11 111 0 01 01 imm12 Rn Rt  (size=11 for 64-bit).
        The scaled offset is imm12 << 3.
        """
        if (word & 0xFFC00000) != 0xF9400000:
            return None
        imm12 = (word >> 10) & 0xFFF
        rn = (word >> 5) & 0x1F
        rt = word & 0x1F
        return rn, rt, imm12 << 3

    @staticmethod
    def _decode_add_imm(word: int, rd: int, page: int) -> int | None:
        """ADD Xd, Xn, #imm{, lsl #12} where Xn == adrp's Rd."""
        if (word & 0x7F800000) != 0x11000000:
            return None
        if ((word >> 5) & 0x1F) != rd:
            return None
        imm12 = (word >> 10) & 0xFFF
        sh = (word >> 22) & 0x1
        return page + (imm12 << (12 if sh else 0))

    def _read_u64(self, pid: int, addr: int) -> int | None:
        try:
            raw = self.service.mem_read(pid, addr, 8)
        except AgentError:
            return None
        if len(raw) != 8:
            return None
        return int.from_bytes(raw, "little")

    def resolve_symbol_ref(self, pid: int, module: str, *, target: str,
                           max_hits: int = 32,
                           window: int = 0x400000) -> dict:
        """Find code that materialises a given address (the inverse of
        resolve_vaddr): scan the module's executable mappings for ADRP / ADRP+ADD
        / ADR sequences whose decoded target equals it.

        `target` accepts three forms, matching how the address is usually known:
          "0x542D920"                  explicit ELF vaddr
          "qword_542D920"              IDA-style <prefix>_<hex> symbol name
          "AiLocalBuffer init done"    a string constant in the module

        Every hit is reported with its machine code and, when the target is a
        plain vaddr, cross-checked against resolve_vaddr so the two independent
        paths visibly agree (or disagree) in the response.
        """
        raw = str(target).strip()
        form = "vaddr"
        vaddr: int | None = None

        if raw.lower().startswith("0x"):
            try:
                vaddr = int(raw, 16)
            except ValueError as exc:
                raise AgentError("bad_request",
                                 detail=f"target {raw!r} is not a hex address") from exc
        elif "_" in raw:
            # IDA-style names carry the address as the trailing hex field.
            tail = raw.rsplit("_", 1)[-1]
            try:
                vaddr = int(tail, 16)
                form = "symbol_name"
            except ValueError:
                vaddr = None
        if vaddr is None:
            # Treat it as a string constant: locate its address in the module.
            form = "string"
            # The constant may be a substring of a longer literal (printf format
            # strings, concatenated messages). Pass 1 wants an exact match; pass 2
            # accepts a containing string and reports the offset inside it, so
            # "BSS_PROBE_READY" resolves even though the literal is
            # "BSS_PROBE_READY pid=%d".
            hits = self.strings(pid, module=module, min_length=max(4, len(raw)),
                                limit=256, filter=_re.escape(raw))
            cand = hits.get("strings") or []
            exact = [h for h in cand if h.get("value") == raw]
            if exact:
                found = exact
                substr_off = 0
            else:
                holder = next((h for h in cand
                               if raw in str(h.get("value", ""))), None)
                if holder is None:
                    found = []
                    substr_off = 0
                else:
                    found = [holder]
                    substr_off = str(holder["value"]).index(raw)
            if not found:
                raise AgentError(
                    "not_found",
                    detail=f"{raw!r} is neither an address, an <name>_<hex> symbol, "
                           f"nor a string found in {module!r}")
            mod = next((m for m in self.service.target_maps(pid)
                        if m.path and m.path.rsplit("/", 1)[-1] == module), None)
            if mod is None:
                raise AgentError("not_found",
                                 detail=f"module {module!r} not mapped in pid {pid}")
            vaddr = (int(found[0]["address"], 16) + substr_off
                     - (mod.start - mod.file_offset))

        view = MapsView.from_maps(self.service.target_maps(pid))
        v = view.modules.get(module)
        if v is None:
            raise AgentError("not_found",
                             detail=f"module {module!r} not mapped in pid {pid}")

        # ADR/ADRP decode against a LIVE pc, so their results are RUNTIME
        # addresses, while an ELF vaddr is bias-relative. Comparing them
        # directly silently finds nothing. Normalise once, up front.
        #
        # A caller may also paste a RUNTIME address (that is what IDA shows for a
        # loaded binary, and what IDA-style symbol names embed). Detect that: if
        # the value already falls inside this module's mapped range it IS the
        # runtime address, so do not add the bias again.
        segs = [x for x in v.segments if not x.mirror] or v.segments
        mod_lo = min(x.start for x in segs)
        mod_hi = max(x.end for x in segs)
        # The .bss lives in an anonymous mapping AFTER the last segment, so the
        # plain segment range does not cover it. Widen the "this looks like a
        # runtime address" window by the module's BSS extent.
        # One model instead of two ad-hoc anchor derivations (this block used to
        # compute the same set twice, once inside a try and once outside).
        try:
            model = AddressModel.build(pid, module, self.service.target_maps(pid),
                                       self.service.mem_read)
        except AddressModelError:
            model = None
        if model is not None:
            mod_hi = max(mod_hi, model.to_runtime(model.elf.bss_end))
            already_runtime = model.is_runtime_addr(vaddr)
        else:
            already_runtime = mod_lo <= vaddr < mod_hi
        load_bias = (model.base
                     if model is not None and not model.base_is_ambiguous else None)
        if already_runtime:
            wanted = vaddr
        elif load_bias is not None:
            wanted = vaddr + load_bias
        else:
            # Multi-anchor module: fall back to the offset inside the segment
            # that contains the vaddr in ELF space.
            wanted = None
            try:
                wanted = int(self.resolve_vaddr(pid, module, vaddr)["runtime"], 16)
            except AgentError:
                wanted = None
            if wanted is None:
                raise AgentError(
                    "bad_request",
                    detail=f"cannot map vaddr {vaddr:#x} to a runtime address in "
                           f"{module!r} (multi-anchor layout); resolve_vaddr failed")

        hits_list: list[dict] = []
        scanned = 0
        for seg in v.segments:
            if "x" not in seg.flags_str():
                continue
            start, end = seg.start, seg.end
            stop = min(end, start + window)
            pos = start
            while pos < stop and len(hits_list) < max_hits:
                take = min(0x10000, stop - pos)
                try:
                    blob = self.service.mem_read(pid, pos, take)
                except AgentError:
                    pos += 0x1000
                    continue
                scanned += len(blob)
                for off in range(0, len(blob) - 7, 4):
                    pc = pos + off
                    w0 = int.from_bytes(blob[off:off + 4], "little")
                    adrp = self._decode_adrp(w0, pc)
                    if adrp is not None:
                        rd, page = adrp
                        w1 = int.from_bytes(blob[off + 4:off + 8], "little")
                        full = self._decode_add_imm(w1, rd, page)
                        if full == wanted:
                            hits_list.append({
                                "insn_addr": f"0x{pc:x}",
                                "pattern": "ADRP+ADD",
                                "machine_code": blob[off:off + 8].hex(),
                                "decoded_target": f"0x{full:x}",
                            })
                            continue
                        # ADRP + LDR [Xn, #imm]: the address sits in a pointer
                        # table slot in .rodata, not in the instruction. This is
                        # what the compiler emits for `void *const tbl[] =
                        # {&obj}` and for 64-bit constants loaded via a table.
                        ldr = self._decode_ldr_imm(w1)
                        if ldr is not None and ldr[0] == rd:
                            slot = page + ldr[2]
                            val = self._read_u64(pid, slot)
                            if val is not None and val in (wanted, vaddr):
                                hits_list.append({
                                    "insn_addr": f"0x{pc:x}",
                                    "pattern": "ADRP+LDR",
                                    "machine_code": blob[off:off + 8].hex(),
                                    "decoded_target": f"0x{val:x}",
                                    "literal_slot": f"0x{slot:x}",
                                })
                                continue
                        if page == (wanted & ~0xFFF):
                            hits_list.append({
                                "insn_addr": f"0x{pc:x}",
                                "pattern": "ADRP",
                                "machine_code": blob[off:off + 4].hex(),
                                "decoded_target": f"0x{page:x}",
                            })
                        continue
                    adr = self._decode_adr(w0, pc)
                    if adr == wanted:
                        hits_list.append({
                            "insn_addr": f"0x{pc:x}",
                            "pattern": "ADR",
                            "machine_code": blob[off:off + 4].hex(),
                            "decoded_target": f"0x{adr:x}",
                        })
                        continue
                    # LDR (literal): the address lives in an 8-byte slot in
                    # .rodata, not in the instruction. Only a hit when that slot
                    # actually contains our target — this is distinct from ADRP,
                    # whose immediate IS the address.
                    lit = self._decode_ldr_literal(w0, pc)
                    if lit is not None:
                        slot = self._read_u64(pid, lit)
                        if slot is not None and slot in (wanted, vaddr):
                            hits_list.append({
                                "insn_addr": f"0x{pc:x}",
                                "pattern": "LDR-literal",
                                "machine_code": blob[off:off + 4].hex(),
                                "decoded_target": f"0x{slot:x}",
                                "literal_slot": f"0x{lit:x}",
                            })
                pos += take

        # Attach the runtime address of each hit and cross-check the tool chain.
        expected_runtime: str | None = None
        if form == "vaddr":
            try:
                rv = self.resolve_vaddr(pid, module, vaddr)
                expected_runtime = rv["runtime"]
            except AgentError:
                expected_runtime = None
        for h in hits_list:
            h["runtime_addr"] = h["insn_addr"]
            if expected_runtime is None:
                continue
            exp = int(expected_runtime, 16)
            got = int(h["decoded_target"], 16)
            if h["pattern"] == "ADRP":
                # A bare ADRP only pins the 4 KiB page; that is still a match.
                ok = got == (exp & ~0xFFF)
            else:
                ok = got == exp
            h["crosscheck_vs_resolve_vaddr"] = "match" if ok else "MISMATCH"
            if not ok:
                h["crosscheck_delta"] = f"0x{got - exp:+#x}"

        return {
            "pid": pid,
            "module": module,
            "target": raw,
            "target_form": form,
            "vaddr": f"0x{vaddr:x}",
            "target_space": "runtime" if already_runtime else "elf_vaddr",
            "expected_runtime": expected_runtime,
            "scanned_bytes": scanned,
            "count": len(hits_list),
            "truncated": len(hits_list) >= max_hits,
            "references": hits_list,
        }

    def process_alive(self, pid: int, *, expected_cookie: int | None = None) -> dict:
        """Liveness with pid-reuse detection.

        A bare ping is not enough: Android recycles pids aggressively, so
        "alive" can mean "a different process now owns this number". When the
        caller supplies the `start_cookie` from find_process, we also report
        whether the pid still refers to the SAME process.
        """
        alive = self.service.process_alive(pid)
        out = {"pid": pid, "alive": alive}
        if expected_cookie is None:
            return out
        out["expected_cookie"] = f"0x{expected_cookie:x}"
        if not alive:
            out["cookie_match"] = False
            return out
        # The kernel hands us the target's start_cookie when the target is
        # opened, and rejects a mismatched expected_cookie with -ESTALE. Use
        # exactly that: try to open (or reuse) the target pinned to the cookie
        # the caller remembers. -ESTALE means the pid now belongs to a
        # different process — a silent pid reuse that a bare liveness ping
        # cannot detect.
        try:
            session = self.service.ensure_target(pid, expected_cookie=expected_cookie)
        except AgentError as exc:
            if exc.error == "stale_target":
                out["cookie_match"] = False
                out["note"] = ("pid was RECYCLED: the number now belongs to a "
                               "different process. Addresses from the earlier "
                               "session are invalid; re-run find_process.")
                return out
            out["cookie_match"] = None
            out["note"] = f"could not confirm (open failed: {exc.error})"
            return out
        current = session.start_cookie
        out["current_cookie"] = f"0x{current:x}"
        out["cookie_match"] = current == expected_cookie
        if not out["cookie_match"]:
            out["note"] = ("pid was RECYCLED: the number now belongs to a different "
                           "process. Addresses from the earlier session are invalid.")
        return out

    def watch_process(self, pid: int, *, expected_cookie: int | None = None,
                      count: int = 30, interval_s: float = 1.0,
                      stop_on_death: bool = True) -> dict:
        """Poll liveness on the HOST side and report the transition.

        Doing this in one tool call keeps a long observation out of the model's
        context: the alternative is N round trips, each burning tokens to say
        "still alive". Returns the first sample where the process died (or the
        pid was recycled), plus a compact summary of what was seen.
        """
        count = max(1, min(int(count), 600))
        interval_s = max(0.05, min(float(interval_s), 30.0))
        samples: list[dict] = []
        died_at = None
        recycled_at = None
        started = time.monotonic()

        for i in range(count):
            st = self.process_alive(pid, expected_cookie=expected_cookie)
            rec = {
                "index": i,
                "elapsed_s": round(time.monotonic() - started, 3),
                "alive": st["alive"],
            }
            if expected_cookie is not None:
                rec["cookie_match"] = st.get("cookie_match")
            samples.append(rec)

            if not st["alive"]:
                died_at = rec
                if stop_on_death:
                    break
            elif expected_cookie is not None and st.get("cookie_match") is False:
                recycled_at = rec
                if stop_on_death:
                    break
            if i + 1 < count:
                time.sleep(interval_s)

        last = samples[-1] if samples else None
        return {
            "pid": pid,
            "samples_taken": len(samples),
            "interval_s": interval_s,
            "requested": count,
            "duration_s": round(time.monotonic() - started, 3),
            "survived": last["alive"] if last else None,
            "died": died_at is not None,
            "recycled": recycled_at is not None,
            "event": died_at or recycled_at,
            # Keep the payload small: the full series is only useful when
            # something actually happened.
            "samples": samples if (died_at or recycled_at) else samples[:3],
        }

    def resolve_vaddr(self, pid: int, module: str, vaddr: int) -> dict:
        """Translate any ELF vaddr (`.text` / `.data` / **`.bss`** …) into a live
        runtime address. This is the single, assumption-free entry point for
        address math — prefer it over arithmetic on load_bias/bss fields.

        Why it exists: `.bss` is NOBITS and lives in a SEPARATE anonymous mapping
        (`[anon:.bss]`) after the module's last file-backed segment, so
        file-offset based helpers (resolve_rva) cannot express it and naive
        `vaddr + load_bias` breaks on multi-bias modules.

        Resolution order (strongest evidence first):
          1. **Live mapping table**: find which runtime mapping covers
             `module_base + vaddr` using the ELF PT_LOAD whose vaddr range
             contains `vaddr`; for a file-backed PT_LOAD this is exact; for
             NOBITS the target falls past `p_filesz`, so we fall through.
          2. **Adjacent `[anon:.bss]`**: when `vaddr` lies in [bss_start,bss_end),
             the address is `anon_bss.start + (vaddr - elf_bss_vaddr)`.
          3. **Arithmetic fallback**: `vaddr + load_bias`, explicitly flagged
             `confidence: "arithmetic"` so callers know it is uncorroborated.

        Every successful result is verified by a 1-byte read; an unreadable
        result is reported as such rather than returned as if valid.
        """
        try:
            model = AddressModel.build(pid, module, self.service.target_maps(pid),
                                       self.service.mem_read)
        except AddressModelError as exc:
            slug = "unavailable" if exc.unavailable else "not_found"
            raise AgentError(slug, detail=exc.detail) from exc
        v = model.view
        segs = model.segments
        first = segs[0]
        info = model.elf
        load_bias_abs = None if model.base_is_ambiguous else model.base

        method = ""
        runtime: int | None = None
        note = ""

        # -- 1) NOBITS: resolve through the live [anon:.bss] mapping -----------
        in_bss = (info.bss_start is not None and info.bss_end is not None
                  and info.bss_start <= vaddr < info.bss_end)
        if in_bss:
            bss, bss_note = self._resolve_bss_bounds(model)
            if bss is not None:
                # Anchor on the LIVE mapping start, not on info.bss_start: the
                # latter is a conservative lower bound (p_vaddr + p_filesz), so
                # using it directly shifts every .bss translation down by the
                # section's alignment padding (measured: 0xc on a 16-byte
                # aligned .bss). The offset within .bss is preserved either way
                # because both ends move together.
                bss_start = int(bss[0], 16)
                runtime = bss_start + (vaddr - info.bss_start)
                method = "anon_bss_mapping"
                note = bss_note
                # Correct the alignment gap: when the ELF lower bound sits a few
                # bytes BELOW the mapping start, shift back so the first real
                # .bss byte maps exactly onto the mapping start.
                gap = (bss_start - info.to_runtime(info.bss_start, load_bias_abs)
                       if load_bias_abs is not None else 0)
                if gap > 0 and bss_note and "snapped up" in bss_note:
                    runtime -= gap
            elif load_bias_abs is not None:
                runtime = vaddr + load_bias_abs
                method = "arithmetic"
                note = "no [anon:.bss] mapping; arithmetic only"

        # -- 2) PT_LOAD: file-backed bytes, then the zero-filled tail ----------
        # The two halves need different arithmetic and a vaddr in the second
        # half has NO file offset at all. Testing only p_filesz (as this did)
        # made a vaddr in [p_vaddr+p_filesz, p_vaddr+p_memsz) look like it was
        # covered by nothing, and the caller got "not covered by any PT_LOAD"
        # for an address sitting inside a segment — the field report's
        # 0x1D38800 case.
        if runtime is None:
            load, where = model.load_covering(vaddr)
            if where == "file" and load is not None:
                file_off = load.offset + (vaddr - load.vaddr)
                seg = next((x for x in segs
                            if x.file_offset <= file_off
                            < x.file_offset + (x.end - x.start)), None)
                if seg is not None:
                    runtime = seg.start + (file_off - seg.file_offset)
                    method = "segment_mapping"
            elif where == "zero" and load is not None:
                # The loader zero-fills this tail in an anonymous mapping that
                # follows the segment's file-backed bytes. Anchor on the segment
                # start, which is what the mapping table actually proves.
                file_end_off = load.offset + load.filesz
                seg = next((x for x in segs
                            if x.file_offset <= file_end_off
                            < x.file_offset + (x.end - x.start)), None)
                if seg is not None:
                    runtime = seg.start + (vaddr - load.vaddr)
                    method = "zero_fill_tail"
                    note = (f"vaddr is past p_filesz; zero-filled BSS tail of the "
                            f"segment at 0x{seg.start:x}")

        # -- 3) arithmetic last resort ----------------------------------------
        if runtime is None:
            if load_bias_abs is None:
                raise AgentError(
                    "bad_request",
                    detail=f"vaddr {vaddr:#x} is not covered by any PT_LOAD of "
                           f"{module!r} and no unambiguous load anchor exists "
                           f"(multi-bias module); pass a vaddr inside a segment")
            runtime = vaddr + load_bias_abs
            method = "arithmetic"
            note = "not corroborated by the mapping table"

        readable = None
        try:
            self.service.mem_read(pid, runtime, 1)
            readable = True
        except AgentError:
            readable = False

        # Guard against the classic mistake: passing a MAPPING start (page-
        # aligned, e.g. 0x2184000) instead of an ELF p_vaddr (0x2185770).
        # Those differ by a few pages; the arithmetic silently yields an
        # address outside the intended segment.
        warnings: list[str] = []
        if method == "segment_mapping":
            on_load_start = any(load.vaddr == vaddr for load in info.loads)
            if not on_load_start:
                nearest = min(info.loads, key=lambda x: abs(x.vaddr - vaddr))
                if abs(nearest.vaddr - vaddr) <= 0x10000:
                    warnings.append(
                        f"vaddr {vaddr:#x} is not a PT_LOAD p_vaddr; the nearest "
                        f"one is {nearest.vaddr:#x} (delta "
                        f"{vaddr - nearest.vaddr:+#x}). If you meant a mapping "
                        f"start, use address_resolve/base+offset instead")
        if not readable:
            warnings.append("result is not readable: the address is likely outside "
                            "any mapped region")

        return {
            "pid": pid,
            "module": module,
            "vaddr": f"0x{vaddr:x}",
            "runtime": f"0x{runtime:x}",
            "method": method,
            "in_bss": in_bss,
            "readable": readable,
            "note": note,
            "warnings": warnings,
            "load_bias": f"0x{load_bias_abs:x}" if load_bias_abs is not None else None,
        }

    def resolve_rva(self, pid: int, module: str, *, rva: int | None = None,
                    file_offset: int | None = None) -> dict:
        """D20: forward file-offset → runtime resolution, plus vaddr-RVA →
        file-offset conversion via the module's live phdrs (p_vaddr→p_offset).

        Exactly one of rva/file_offset. Note the tool-face `rva` convention
        (address_resolve/disassemble) is the FILE OFFSET — the `rva` parameter
        here is the R4-era vaddr flavour, provided for offline-record
        cross-checks. Mirror segments never bear translations."""
        if (rva is None) == (file_offset is None):
            raise AgentError("bad_request",
                             detail="resolve_rva: give exactly one of rva= or file_offset=")
        view = MapsView.from_maps(self.service.target_maps(pid))
        v = view.modules.get(module)
        if v is None:
            raise AgentError("not_found", detail=f"module {module!r} not mapped in pid {pid}")
        segs = [s for s in v.segments if not s.mirror] or v.segments

        used = "file_offset"
        fo = file_offset
        if rva is not None:
            used = "vaddr"
            # Only the vaddr flavour needs the ELF header; build the model
            # lazily so a plain file_offset lookup costs nothing extra.
            try:
                model = AddressModel.build(pid, module,
                                           self.service.target_maps(pid),
                                           self.service.mem_read)
            except AddressModelError as exc:
                slug = "unavailable" if exc.unavailable else "backend_error"
                raise AgentError(slug,
                                 detail=f"phdr parse failed for {module!r}: "
                                        f"{exc.detail}") from exc
            info = model.elf
            # Only the FILE-BACKED part of a PT_LOAD has a file offset. Using
            # max(memsz, filesz) here (the old behaviour) invented an offset for
            # NOBITS bytes: a .bss vaddr produced a bogus file offset that then
            # failed the segment lookup with a misleading "file offset not
            # covered" message.
            fo = None
            in_nobits = False
            for load in info.loads:
                if not (load.vaddr <= rva < load.vaddr + load.memsz):
                    continue
                if rva < load.vaddr + load.filesz:
                    fo = rva - load.vaddr + load.offset
                else:
                    in_nobits = True
                break
            if fo is None and in_nobits:
                raise AgentError(
                    "bad_request",
                    detail=f"vaddr 0x{rva:x} lies in the NOBITS part of a PT_LOAD "
                           f"(beyond p_filesz): it consumes no file space, so no "
                           f"file offset exists. Use resolve_vaddr(pid, module, "
                           f"vaddr) instead — it resolves through the live "
                           f"[anon:.bss] mapping.",
                )
            if fo is None:
                # Distinguish "NOBITS / not file-backed" (a vaddr that exists
                # but consumes no file space — .bss and friends) from a truly
                # bogus vaddr. Both used to surface the same opaque not_found,
                # which sent callers hunting through file-offset arithmetic for
                # an address that has no file offset at all.
                in_bss = (info.bss_start is not None and info.bss_end is not None
                          and info.bss_start <= rva < info.bss_end)
                if in_bss:
                    raise AgentError(
                        "bad_request",
                        detail=f"vaddr 0x{rva:x} lies in the NOBITS range "
                               f"(0x{info.bss_start:x}..0x{info.bss_end:x}, .bss): "
                               f"it consumes no file space, so no file offset exists. "
                               f"Use resolve_vaddr(pid, module, vaddr) instead — it "
                               f"resolves through the live [anon:.bss] mapping.",
                    )
                raise AgentError(
                    "not_found",
                    detail=f"vaddr rva 0x{rva:x} not within any PT_LOAD of "
                           f"{module!r} (loads: "
                           + ", ".join(f"0x{l.vaddr:x}+0x{max(l.memsz, l.filesz):x}"
                                       for l in info.loads)
                           + "); did you pass a FILE OFFSET as rva?")

        bearing = [x for x in segs
                   if x.file_offset <= fo < x.file_offset + x.size]
        if not bearing:
            table = [{"start": f"0x{x.start:x}", "end": f"0x{x.end:x}",
                      "file_offset": f"0x{x.file_offset:x}",
                      "permissions": x.flags_str()} for x in segs]
            raise AgentError(
                "not_found",
                detail=f"file offset 0x{fo:x} is not covered by any non-mirror segment "
                       f"of {module!r}; non-mirror segments: {table}")

        def seg_info(x):
            return {
                "start": f"0x{x.start:x}",
                "end": f"0x{x.end:x}",
                "file_offset": f"0x{x.file_offset:x}",
                "permissions": x.flags_str(),
                "translation_base": f"0x{x.start - x.file_offset:x}",
                "alias_group": x.alias_group,
            }

        if len(bearing) > 1:
            # D21: file-space alias — file-offset→runtime is non-injective,
            # return every candidate (segment order) instead of guessing
            return {
                "pid": pid,
                "module": module,
                "file_offset": f"0x{fo:x}",
                **({"vaddr": f"0x{rva:x}"} if rva is not None else {}),
                "used": used,
                "alias": True,
                "candidates": [
                    {"runtime": f"0x{x.start + (fo - x.file_offset):x}",
                     "segment": seg_info(x)}
                    for x in bearing
                ],
            }

        bearing_seg = bearing[0]
        runtime = bearing_seg.start + (fo - bearing_seg.file_offset)
        return {
            "pid": pid,
            "module": module,
            "file_offset": f"0x{fo:x}",
            **({"vaddr": f"0x{rva:x}"} if rva is not None else {}),
            "used": used,
            "runtime": f"0x{runtime:x}",
            "segment": seg_info(bearing_seg),
        }

    # -- multi-span sampling & pointer search (R5 F1/F2) ---------------------------

    def watch_many(self, pid: int, spans: list[dict], *, interval_ms: int = 200,
                   count: int = 10, changes_only: bool = False,
                   mirror_samples: bool = True) -> dict:
        """F1: multi-address sampling orchestrated over MEM_READV — one batch
        read per tick (fault isolation per span), per-span sample arrays in
        the same shape as watch's. Zero protocol additions."""
        parsed = []
        for span in spans:
            addr = span.get("address")
            size = int(span.get("size", 0))
            if isinstance(addr, str):
                addr = int(addr, 16)
            if not isinstance(addr, int) or addr < 0 or size <= 0:
                raise AgentError("bad_request", detail=f"bad span {span!r}")
            parsed.append((addr, size))
        if not parsed:
            raise AgentError("bad_request", detail="watch_many needs at least one span")
        count = max(1, min(int(count), 256))
        samples: list[list] = [[] for _ in parsed]
        previous: list[bytes | None] = [None] * len(parsed)
        started_wall = time.time()
        for i in range(count):
            results = self.service.mem_readv(pid, parsed)
            # monotonic for the sampling series (wall-clock jumps would fake a
            # gap between samples); the absolute wall time is reported once, at
            # the start, so a caller can still correlate with external logs.
            tick = time.monotonic()
            for j, (addr, size) in enumerate(parsed):
                data = results[j]
                changed = None if previous[j] is None else data != previous[j]
                sample: dict = {
                    "index": i,
                    "timestamp_monotonic": round(tick, 6),
                    "data_hex": data.hex() if data is not None else None,
                    "changed": changed,
                }
                if data is None:
                    sample["error"] = "read_failed"
                if not changes_only or changed is not False:
                    samples[j].append(sample)
                previous[j] = data
            if i + 1 < count:
                time.sleep(interval_ms / 1000.0)
        # A `changes_only` run returns fewer samples than `count` BY DESIGN —
        # unchanged ticks are dropped. Without saying so, a caller cannot tell
        # "sampled 30 times, nothing moved" from "only managed one sample",
        # which are very different conclusions.
        stopped_reason = None
        if changes_only:
            kept = [len(samples[j]) for j in range(len(parsed))]
            if all(k < count for k in kept):
                stopped_reason = "no_changes"
        per_span = [
            {"address": f"0x{addr:x}", "size": size, "samples": samples[j],
             "count_requested": count, "samples_returned": len(samples[j])}
            for j, (addr, size) in enumerate(parsed)
        ]
        # A span that could not be read must say so at the span level too, not
        # only inside each sample. A caller looping over spans checks the span
        # first; making them dig into samples to discover every tick failed is
        # how "it returned data, so it worked" mistakes happen.
        for entry in per_span:
            failures = sum(1 for s in entry["samples"] if s.get("error"))
            if failures:
                entry["error"] = "read_failed"
                entry["failed_samples"] = failures
        return {
            "pid": pid,
            "count": count,
            "interval_ms": interval_ms,
            "started_wall": started_wall,
            "clock": "timestamp_monotonic is time.monotonic(); add started_wall "
                     "to convert to wall-clock, so a system clock jump cannot "
                     "fake a gap between samples",
            "count_requested": count,
            "changes_only": changes_only,
            **({"stopped_reason": stopped_reason} if stopped_reason else {}),
            # `spans` is the structured form; `samples` mirrors watch(), which
            # returns a flat `samples` list. Callers written against watch
            # reasonably expect the same key here and silently get nothing when
            # it is absent — so provide both rather than making the shape a trap.
            "spans": per_span,
            # `samples` mirrors watch()'s flat shape, but it is the SAME data as
            # spans[].samples — so it doubles the payload. On by default because
            # a strict client rejects a response whose shape it cannot match;
            # turn it off for large captures where the duplication is real cost.
            **({"samples": [entry["samples"] for entry in per_span]}
               if mirror_samples else {}),
        }

    def pointers_to(self, pid: int, addresses, *, module: str | None = None,
                    preset: str | None = None, ranges: list[dict] | None = None,
                    strip_pac: bool = True, limit: int = 256) -> dict:
        """F2: semantic wrapper around a hex scan — find in-region locations
        whose 8-byte little-endian value equals a target address.

        strip_pac (default) masks the top two pattern bytes so PAC-tagged
        pointers still match. Region: explicit ranges[] / module=<basename> /
        preset — falls back to the pid's last preset (default anon). Uses the
        dispatched scan engine (device when bit0; the device single job slot
        means a running scan gets cancelled_old)."""
        if isinstance(addresses, (int, str)):
            addresses = [addresses]
        targets = []
        for a in addresses:
            t = int(a, 16) if isinstance(a, str) else int(a)
            if not isinstance(t, int) or t < 0 or t > 0xFFFFFFFFFFFFFFFF:
                raise AgentError("bad_request", detail=f"bad target address {a!r}")
            targets.append(t)
        if not targets:
            raise AgentError("bad_request", detail="pointers_to needs at least one address")
        if len(targets) > 64:
            raise AgentError("bad_request", detail="at most 64 targets per call")

        explicit_ranges: list[tuple[int, int]] | None = None
        if ranges:
            explicit_ranges = []
            for r in ranges:
                lo = int(r["start"], 16) if isinstance(r["start"], str) else int(r["start"])
                hi = int(r["end"], 16) if isinstance(r["end"], str) else int(r["end"])
                if hi <= lo:
                    raise AgentError("bad_request", detail=f"bad range {r!r}")
                explicit_ranges.append((lo, hi))
            region_ranges = explicit_ranges
        else:
            effective = preset or (f"module:{module}" if module else None) \
                or self._scan_presets.get(pid, "anon")
            region_ranges, _cats = self.compute_preset_ranges(pid, effective)
            if not region_ranges:
                raise AgentError("not_found",
                                 detail=f"preset {effective!r} matched no readable ranges")
        ranges_payload = [{"addr": f"0x{lo:x}", "size": f"0x{hi - lo:x}"}
                          for lo, hi in explicit_ranges] if explicit_ranges else None
        wire_preset = None if explicit_ranges else (
            preset or (f"module:{module}" if module else None)
            or self._scan_presets.get(pid, "anon"))

        def to_pattern(t: int) -> tuple[str, bytes, bytes]:
            raw = t.to_bytes(8, "little")
            if strip_pac:
                mask = b"\xff" * 6 + b"\x00\x00"
            else:
                mask = b"\xff" * 8
            pattern = bytes(p & m for p, m in zip(raw, mask))
            text = " ".join(f"{b:02X}" if m else "??" for b, m in zip(pattern, mask))
            return text, pattern, mask

        agent_route = self._scan_route(pid) == "agent"
        engine_tag = "agent-scan" if agent_route else "host-scan"
        # V1.3 §2.3 (bit11): single multi-value round trip when the agent
        # declares SCAN_VALUES. Typed u64 matching is exact — PAC-tagged
        # pointers only match on the hex-fallback path (strip_pac wildcards).
        use_values = agent_route and self.service.has_agent_cap(AGENT_CAP_SCAN_VALUES) \
            and not strip_pac
        out_targets = [{"address": f"0x{t:x}", "found": 0, "pointers": []}
                       for t in targets]
        scans = 0
        if use_values:
            resp = self.service.agent_scan_start(
                pid, kind="value", type="u64", values=targets, alignment=8,
                preset=wire_preset, ranges=ranges_payload)
            scans = 1
            self._agent_wait(int(resp["job_id"]))
            page = self.service.agent_scan_results(0, limit)
            for h in page.get("hits", []):
                vi = int(h.get("value_index", 0))
                if 0 <= vi < len(out_targets):
                    out_targets[vi]["pointers"].append(
                        {"address": str(h["address"]), "value": h.get("value")})
                    out_targets[vi]["found"] += 1
            match_mode = "exact-u64"
        elif agent_route:
            for t in targets:
                pattern_str, _pattern, _mask = to_pattern(t)
                resp = self.service.agent_scan_start(
                    pid, kind="hex", pattern=pattern_str,
                    preset=wire_preset, ranges=ranges_payload)
                scans += 1
                self._agent_wait(int(resp["job_id"]))
                page = self.service.agent_scan_results(0, limit)
                for h in page.get("hits", []):
                    out_targets[targets.index(t)]["pointers"].append(
                        {"address": str(h["address"]),
                         "value": h.get("value_hex", h.get("value"))})
                out_targets[targets.index(t)]["found"] = len(
                    out_targets[targets.index(t)]["pointers"])
            match_mode = "pattern+pac-wildcard" if strip_pac else "pattern-exact"
        else:
            backend = self.service.backend_info()
            engine = ScanEngine(self.service.mem_read,
                                max_transfer=backend.max_transfer_size,
                                readv_fn=self.service.mem_readv,
                                max_iov=backend.max_iov)
            engine.set_ranges(pid, region_ranges)
            for t in targets:
                pattern_str, pattern, mask = to_pattern(t)
                scans += 1
                engine.scan_hex(pid, pattern, mask)
                for h in engine.results(0, limit):
                    out_targets[targets.index(t)]["pointers"].append(
                        {"address": h["address"], "value": h["value"]})
                out_targets[targets.index(t)]["found"] = len(
                    out_targets[targets.index(t)]["pointers"])
            match_mode = "pattern+pac-wildcard" if strip_pac else "pattern-exact"
        return {
            "pid": pid,
            "targets": out_targets,
            "strip_pac": strip_pac,
            "ranges": len(region_ranges),
            "scans": scans,
            "match": match_mode,
            "engine": engine_tag,
        }

    # -- batch read ------------------------------------------------------------------------

    def read_batch(self, pid: int, spans: list[dict]) -> dict:
        """Batch read via agent MEM_READV: [{address,size}, ...] up to max_iov per call.
        Returns per-span entries with data_hex or error."""
        parsed = []
        for span in spans:
            addr = span.get("address")
            size = int(span.get("size", 0))
            if isinstance(addr, str):
                addr = int(addr, 16)
            if not isinstance(addr, int) or addr < 0 or size <= 0:
                raise AgentError("bad_request", detail=f"bad span {span!r}")
            parsed.append((addr, size))
        results = self.service.mem_readv(pid, parsed)
        entries = []
        for (addr, size), data in zip(parsed, results):
            if data is None:
                entries.append({"address": f"0x{addr:x}", "size": size, "error": "read_failed"})
            else:
                entries.append({"address": f"0x{addr:x}", "size": len(data), "data_hex": data.hex()})
        return {"pid": pid, "count": len(entries), "spans": entries}

    # -- symbols ---------------------------------------------------------------------------

    @staticmethod
    def _symbol_row(resp: dict, i: int, default_module: str | None) -> dict:
        """One cmd 61 column-row → host symbol dict. `bind` is not carried on
        the cmd 61 wire (draft §3.1); module attribution comes from
        modules/module_indexes when the agent provides them."""
        modules = resp.get("modules") or []
        idx = resp.get("module_indexes") or []
        module: str | None = default_module
        if i < len(idx) and isinstance(idx[i], int) and 0 <= idx[i] < len(modules):
            module = modules[idx[i]]
        binds = resp.get("binds") or []
        # D11 (v1.2.2 附录): json carries a binds column; old agents without it
        # degrade to the empty string — never an error
        bind = binds[i] if i < len(binds) and binds[i] else ""
        return {
            "name": resp["names"][i],
            "address": resp["addresses"][i],
            "size": resp["sizes"][i],
            "type": resp["types"][i] or "NOTYPE",
            "bind": bind,
            "module": module,
        }

    def symbol_list(self, pid: int, name: str, *, limit: int = 512,
                    filter: str | None = None, fields: str = "full") -> dict:
        """fields: "full" (default) or "names_only" (F4 — trims rows to
        {name,address} for large modules / quick lookups)."""
        if self.service.has_agent_cap(AGENT_CAP_SYMBOL_BATCH):
            resp = self.service.symbol_batch(pid, module=name, filter=filter)
            symbols = [self._symbol_row(resp, i, name) for i in range(resp["count"])]
            if fields == "names_only":
                symbols = [{"name": r["name"], "address": r["address"]} for r in symbols]
            return {
                "pid": pid,
                "module": name,
                "total": int(resp["count"]),
                "shown": min(int(resp["count"]), limit),
                "symbols": symbols[:limit],
                "engine": "agent-symbols",
            }
        read_fn = self._read_for(pid)
        maps = self.service.target_maps(pid)
        module_maps = [m for m in maps if m.path.rstrip("/").split("/")[-1] == name]
        if not module_maps:
            raise AgentError("not_found", detail=f"module {name!r} not mapped in pid {pid}")
        first = min(module_maps, key=lambda m: m.start)
        mem_size = max(m.end for m in module_maps) - first.start
        header = read_fn(first.start, 0x1000)
        try:
            syms = load_symbols(read_fn, first.start, mem_size, header)
        except SymbolError as exc:
            raise AgentError("backend_error", detail=str(exc)) from exc
        if filter:
            f = filter.lower()
            syms = [s for s in syms if f in s.name.lower()]
        rows = [s.to_dict() for s in syms[:limit]]
        if fields == "names_only":
            rows = [{"name": r["name"], "address": r["address"]} for r in rows]
        return {
            "pid": pid,
            "module": name,
            "total": len(syms),
            "shown": min(len(syms), limit),
            "symbols": rows,
            "engine": "host-symbols",
        }

    def symbol_find(self, pid: int, name: str, module: str | None = None) -> dict:
        """Exact symbol name lookup. Tries one module (or all executable file-backed
        modules until found) and returns matches with absolute addresses."""
        if self.service.has_agent_cap(AGENT_CAP_SYMBOL_BATCH):
            # DESIGN_V3_HOST §3.1: single full-module request + anchored filter
            # (server-side filtering runs before max_symbols counting).
            resp = self.service.symbol_batch(pid, module=module, filter=f"^({_re.escape(name)})$")
            if not resp["count"]:
                detail = f"symbol {name!r} not found" + (f" in {module!r}" if module else "")
                raise AgentError("not_found", detail=detail)
            matches = [self._symbol_row(resp, i, module) for i in range(resp["count"])]
            first_module = next((m["module"] for m in matches if m.get("module")), module)
            return {"pid": pid, "module": first_module, "matches": matches,
                    "engine": "agent-symbols"}
        read_fn = self._read_for(pid)
        maps = self.service.target_maps(pid)
        if module:
            candidates = [module]
        else:
            candidates = sorted({m.path.rstrip("/").split("/")[-1]
                                 for m in maps if m.flags & MAP_EXEC and m.path})
        tried = []
        for mod_name in candidates:
            try:
                listed = self.symbol_list(pid, mod_name, limit=1_000_000)
            except AgentError:
                continue  # no symtab / not mapped
            tried.append(mod_name)
            hits = [s for s in listed["symbols"] if s["name"] == name]
            if hits:
                return {"pid": pid, "module": mod_name, "matches": hits,
                        "engine": "host-symbols"}
        raise AgentError("not_found", detail=f"symbol {name!r} not found (tried: {tried[:8]})")

    # -- native binary analysis -----------------------------------------------------

    @staticmethod
    def _resolve_module_maps(maps, module: str | None, address: int | None):
        """Match module entries by file-name suffix, or by containing address."""
        name: str | None = None
        entries = []
        for m in maps:
            mname = m.path.rsplit("/", 1)[-1] if m.path else ""
            if module is not None:
                if mname == module or mname.startswith(module) or m.path.endswith(module):
                    name = mname
                    entries.append(m)
            elif address is not None and m.start <= address < m.end:
                name = mname or f"anon@0x{m.start:x}"
                entries.append(m)
        return name, entries

    def disassemble(self, pid: int, address: int, count: int = 48, module: str | None = None,
                    engine: str = "auto") -> dict:
        """Disassemble a live A64 window. Engine: capstone (full ISA, default
        when installed) or "subset" (built-in length-decoded fallback). With
        bit8 the device decodes via cmd 67 (engine=agent-capstone)."""
        maps = self.service.target_maps(pid)
        name, entries = self._resolve_module_maps(maps, module, address)
        if not entries:
            detail = (f"address 0x{address:x} not inside any mapped module"
                      if module is None else f"module {module!r} not found")
            raise AgentError("not_found", detail=detail)
        region = next((e for e in entries if e.start <= address < e.end), None)
        if region is None:
            # Deliberately NOT auto-converting: silently translating a vaddr
            # here would hide coordinate mistakes and make the tool answer
            # about an address the caller never meant. Point at the right tool
            # instead — resolve_vaddr handles .bss and multi-bias layouts.
            raise AgentError(
                "bad_request",
                detail=(f"address 0x{address:x} is not inside any mapped segment of "
                        f"{name!r}. If you have an ELF vaddr (IDA/readelf), call "
                        f"resolve_vaddr(pid, {name!r}, vaddr) first and pass the "
                        f"returned 'runtime' address here — .bss and multi-bias "
                        f"modules need that conversion, and doing it by hand is "
                        f"the usual source of wrong addresses."))
        count = max(1, min(int(count), 4096))
        # D9: file-layout rva via the per-mapping translation — the old
        # min(start) single-bias subtraction mislabeled multi-bias modules
        rva = address - region.start + region.file_offset
        if self.service.has_agent_cap(AGENT_CAP_DISASSEMBLE) and engine in ("auto", "capstone"):
            try:
                resp = self.service.disassemble_remote(pid, address, count=count)
            except AgentError as exc:
                if exc.error != "unsupported":
                    raise  # draft §3.7: missing capstone → host-side fallback
            else:
                instructions = [
                    {
                        "addr": ins["address"],
                        "rva": int(str(ins["address"]), 16) - region.start + region.file_offset,
                        "bytes": ins["bytes_hex"],
                        "text": f"{ins['mnemonic']} {ins['op_str']}".strip(),
                    }
                    for ins in resp.get("instructions", [])
                ]
                return {
                    "pid": pid,
                    "module": name,
                    "address": f"0x{address:x}",
                    "rva": f"0x{rva:x}",
                    "engine": "agent-capstone",
                    "count": len(instructions),
                    "instructions": instructions,
                    "source": "live_memory",
                }
        end = min(address + count * 4, region.end)
        read_fn = self._read_for(pid)
        data = read_fn(address, end - address)
        decoded = disassemble_a64_ex(data, address, max_instructions=count, engine=engine)
        return {
            "pid": pid,
            "module": name,
            "address": f"0x{address:x}",
            "rva": f"0x{rva:x}",
            "engine": decoded["engine"],
            "count": len(decoded["instructions"]),
            "instructions": decoded["instructions"],
            "source": "live_memory",
        }

    def strings(self, pid: int, *, module: str | None = None, address: int | None = None,
                size: int | None = None, min_length: int = 4, limit: int = 200,
                filter: str | None = None, async_run: bool = False) -> dict:
        """Extract printable-ASCII strings from a module's readable segments
        (module mode, chunked with per-chunk fault skip) or an explicit window.
        async_run=True (D10): device-side job via cmd 62 async — returns
        {'job_id',...}; poll scan_status / scan_results (kind=strings)."""
        if self.service.has_agent_cap(AGENT_CAP_STRINGS):
            return self._agent_strings(pid, module=module, address=address, size=size,
                                       min_length=min_length, limit=limit, filter=filter,
                                       async_run=async_run)
        if async_run:
            raise AgentError("bad_request",
                             detail="strings async=true requires agent STRINGS capability (bit5)")
        read_fn = self._read_for(pid)
        if module is not None:
            maps = self.service.target_maps(pid)
            name, entries = self._resolve_module_maps(maps, module, None)
            if not entries:
                raise AgentError("not_found", detail=f"module {module!r} not found")
            results: list[dict] = []
            scanned = skipped = 0
            truncated = False
            for e in entries:
                if not (e.flags & MAP_READ):
                    continue
                pos = e.start
                while pos < e.end and not truncated:
                    take = min(0x100000, e.end - pos)
                    try:
                        data = read_fn(pos, take)
                    except AgentError:
                        skipped += take
                        pos += take
                        continue
                    items = extract_strings(
                        data, offset=pos, min_length=min_length,
                        limit=max(0, limit - len(results)), filter=filter,
                    )
                    for item in items:
                        # D16: address (hex) instead of the misleading decimal offset
                        results.append({
                            "address": f"0x{item['offset']:x}",
                            "length": item["length"],
                            "value": item["value"],
                        })
                    scanned += take
                    pos += take
                    if len(results) >= limit:
                        truncated = True
            return {
                "pid": pid, "module": name, "count": len(results), "strings": results,
                "scanned_bytes": scanned, "skipped_bytes": skipped, "truncated": truncated,
                "engine": "host-strings",
            }
        if address is None:
            raise AgentError("bad_request", detail="strings: provide module= or address=")
        if not size or size <= 0:
            raise AgentError("bad_request", detail="strings: address mode requires size")
        size = min(int(size), 0x1000000)
        data = read_fn(address, size)
        items = extract_strings(data, offset=address, min_length=min_length,
                                limit=limit, filter=filter)
        rows = [{"address": f"0x{item['offset']:x}", "length": item["length"],
                 "value": item["value"]} for item in items]
        return {"pid": pid, "address": f"0x{address:x}", "size": size,
                "count": len(rows), "strings": rows, "truncated": len(rows) >= limit,
                "engine": "host-strings"}

    def _agent_strings(self, pid: int, *, module: str | None, address: int | None,
                       size: int | None, min_length: int, limit: int,
                       filter: str | None, async_run: bool = False) -> dict:
        """cmd 62 path: device extracts strings, host maps back to the
        {offset,length,value} shape (offset = absolute address)."""
        if module is not None:
            preset, win = f"module:{module}", None
        elif address is not None and size:
            preset, win = None, (address, min(int(size), 0x1000000))
        else:
            raise AgentError("bad_request", detail="strings: provide module= or address=")

        if async_run:
            # D10: explicit async entry — device job shared with the scan slot;
            # polled via scan_status/scan_results (kind=strings). No silent
            # auto-async on the sync path (explicit over surprise).
            resp = self.service.strings_scan(
                pid, preset=preset,
                addr=win[0] if win else None, size=win[1] if win else None,
                min_len=min_length, max_results=limit, regex=filter, async_run=True)
            dev_job = int(resp["job_id"])
            cancel_event = threading.Event()

            def run(progress) -> dict:
                st = self._agent_strings_wait(dev_job, progress, cancel_event)
                rows = self._agent_strings_rows(self.service.agent_scan_results(0, limit))
                return {
                    "count": len(rows),
                    "truncated": bool(st.get("truncated", False)),
                    "scanned_bytes": parse_u64(st.get("scanned_bytes", "0x0"), field="scanned_bytes"),
                    "skipped_bytes": parse_u64(st.get("skipped_bytes", "0x0"), field="skipped_bytes"),
                    "strings": rows,
                    "engine": "agent-strings",
                }

            job_id = self._jobs.start(pid, "strings", run, cancel_event=cancel_event)
            self._agent_job_map[job_id] = dev_job
            return {"job_id": job_id, "pid": pid, "kind": "strings", "state": "running",
                    "async": True, "poll": "scan_status"}

        try:
            resp = self.service.strings_scan(
                pid, preset=preset,
                addr=win[0] if win else None, size=win[1] if win else None,
                min_len=min_length, max_results=limit, regex=filter)
        except AgentError as exc:
            if exc.error == "bad_request":
                # D10: keep the device's threshold rejection, add the exit ramp
                exc.detail = f"{exc.detail} (module too large for sync scan — use async=true)".lstrip(" (")
            raise
        rows = self._agent_strings_rows(resp)
        if module is not None:
            return {
                "pid": pid, "module": module, "count": int(resp["count"]),
                "strings": rows,
                "scanned_bytes": parse_u64(resp.get("scanned_bytes", "0x0"), field="scanned_bytes"),
                "skipped_bytes": parse_u64(resp.get("skipped_bytes", "0x0"), field="skipped_bytes"),
                "truncated": bool(resp.get("truncated", False)),
                "engine": "agent-strings",
            }
        return {
            "pid": pid, "address": f"0x{win[0]:x}", "size": win[1],
            "count": int(resp["count"]), "strings": rows,
            "truncated": bool(resp.get("truncated", False)),
            "engine": "agent-strings",
        }

    @staticmethod
    def _agent_strings_rows(resp: dict) -> list[dict]:
        # D16: rows carry "address" (hex string, tool-face convention) — the
        # old "offset" was a decimal-int address and misled address math
        out = []
        for r in resp.get("results", []) + resp.get("hits", []):
            out.append({
                "address": str(r["address"]),
                "length": int(r.get("length", len(str(r["value"])))),
                "value": r["value"],
            })
        return out

    def _agent_strings_wait(self, dev_job: int, progress=None, cancel_event=None,
                            timeout: float = 3600.0) -> dict:
        """Strings jobs share the scan poller; only the labels and cadence differ."""
        return self._agent_wait(dev_job, progress=progress,
                                cancel_event=cancel_event, timeout=timeout,
                                label="strings job", poll_interval=0.1)

    def pull_apk(self, pid: int, out_path: str) -> dict:
        """Pull the APK backing this pid to the host. With bit6 the file comes
        through the dump-pull pipeline (chunked, compressed); otherwise host adb."""
        maps = self.service.target_maps(pid)
        apk_paths = [m.path for m in maps if m.path.endswith("/base.apk")]
        if not apk_paths:
            raise AgentError("not_found", detail="no base.apk mapping found for this pid")
        src = apk_paths[0]
        if self.service.has_agent_cap(AGENT_CAP_DUMP_PIPELINE):
            result = pull_dump_with_resume(self.service, out_path, path=src)
            return {"pid": pid, "remote": src, "local": result["path"],
                    "size": result["size"], "engine": "agent-dump"}
        adb = shutil.which("adb")
        if not adb:
            raise AgentError("unavailable", detail="adb not found on host PATH")
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        try:
            proc = subprocess.run([adb, "pull", src, out_path],
                                  capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            raise AgentError("backend_error", detail="adb pull timed out") from exc
        if proc.returncode != 0:
            raise AgentError("backend_error",
                             detail=f"adb pull failed: {proc.stderr.strip()[:300]}")
        return {"pid": pid, "remote": src, "local": os.path.abspath(out_path),
                "size": os.path.getsize(out_path), "engine": "host-adb"}

    def apk_info(self, apk_path: str | None = None, *, pid: int | None = None) -> dict:
        """APK metadata. Exactly one of apk_path (host file, v2 behavior) or
        pid (device-resolved via cmd 66, requires bit7 — DESIGN_V3_HOST §3.4;
        no silent fallback to pull_apk: that is an implicit bulk transfer)."""
        if (apk_path is None) == (pid is None):
            raise AgentError("bad_request",
                             detail="apk_info: give exactly one of apk_path= or pid=")
        if pid is not None:
            if not self.service.has_agent_cap(AGENT_CAP_APK_INFO):
                raise AgentError(
                    "bad_request",
                    detail="agent does not declare APK_INFO (bit7); "
                           "use pull_apk + apk_info(apk_path=...) instead",
                )
            resp = self.service.apk_info_remote(pid)
            return {
                "path": resp.get("apk_path"),
                "package": resp.get("package"),
                "version_name": resp.get("version_name"),
                "version_code": resp.get("version_code"),
                "min_sdk": resp.get("min_sdk"),
                "target_sdk": resp.get("target_sdk"),
                "entry_activity": resp.get("entry_activity"),
                "activities": resp.get("activities", []),
                "launcher_activities": resp.get("launcher_activities", []),
                "permissions": resp.get("permissions", []),
                "split_apks": resp.get("split_apks", []),
                "engine": "agent-apk",
            }
        if not os.path.exists(apk_path):
            raise AgentError("not_found", detail=f"{apk_path} not found on host")
        try:
            info = parse_apk_manifest(apk_path)
        except (ApkParseError, zipfile.BadZipFile) as exc:
            raise AgentError("bad_request", detail=f"apk parse failed: {exc}") from exc
        info["path"] = os.path.abspath(apk_path)
        info["engine"] = "host-apk"
        return info

    # -- decompile (IDA Pro / idalib, async jobs) --------------------------------

    # Decompilation runs on IDA Pro (idalib); see tanyao/ida_backend.py.
    # The old headless-Ghidra entry points are gone — ghidra_scripts/ is kept
    # only as historical reference for the output layout.

    @staticmethod
    def _page_entropy(data: bytes) -> float:
        """Shannon entropy in bits/byte (F5 pre-flight: encrypted/compressed
        pages read as near-uniform, ~8.0, and waste hours of Ghidra time)."""
        import math

        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = 0.0
        for f in freq:
            if f:
                p = f / n
                ent -= p * math.log2(p)
        return ent

    def _entropy_guard(self, pid: int, entries, *, force: bool) -> str | None:
        """F5: for >64MB modules, sample strided pages and warn when a majority
        read as high-entropy. Returns a note (forced/None) or raises when the
        caller has not passed force=true."""
        total = sum(e.end - e.start for e in entries if e.flags & MAP_READ)
        if total <= INLINE_LIMIT:
            return None
        readable = [e for e in entries if e.flags & MAP_READ]
        if not readable:
            return None
        read_fn = self._read_for(pid)
        page, samples = 0x1000, 16
        high = checked = 0
        for i in range(samples):
            e = readable[i % len(readable)]
            span = e.end - e.start
            addr = e.start + (span * (i + 1)) // (samples + 2)
            addr -= addr % page
            take = min(page, e.end - addr)
            if take <= 0:
                continue
            try:
                data = read_fn(addr, take)
            except AgentError:
                continue
            checked += 1
            if self._page_entropy(data) > 7.5:
                high += 1
        if checked and high / checked > 0.5:
            note = f"{high}/{checked} sampled pages >7.5 bits/byte"
            if not force:
                raise AgentError(
                    "bad_request",
                    detail=f"module looks encrypted/compressed ({note}) — decompiling it "
                           f"typically wastes hours; re-call with force=true to proceed")
            return f"forced past high-entropy warning ({note})"
        return None

    def decompile_start(self, pid: int, module: str, out_dir: str | None = None,
                        max_functions: int = 2000, force: bool = False) -> dict:
        """Dump a module and decompile it with IDA Pro (idalib + Hex-Rays).

        Long-running: returns a job id immediately; poll decompile_status.
        Sources + index.json land in out_dir. Modules >64MB get an entropy
        pre-flight (F5): pass force=true to override.

        Engine note: this used to shell out to headless Ghidra. IDA runs
        in-process through idalib, which removes the JVM dependency, gives real
        per-function progress, and keeps the same output layout so downstream
        consumers (and the MCP tool contract) are unchanged.
        """
        maps = self.service.target_maps(pid)
        name, entries = self._resolve_module_maps(maps, module, None)
        if not entries:
            raise AgentError("not_found", detail=f"module {module!r} not found")
        entropy_note = self._entropy_guard(pid, entries, force=force)

        ok, detail = ida_backend.ida_available()
        if not ok:
            # Structured, non-fatal: the tool contract says "engine unavailable",
            # not "crash". Callers may still use dump_module + a local IDA GUI.
            raise AgentError("unavailable", detail=detail)

        if out_dir is None:
            out_dir = f"/tmp/tanyao-decomp/{name}-{pid}"
        out_dir = os.path.abspath(out_dir)
        os.makedirs(out_dir, exist_ok=True)
        dump_path = os.path.join(out_dir, f"{name}.dump.so")
        dump_info = self.dump_module(pid, name, dump_path)

        job_id = uuid.uuid4().hex[:16]
        job = ida_backend.start_decompile(
            dump_path, out_dir,
            max_functions=max_functions,
            job_id=job_id, pid=pid, module=name,
        )
        self._ida_jobs[job_id] = job
        return {
            "job_id": job_id,
            "pid": pid,
            "module": name,
            "engine": "ida",
            "out_dir": out_dir,
            "dump": dump_info["out"],
            "entropy_note": entropy_note,
            "note": "poll decompile_status(pid, job_id); .c files + index.json land in out_dir",
        }

    def decompile_status(self, pid: int, job_id: str) -> dict:
        ida_job = self._ida_jobs.get(job_id)
        if ida_job is not None:
            if ida_job.pid != pid:
                raise AgentError("not_found",
                                 detail=f"no such job {job_id!r} for pid {pid}")
            return ida_job.to_dict()
        job = self._jobs.get(job_id)
        if job is None or job.pid != pid:
            raise AgentError("not_found", detail=f"no such job {job_id!r} for pid {pid}")
        return job.to_dict()

    # -- dump -------------------------------------------------------------------------------

    def diff_module(self, pid: int, module: str, *, local_path: str | None = None,
                    max_ranges: int = 256, context: int = 16,
                    exec_only: bool = True,
                    range_lo: int | None = None, range_hi: int | None = None,
                    chunk_bytes: int = 0, next_offset: int | None = None) -> dict:
        """Compare a module's LIVE memory against its on-disk file.

        This is the dynamic analogue of a checksum: the disk image is what the
        linker produced, the live image is what is actually executing. Any
        difference is a runtime modification — inline hooks, detours, self-
        modifying code, or anti-tamper patching. Static analysis cannot see
        them at all, because it only ever looks at the file.

        `local_path` may point at the on-disk .so; when omitted we try the path
        recorded in the target's own maps (the file the loader mapped).

        Windowing (`range_lo` / `range_hi` / `chunk_bytes`) exists because a
        full comparison of a large module is slow and the target may not survive
        it: `chunk_bytes` caps how much is compared per call and returns
        `next_offset` so the caller can walk the module across several calls
        with a pause between each. Addresses are ELF vaddrs.

        `exec_only` (default True) restricts the comparison to executable
        segments. Writable data (.data/.bss) legitimately differs from the file
        after start-up — globals are initialised, heap pointers are written —
        so including it buries the real signal (patched CODE) under hundreds of
        benign entries. Pass exec_only=False when you are hunting a data patch
        instead.

        Returns patched ranges with both byte strings, so a caller can triage
        without re-dumping anything.
        """
        maps = self.service.target_maps(pid)
        view = MapsView.from_maps(maps)
        v = view.modules.get(module)
        if v is None:
            raise AgentError("not_found",
                             detail=f"module {module!r} not mapped in pid {pid}")
        segs = [x for x in v.segments if not x.mirror] or v.segments

        disk_path = local_path or v.path
        if not disk_path:
            raise AgentError(
                "bad_request",
                detail=f"no on-disk path known for {module!r}; pass local_path=")
        if not os.path.exists(disk_path):
            raise AgentError(
                "not_found",
                detail=f"local file {disk_path!r} not found (pull it first or "
                       f"pass local_path=)")

        base = min(x.start for x in segs)
        ranges: list[dict] = []
        total_diff = 0
        compared = 0
        truncated = False

        # The runtime `file_offset` of a mapping is PAGE-ALIGNED down from the
        # ELF p_offset (mmap works in pages), so seeking to it in the file is
        # off by up to a page — that produced 802 phantom "differences" against
        # an unpatched binary. Recover the true mapping from the ELF program
        # headers instead: for the segment containing a given runtime start,
        # the byte at (start + k) corresponds to file offset
        #     p_offset + (start - (load_base + p_vaddr)) + k
        try:
            model = AddressModel.build(pid, module, maps, self.service.mem_read)
        except AddressModelError as exc:
            slug = "unavailable" if exc.unavailable else "not_found"
            raise AgentError(slug, detail=f"cannot build address model for diff: "
                                          f"{exc.detail}") from exc
        info = model.elf
        # Two layouts exist and they need different arithmetic:
        #   * ET_DYN loaded at 0 with p_vaddr already relative      (usual .so)
        #   * ET_EXEC / prelinked PIE whose p_vaddr IS the runtime   (this PIE)
        # Distinguish them by checking whether any PT_LOAD's p_vaddr already
        # falls inside the module's mapped range; AddressModel owns the window.
        in_range = any(
            min(x.start for x in segs) <= ld.vaddr < max(x.end for x in segs)
            for ld in info.loads)
        load_base = 0 if in_range else model.base

        def disk_offset_for(rt_start: int) -> int | None:
            """Map a runtime address to a file offset via the live p_vaddrs."""
            for ld in info.loads:
                rt_lo = load_base + ld.vaddr
                if rt_lo <= rt_start < rt_lo + ld.filesz:
                    return ld.offset + (rt_start - rt_lo)
            return None

        with open(disk_path, "rb") as fh:
            stop_after = None
            if chunk_bytes and chunk_bytes > 0:
                begin = next_offset if next_offset is not None else (range_lo or 0)
                stop_after = begin + chunk_bytes

            for seg in segs:
                span = seg.size
                if span <= 0:
                    continue
                if exec_only and "x" not in seg.flags_str():
                    continue

                # Window the segment in ELF-vaddr space.
                lo, hi = 0, span
                if range_lo is not None:
                    lo = max(lo, range_lo - (seg.start - base))
                if range_hi is not None:
                    hi = min(hi, range_hi - (seg.start - base))
                if lo >= hi:
                    continue
                if stop_after is not None:
                    # Chunked mode: compare only [begin, begin+chunk). `begin`
                    # is the caller's absolute vaddr cursor, so the window must
                    # SLIDE, not accumulate — a previous version left `lo` at
                    # the segment start and re-compared earlier bytes.
                    begin = next_offset if next_offset is not None else (range_lo or 0)
                    abs_lo = (seg.start - base) + lo
                    abs_hi = (seg.start - base) + hi
                    if abs_hi <= begin:
                        continue
                    lo = max(lo, begin - (seg.start - base))
                    hi = min(hi, stop_after - (seg.start - base))
                if lo >= hi:
                    continue

                run_start = seg.start + lo
                run_span = hi - lo
                foff = disk_offset_for(run_start)
                if foff is None:
                    # Segment starts outside any file-backed PT_LOAD (pure BSS).
                    continue
                try:
                    live = self.service.mem_read(pid, run_start, run_span)
                except AgentError:
                    continue
                fh.seek(foff)
                disk = fh.read(run_span)
                if not disk:
                    continue
                span = run_span
                seg_start = run_start
                seg_foff = foff
                n = min(len(live), len(disk))
                compared += n
                i = 0
                while i < n:
                    if live[i] != disk[i]:
                        start = i
                        while i < n and live[i] != disk[i]:
                            i += 1
                        if len(ranges) >= max_ranges:
                            truncated = True
                            break
                        lo = max(0, start - 0)
                        hi = min(n, i)
                        ranges.append({
                            "runtime_addr": f"0x{seg_start + lo:x}",
                            "file_offset": f"0x{seg_foff + lo:x}",
                            "size": hi - lo,
                            "live_hex": live[lo:hi][:context].hex(),
                            "disk_hex": disk[lo:hi][:context].hex(),
                        })
                        total_diff += hi - lo
                    else:
                        i += 1
                if truncated:
                    break

        # Where a chunked caller should resume (ELF vaddr), or None when done.
        resume = None
        if chunk_bytes and chunk_bytes > 0:
            begin = next_offset if next_offset is not None else (range_lo or 0)
            scanned_hi = begin
            for seg in segs:
                if exec_only and "x" not in seg.flags_str():
                    continue
                seg_abs_lo = seg.start - base
                seg_abs_hi = seg_abs_lo + seg.size
                if seg_abs_hi <= begin:
                    continue
                if range_hi is not None and seg_abs_lo >= range_hi:
                    continue
                scanned_hi = max(scanned_hi, min(seg_abs_hi, begin + chunk_bytes))
            resume = scanned_hi

        return {
            "pid": pid,
            "module": module,
            "disk_path": disk_path,
            "next_offset": f"0x{resume:x}" if resume is not None else None,
            "compared_bytes": compared,
            "exec_only": exec_only,
            "total_diff_bytes": total_diff,
            "patched_ranges": ranges,
            "range_count": len(ranges),
            "truncated": truncated,
            "note": ("non-zero total_diff_bytes means the live image differs from "
                     "the file: runtime patching / inline hooks / self-modifying "
                     "code. Static analysis on the file cannot see this. "
                     + ("Only executable segments were compared; pass "
                        "exec_only=false to include writable data."
                        if exec_only else
                        "Writable data was included — initialised globals differ "
                        "legitimately, so expect noise.")),
        }

    def dump_module(self, pid: int, module: str, out_path: str, *, include_anonymous: bool = False) -> dict:
        """Module dump. bit6: device rebuilds to file layout (cmd 63), host pulls
        it chunked with crc32/resume/sha256 (cmd 65) and cleans up (cmd 68);
        without bit6 the frozen host-side chunked-read reconstruction runs."""
        if self.service.has_agent_cap(AGENT_CAP_DUMP_PIPELINE):
            return self._agent_dump_module(pid, module, out_path, include_anonymous)
        maps = self.service.target_maps(pid)
        read_fn = self._read_for(pid)
        image, manifest = _dump_module(pid, module, maps, read_fn, include_anonymous=include_anonymous)
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(image)
        manifest_path = out_path + ".manifest.json"
        import json

        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest.to_dict(), fh, ensure_ascii=False, indent=2)
        return {
            "pid": pid,
            "module": module,
            "out": os.path.abspath(out_path),
            "size": len(image),
            "manifest": manifest_path,
            "mappings": len(manifest.entries),
            "skipped": len(manifest.skipped),
            "engine": "host-dump",
        }

    def _agent_dump_module(self, pid: int, module: str, out_path: str,
                           include_anonymous: bool) -> dict:
        out_name = _re.sub(r"[^A-Za-z0-9._-]", "_", module) or "dump"
        start = self.service.dump_start(pid, module=module,
                                        include_anonymous=include_anonymous,
                                        out_name=out_name)
        dump_id = str(start["dump_id"])
        expected_sha = start.get("sha256")
        raw_size = start.get("size")
        expected_size = parse_u64(raw_size, field="size") if raw_size is not None else None
        result = pull_dump_with_resume(
            self.service, out_path, dump_id=dump_id,
            expected_sha256=expected_sha, expected_size=expected_size,
            state_store=self._pull_states,
        )
        manifest = start.get("manifest")
        if not isinstance(manifest, dict):
            # device without the manifest amendment: reconstruct a faithful shell
            manifest = {
                "pid": pid,
                "module": module,
                "total_size": expected_size,
                "maps_source": start.get("maps_source"),
                "mappings": [],
                "skipped": start.get("skipped", []),
                "sanitized": ["e_shoff", "e_shentsize", "e_shnum", "e_shstrndx"]
                if start.get("sanitized") else [],
            }
        manifest_path = out_path + ".manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
        # explicit cleanup after the verified pull (host responsibility, §4.3)
        try:
            self.service.dump_cleanup(dump_id)
        except AgentError:
            pass  # best effort; dump_status(list) exposes leftovers
        return {
            "pid": pid,
            "module": module,
            "out": result["path"],
            "size": result["size"],
            "manifest": manifest_path,
            "mappings": len(manifest.get("mappings", [])),
            "skipped": len(manifest.get("skipped", [])),
            "dump_id": dump_id,
            "sha256": result["sha256"],
            "maps_source": start.get("maps_source"),
            "sanitized": bool(start.get("sanitized")),
            "engine": "agent-dump",
        }


__all__ = ["AnalysisFacade", "WriteDisabled", "AgentUnavailable", "AgentError"]
