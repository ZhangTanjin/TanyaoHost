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
import zipfile
from typing import Any

from .connection import AgentError
from .constants import (
    AGENT_CAP_APK_INFO,
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
    parse_u64,
)
from .dump import dump_module as _dump_module
from .dump import pull_dump_with_resume
from .dump import watch as _watch
from .elfinfo import ElfParseError, parse_elf64
from .mapsview import MAP_ANONYMOUS, MAP_READ, MapsView
from .jobs import JobManager, ScanCancelled
from .native import ApkParseError, disassemble_a64_ex, extract_strings, parse_apk_manifest
from .pointer import PointerChainError, resolve_chain
from .scan import TYPES, ScanEngine
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


class AnalysisFacade:
    def __init__(self, service: TanyaoService) -> None:
        self.service = service
        self._scans: dict[int, ScanEngine] = {}
        self._jobs = JobManager()
        self._write_enabled = os.environ.get("TANYAO_ALLOW_WRITE") == "1"
        # v3 engine dispatch state (agent-scan path): last preset per pid for
        # cmd 50 passthrough, per-pid device-job metadata, and a map of host
        # job ids to device job ids so scan_cancel reaches the agent.
        self._scan_presets: dict[int, str] = {}
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

    def find_process(self, name: str) -> dict:
        try:
            return {"pid": self.service.process_find(name)}
        except AgentError as exc:
            if exc.error == "not_found":
                # O4: the kernel legacy match needs the FULL cmdline name. Guide
                # the caller instead of auto-retrying or enumerating — parameter
                # choice stays with the AI (no fuzzy match host-side: cmd 41
                # returns bare pids without names).
                return {
                    "pid": None,
                    "found": False,
                    "hint": "use the FULL package/process name as in /proc/<pid>/cmdline "
                            "(e.g. com.tencent.lolm); short names (lolm) are not matched — "
                            "call list_processes to enumerate pids",
                }
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
                "base": f"0x{v.first_map:x}",
                "segments": [
                    {
                        "start": f"0x{s.start:x}",
                        "end": f"0x{s.end:x}",
                        "size": s.size,
                        "file_offset": f"0x{s.file_offset:x}",
                        "permissions": s.flags_str(),
                    }
                    for s in v.segments
                ],
            })
        return {
            "pid": pid,
            "count": len(modules),
            "maps_source": self.service.maps_source(),
            "modules": modules,
        }

    def resolve_module(self, pid: int, name: str) -> dict:
        maps = self.service.target_maps(pid)
        module_maps = [m for m in maps if self._module_of(m.path) == name]
        if not module_maps:
            raise AgentError("not_found", detail=f"module {name!r} not mapped in pid {pid}")
        first = min(module_maps, key=lambda m: m.start)
        header_size = 0x1000
        data = self.service.mem_read(pid, first.start, min(header_size, first.size))
        try:
            info = parse_elf64(data, allow_zero_magic=True)
        except ElfParseError as exc:
            return {"pid": pid, "module": name, "first_map": f"0x{first.start:x}", "error": str(exc)}
        base = first.start
        mirror = any(
            m.file_offset == 0 and m.start != base and m.size >= first.size * 2 for m in module_maps
        )
        load_bias_abs = base - info.load_bias  # ELF-arithmetic anchor (legacy field)
        bss = None
        if info.bss_end:
            bss_lo = info.bss_start + load_bias_abs
            bss_hi = info.bss_end + load_bias_abs
            # D9: arithmetic BSS bounds must never leak past THIS module's own
            # mappings — on multi-bias modules the single-anchor arithmetic
            # spills into a neighbor's territory (field: lolm libil2cpp BSS end
            # landing inside libunity.so)
            module_hi = max(m.end for m in module_maps)
            if bss_lo < module_hi:
                bss = [f"0x{bss_lo:x}", f"0x{min(bss_hi, module_hi):x}"]
        return {
            "pid": pid,
            "module": name,
            "first_map": f"0x{base:x}",
            "load_bias": f"0x{load_bias_abs:x}",
            "bss": bss,
            "mirror_detected": mirror,
        }

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
            "module_offset": f"0x{address - seg.start + seg.file_offset:x}" if path else None,
        }
        out.update(out_extra)
        if path and seg.flags & MAP_EXEC:
            try:
                resolved = self.resolve_module(pid, module)
                if isinstance(resolved.get("load_bias"), str):
                    out["load_bias"] = resolved["load_bias"]
            except AgentError:
                pass
        if path:
            # D9: file-layout rva straight from the per-mapping translation
            file_offset = address - seg.start + seg.file_offset
            out["file_offset"] = f"0x{file_offset:x}"
            out["rva"] = out["file_offset"]
        return out

    # -- memory ----------------------------------------------------------------------

    def read_memory(self, pid: int, address: int, size: int, *, as_type: str | None = None, count: int = 1) -> dict:
        if as_type:
            fmt, width, _kind = TYPES[as_type]
            total = width * max(1, count)
            data = self.service.mem_read(pid, address, total)
            values = [struct.unpack_from(fmt, data, i * width)[0] for i in range(max(1, count))]
            return {
                "pid": pid,
                "address": f"0x{address:x}",
                "type": as_type,
                "count": count,
                "values": values,
                "data_hex": data.hex(),
            }
        data = self.service.mem_read(pid, address, size)
        return {"pid": pid, "address": f"0x{address:x}", "size": size, "data_hex": data.hex()}

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
                    timeout: float = 600.0) -> dict:
        """Poll device job status until done. Maps cancel/error to host semantics."""
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
                raise AgentError("backend_error", detail=str(st.get("error") or "agent scan failed"))
            if time.monotonic() > deadline:
                raise AgentError("backend_error", detail=f"agent scan job {dev_job} timed out")
            time.sleep(0.05)

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
        return {"job_id": job_id, "pid": pid, "kind": kind, "state": "running",
                "async": True, "poll": "scan_status"}

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
    ) -> dict:
        """First scan. With async_run=True (or estimated bytes > threshold) this runs
        as a background job: returns {'job_id','state':'running'} — poll scan_status."""
        if self._scan_route(pid) == "agent":
            dev_job, meta = self._agent_scan_start(
                pid, kind="value", vtype=vtype, value=value,
                epsilon=epsilon, alignment=alignment or 0,
                ranges=self._explicit_ranges_payload(pid),
            )
            engine = self._scans.get(pid)
            est = sum(e - s for s, e in engine.state.ranges) if engine else 0
            INLINE_LIMIT = 64 * 1024 * 1024
            if async_run or est > INLINE_LIMIT:
                return self._start_agent_scan_job(pid, "value", dev_job, meta)
            st = self._agent_wait(dev_job)
            summary = self._agent_summary(pid, st, meta)
            return summary | {"found": summary["count"],
                              "results": self._agent_results_page(dev_job, 0, 32),
                              "async": False}
        engine = self._scan_for(pid)
        est = sum(e - s for s, e in engine.state.ranges)
        INLINE_LIMIT = 64 * 1024 * 1024  # >64MB: force async
        if async_run or est > INLINE_LIMIT:
            return self._start_scan_job(pid, "value", vtype, value, epsilon=epsilon, alignment=alignment)
        found = engine.scan_value(pid, vtype, value, epsilon=epsilon, alignment=alignment)
        return engine.summary() | {"found": found, "results": engine.results(limit=32), "async": False,
                                   "engine": "host-scan"}

    def scan_hex(self, pid: int, pattern: str, *, async_run: bool = False) -> dict:
        if self._scan_route(pid) == "agent":
            dev_job, meta = self._agent_scan_start(pid, kind="hex", pattern=pattern,
                                                   ranges=self._explicit_ranges_payload(pid))
            engine = self._scans.get(pid)
            est = sum(e - s for s, e in engine.state.ranges) if engine else 0
            INLINE_LIMIT = 64 * 1024 * 1024
            if async_run or est > INLINE_LIMIT:
                return self._start_agent_scan_job(pid, "hex", dev_job, meta)
            st = self._agent_wait(dev_job)
            summary = self._agent_summary(pid, st, meta)
            return summary | {"found": summary["count"],
                              "results": self._agent_results_page(dev_job, 0, 256),
                              "async": False}
        pattern_bytes, mask_bytes = _parse_aob(pattern)
        engine = self._scan_for(pid)
        est = sum(e - s for s, e in engine.state.ranges)
        INLINE_LIMIT = 64 * 1024 * 1024
        if async_run or est > INLINE_LIMIT:
            return self._start_scan_job(pid, "hex", bytes(pattern_bytes), bytes(mask_bytes))
        found = engine.scan_hex(pid, bytes(pattern_bytes), bytes(mask_bytes))
        return engine.summary() | {"found": found, "results": engine.results(), "async": False,
                                   "engine": "host-scan"}

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

    def scan_next(self, pid: int, mode: str, value: float | None = None, *, epsilon: float = 0.0) -> dict:
        if self._agent_scan_enabled(pid):
            meta = self._agent_scan_meta.get(pid)
            if meta is None:
                raise AgentError("bad_request", detail="no scan in progress for this pid")
            if any(j.state == "running" for j in self._jobs.list_for(pid)):
                raise AgentError("bad_request", detail="a scan job is still running; poll scan_status first")
            resp = self.service.agent_scan_refine(mode, value, epsilon=epsilon)
            st = self.service.agent_scan_status(meta["dev_job"])
            summary = self._agent_summary(pid, st, meta)
            return summary | {"found": int(resp.get("matches", 0))}
        engine = self._scans.get(pid)
        if engine is None or engine.state.scan_round == 0:
            raise AgentError("bad_request", detail="no scan in progress for this pid")
        if any(j.state == "running" for j in self._jobs.list_for(pid)):
            raise AgentError("bad_request", detail="a scan job is still running; poll scan_status first")
        found = engine.refine(pid, mode, value, epsilon=epsilon)
        return engine.summary() | {"found": found, "engine": "host-scan"}

    def scan_results(self, pid: int, *, offset: int = 0, limit: int = 256) -> dict:
        if self._agent_scan_enabled(pid):
            meta = self._agent_scan_meta.get(pid)
            if meta is None:
                raise AgentError("bad_request", detail="no scan for this pid")
            st = self.service.agent_scan_status(meta["dev_job"])
            summary = self._agent_summary(pid, st, meta)
            return summary | {"results": self._agent_results_page(meta["dev_job"], offset, limit)}
        engine = self._scans.get(pid)
        if engine is None:
            raise AgentError("bad_request", detail="no scan for this pid")
        return engine.summary() | {"results": engine.results(offset, limit), "engine": "host-scan"}

    def scan_clear(self, pid: int) -> dict:
        if self._agent_scan_enabled(pid):
            self.service.agent_scan_clear()
            return {"cleared": True, "engine": "agent-scan"}
        engine = self._scans.get(pid)
        if engine:
            engine.clear()
        return {"cleared": True, "engine": "host-scan"}

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

    def symbol_list(self, pid: int, name: str, *, limit: int = 512, filter: str | None = None) -> dict:
        if self.service.has_agent_cap(AGENT_CAP_SYMBOL_BATCH):
            resp = self.service.symbol_batch(pid, module=name, filter=filter)
            symbols = [self._symbol_row(resp, i, name) for i in range(resp["count"])]
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
        return {
            "pid": pid,
            "module": name,
            "total": len(syms),
            "shown": min(len(syms), limit),
            "symbols": [s.to_dict() for s in syms[:limit]],
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
            raise AgentError("bad_request", detail=f"address 0x{address:x} not inside module {name}")
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
                raise AgentError("backend_error", detail=str(st.get("error") or "strings job failed"))
            if time.monotonic() > deadline:
                raise AgentError("backend_error", detail=f"strings job {dev_job} timed out")
            time.sleep(0.1)

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

    # -- decompile (Ghidra headless, async jobs) ----------------------------------

    GHIDRA_HEADLESS = "/opt/ghidra/support/analyzeHeadless"
    GHIDRA_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "ghidra_scripts", "TanyaoDecomp.java")

    def decompile_start(self, pid: int, module: str, out_dir: str | None = None,
                        max_functions: int = 2000) -> dict:
        """Dump a module, import it into headless Ghidra, auto-analyze and
        decompile all functions to C. Long-running: returns a job id immediately;
        poll decompile_status. C sources + index.json land in out_dir."""
        maps = self.service.target_maps(pid)
        name, entries = self._resolve_module_maps(maps, module, None)
        if not entries:
            raise AgentError("not_found", detail=f"module {module!r} not found")
        if not os.path.exists(self.GHIDRA_HEADLESS):
            raise AgentError("unavailable", detail="Ghidra not installed at /opt/ghidra")
        if not os.path.exists(self.GHIDRA_SCRIPT):
            raise AgentError("unavailable", detail=f"missing script {self.GHIDRA_SCRIPT}")
        if out_dir is None:
            out_dir = f"/tmp/tanyao-decomp/{name}-{pid}"
        out_dir = os.path.abspath(out_dir)
        os.makedirs(out_dir, exist_ok=True)
        dump_path = os.path.join(out_dir, f"{name}.dump.so")
        dump_info = self.dump_module(pid, name, dump_path)
        proj_dir = os.path.join(out_dir, "proj")
        os.makedirs(proj_dir, exist_ok=True)
        cmd = [
            self.GHIDRA_HEADLESS, proj_dir, "tanyao",
            "-import", dump_path,
            "-scriptPath", os.path.dirname(self.GHIDRA_SCRIPT),
            "-postScript", "TanyaoDecomp.java", out_dir, str(max(1, int(max_functions))),
            "-deleteProject",
        ]

        def run(progress):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            except subprocess.TimeoutExpired as exc:
                raise AgentError("backend_error", detail="ghidra headless timed out (3600s)") from exc
            log = (proc.stdout or "") + "\n" + (proc.stderr or "")
            if "TANYAO_DECOMP_DONE" not in log:
                err_lines = [ln for ln in log.splitlines()
                             if "ERROR" in ln or "TANYAO_DECOMP_ERROR" in ln][:6]
                raise AgentError("backend_error",
                                 detail="ghidra failed: " + " | ".join(err_lines)[:600])
            funcs = []
            idx_path = os.path.join(out_dir, "index.json")
            if os.path.exists(idx_path):
                with open(idx_path, encoding="utf-8") as fh:
                    funcs = json.load(fh).get("functions", [])
            return {
                "out_dir": out_dir,
                "dump": dump_info["out"],
                "function_count": len(funcs),
                "functions": funcs,
                "log_tail": [ln for ln in log.strip().splitlines() if ln.strip()][-4:],
            }

        job_id = self._jobs.start(pid, "decompile", run)
        return {
            "job_id": job_id,
            "pid": pid,
            "module": name,
            "out_dir": out_dir,
            "dump": dump_info["out"],
            "note": "poll decompile_status(pid, job_id); .c files + index.json land in out_dir",
        }

    def decompile_status(self, pid: int, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if job is None or job.pid != pid:
            raise AgentError("not_found", detail=f"no such job {job_id!r} for pid {pid}")
        return job.to_dict()

    # -- dump -------------------------------------------------------------------------------

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
