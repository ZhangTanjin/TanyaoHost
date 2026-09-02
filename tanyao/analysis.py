"""Analysis facade: binds scan/elf/pointer/dump engines to a TanyaoService.

This is what IPC and MCP call. One facade per agent connection.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import zipfile
from typing import Any

from .connection import AgentError
from .constants import MAP_EXEC, MAP_READ, MAP_WRITE
from .dump import dump_module as _dump_module
from .dump import watch as _watch
from .elfinfo import ElfParseError, parse_elf64
from .jobs import JobManager
from .native import ApkParseError, disassemble_a64_ex, extract_strings, parse_apk_manifest
from .pointer import PointerChainError, resolve_chain
from .scan import TYPES, ScanEngine
from .service import AgentUnavailable, TanyaoService
from .symbols import SymbolError, load_symbols


class WriteDisabled(Exception):
    pass


class AnalysisFacade:
    def __init__(self, service: TanyaoService) -> None:
        self.service = service
        self._scans: dict[int, ScanEngine] = {}
        self._jobs = JobManager()
        self._write_enabled = os.environ.get("TANYAO_ALLOW_WRITE") == "1"

    # -- helpers ----------------------------------------------------------------

    def _read_for(self, pid: int):
        def read_fn(addr: int, size: int) -> bytes:
            return self.service.mem_read(pid, addr, size)

        return read_fn

    def _scan_for(self, pid: int) -> ScanEngine:
        engine = self._scans.get(pid)
        if engine is None:
            backend = self.service.backend_info()
            engine = ScanEngine(self.service.mem_read, max_transfer=backend.max_transfer_size)
            self._scans[pid] = engine
        return engine

    # -- process / module ----------------------------------------------------------

    def find_process(self, name: str) -> dict:
        try:
            return {"pid": self.service.process_find(name)}
        except AgentError as exc:
            if exc.error == "not_found":
                return {"pid": None, "found": False}
            raise

    def list_modules(self, pid: int, name_filter: str | None = None) -> dict:
        maps = self.service.target_maps(pid)
        modules: dict[str, dict] = {}
        for m in maps:
            if not m.path:
                continue
            basename = m.path.rstrip("/").split("/")[-1]
            if name_filter and name_filter.lower() not in basename.lower():
                continue
            entry = modules.setdefault(
                basename,
                {"name": basename, "path": m.path, "ranges": 0, "start": m.start, "end": m.end},
            )
            entry["ranges"] += 1
            entry["start"] = min(entry["start"], m.start)
            entry["end"] = max(entry["end"], m.end)
        return {
            "pid": pid,
            "count": len(modules),
            "maps_source": self.service.maps_source(),
            "modules": [
                {
                    "name": v["name"],
                    "path": v["path"],
                    "base": f"0x{v['start']:x}",
                    "end": f"0x{v['end']:x}",
                    "ranges": v["ranges"],
                }
                for v in sorted(modules.values(), key=lambda e: e["start"])
            ],
        }

    def resolve_module(self, pid: int, name: str) -> dict:
        maps = self.service.target_maps(pid)
        module_maps = [m for m in maps if m.path.rstrip("/").split("/")[-1] == name]
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
        load_bias_abs = base - info.load_bias  # absolute address where the ELF's vaddr 0 lands
        return {
            "pid": pid,
            "module": name,
            "first_map": f"0x{base:x}",
            "load_bias": f"0x{load_bias_abs:x}",
            "bss": [f"0x{info.bss_start + load_bias_abs:x}", f"0x{info.bss_end + load_bias_abs:x}"] if info.bss_end else None,
            "mirror_detected": mirror,
        }

    def address_resolve(self, pid: int, address: int) -> dict:
        maps = self.service.target_maps(pid)
        for m in maps:
            if m.start <= address < m.end:
                out: dict[str, Any] = {
                    "pid": pid,
                    "address": f"0x{address:x}",
                    "start": f"0x{m.start:x}",
                    "end": f"0x{m.end:x}",
                    "permissions": m.flags_str(),
                    "path": m.path,
                    "module": m.path.rstrip("/").split("/")[-1] if m.path else None,
                    "module_offset": f"0x{address - m.start + m.file_offset:x}" if m.path else None,
                }
                if m.path and m.flags & MAP_EXEC:
                    try:
                        resolved = self.resolve_module(pid, m.path.rstrip("/").split("/")[-1])
                        bias_text = resolved.get("load_bias")
                        if isinstance(bias_text, str):
                            bias = int(bias_text, 16)
                            out["load_bias"] = bias_text
                            out["rva"] = f"0x{address - bias:x}"
                    except AgentError:
                        pass
                return out
        raise AgentError("not_found", detail=f"address 0x{address:x} not in any mapping of pid {pid}")

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

    def scan_set_default_ranges(self, pid: int, *, preset: str = "anon") -> dict:
        """preset: anon (default, readable anonymous/heap), stack, module:<name>,
        all_readable."""
        maps = self.service.target_maps(pid)
        engine = self._scan_for(pid)
        if preset == "anon":
            engine.set_default_ranges(pid, maps)
        elif preset == "all_readable":
            engine.set_ranges(pid, [(m.start, m.end) for m in maps if m.flags & MAP_READ])
        elif preset == "stack":
            stack_maps = [m for m in maps if "[stack" in m.path]
            if not stack_maps:
                raise AgentError("bad_request", detail="no [stack] mapping found")
            engine.set_ranges(pid, [(m.start, m.end) for m in stack_maps])
        elif preset.startswith("module:"):
            name = preset.split(":", 1)[1]
            matches = [m for m in maps if m.path.rstrip("/").split("/")[-1] == name and m.flags & MAP_READ]
            if not matches:
                raise AgentError("not_found", detail=f"module {name!r} not mapped")
            engine.set_ranges(pid, [(m.start, m.end) for m in matches])
        else:
            raise AgentError("bad_request", detail=f"unknown preset {preset!r}")
        total = sum(e - s for s, e in engine.state.ranges)
        return {"pid": pid, "preset": preset, "ranges": len(engine.state.ranges), "total_bytes": total}

    def scan_set_range(self, pid: int, start: int, end: int) -> dict:
        engine = self._scan_for(pid)
        engine.set_ranges(pid, [(start, end)])
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
        engine = self._scan_for(pid)
        est = sum(e - s for s, e in engine.state.ranges)
        INLINE_LIMIT = 64 * 1024 * 1024  # >64MB: force async
        if async_run or est > INLINE_LIMIT:
            return self._start_scan_job(pid, "value", vtype, value, epsilon=epsilon, alignment=alignment)
        found = engine.scan_value(pid, vtype, value, epsilon=epsilon, alignment=alignment)
        return engine.summary() | {"found": found, "results": engine.results(limit=32), "async": False}

    def scan_hex(self, pid: int, pattern: str, *, async_run: bool = False) -> dict:
        tokens = pattern.split()
        pattern_bytes = bytearray()
        mask_bytes = bytearray()
        for tok in tokens:
            if tok in ("?", "??"):
                pattern_bytes.append(0)
                mask_bytes.append(0)
            else:
                pattern_bytes.append(int(tok, 16))
                mask_bytes.append(0xFF)
        engine = self._scan_for(pid)
        est = sum(e - s for s, e in engine.state.ranges)
        INLINE_LIMIT = 64 * 1024 * 1024
        if async_run or est > INLINE_LIMIT:
            return self._start_scan_job(pid, "hex", bytes(pattern_bytes), bytes(mask_bytes))
        found = engine.scan_hex(pid, bytes(pattern_bytes), bytes(mask_bytes))
        return engine.summary() | {"found": found, "results": engine.results(), "async": False}

    def scan_start(self, pid: int, kind: str, *, type: str | None = None, value=None,
                   pattern: str | None = None, epsilon: float = 0.0,
                   alignment: int | None = None) -> dict:
        """Public async-scan entry (MCP scan_start). Validates kind/params then
        hands off to the background job runner."""
        if kind == "value":
            if type is None or value is None:
                raise AgentError("bad_request", detail="value scan requires 'type' and 'value'")
            return self._start_scan_job(pid, "value", type, value, epsilon=epsilon, alignment=alignment)
        if kind == "hex":
            if not pattern:
                raise AgentError("bad_request", detail="hex scan requires 'pattern'")
            return self._start_scan_job(pid, "hex", pattern)
        raise AgentError("bad_request", detail=f"unknown scan kind {kind!r}")

    def _start_scan_job(self, pid: int, kind: str, *args, **kwargs) -> dict:
        engine = self._scan_for(pid)

        def run(progress) -> dict:
            if kind == "value":
                engine.scan_value(pid, args[0], args[1], epsilon=kwargs.get("epsilon", 0.0),
                                  alignment=kwargs.get("alignment"), progress=progress)
            else:
                engine.scan_hex(pid, args[0], args[1])
            return engine.summary() | {"results": engine.results(limit=32)}

        job_id = self._jobs.start(pid, kind, run)
        return {"job_id": job_id, "pid": pid, "kind": kind, "state": "running",
                "async": True, "poll": "scan_status"}

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
        engine = self._scans.get(pid)
        if engine is None or engine.state.scan_round == 0:
            raise AgentError("bad_request", detail="no scan in progress for this pid")
        if any(j.state == "running" for j in self._jobs.list_for(pid)):
            raise AgentError("bad_request", detail="a scan job is still running; poll scan_status first")
        found = engine.refine(pid, mode, value, epsilon=epsilon)
        return engine.summary() | {"found": found}

    def scan_results(self, pid: int, *, offset: int = 0, limit: int = 256) -> dict:
        engine = self._scans.get(pid)
        if engine is None:
            raise AgentError("bad_request", detail="no scan for this pid")
        return engine.summary() | {"results": engine.results(offset, limit)}

    def scan_clear(self, pid: int) -> dict:
        engine = self._scans.get(pid)
        if engine:
            engine.clear()
        return {"cleared": True}

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

    def symbol_list(self, pid: int, name: str, *, limit: int = 512, filter: str | None = None) -> dict:
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
        }

    def symbol_find(self, pid: int, name: str, module: str | None = None) -> dict:
        """Exact symbol name lookup. Tries one module (or all executable file-backed
        modules until found) and returns matches with absolute addresses."""
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
                return {"pid": pid, "module": mod_name, "matches": hits}
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
        when installed) or "subset" (built-in length-decoded fallback)."""
        maps = self.service.target_maps(pid)
        name, entries = self._resolve_module_maps(maps, module, address)
        if not entries:
            detail = (f"address 0x{address:x} not inside any mapped module"
                      if module is None else f"module {module!r} not found")
            raise AgentError("not_found", detail=detail)
        load_bias = min(e.start for e in entries)
        region = next((e for e in entries if e.start <= address < e.end), None)
        if region is None:
            raise AgentError("bad_request", detail=f"address 0x{address:x} not inside module {name}")
        count = max(1, min(int(count), 4096))
        end = min(address + count * 4, region.end)
        read_fn = self._read_for(pid)
        data = read_fn(address, end - address)
        decoded = disassemble_a64_ex(data, address, max_instructions=count, engine=engine)
        return {
            "pid": pid,
            "module": name,
            "address": f"0x{address:x}",
            "rva": f"0x{address - load_bias:x}",
            "engine": decoded["engine"],
            "count": len(decoded["instructions"]),
            "instructions": decoded["instructions"],
            "source": "live_memory",
        }

    def strings(self, pid: int, *, module: str | None = None, address: int | None = None,
                size: int | None = None, min_length: int = 4, limit: int = 200,
                filter: str | None = None) -> dict:
        """Extract printable-ASCII strings from a module's readable segments
        (module mode, chunked with per-chunk fault skip) or an explicit window."""
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
                    results.extend(items)
                    scanned += take
                    pos += take
                    if len(results) >= limit:
                        truncated = True
            return {
                "pid": pid, "module": name, "count": len(results), "strings": results,
                "scanned_bytes": scanned, "skipped_bytes": skipped, "truncated": truncated,
            }
        if address is None:
            raise AgentError("bad_request", detail="strings: provide module= or address=")
        if not size or size <= 0:
            raise AgentError("bad_request", detail="strings: address mode requires size")
        size = min(int(size), 0x1000000)
        data = read_fn(address, size)
        items = extract_strings(data, offset=address, min_length=min_length,
                                limit=limit, filter=filter)
        return {"pid": pid, "address": f"0x{address:x}", "size": size,
                "count": len(items), "strings": items, "truncated": len(items) >= limit}

    def pull_apk(self, pid: int, out_path: str) -> dict:
        """Pull the APK backing this pid to the host (host adb; no agent command)."""
        maps = self.service.target_maps(pid)
        apk_paths = [m.path for m in maps if m.path.endswith("/base.apk")]
        if not apk_paths:
            raise AgentError("not_found", detail="no base.apk mapping found for this pid")
        src = apk_paths[0]
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
                "size": os.path.getsize(out_path)}

    def apk_info(self, apk_path: str) -> dict:
        """Parse AndroidManifest.xml (binary AXML) from a local APK file."""
        if not os.path.exists(apk_path):
            raise AgentError("not_found", detail=f"{apk_path} not found on host")
        try:
            info = parse_apk_manifest(apk_path)
        except (ApkParseError, zipfile.BadZipFile) as exc:
            raise AgentError("bad_request", detail=f"apk parse failed: {exc}") from exc
        info["path"] = os.path.abspath(apk_path)
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
        }


__all__ = ["AnalysisFacade", "WriteDisabled", "AgentUnavailable", "AgentError"]
