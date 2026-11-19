"""MCP stdio server (newline-delimited JSON-RPC) bridging to the HTTP IPC core.

Follows the AMem/MiniMem pattern: AI ──MCP/stdio──▶ this ──HTTP──▶ IPC core.
Zero third-party dependencies; speaks raw MCP stdio (newline-delimited JSON-RPC 2.0).

Run:  python3 -m tanyao.mcp_server          (requires `serve` to be running)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

IPC_URL = os.environ.get("TANYAO_IPC_URL", "http://127.0.0.1:28101/")
SERVER_NAME = "tanyao-host"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"


def _ipc_call(method: str, params: dict) -> dict:
    body = json.dumps({"method": method, "params": params}).encode("utf-8")
    request = urllib.request.Request(
        IPC_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"ok": False, "error": f"http_{exc.code}"}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "error": "ipc_unreachable", "detail": str(exc)}
    return payload


# --- MCP tool definitions -----------------------------------------------------

def _obj(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or []}


TOOLS = [
    {
        "name": "get_status",
        "description": "Get backend/connection status: connected, agent generation, backend capabilities, whether memory write is enabled. `connected` is a PROBE (one small round trip with a brief retry), not a socket-state snapshot, so a link that is a moment away from being usable does not read as down; when the retry is what made it succeed the response carries `recovering: true`. Always check `skipped_caps`: if it contains `multi_conn` the agent is in single-connection mode, where every target shares one connection and two pids can end up with the same kernel handle — a wrong-answer failure, not an error.",
        "inputSchema": _obj({}),
    },
    {
        "name": "find_process",
        "description": "Find a process PID on the device. Default (mode=exact): 'name' must be the FULL package/process name as shown in /proc/<pid>/cmdline (e.g. com.tencent.lolm); short names are NOT matched. mode=substring (needs agent FUZZY_FIND capability) matches case-sensitive substrings — use it for short names like 'lolm'. If unsure, call list_processes first.",
        "inputSchema": _obj(
            {
                "name": {"type": "string", "description": "full package/process name (exact mode) or substring (substring mode)"},
                "mode": {"type": "string", "description": "exact (default) | substring", "enum": ["exact", "substring"]},
            },
            ["name"],
        ),
    },
    {
        "name": "process_alive",
        "description": "Check whether a pid is alive, and — when you pass expected_cookie (the start_cookie from find_process) — whether it is still the SAME process. Android recycles pids quickly, so a bare 'alive' can mean a different process now owns the number; cookie_match=false means your cached addresses are invalid and you must re-run find_process. Cheaper and safer than discovering it via a failed read.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "expected_cookie": {"type": "string", "description": "start_cookie from find_process (0x hex)"},
            },
            ["pid"],
        ),
    },
    {
        "name": "watch_process",
        "description": "Poll a pid's liveness on the HOST side for a while and report the transition. Use this instead of looping process_alive yourself: one call keeps the observation out of your context (the alternative is N round trips each saying 'still alive'). Returns died/recycled plus the deciding sample; the full series is only included when something actually happened. Designed for 'is the target still up while I run a long scan?'.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "expected_cookie": {"type": "string", "description": "start_cookie; enables pid-reuse detection"},
                "count": {"type": "integer", "description": "max samples (default 30, cap 600)"},
                "interval_s": {"type": "number", "description": "seconds between samples (default 1.0)"},
                "stop_on_death": {"type": "boolean", "description": "return as soon as the process dies or is recycled (default true)"},
            },
            ["pid"],
        ),
    },
    {
        "name": "list_processes",
        "description": "List all PIDs visible to the backend.",
        "inputSchema": _obj({"bytes": {"type": "integer", "description": "PID bitmap size in bytes, default 8192"}}),
    },
    {
        "name": "list_modules",
        "description": "List mapped modules of a process with base addresses.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "filter": {"type": "string", "description": "case-insensitive substring filter on module name"},
            },
            ["pid"],
        ),
    },
    {
        "name": "resolve_module",
        "description": "Resolve a mapped module's ELF semantics: full segment table, load bias, BSS bounds (from the live [anon:.bss] mapping), mirror detection. IMPORTANT semantics: each segment's 'translation_base' equals start - file_offset, which is a per-segment anchor IN FILE-OFFSET SPACE — the identity is start == translation_base + file_offset, NOT + vaddr. To convert an ELF vaddr (including .bss) to a runtime address use resolve_vaddr, never this arithmetic. 'bss_note' states the evidence used for the BSS bounds (a live [anon:.bss] mapping is authoritative; 'arithmetic' means uncorroborated).",
        "inputSchema": _obj({"pid": {"type": "integer"}, "name": {"type": "string"}}, ["pid", "name"]),
    },
    {
        "name": "address_resolve",
        "description": "Resolve which module/mapping contains an address. Returns module, file_offset and rva — ALL tool-face rva fields are FILE OFFSETS (same as dump manifests). Addition identity: address == bearing_segment.translation_base + rva; adding load_bias works only when it equals the bearing segment's translation_base (multi-bias segments like .data.rel.ro will drift).",
        "inputSchema": _obj({"pid": {"type": "integer"}, "address": {"type": "string", "description": "0x hex address"}}, ["pid", "address"]),
    },
    {
        "name": "read_memory",
        "description": "Read process memory. Returns hex data; with as_type decodes typed values (u8..u64, i8..i64, f32, f64). strip_pac=true additionally returns PAC-masked views (values_stripped for typed u64 reads, pointers_stripped for raw buffers) while data_hex keeps the untouched bytes — use it when walking pointer chains, where signed pointers otherwise poison the address arithmetic. It is OFF by default because this is the raw primitive used for diffing and disassembly.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "address": {"type": "string"},
                "size": {"type": "integer", "description": "byte count for raw read"},
                "as_type": {"type": "string", "description": "typed read: u32/u64/f32/f64/ptr ..."},
                "count": {"type": "integer", "description": "array element count for typed read"},
                "pid_cookie": {"type": "string", "description": "start_cookie from find_process; rejects the read if the pid was reused by a restarted process (stale_target)"},
            },
            ["pid", "address"],
        ),
    },
    {
        "name": "write_bytes",
        "description": "DANGEROUS: write bytes into process memory. Disabled unless TANYAO_ALLOW_WRITE=1 on the host. Always prefer reading first.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "address": {"type": "string"},
                "data_hex": {"type": "string", "description": "hex bytes, e.g. 'DE AD BE EF' or 'deadbeef'"},
                "expect_old_hex": {"type": "string", "description": "pre-write comparison bytes (recommended)"},
            },
            ["pid", "address", "data_hex"],
        ),
    },
    {
        "name": "resolve_offset_chain",
        "description": "Walk a pointer chain: earlier offsets dereference pointers, last offset locates the field. PAC stripping on by default.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "start": {"type": "string", "description": "0x hex start address"},
                "offsets": {"type": "array", "items": {"type": "string"}, "description": "hex offsets like '0x10'"},
                "vtype": {"type": "string", "description": "final field type, default u64"},
                "strip_pac": {"type": "boolean", "description": "apply low-48 mask, default true"},
            },
            ["pid", "start", "offsets"],
        ),
    },
    {
        "name": "read_batch",
        "description": "Batch read multiple disjoint memory ranges in one round trip (agent MEM_READV). Returns per-span hex or error.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "spans": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"address": {"type": "string"}, "size": {"type": "integer"}}, "strip_pac": {"type": "boolean", "description": "also return PAC-masked pointer views (default false)"},
                "required": ["address", "size"]},
                    "description": "up to max_iov spans per call",
                },
            },
            ["pid", "spans"],
        ),
    },
    {
        "name": "scan_start",
        "description": "Start a first scan as a background job (recommended for large ranges): returns job_id; poll with scan_status. RISK NOTE: a wide scan reads every byte of the chosen ranges through the kernel within milliseconds of wall clock — on a protected/live target this is the most observable operation the toolkit performs, and it also competes for the target's CPU and page cache. The device worker throttles itself (nice 19 + inter-chunk pacing, default 2 ms) but does not make the read pattern invisible. Prefer narrow ranges or module:/stack presets over all_readable when the target matters.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "kind": {"type": "string", "description": "'value' or 'hex'"},
                "type": {"type": "string", "description": "for value scans: u8..u64/i8..i64/f32/f64"},
                "value": {"type": "number", "description": "for value scans"},
                "pattern": {"type": "string", "description": "for hex scans: '7F 45 4C 46 ??'"},
                "epsilon": {"type": "number"},
                "alignment": {"type": "integer"},
            },
            ["pid", "kind"],
        ),
    },
    {
        "name": "scan_cancel",
        "description": "Request cancellation of a running scan job (the engine stops between chunks; job state becomes cancelled).",
        "inputSchema": _obj({"pid": {"type": "integer"}, "job_id": {"type": "string"}}, ["pid", "job_id"]),
    },
    {
        "name": "scan_status",
        "description": "Poll a background scan job (or list recent jobs): state running/done/error, progress bytes, summary+results when done.",
        "inputSchema": _obj({"pid": {"type": "integer"}, "job_id": {"type": "string"}}, ["pid"]),
    },
    {
        "name": "symbol_list",
        "description": "List dynamic symbols (dynsym) of a mapped module read from live memory: name, absolute address, size, type, bind. fields=names_only trims rows to {name,address} for large modules.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "limit": {"type": "integer"},
                "filter": {"type": "string", "description": "case-insensitive substring on symbol name"},
                "fields": {"type": "string", "description": "full (default) | names_only", "enum": ["full", "names_only"]},
            },
            ["pid", "module"],
        ),
    },
    {
        "name": "symbol_find",
        "description": "Exact symbol name lookup across one module (module=<name>) or all executable modules; returns absolute address for read/scan use.",
        "inputSchema": _obj(
            {"pid": {"type": "integer"}, "name": {"type": "string"}, "module": {"type": "string"}},
            ["pid", "name"],
        ),
    },
    {
        "name": "scan_set_default_ranges",
        "description": "Set scan ranges: preset 'anon' (readable anonymous/heap, default), 'stack', 'module:<name>', or 'all_readable' (EVERY readable file mapping incl. ART boot images — huge; scope deliberately). Response reports the actual selected segments/bytes/classes (F6).",
        "inputSchema": _obj(
            {"pid": {"type": "integer"}, "preset": {"type": "string", "description": "anon | stack | module:<name> | all_readable"}},
            ["pid"],
        ),
    },
    {
        "name": "scan_value",
        "description": "First scan: find all occurrences of a typed value in the scan ranges. ALWAYS reports what it scanned: range_source (explicit/preset/inherited/default), scan_bytes, scan_segments, effective_ranges. `inherited` means this call did not choose the scope — it merely failed to change one set earlier, which is the shape of a real incident where a stale all_readable preset made a scan read 5.88 GB and killed the target. A scope above 256 MB is refused unless allow_large=true.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "type": {"type": "string", "description": "u8..u64/i8..i64/f32/f64"},
                "value": {"type": "number"},
                "epsilon": {"type": "number", "description": "float tolerance"},
                "alignment": {"type": "integer"},
                "allow_large": {"type": "boolean", "description": "proceed even when the scope exceeds the 256 MB confirmation limit (default false)"},
            },
            ["pid", "type", "value"],
        ),
    },
    {
        "name": "scan_hex",
        "description": "First scan: AOB pattern like '7F 45 4C 46 ??'. ALWAYS reports what it scanned: range_source (explicit/preset/inherited/default), scan_bytes, scan_segments, effective_ranges. `inherited` means this call did not choose the scope — it merely failed to change one set earlier, which is the shape of a real incident where a stale all_readable preset made a scan read 5.88 GB and killed the target. A scope above 256 MB is refused unless allow_large=true.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "pattern": {"type": "string"},
                "allow_large": {"type": "boolean", "description": "proceed even when the scope exceeds the 256 MB confirmation limit (default false)"},
            },
            ["pid", "pattern"],
        ),
    },
    {
        "name": "scan_next",
        "description": "Refine the previous scan: mode eq/neq/changed/unchanged/increased/decreased against the new value.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "mode": {"type": "string"},
                "value": {"type": "number"},
                "epsilon": {"type": "number"},
            },
            ["pid", "mode"],
        ),
    },
    {
        "name": "scan_results",
        "description": "Get current scan hits (paged).",
        "inputSchema": _obj(
            {"pid": {"type": "integer"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
            ["pid"],
        ),
    },
    {
        "name": "scan_clear",
        "description": "Clear scan state for a process.",
        "inputSchema": _obj({"pid": {"type": "integer"}}, ["pid"]),
    },
    {
        "name": "diff_module",
        "description": "Compare a module's LIVE memory against its on-disk file and list the differing ranges. THIS IS THE ONLY WAY TO SEE RUNTIME PATCHING: inline hooks, detours and self-modifying code exist only in memory, so static analysis on the .so can never reveal them. A non-zero total_diff_bytes means the executing image is not the file you analysed. Returns both byte strings per range so you can triage without re-dumping. For large modules pass range_lo/range_hi or chunk_bytes+next_offset: a single full pass over a 40 MB code segment is slow and may outlive the target.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "local_path": {"type": "string", "description": "on-disk .so to compare against (defaults to the path in the target's maps)"},
                "max_ranges": {"type": "integer", "description": "cap on reported ranges (default 256)"},
                "exec_only": {"type": "boolean", "description": "compare only executable segments (default true). Set false to hunt data patches — expect noise from initialised globals."},
                "range_lo": {"type": "string", "description": "ELF vaddr (0x hex, IDA-style) lower bound for a partial comparison"},
                "range_hi": {"type": "string", "description": "ELF vaddr upper bound for a partial comparison"},
                "chunk_bytes": {"type": "integer", "description": "compare at most this many bytes per call and return next_offset, so a large module can be walked across several calls (use this when the target may not survive a full pass)"},
                "next_offset": {"type": "string", "description": "resume cursor returned by a previous chunked call"},
            },
            ["pid", "module"],
        ),
    },
    {
        "name": "dump_module",
        "description": "Reconstruct a mapped module into a host-side file with a manifest.json (ELF-ish image; anonymous mappings optional).",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "out": {"type": "string", "description": "host output file path"},
                "include_anonymous": {"type": "boolean"},
            },
            ["pid", "module", "out"],
        ),
    },
    {
        "name": "call_export",
        "description": "RISK: controlled in-process call of an allowlisted export function on the LIVE target (ptrace attach is observable by anti-cheat — detection/ban risk borne by the operator; every attempt is audited device-side). DISABLED unless serve was started with TANYAO_ALLOW_CALL=1. Args: up to 8 u64 values (x0-x7). This is an explicitly authorised live-target operation.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string", "description": "module basename, e.g. libil2cpp.so"},
                "symbol": {"type": "string", "description": "export symbol (must be in the device allowlist)"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "up to 8 u64 args (0x hex or decimal), mapped to x0-x7"},
                "ret_type": {"type": "string", "description": "u64 (default) | f64 | void", "enum": ["u64", "f64", "void"]},
                "probe_ret": {"type": "boolean", "description": "device probes 1 byte at the return value first; response carries ret_readable"},
            },
            ["pid", "module", "symbol"],
        ),
    },
    {
        "name": "resolve_vaddr",
        "description": "Translate ANY ELF vaddr (including NOBITS .bss) to a live runtime address. This is the assumption-free entry point for address math — prefer it over arithmetic on load_bias/bss. Handles .bss (a separate [anon:.bss] mapping, not covered by any PT_LOAD), multi-bias modules, and mirror segments. 'method' reports the evidence used (anon_bss_mapping / segment_mapping / arithmetic); 'readable' proves the result by a 1-byte read, so an uncorroborated arithmetic fallback is visible rather than silently wrong.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string", "description": "module basename as in list_modules, e.g. libGameCore.so"},
                "vaddr": {"type": "string", "description": "ELF virtual address (0x hex), as shown by readelf -S"},
            },
            ["pid", "module", "vaddr"],
        ),
    },
    {
        "name": "resolve_symbol_ref",
        "description": "Find the code that materialises an address (the INVERSE of resolve_vaddr): scans the module's executable segments for ADRP / ADRP+ADD / ADR sequences whose decoded target equals it. 'target' accepts three forms: an explicit ELF vaddr ('0x542d920'), an IDA-style name with the hex suffix ('qword_542D920'), or a string constant ('AiLocalBuffer init done' — located in the module first). Every hit carries its machine code and 'crosscheck_vs_resolve_vaddr' (match/MISMATCH), so the two independent paths verify each other. Use this to answer 'who references this variable/string' without manual ADRP decoding.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "target": {"type": "string", "description": "0x vaddr, <name>_<hex> symbol, or a string constant present in the module"},
                "max_hits": {"type": "integer", "description": "cap on returned references (default 32)"},
            },
            ["pid", "module", "target"],
        ),
    },
    {
        "name": "resolve_rva",
        "description": "Resolve a FILE OFFSET to a runtime address, or convert a file-backed vaddr to a file offset. Give exactly ONE of file_offset (the tool-face convention: address_resolve/disassemble 'rva' fields and dump manifests are FILE OFFSETS) or rva (ELF vaddr flavour, converted through live phdrs). Do NOT pass a .bss vaddr here: NOBITS bytes consume no file space and have no file offset — the call fails with a bad_request that points at resolve_vaddr. For any vaddr→runtime conversion prefer resolve_vaddr.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "rva": {"type": "string", "description": "0x hex, vaddr flavour (live-phdr conversion)"},
                "file_offset": {"type": "string", "description": "0x hex, file offset flavour (direct)"},
            },
            ["pid", "module"],
        ),
    },
    {
        "name": "watch_many",
        "description": "Sample MULTIPLE memory spans on one schedule (batched via MEM_READV): per-span sample arrays shaped like watch's. Prefer this over N parallel watch calls.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "spans": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"address": {"type": "string"}, "size": {"type": "integer"}}, "required": ["address", "size"]},
                    "description": "spans to sample, e.g. [{address:'0x..', size:16}]",
                },
                "interval_ms": {"type": "integer", "description": "sampling interval (default 200)"},
                "count": {"type": "integer", "description": "samples per span (default 10, max 256)"},
                "changes_only": {"type": "boolean", "description": "record only samples that changed. A run that drops ticks returns fewer samples than count BY DESIGN — the response carries count_requested, samples_returned and stopped_reason so 'nothing moved' is distinguishable from 'only got one sample'"},
                "mirror_samples": {"type": "boolean", "description": "also return a top-level `samples` array mirroring watch()'s shape (default true). It is the same data as spans[].samples; set false for large captures to avoid doubling the payload"},
            },
            ["pid", "spans"],
        ),
    },
    {
        "name": "pointers_to",
        "description": "Find pointers TO an address: scans the selected region for 8-byte little-endian values equal to each target. strip_pac (default true) masks the top two bytes so PAC-tagged pointers match. Region: module=<basename> / preset / ranges[]; falls back to the pid's last scan preset (default anon). Uses the scan job slot (a running device scan is cancelled).",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "address": {"type": "string", "description": "target address, 0x hex"},
                "addresses": {"type": "array", "items": {"type": "string"}, "description": "up to 64 target addresses (0x hex) — alternative to address"},
                "module": {"type": "string", "description": "scan region = this module's readable mappings"},
                "preset": {"type": "string", "description": "anon | stack | module:<name> | all_readable"},
                "ranges": {"type": "array", "items": {"type": "object", "properties": {"start": {"type": "string"}, "end": {"type": "string"}}, "required": ["start", "end"]}, "description": "explicit ranges [{start,end}] (0x hex)"},
                "strip_pac": {"type": "boolean", "description": "wildcard top two bytes of the pattern (default true)"},
                "limit": {"type": "integer", "description": "max pointer locations per target (default 256)"},
            },
            ["pid"],
        ),
    },
    {
        "name": "watch",
        "description": "Sample a memory range repeatedly; reports per-sample hex and changed flags.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "address": {"type": "string"},
                "size": {"type": "integer"},
                "interval_ms": {"type": "integer"},
                "count": {"type": "integer"},
                "changes_only": {"type": "boolean"},
            },
            ["pid", "address", "size"],
        ),
    },
    {
        "name": "disassemble",
        "description": "Disassemble live A64 instructions at an address. Engine: capstone (full ISA, default when installed) or built-in subset fallback. The self-reported 'rva' is the AUTHORITATIVE runtime↔file-offset reference (mapping-table method; address == bearing_segment.translation_base + rva) — prefer it over resolve_module.load_bias arithmetic, which can be null/ambiguous on mirror or multi-bias modules. Use dump_module + decompile_start (IDA) for full-fidelity analysis.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "address": {"type": "string", "description": "0x hex address inside the module"},
                "count": {"type": "integer", "description": "instruction count (default 48, max 4096)"},
                "module": {"type": "string", "description": "optional module name"},
                "engine": {"type": "string", "description": "auto (default) | capstone | subset"},
            },
            ["pid", "address"],
        ),
    },
    {
        "name": "strings",
        "description": "Extract printable-ASCII strings from a module's readable segments (chunked, fault-tolerant) or an explicit address window. Optional regex filter. Rows carry {address (0x hex), length, value} — NOT a decimal offset. For large modules (device rejects sync scans over 256MiB) use async=true and poll scan_status/scan_results (kind=strings).",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string", "description": "module name (module mode)"},
                "address": {"type": "string", "description": "0x hex start (window mode; requires size)"},
                "size": {"type": "integer", "description": "window size in bytes (window mode, max 16MB)"},
                "min_length": {"type": "integer", "description": "minimum string length (default 4)"},
                "limit": {"type": "integer", "description": "max strings returned (default 200)"},
                "filter": {"type": "string", "description": "regex filter on string values"},
                "async": {"type": "boolean", "description": "run as a device-side job: returns job_id immediately; poll scan_status (kind=strings) and scan_results (default false)"},
            },
            ["pid"],
        ),
    },
    {
        "name": "pull_apk",
        "description": "Pull the APK file backing the target pid to a host path (uses host adb).",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "out": {"type": "string", "description": "host output file path"},
            },
            ["pid", "out"],
        ),
    },
    {
        "name": "apk_info",
        "description": "APK metadata. Give exactly ONE of: apk_path (host file, local AXML parse) or pid (device resolves the APK backing that process via the agent, zero-copy; requires agent APK_INFO capability). Returns package, versions, activities, launcher entry, permissions.",
        "inputSchema": _obj(
            {
                "apk_path": {"type": "string", "description": "host path to the .apk file"},
                "pid": {"type": "integer", "description": "resolve the APK of this device process (zero-mirror; agent capability dependent)"},
            },
            [],
        ),
    },
    {
        "name": "decompile_start",
        "description": "Dump a module and decompile it with IDA Pro (idalib + Hex-Rays): dumps the live image, loads it in-process and emits one .c per function plus index.json. Long-running: returns job_id; poll decompile_status. Modules >64MB get an entropy pre-flight — mostly-encrypted images are rejected unless force=true. Requires IDA Pro with idalib (TANYAO_IDA_DIR, default /home/ufo/ida-pro-9.4); if absent the call returns a structured 'unavailable', so still usable targets are never blocked by a missing decompiler.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "out_dir": {"type": "string", "description": "host output dir (default /tmp/tanyao-decomp/<module>-<pid>)"},
                "max_functions": {"type": "integer", "description": "cap on decompiled functions (default 2000)"},
                "force": {"type": "boolean", "description": "proceed past the high-entropy warning (default false)"},
            },
            ["pid", "module"],
        ),
    },
    {
        "name": "decompile_status",
        "description": "Poll a decompile job: state (running/done/error), function list with entrypoints and .c file names.",
        "inputSchema": _obj(
            {"pid": {"type": "integer"}, "job_id": {"type": "string"}},
            ["pid", "job_id"],
        ),
    },
]


def _tool_to_ipc_name(name: str) -> str:
    return name  # 1:1 mapping by design


def handle_request(message: dict) -> dict | None:
    """Handle one JSON-RPC request/notification. Returns a response dict or None."""
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized" or method.startswith("notifications/"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        ipc = _ipc_call(_tool_to_ipc_name(name), args)
        if ipc.get("ok"):
            text = json.dumps(ipc.get("result"), ensure_ascii=False, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        err_body = {"error": ipc.get("error"), "errno": ipc.get("errno"), "detail": ipc.get("detail")}
        if ipc.get("old_b64"):
            err_body["old_b64"] = ipc.get("old_b64")  # D5: device old bytes for diffing
        text = json.dumps(err_body, ensure_ascii=False)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        }
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }
    return None


def serve() -> None:
    """Blocking stdio loop: newline-delimited JSON-RPC in, single-line JSON out."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_request(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve()
