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
        "description": "Get backend/connection status: connected, agent generation, backend capabilities, whether memory write is enabled.",
        "inputSchema": _obj({}),
    },
    {
        "name": "find_process",
        "description": "Find a process PID by exact name on the device.",
        "inputSchema": _obj({"name": {"type": "string", "description": "exact process name"}}, ["name"]),
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
        "description": "Resolve a mapped module's ELF semantics: first mapping, load bias, BSS bounds, mirror detection.",
        "inputSchema": _obj({"pid": {"type": "integer"}, "name": {"type": "string"}}, ["pid", "name"]),
    },
    {
        "name": "address_resolve",
        "description": "Resolve which module/mapping contains an address; returns module offset and RVA.",
        "inputSchema": _obj({"pid": {"type": "integer"}, "address": {"type": "string", "description": "0x hex address"}}, ["pid", "address"]),
    },
    {
        "name": "read_memory",
        "description": "Read process memory. Returns hex data; with as_type decodes typed values (u8..u64, i8..i64, f32, f64).",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "address": {"type": "string"},
                "size": {"type": "integer", "description": "byte count for raw read"},
                "as_type": {"type": "string", "description": "typed read: u32/u64/f32/f64/ptr ..."},
                "count": {"type": "integer", "description": "array element count for typed read"},
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
                    "items": {"type": "object", "properties": {"address": {"type": "string"}, "size": {"type": "integer"}}, "required": ["address", "size"]},
                    "description": "up to max_iov spans per call",
                },
            },
            ["pid", "spans"],
        ),
    },
    {
        "name": "scan_start",
        "description": "Start a first scan as a background job (recommended for large ranges): returns job_id; poll with scan_status.",
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
        "description": "List dynamic symbols (dynsym) of a mapped module read from live memory: name, absolute address, size, type, bind.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "limit": {"type": "integer"},
                "filter": {"type": "string", "description": "case-insensitive substring on symbol name"},
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
        "description": "Set scan ranges: preset 'anon' (readable anonymous/heap, default), 'stack', 'module:<name>', or 'all_readable'.",
        "inputSchema": _obj(
            {"pid": {"type": "integer"}, "preset": {"type": "string", "description": "anon | stack | module:<name> | all_readable"}},
            ["pid"],
        ),
    },
    {
        "name": "scan_value",
        "description": "First scan: find all occurrences of a typed value in the scan ranges.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "type": {"type": "string", "description": "u8..u64/i8..i64/f32/f64"},
                "value": {"type": "number"},
                "epsilon": {"type": "number", "description": "float tolerance"},
                "alignment": {"type": "integer"},
            },
            ["pid", "type", "value"],
        ),
    },
    {
        "name": "scan_hex",
        "description": "First scan: AOB pattern like '7F 45 4C 46 ??'.",
        "inputSchema": _obj({"pid": {"type": "integer"}, "pattern": {"type": "string"}}, ["pid", "pattern"]),
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
        "description": "Disassemble live A64 instructions at an address. Engine: capstone (full ISA, default when installed) or built-in subset fallback. Use dump_module + decompile/Ghidra for full-fidelity analysis.",
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
        "description": "Extract printable-ASCII strings from a module's readable segments (chunked, fault-tolerant) or an explicit address window. Optional regex filter.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string", "description": "module name (module mode)"},
                "address": {"type": "string", "description": "0x hex start (window mode; requires size)"},
                "size": {"type": "integer", "description": "window size in bytes (window mode, max 16MB)"},
                "min_length": {"type": "integer", "description": "minimum string length (default 4)"},
                "limit": {"type": "integer", "description": "max strings returned (default 200)"},
                "filter": {"type": "string", "description": "regex filter on string values"},
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
        "description": "Dump a module, import into headless Ghidra, auto-analyze and decompile all functions to C sources (+ index.json). Long-running: returns job_id; poll decompile_status. Requires Ghidra at /opt/ghidra.",
        "inputSchema": _obj(
            {
                "pid": {"type": "integer"},
                "module": {"type": "string"},
                "out_dir": {"type": "string", "description": "host output dir (default /tmp/tanyao-decomp/<module>-<pid>)"},
                "max_functions": {"type": "integer", "description": "cap on decompiled functions (default 2000)"},
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
        text = json.dumps(
            {"error": ipc.get("error"), "errno": ipc.get("errno"), "detail": ipc.get("detail")},
            ensure_ascii=False,
        )
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
