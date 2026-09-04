"""HTTP IPC server (127.0.0.1:28101, MiniMem-style hardening) + JSON-RPC method table.

Security constraints (from AndroidMiniMem docs, adapted):
- bind loopback only
- require POST, Content-Type: application/json
- exactly one Content-Length header, no Transfer-Encoding
- reject requests with an Origin header (browser CORS surface)
- small request body cap (1 MiB)
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .analysis import AnalysisFacade
from .connection import AgentError
from .constants import undeclared_agent_caps
from .service import AgentUnavailable

MAX_BODY = 1 << 20
IPC_PORT = 28101


def build_method_table(facade: AnalysisFacade) -> dict:
    """method name -> callable(payload dict) -> JSON-serializable dict.
    This table is the ONLY place IPC and MCP surfaces diverge (MCP wraps these)."""

    def _backend_dict(service) -> dict:
        info = service.backend_info()
        return {
            "name": info.name,
            "abi_major": info.abi_major,
            "abi_minor": info.abi_minor,
            "capabilities": hex(info.capabilities),
            "page_size": info.page_size,
            "pointer_bits": info.pointer_bits,
            "max_transfer_size": info.max_transfer_size,
            "max_iov": info.max_iov,
            "backend_flags": hex(info.backend_flags),
        }

    def need_pid(payload: dict) -> int:
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise AgentError("bad_request", detail="integer 'pid' required")
        return pid

    def parse_addr(payload: dict, key: str = "address") -> int:
        raw = payload.get(key)
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str) and raw.lower().startswith("0x"):
            return int(raw, 16)
        raise AgentError("bad_request", detail=f"'{key}' must be 0x hex string or int")

    def get_status(_payload: dict) -> dict:
        caps = facade.service.agent_capabilities()
        return {
            "connected": facade.service.is_connected(),
            "generation": facade.service.generation(),
            "backend": _backend_dict(facade.service),
            "write_enabled": facade._write_enabled,
            "agent_capabilities": hex(caps),
            "skipped_caps": undeclared_agent_caps(caps),
        }

    methods = {
        "get_status": get_status,
        "ping_agent": lambda p: facade.service.ping(),
        "connect": lambda p: {"backend": facade.service.connect().name},
        "find_process": lambda p: facade.find_process(str(p["name"])),
        "list_processes": lambda p: {"pids": facade.service.process_list(int(p.get("bytes", 8192)))},
        "process_alive": lambda p: {"alive": facade.service.process_alive(need_pid(p))},
        "list_modules": lambda p: facade.list_modules(need_pid(p), p.get("filter")),
        "get_module_base": lambda p: {
            "base": hex(facade.service.module_base(need_pid(p), str(p["name"])))
        },
        "resolve_module": lambda p: facade.resolve_module(need_pid(p), str(p["name"])),
        "address_resolve": lambda p: facade.address_resolve(need_pid(p), parse_addr(p)),
        "read_memory": lambda p: facade.read_memory(
            need_pid(p),
            parse_addr(p),
            int(p.get("size", 16)),
            as_type=p.get("as_type"),
            count=int(p.get("count", 1)),
        ),
        "write_bytes": lambda p: facade.write_bytes(
            need_pid(p),
            parse_addr(p),
            bytes.fromhex(str(p["data_hex"]).replace(" ", "")),
            expect_old=bytes.fromhex(p["expect_old_hex"].replace(" ", "")) if p.get("expect_old_hex") else None,
        ),
        "resolve_offset_chain": lambda p: facade.resolve_offset_chain(
            need_pid(p),
            parse_addr(p, "start"),
            [int(o, 16) if isinstance(o, str) else int(o) for o in p.get("offsets", [])],
            vtype=p.get("vtype", "u64"),
            strip_pac=bool(p.get("strip_pac", True)),
            pointer_mask=int(p["pointer_mask"], 16) if isinstance(p.get("pointer_mask"), str) else p.get("pointer_mask"),
        ),
        "watch": lambda p: facade.watch(
            need_pid(p),
            parse_addr(p),
            int(p.get("size", 16)),
            interval_ms=int(p.get("interval_ms", 200)),
            count=int(p.get("count", 10)),
            changes_only=bool(p.get("changes_only", False)),
        ),
        "scan_set_default_ranges": lambda p: facade.scan_set_default_ranges(
            need_pid(p), preset=str(p.get("preset", "anon"))
        ),
        "scan_set_range": lambda p: facade.scan_set_range(
            need_pid(p), parse_addr(p, "start"), parse_addr(p, "end")
        ),
        "scan_value": lambda p: facade.scan_value(
            need_pid(p),
            str(p.get("type", "u32")),
            float(p["value"]) if isinstance(p["value"], float) else int(p["value"]),
            epsilon=float(p.get("epsilon", 0.0)),
            alignment=int(p["alignment"]) if p.get("alignment") else None,
            async_run=bool(p.get("async", False)),
        ),
        "scan_hex": lambda p: facade.scan_hex(
            need_pid(p), str(p["pattern"]), async_run=bool(p.get("async", False))
        ),
        "scan_start": lambda p: facade.scan_start(
            need_pid(p),
            str(p.get("kind", "value")),
            type=p.get("type"),
            value=p.get("value"),
            pattern=p.get("pattern"),
            epsilon=float(p.get("epsilon", 0.0)),
            alignment=int(p["alignment"]) if p.get("alignment") else None,
        ),
        "scan_cancel": lambda p: facade.scan_cancel(
            need_pid(p), str(p["job_id"])
        ),
        "scan_status": lambda p: facade.scan_status(
            need_pid(p), str(p["job_id"]) if p.get("job_id") else None
        ),
        "scan_next": lambda p: facade.scan_next(
            need_pid(p),
            str(p["mode"]),
            (float(p["value"]) if isinstance(p.get("value"), float) else int(p["value"])) if p.get("value") is not None else None,
            epsilon=float(p.get("epsilon", 0.0)),
        ),
        "scan_results": lambda p: facade.scan_results(
            need_pid(p), offset=int(p.get("offset", 0)), limit=int(p.get("limit", 256))
        ),
        "scan_clear": lambda p: facade.scan_clear(need_pid(p)),
        "read_batch": lambda p: facade.read_batch(
            need_pid(p),
            p.get("spans", []),
        ),
        "symbol_list": lambda p: facade.symbol_list(
            need_pid(p), str(p["module"]),
            limit=int(p.get("limit", 512)),
            filter=p.get("filter"),
        ),
        "symbol_find": lambda p: facade.symbol_find(
            need_pid(p), str(p["name"]),
            module=str(p["module"]) if p.get("module") else None,
        ),
        "disassemble": lambda p: facade.disassemble(
            need_pid(p),
            parse_addr(p),
            count=int(p.get("count", 48)),
            module=str(p["module"]) if p.get("module") else None,
            engine=str(p.get("engine", "auto")),
        ),
        "strings": lambda p: facade.strings(
            need_pid(p),
            module=str(p["module"]) if p.get("module") else None,
            address=parse_addr(p) if p.get("address") else None,
            size=int(p["size"]) if p.get("size") else None,
            min_length=int(p.get("min_length", 4)),
            limit=int(p.get("limit", 200)),
            filter=p.get("filter"),
        ),
        "pull_apk": lambda p: facade.pull_apk(
            need_pid(p), str(p["out"]),
        ),
        "apk_info": lambda p: facade.apk_info(
            str(p["apk_path"]) if p.get("apk_path") else None,
            pid=int(p["pid"]) if p.get("pid") else None,
        ),
        "decompile_start": lambda p: facade.decompile_start(
            need_pid(p),
            str(p["module"]),
            out_dir=str(p["out_dir"]) if p.get("out_dir") else None,
            max_functions=int(p.get("max_functions", 2000)),
        ),
        "decompile_status": lambda p: facade.decompile_status(
            need_pid(p), str(p["job_id"]),
        ),
        "dump_module": lambda p: facade.dump_module(
            need_pid(p), str(p["module"]), str(p["out"]),
            include_anonymous=bool(p.get("include_anonymous", False)),
        ),
    }
    return methods


class IpcRequestHandler(BaseHTTPRequestHandler):
    methods: dict = {}
    server_version = "tanyao-ipc/0.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def do_POST(self):  # noqa: N802
        try:
            if self.headers.get("Origin"):
                self._reject(403, "origin_not_allowed")
                return
            if self.headers.get("Transfer-Encoding"):
                self._reject(400, "transfer_encoding_not_allowed")
                return
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1 or not lengths[0].isdigit():
                self._reject(400, "bad_content_length")
                return
            if int(lengths[0]) > MAX_BODY:
                self._reject(413, "body_too_large")
                return
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                self._reject(415, "json_only")
                return
            body = self.rfile.read(int(lengths[0]))
            req = json.loads(body.decode("utf-8"))
            method = req.get("method")
            params = req.get("params") or {}
            if not isinstance(method, str) or not isinstance(params, dict):
                self._reject(400, "bad_request_shape")
                return
            handler = self.methods.get(method)
            if handler is None:
                self._reply(404, {"ok": False, "error": "unknown_method", "method": method})
                return
            try:
                result = handler(params)
                self._reply(200, {"ok": True, "result": result})
            except AgentError as exc:
                body = {"ok": False, "error": exc.error, "errno": exc.errno, "detail": exc.detail}
                if exc.payload.get("old_b64"):
                    # D5: keep the device-attached old bytes so callers can diff
                    body["old_b64"] = exc.payload["old_b64"]
                self._reply(200, body)
            except (KeyError, ValueError) as exc:
                self._reply(200, {"ok": False, "error": "bad_request", "detail": str(exc)})
            except AgentUnavailable as exc:
                self._reply(200, {"ok": False, "error": "agent_unavailable", "detail": str(exc)})
        except Exception as exc:  # noqa: BLE001
            try:
                self._reply(500, {"ok": False, "error": "internal", "detail": str(exc)})
            except Exception:
                pass

    def _reply(self, code: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _reject(self, code: int, error: str) -> None:
        self._reply(code, {"ok": False, "error": error})


class IpcServer:
    def __init__(self, facade: AnalysisFacade, port: int = IPC_PORT) -> None:
        handler = type("BoundHandler", (IpcRequestHandler,), {"methods": build_method_table(facade)})
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="tanyao-ipc")
        self.port = port

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
