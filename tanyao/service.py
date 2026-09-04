"""TanyaoService: the single source of truth for agent interaction.

Higher layers (HTTP IPC, MCP, GUI) must all go through this class.
Owns connection lifecycle, reconnect with generation tracking, handle/cookie
caching, and chunked read/write. Implements PROTOCOL.md ops as typed methods.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .constants import (
    AGENT_CAP_SCAN,
    CMD_APK_INFO,
    CMD_BACKEND_INFO,
    CMD_DISASSEMBLE,
    CMD_DUMP_CLEANUP,
    CMD_DUMP_PULL,
    CMD_DUMP_START,
    CMD_DUMP_STATUS,
    CMD_MEM_READ,
    CMD_MEM_READV,
    CMD_MEM_WRITE,
    CMD_MODULE_BASE,
    CMD_PING,
    CMD_PROCESS_ALIVE,
    CMD_PROCESS_FIND,
    CMD_PROCESS_LIST,
    CMD_SCAN_CANCEL,
    CMD_SCAN_CLEAR,
    CMD_SCAN_RESULTS,
    CMD_SCAN_REFINE,
    CMD_SCAN_START,
    CMD_SCAN_STATUS,
    CMD_SESSION_INFO,
    CMD_STRINGS_SCAN,
    CMD_SYMBOL_BATCH,
    CMD_TARGET_CLOSE,
    CMD_TARGET_MAPS,
    CMD_TARGET_OPEN,
    CMD_WRITE_TXN,
    DEFAULT_PORT,
    ProtocolError,
    b64_decode,
    b64_encode,
    hex_u64,
    parse_u64,
)
from .connection import AgentConnection, AgentError
from .frames import Frame, decode_dump_chunk, decode_packed_symbols

# Protocol v1 returns bytes as base64 inside a 16MiB JSON payload. A 4MiB raw
# ceiling leaves room for base64 expansion and JSON metadata while keeping
# single-span read/write requests portable across agent implementations.
MAX_TRANSFER_FALLBACK = 4 * 1024 * 1024


@dataclass(slots=True)
class BackendInfo:
    abi_major: int
    abi_minor: int
    capabilities: int
    page_size: int
    pointer_bits: int
    max_transfer_size: int
    max_iov: int
    backend_flags: int
    name: str


@dataclass(slots=True)
class MapEntry:
    start: int
    end: int
    file_offset: int
    flags: int
    path: str

    @property
    def size(self) -> int:
        return self.end - self.start

    def flags_str(self) -> str:
        text = ""
        text += "r" if self.flags & 1 else "-"
        text += "w" if self.flags & 2 else "-"
        text += "x" if self.flags & 4 else "-"
        text += "p" if self.flags & 8 else ("s" if self.flags & 16 else "-")
        return text


@dataclass(slots=True)
class TargetSession:
    pid: int
    handle: int
    start_cookie: int
    opened_at: float = field(default_factory=time.monotonic)


class AgentUnavailable(Exception):
    """Agent connection cannot be established or died mid-request."""


class TanyaoService:
    """Thread-safe facade over one agent connection."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        token: str | None = None,
        *,
        auto_reconnect: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._token = token
        self._auto_reconnect = auto_reconnect
        self._lock = threading.RLock()
        self._conn: AgentConnection | None = None
        self._backend: BackendInfo | None = None
        self._targets: dict[int, TargetSession] = {}

    # -- connection management -------------------------------------------------

    def connect(self) -> BackendInfo:
        with self._lock:
            if self._conn is not None and self._conn.is_connected:
                return self._backend  # type: ignore[return-value]
            self._drop_connection()
            conn = AgentConnection(self._host, self._port, self._token)
            try:
                conn.connect()
                info_payload = conn.request(CMD_BACKEND_INFO, {})
            except (OSError, TimeoutError, AgentError) as exc:
                raise AgentUnavailable(f"cannot reach agent at {self._host}:{self._port}: {exc}") from exc
            self._conn = conn
            self._backend = BackendInfo(
                abi_major=int(info_payload["abi_major"]),
                abi_minor=int(info_payload["abi_minor"]),
                capabilities=parse_u64(info_payload["capabilities"], field="capabilities"),
                page_size=int(info_payload["page_size"]),
                pointer_bits=int(info_payload["pointer_bits"]),
                max_transfer_size=parse_u64(info_payload["max_transfer_size"], field="max_transfer_size"),
                max_iov=int(info_payload["max_iov"]),
                backend_flags=parse_u64(info_payload["backend_flags"], field="backend_flags"),
                name=str(info_payload.get("name", "")),
            )
            self._targets.clear()
            return self._backend

    def _drop_connection(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
        self._targets.clear()

    def close(self) -> None:
        with self._lock:
            self._drop_connection()

    def is_connected(self) -> bool:
        with self._lock:
            return self._conn is not None and self._conn.is_connected

    def generation(self) -> int | None:
        with self._lock:
            return self._conn.generation if self._conn else None

    def _execute_frame(self, cmd: int, payload: dict) -> Frame:
        """Run one RPC with reconnect-once semantics, returning the raw Frame
        (binary-payload ops use this). Caller must hold lock (or accept races)."""
        if self._conn is None:
            if not self._auto_reconnect:
                raise AgentUnavailable("not connected")
            self.connect()
        assert self._conn is not None
        old_generation = self._conn.generation
        try:
            return self._conn.request_raw(cmd, payload)
        except (ConnectionError, TimeoutError, OSError) as exc:
            # transport-level failure: drop and optionally retry once
            self._drop_connection()
            if not self._auto_reconnect:
                raise AgentUnavailable(f"agent connection lost: {exc}") from exc
            self.connect()
            assert self._conn is not None
            if self._conn.generation != old_generation:
                # agent restarted; handles/cookies are gone, sessions rebuilt on demand
                self._targets.clear()
            try:
                return self._conn.request_raw(cmd, payload)
            except (ConnectionError, TimeoutError, OSError) as exc2:
                self._drop_connection()
                raise AgentUnavailable(f"agent connection lost twice: {exc2}") from exc2
        except AgentError as exc:
            if exc.error == "auth_failed":
                self._drop_connection()
            raise
        except ProtocolError as exc:
            # A framing/handshake violation leaves the stream untrustworthy:
            # drop the socket so the next call reconnects cleanly instead of
            # parsing garbage from a desynced buffer.
            self._drop_connection()
            raise AgentError("protocol_error", detail=str(exc)) from exc

    def _execute(self, cmd: int, payload: dict) -> dict:
        """JSON-op variant of _execute_frame."""
        frame = self._execute_frame(cmd, payload)
        if isinstance(frame.payload, bytes):
            raise AgentError("protocol_error", detail=f"cmd {cmd}: unexpected binary payload")
        return frame.payload

    def _require_handle(self, pid: int) -> TargetSession:
        """Get or reopen the target session for pid.

        Kernel rule (transport_anon.c): ONE open target per agent session.
        Opening a different pid while another target is held returns EBUSY.
        Host policy: single-active-target — close the currently held target
        before opening a new one, and on EBUSY close-then-retry once (recovers
        slots leaked by pre-fix agents or stale kernel state).
        """
        session = self._targets.get(pid)
        if session is not None:
            return session
        info = self._backend or self.connect()
        if not info.capabilities & (1 << 1):  # TANYAO_CAP_TARGET_HANDLE
            raise AgentError("backend_error", detail="backend lacks TARGET_HANDLE capability")
        # single-active-target: release any other held target first
        self._release_all_targets()
        try:
            resp = self._execute(
                CMD_TARGET_OPEN,
                {"pid": pid},
            )
        except AgentError as exc:
            if exc.error == "backend_error" and exc.errno == -16:  # EBUSY: slot occupied
                # close-then-retry once (agent restart, leaked slot, etc.)
                self._release_all_targets(force_rpc=True)
                try:
                    resp = self._execute(CMD_TARGET_OPEN, {"pid": pid})
                except AgentError as retry_exc:
                    if retry_exc.error == "backend_error" and retry_exc.errno == -3:
                        raise AgentError("not_found", detail=f"pid {pid} does not exist") from retry_exc
                    raise
            elif exc.error == "backend_error" and exc.errno == -3:  # ESRCH: process gone
                raise AgentError("not_found", detail=f"pid {pid} does not exist") from exc
            raise
        session = TargetSession(
            pid=pid,
            handle=parse_u64(resp["handle"], field="handle"),
            start_cookie=parse_u64(resp["start_cookie"], field="start_cookie"),
        )
        self._targets[pid] = session
        return session

    # -- info -------------------------------------------------------------------

    def backend_info(self) -> BackendInfo:
        with self._lock:
            return self._backend or self.connect()

    # -- agent capability dispatch (v1.1 §7.1 / v1.2 draft §1) -------------------

    def agent_capabilities(self) -> int:
        """Agent-layer capability bitmap from hello. Selection rule (v1.2 §6):
        dispatch reads ONLY this bitmap, never the hello version string."""
        with self._lock:
            if self._conn is None:
                if not self._auto_reconnect:
                    raise AgentUnavailable("not connected")
                self.connect()
            assert self._conn is not None
            return self._conn.agent_capabilities

    def has_agent_cap(self, bit: int) -> bool:
        """bit is an AGENT_CAP_* mask (e.g. AGENT_CAP_SCAN = 1 << 0)."""
        with self._lock:
            return bool(self.agent_capabilities() & bit)

    def ping(self) -> dict:
        with self._lock:
            return self._execute(CMD_PING, {})

    def session_info(self) -> dict:
        with self._lock:
            resp = self._execute(CMD_SESSION_INFO, {})
            return {
                "session_id": parse_u64(resp.get("session_id", "0x0"), field="session_id"),
                "capabilities": parse_u64(resp.get("capabilities", "0x0"), field="capabilities"),
            }

    def _release_all_targets(self, *, force_rpc: bool = False) -> None:
        """Close every held target (single-active-target policy).

        force_rpc: also send TARGET_CLOSE for handles we believe are already
        closed — used after agent restarts where our cache may lag kernel state.
        """
        for other_pid, other in list(self._targets.items()):
            try:
                self._execute(CMD_TARGET_CLOSE, {"handle": hex_u64(other.handle)})
            except AgentError:
                if not force_rpc:
                    pass  # kernel cleans up with fd anyway
            self._targets.pop(other_pid, None)

    def close_target(self, pid: int) -> None:
        """Explicitly close a cached target session (optional; happens implicitly on disconnect)."""
        with self._lock:
            session = self._targets.pop(pid, None)
            if session is None:
                return
            try:
                self._execute(CMD_TARGET_CLOSE, {"handle": hex_u64(session.handle)})
            except AgentError:
                pass  # best-effort; kernel cleans up with the fd anyway

    # -- process/module (legacy ops) ---------------------------------------------

    def process_find(self, name: str) -> int:
        with self._lock:
            resp = self._execute(CMD_PROCESS_FIND, {"name": name})
            return int(resp["pid"])

    def process_list(self, bitmap_bytes: int = 8192) -> list[int]:
        with self._lock:
            resp = self._execute(CMD_PROCESS_LIST, {"bytes": bitmap_bytes})
            return [int(p) for p in resp.get("pids", [])]

    def process_alive(self, pid: int) -> bool:
        """Process liveness, tolerant of the kernel legacy-op quirk (field
        defect D4): kOpIsAlive answers from find_get_pid, which still reports
        pids pinned by our own open target after the process died. The direct
        cmd 42 stays the primary answer (protocol semantics untouched); a TRUE
        is corroborated against the session-independent process table (cmd 41)
        before being reported, with one re-check to absorb fork/listing races."""
        with self._lock:
            resp = self._execute(CMD_PROCESS_ALIVE, {"pid": pid})
            if not bool(resp["alive"]):
                return False
            if pid in self.process_list():
                return True
            time.sleep(0.05)
            return pid in self.process_list()

    def module_base(self, pid: int, name: str) -> int:
        with self._lock:
            resp = self._execute(CMD_MODULE_BASE, {"pid": pid, "name": name})
            return parse_u64(resp["base"], field="base")

    # -- maps ---------------------------------------------------------------------

    def maps_source(self) -> str:
        """Source of the last target_maps snapshot: 'target_maps' or 'proc_maps'."""
        return getattr(self, "_last_maps_source", "target_maps")

    def target_maps(self, pid: int) -> list[MapEntry]:
        with self._lock:
            session = self._require_handle(pid)
            info = self._backend or self.connect()
            capacity = 4096
            if not info.capabilities & (1 << 5):  # TANYAO_CAP_MAPS
                raise AgentError("backend_error", detail="backend lacks MAPS capability")
            resp = self._execute(
                CMD_TARGET_MAPS,
                {"handle": hex_u64(session.handle), "capacity": capacity},
            )
            status = int(resp.get("status", 0))
            if status == -28:  # ENOSPC: snapshot exceeds capacity; ABI says retry with total_count
                total = int(resp.get("total_count", 0))
                if total > capacity:
                    resp = self._execute(
                        CMD_TARGET_MAPS,
                        {"handle": hex_u64(session.handle), "capacity": min(total, 65535)},
                    )
                    status = int(resp.get("status", 0))
            if status != 0:
                total = int(resp.get("total_count", 0))
                raise AgentError(
                    "backend_error",
                    errno=status,
                    detail=(
                        f"target_maps snapshot incomplete (status={status}): process has "
                        f"{total} mappings, kernel snapshot limit is {capacity}. "
                        "Requires agent-side /proc/<pid>/maps fallback (PROC_MAPS op, pending)."
                    ),
                )
            entries = []
            for entry in resp.get("entries", []):
                entries.append(
                    MapEntry(
                        start=parse_u64(entry["start"], field="start"),
                        end=parse_u64(entry["end"], field="end"),
                        file_offset=parse_u64(entry["file_offset"], field="file_offset"),
                        flags=int(entry["flags"]),
                        path=str(entry.get("path", "")),
                    )
                )
            # PROTOCOL.md §4.7: "target_maps" (kernel snapshot) or "proc_maps" (agent fallback)
            self._last_maps_source = str(resp.get("maps_source", "target_maps"))
            return entries

    # -- device-local scan engine (PROTOCOL.md §7, requires AGENT_CAP_SCAN) ------

    def agent_scan_start(
        self,
        pid: int,
        *,
        kind: str,
        type: str | None = None,
        value=None,
        pattern: str | None = None,
        epsilon: float = 0.0,
        alignment: int = 0,
        preset: str | None = "anon",
        module: str = "",
        ranges: list[dict] | None = None,
    ) -> dict:
        """cmd 50: start a device-local scan job (returns immediately).

        ranges (v1.2.1 附录): explicit segments [{"addr","size"}...]; the agent
        must have declared bit9 — the facade routes those scans to the host
        engine otherwise, so this method never sends ranges blindly."""
        with self._lock:
            payload: dict = {
                "pid": pid,
                "kind": kind,
                "epsilon": epsilon,
                "alignment": alignment or 0,
                "module": module or "",
            }
            if ranges:
                payload["ranges"] = ranges  # present → agent ignores preset
            else:
                payload["preset"] = preset or "anon"
            if type:
                payload["type"] = type
            if value is not None:
                payload["value"] = value
            if pattern:
                payload["pattern"] = pattern
            return self._execute(CMD_SCAN_START, payload)

    def agent_scan_status(self, job_id: int | None = None) -> dict:
        """cmd 51: job status; job_id omitted = current job."""
        with self._lock:
            payload = {"job_id": int(job_id)} if job_id is not None else {}
            return self._execute(CMD_SCAN_STATUS, payload)

    def agent_scan_refine(self, mode: str, value=None, *, epsilon: float = 0.0) -> dict:
        """cmd 52: refine current job hits (synchronous)."""
        with self._lock:
            payload: dict = {"mode": mode, "epsilon": epsilon}
            if value is not None:
                payload["value"] = value
            return self._execute(CMD_SCAN_REFINE, payload)

    def agent_scan_results(self, offset: int = 0, limit: int = 256) -> dict:
        """cmd 53: paged hits of the current job."""
        with self._lock:
            return self._execute(CMD_SCAN_RESULTS, {"offset": int(offset), "limit": int(limit)})

    def agent_scan_cancel(self, job_id: int | None = None) -> dict:
        """cmd 54: cancel the running job."""
        with self._lock:
            payload = {"job_id": int(job_id)} if job_id is not None else {}
            return self._execute(CMD_SCAN_CANCEL, payload)

    def agent_scan_clear(self) -> dict:
        """cmd 55: clear results, keep range configuration."""
        with self._lock:
            return self._execute(CMD_SCAN_CLEAR, {})

    # -- symbol batch / strings scan (v1.2 draft §3.1/§3.2) -----------------------

    def symbol_batch(
        self,
        pid: int,
        *,
        module: str | None = None,
        filter: str | None = None,
        format: str = "json",
        max_symbols: int = 65536,
        include_undef: bool = False,
    ) -> dict:
        """cmd 61 symbol_batch. format="packed" returns the binary-frame layout
        decoded into the same column shape (types not represented on packed wire)."""
        with self._lock:
            payload: dict = {
                "pid": pid,
                "format": format,
                "max_symbols": int(max_symbols),
                "include_undef": bool(include_undef),
            }
            if module:
                payload["module"] = module
            if filter:
                payload["filter"] = filter
            if format == "packed":
                frame = self._execute_frame(CMD_SYMBOL_BATCH, payload)
                if not isinstance(frame.payload, bytes):
                    raise AgentError("protocol_error", detail="packed symbol_batch: JSON response")
                decoded = decode_packed_symbols(frame.payload)
                return decoded
            resp = self._execute(CMD_SYMBOL_BATCH, payload)
            resp.setdefault("module_indexes", [])
            return resp

    def strings_scan(
        self,
        pid: int,
        *,
        preset: str | None = None,
        addr: int | None = None,
        size: int | None = None,
        min_len: int = 4,
        max_len: int = 256,
        regex: str | None = None,
        max_results: int = 1024,
        async_run: bool = False,
    ) -> dict:
        """cmd 62 strings_scan (sync mode; async jobs surface via scan_status)."""
        with self._lock:
            payload: dict = {
                "pid": pid,
                "min_len": int(min_len),
                "max_len": int(max_len),
                "max_results": int(max_results),
                "async": bool(async_run),
            }
            if preset:
                payload["preset"] = preset
            elif addr is not None and size:
                payload["addr"] = hex_u64(addr)
                payload["size"] = hex_u64(size)
            else:
                raise AgentError("bad_request", detail="strings_scan needs preset or addr+size")
            if regex:
                payload["regex"] = regex
            return self._execute(CMD_STRINGS_SCAN, payload)

    # -- dump pipeline / apk / disassemble / write_txn (v1.2 draft §3.3-§3.7) ------

    def dump_start(self, pid: int, *, module: str, include_anonymous: bool = False,
                   out_name: str | None = None) -> dict:
        """cmd 63: device-side file-layout dump to /data/local/tmp/tanyao-dump."""
        with self._lock:
            payload: dict = {"pid": pid, "module": module,
                             "include_anonymous": bool(include_anonymous)}
            if out_name:
                payload["out_name"] = out_name
            return self._execute(CMD_DUMP_START, payload)

    def dump_status(self, dump_id: str | None = None, *, list_all: bool = False) -> dict:
        """cmd 64: single-dump status or the directory listing."""
        with self._lock:
            payload = {"list": True} if list_all else {"dump_id": dump_id}
            return self._execute(CMD_DUMP_STATUS, payload)

    def dump_pull(self, dump_id: str | None = None, *, path: str | None = None,
                  offset: int = 0, chunk: int = 256 * 1024, compress: bool = True):
        """cmd 65: one chunk as a verified DumpChunk (24B sub-header + data)."""
        with self._lock:
            payload: dict = {"offset": hex_u64(offset), "chunk": hex_u64(chunk),
                             "compress": bool(compress)}
            if dump_id:
                payload["dump_id"] = dump_id
            elif path:
                payload["path"] = path  # draft §3.6: /data/app/ prefix only
            else:
                raise AgentError("bad_request", detail="dump_pull needs dump_id or path")
            frame = self._execute_frame(CMD_DUMP_PULL, payload)
        if not isinstance(frame.payload, bytes):
            raise AgentError("protocol_error", detail="dump_pull returned a JSON frame")
        try:
            return decode_dump_chunk(frame.payload)
        except ProtocolError as exc:
            raise AgentError("internal", detail=str(exc)) from exc

    def dump_cleanup(self, dump_id: str) -> dict:
        """cmd 68: explicit, auditable device-side cleanup (never automatic)."""
        with self._lock:
            return self._execute(CMD_DUMP_CLEANUP, {"dump_id": dump_id})

    def apk_info_remote(self, pid: int) -> dict:
        """cmd 66: zero-mirror apk metadata resolved from the target's maps."""
        with self._lock:
            return self._execute(CMD_APK_INFO, {"pid": pid})

    def disassemble_remote(self, pid: int, addr: int, *, count: int | None = None,
                           size: int | None = None) -> dict:
        """cmd 67: device-side capstone disassembly (draft-shaped instructions)."""
        with self._lock:
            payload: dict = {"pid": pid, "addr": hex_u64(addr)}
            if count is not None:
                payload["count"] = int(count)
            if size is not None:
                payload["size"] = hex_u64(size)
            return self._execute(CMD_DISASSEMBLE, payload)

    def write_txn(self, pid: int, addr: int, data: bytes, *,
                  expect_old: bytes | None = None, verify: bool = True) -> dict:
        """cmd 60 (PROTOCOL.md §7.5): single-round-trip write transaction. The
        write GATE and expect/verify POLICY stay host-side; the device just
        executes old-read → compare → write → readback atomically-ish."""
        with self._lock:
            session = self._require_handle(pid)
            payload: dict = {
                "handle": hex_u64(session.handle),
                "addr": hex_u64(addr),
                "data_b64": b64_encode(data),
                "verify": bool(verify),
            }
            if expect_old is not None:
                payload["expect_old_b64"] = b64_encode(expect_old)
            return self._execute(CMD_WRITE_TXN, payload)

    # -- memory -------------------------------------------------------------------

    def mem_read(self, pid: int, address: int, size: int) -> bytes:
        """Read exactly `size` bytes, chunking across backend max_transfer_size.

        Raises AgentError with 'partial_read' semantics if a chunk fails midway.
        """
        if size < 0:
            raise ValueError("size must be non-negative")
        with self._lock:
            session = self._require_handle(pid)
            info = self._backend or self.connect()
            chunk_limit = min(info.max_transfer_size, MAX_TRANSFER_FALLBACK)
            chunks: list[bytes] = []
            offset = 0
            while offset < size:
                take = min(chunk_limit, size - offset)
                resp = self._execute(
                    CMD_MEM_READ,
                    {
                        "handle": hex_u64(session.handle),
                        "addr": hex_u64(address + offset),
                        "size": hex_u64(take),
                    },
                )
                status = int(resp.get("status", -1))
                data = b64_decode(resp.get("data_b64", ""))
                if status != 0:
                    raise AgentError(
                        "backend_error",
                        errno=status,
                        detail=f"mem_read failed at offset {offset} ({len(data)}/{take} bytes)",
                    )
                if len(data) != take:
                    raise AgentError(
                        "backend_error",
                        errno=status,
                        detail=f"short read: got {len(data)}, want {take}",
                    )
                chunks.append(data)
                offset += take
            return b"".join(chunks)

    def mem_readv(self, pid: int, spans: list[tuple[int, int]]) -> list[bytes | None]:
        """Batch read. Returns per-span bytes, or None for failed spans.

        Field-test P2-1 hardening: a bad span must not pollute later spans in
        the same batch. The kernel readv stops at the first failing iov
        ("completed prefix" semantics), so if the reported completed_iov is
        short, every span AFTER the failure point is re-issued individually to
        recover independent results."""
        with self._lock:
            session = self._require_handle(pid)
            info = self._backend or self.connect()
            max_iov = max(1, info.max_iov)
            results: list[bytes | None] = []
            for start in range(0, len(spans), max_iov):
                batch = spans[start : start + max_iov]
                payload = {
                    "handle": hex_u64(session.handle),
                    "iov": [
                        {"addr": hex_u64(addr), "size": hex_u64(size)} for addr, size in batch
                    ],
                }
                try:
                    resp = self._execute(CMD_MEM_READV, payload)
                except AgentError:
                    results.extend([None] * len(batch))
                    continue
                batch_results: list[bytes | None] = [None] * len(batch)
                reported = resp.get("spans", [])
                completed_iov = int(resp.get("completed_iov", len(reported)))
                for i, span in enumerate(reported):
                    if i < len(batch) and int(span.get("status", -1)) == 0:
                        batch_results[i] = b64_decode(span.get("data_b64", ""))
                # kernel prefix semantics: spans after the first failure were not
                # attempted; re-read them one-by-one for span isolation
                first_fail = None
                if completed_iov < len(batch):
                    first_fail = completed_iov
                else:
                    for i, span in enumerate(reported):
                        if int(span.get("status", -1)) != 0:
                            first_fail = i
                            break
                if first_fail is not None:
                    for i in range(first_fail, len(batch)):
                        if batch_results[i] is not None:
                            continue
                        addr, size = batch[i]
                        try:
                            batch_results[i] = self.mem_read(pid, addr, size)
                        except AgentError:
                            batch_results[i] = None
                results.extend(batch_results)
            return results

    def mem_write(self, pid: int, address: int, data: bytes) -> int:
        """Write bytes, chunking across backend max_transfer_size. Returns bytes written."""
        with self._lock:
            session = self._require_handle(pid)
            info = self._backend or self.connect()
            if not info.capabilities & (1 << 4):  # TANYAO_CAP_MEM_WRITE
                raise AgentError("backend_error", detail="backend lacks MEM_WRITE capability")
            chunk_limit = min(info.max_transfer_size, MAX_TRANSFER_FALLBACK)
            written = 0
            offset = 0
            while offset < len(data):
                take = min(chunk_limit, len(data) - offset)
                resp = self._execute(
                    CMD_MEM_WRITE,
                    {
                        "handle": hex_u64(session.handle),
                        "addr": hex_u64(address + offset),
                        "data_b64": b64_encode(data[offset : offset + take]),
                    },
                )
                status = int(resp.get("status", -1))
                result_size = parse_u64(resp.get("result_size", "0x0"), field="result_size")
                if status != 0 or result_size != take:
                    raise AgentError(
                        "backend_error",
                        errno=status,
                        detail=f"short write at offset {offset}: wrote {result_size}/{take}",
                    )
                written += result_size
                offset += take
            return written
