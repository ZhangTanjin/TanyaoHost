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
    CMD_BACKEND_INFO,
    CMD_MEM_READ,
    CMD_MEM_READV,
    CMD_MEM_WRITE,
    CMD_MODULE_BASE,
    CMD_PING,
    CMD_PROCESS_ALIVE,
    CMD_PROCESS_FIND,
    CMD_PROCESS_LIST,
    CMD_SESSION_INFO,
    CMD_TARGET_CLOSE,
    CMD_TARGET_MAPS,
    CMD_TARGET_OPEN,
    DEFAULT_PORT,
    ProtocolError,
    b64_decode,
    b64_encode,
    hex_u64,
    parse_u64,
)
from .connection import AgentConnection, AgentError

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

    def _execute(self, cmd: int, payload: dict) -> dict:
        """Run one RPC with reconnect-once semantics. Caller must hold lock (or accept races)."""
        if self._conn is None:
            if not self._auto_reconnect:
                raise AgentUnavailable("not connected")
            self.connect()
        assert self._conn is not None
        old_generation = self._conn.generation
        try:
            return self._conn.request(cmd, payload)
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
                return self._conn.request(cmd, payload)
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
        with self._lock:
            resp = self._execute(CMD_PROCESS_ALIVE, {"pid": pid})
            return bool(resp["alive"])

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
