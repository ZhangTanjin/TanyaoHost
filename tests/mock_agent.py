"""Mock tanyao-agent: a faithful implementation of PROTOCOL.md v1 over TCP.

Purposes:
1. End-to-end tests for tanyao-host without a device.
2. A small, readable REFERENCE IMPLEMENTATION for the TanyaoCli engineer
   (the real agent is C++; semantics must match this exactly).

Fake world:
- backend "mock", caps = SESSION|TARGET_HANDLE|MEM_READ|MEM_READV|MEM_WRITE|MAPS
- process "com.demo.game" pid=4321 with three mappings:
    base+0x0000 r-x  /data/app/libdemo.so   (synthetic ELF64 header, 0x3000 bytes)
    base+0x2000 rw-  /data/app/libdemo.so   (data: u32 array, 0x1000 bytes)
    heap_start      rw-  [anon:libc_malloc] (0x10000 bytes)
- token from env TANYAO_MOCK_TOKEN, default "tanyao-dev-token".
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import socket
import struct
import threading
import time
import zlib

# --- protocol constants (mirrors PROTOCOL.md; host code is the canonical copy) ---
FRAME_MAGIC = 0x54594F31
PROTOCOL_VERSION = 1
FLAG_RESPONSE = 0x01
FLAG_ERROR = 0x02
FLAG_PAYLOAD_BINARY = 0x04
HEADER = struct.Struct(">IBBHIII")  # magic, version, flags, reserved, seq, cmd, length = 20 bytes
MAX_PAYLOAD = 16 * 1024 * 1024

CMD_HELLO = 0
CMD_AUTH = 1
CMD_PING = 2
CMD_SHUTDOWN = 3
CMD_BACKEND_INFO = 10
CMD_SESSION_INFO = 11
CMD_TARGET_OPEN = 20
CMD_TARGET_CLOSE = 21
CMD_TARGET_MAPS = 22
CMD_MEM_READ = 30
CMD_MEM_READV = 31
CMD_MEM_WRITE = 32
CMD_PROCESS_FIND = 40
CMD_PROCESS_LIST = 41
CMD_PROCESS_ALIVE = 42
CMD_MODULE_BASE = 43
# v1.1 device-local scan engine (PROTOCOL.md §7)
CMD_SCAN_START = 50
CMD_SCAN_STATUS = 51
CMD_SCAN_REFINE = 52
CMD_SCAN_RESULTS = 53
CMD_SCAN_CANCEL = 54
CMD_SCAN_CLEAR = 55
CMD_WRITE_TXN = 60
# v1.2 compute-down ops (PROTOCOL_V1.2_DRAFT.md §3)
CMD_SYMBOL_BATCH = 61
CMD_STRINGS_SCAN = 62
CMD_DUMP_START = 63
CMD_DUMP_STATUS = 64
CMD_DUMP_PULL = 65
CMD_APK_INFO = 66
CMD_DISASSEMBLE = 67
CMD_DUMP_CLEANUP = 68

CAP_SESSION = 1 << 0
CAP_TARGET_HANDLE = 1 << 1
CAP_MEM_READ = 1 << 2
CAP_MEM_READV = 1 << 3
CAP_MEM_WRITE = 1 << 4
CAP_MAPS = 1 << 5

# Agent-layer capability bits (hello.capabilities namespace) — mirrors
# tanyao.constants; scan ops are gated on AGENT_CAP_SCAN.
AGENT_CAP_SCAN = 1 << 0
AGENT_CAP_WRITE_TXN = 1 << 1
AGENT_CAP_SYMBOL_BATCH = 1 << 3
AGENT_CAP_BINARY_FRAMES = 1 << 4
AGENT_CAP_STRINGS = 1 << 5
AGENT_CAP_DUMP_PIPELINE = 1 << 6
AGENT_CAP_APK_INFO = 1 << 7
AGENT_CAP_DISASSEMBLE = 1 << 8

BASE = 0x7000000000
HEAP_START = 0x7200000000
DEMO_PID = 4321
MODULE_PATH = "/data/app/libdemo.so"

# Device scan engine constants (PROTOCOL.md §7.4 parity)
SCAN_MAX_HITS = 200_000
SCAN_CHUNK = 2 * 1024 * 1024
SCAN_MIN_GRAN = 4096
SCAN_MAX_GRAN = 64 * 1024 * 1024

# packed symbol table (v1.2 draft §3.1), mirrors tanyao.frames
PACKED_SYMBOL_HEADER = struct.Struct(">IIII")
PACKED_SYMBOL_ENTRY = struct.Struct(">QIII")

# name -> (little-endian struct fmt, size, is_float); mirrors host scan.TYPES
SCAN_TYPES: dict[str, tuple[str, int, bool]] = {
    "u8": ("<B", 1, False), "u16": ("<H", 2, False), "u32": ("<I", 4, False),
    "u64": ("<Q", 8, False), "i8": ("<b", 1, False), "i16": ("<h", 2, False),
    "i32": ("<i", 4, False), "i64": ("<q", 8, False),
    "f32": ("<f", 4, True), "f64": ("<d", 8, True),
}


def build_elf64() -> bytes:
    """Minimal AArch64 shared-object image: two PT_LOADs plus a PT_DYNAMIC with a
    working dynsym/dynstr/DT_HASH trio, so host-side symbol parsing is testable.

    Layout (all within PT_LOAD 1, vaddr 0..0x3000):
      0x0000 ELF header (64B)
      0x0040 program headers (3 x 56B = 168B, ends 0xE8)
      0x0100 PT_DYNAMIC array (4 entries x 16B = 64B, ends 0x140)
      0x0140 DT_HASH: nbucket=1, nchain=3, bucket[1], chain[3] (24B, ends 0x158)
      0x0180 dynsym: 3 x 24B (null + demo_start + demo_data), ends 0x1C8
      0x01C8 dynstr: "\\0demo_start\\0demo_data\\0" (22B)
    Symbol values: demo_start -> vaddr 0x1B40 (FUNC), demo_data -> vaddr 0x2010 (OBJECT).
    """
    ehsize, phentsize, phnum = 64, 56, 3
    phoff = ehsize
    e = bytearray(0x2000)
    e[0:4] = b"\x7fELF"
    e[4], e[5], e[6] = 2, 1, 1  # ELF64, little-endian, current version
    struct.pack_into("<HHIQQQIHHHHHH", e, 16,
                     3,        # e_type = ET_DYN
                     183,      # e_machine = EM_AARCH64
                     1,        # e_version
                     0x1B40,   # e_entry
                     phoff,    # e_phoff
                     0,        # e_shoff
                     0,        # e_flags
                     ehsize,   # e_ehsize
                     phentsize, phnum,   # e_phentsize, e_phnum
                     0, 0, 0)  # shentsize/shnum/shstrndx
    # PT_LOAD 1: file vaddr 0, exec (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
    struct.pack_into("<IIQQQQQQ", e, phoff,
                     1, 5, 0, 0, 0x3000, 0x3000, 0, 0x1000)
    # PT_LOAD 2: file vaddr 0x2000, rw, memsz > filesz (BSS)
    struct.pack_into("<IIQQQQQQ", e, phoff + phentsize,
                     1, 6, 0x2000, 0x2000, 0, 0x200, 0x400, 0x1000)
    # PT_DYNAMIC: vaddr 0x100, 64 bytes
    struct.pack_into("<IIQQQQQQ", e, phoff + 2 * phentsize,
                     2, 6, 0x100, 0x100, 0, 0x40, 0x40, 8)

    # dynamic array at 0x100: HASH, STRTAB, SYMTAB, STRSZ
    SYMTAB, STRTAB, HASH = 0x180, 0x1C8, 0x140
    strtab = b"\x00demo_start\x00demo_data\x00"
    assert len(strtab) == 22
    struct.pack_into("<QQ", e, 0x100, 4, HASH)        # DT_HASH
    struct.pack_into("<QQ", e, 0x110, 5, STRTAB)      # DT_STRTAB
    struct.pack_into("<QQ", e, 0x120, 6, SYMTAB)      # DT_SYMTAB
    struct.pack_into("<QQ", e, 0x130, 10, len(strtab))  # DT_STRSZ
    struct.pack_into("<QQ", e, 0x140, 0, 0)           # DT_NULL

    # DT_HASH at 0x140: nbucket=1, nchain=3, bucket[0]=1, chain=[0,0,2]
    struct.pack_into("<II", e, HASH, 1, 3)
    struct.pack_into("<I", e, HASH + 8, 1)       # bucket[0] -> symbol 1
    struct.pack_into("<III", e, HASH + 12, 0, 0, 2)  # chain (terminator on idx 2)

    # dynsym at 0x180: [null, demo_start, demo_data]
    struct.pack_into("<IBBHQQ", e, SYMTAB, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", e, SYMTAB + 24, 1, 0x12, 0, 1, 0x1B40, 0x40)  # FUNC GLOBAL (shndx=1: defined)
    struct.pack_into("<IBBHQQ", e, SYMTAB + 48, 12, 0x11, 0, 1, 0x2010, 8)    # OBJECT GLOBAL (shndx=1)
    e[STRTAB:STRTAB + len(strtab)] = strtab
    return bytes(e)


class FakeMemory:
    """A set of flat regions; reads outside any region return EFAULT semantics."""

    def __init__(self) -> None:
        self.regions: list[tuple[int, bytearray]] = []

    def add(self, start: int, size: int, fill: bytes | None = None) -> bytearray:
        buf = bytearray(size)
        if fill:
            buf[: len(fill)] = fill
        self.regions.append((start, buf))
        return buf

    def _find(self, addr: int, size: int) -> tuple[bytearray, int] | None:
        for start, buf in self.regions:
            if start <= addr and addr + size <= start + len(buf):
                return buf, addr - start
        return None

    def read(self, addr: int, size: int) -> bytes:
        # poisoned ranges always fault (simulates [vvar] VM_PFNMAP pages, P1)
        for plo, phi in getattr(self, "poison", []):
            if addr < phi and addr + size > plo:
                raise MemoryFault()
        found = self._find(addr, size)
        if found is None:
            raise MemoryFault()
        buf, off = found
        return bytes(buf[off : off + size])

    def write(self, addr: int, data: bytes) -> None:
        found = self._find(addr, len(data))
        if found is None:
            raise MemoryFault()
        buf, off = found
        buf[off : off + len(data)] = data


class MemoryFault(Exception):
    pass


class MockScanJob:
    """One device-local scan job (single job slot, v1.1 semantics)."""

    __slots__ = ("id", "spec", "ranges", "state", "round", "scanned", "total",
                 "skipped", "hits", "truncated", "error", "started", "finished",
                 "cancel", "dead_gran", "hex_carry",
                 "str_start", "str_buf", "str_total")

    def __init__(self, job_id: int, spec: dict, ranges: list[tuple[int, int]]) -> None:
        self.id = job_id
        self.spec = spec
        self.ranges = ranges
        self.state = "running"  # running | done | error | cancelled
        self.round = 1  # first scan counts as round 1 (PROTOCOL.md §7.3)
        self.scanned = 0
        self.total = sum(hi - lo for lo, hi in ranges)
        self.skipped: list[tuple[int, int]] = []
        self.hits: list[dict] = []
        self.truncated = False
        self.error = ""
        self.started = time.monotonic()
        self.finished: float | None = None
        self.cancel = threading.Event()
        self.dead_gran = SCAN_MIN_GRAN
        self.hex_carry = b""
        # strings state machine (kind == "strings")
        self.str_start = None
        self.str_buf = bytearray()
        self.str_total = 0


def _parse_aob(pattern: str) -> tuple[bytes, bytes]:
    """Parse "7F 45 ?? 46" into (pattern, mask); 0x00 mask = wildcard."""
    pb = bytearray()
    mb = bytearray()
    for tok in pattern.split():
        if tok in ("?", "??"):
            pb.append(0)
            mb.append(0)
        else:
            pb.append(int(tok, 16))
            mb.append(0xFF)
    return bytes(pb), bytes(mb)


def _mock_match(found, want, eps: float) -> bool:
    """Float: eps>0 window else isclose(rel_tol=1e-6); ints exact (§7.4)."""
    if isinstance(found, float) or isinstance(want, float):
        if eps > 0:
            return abs(found - want) <= eps
        return math.isclose(found, want, rel_tol=1e-6)
    return found == want


def _raw8(value, fmt: str, size: int) -> bytes:
    """Raw 8-byte little-endian form of a hit value (value_hex backing)."""
    if isinstance(value, float):
        return struct.pack(fmt, value) + b"\x00" * (8 - size)
    return (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def _u64(value, field: str = "value") -> int:
    if isinstance(value, str) and value.lower().startswith("0x"):
        return int(value, 16)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ProtocolFail("bad_request", detail=f"bad u64 field {field}")


def hx(v: int) -> str:
    """u64 → lowercase 0x hex string (module-level for op helpers)."""
    return f"0x{v:x}"


class MockAgent:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, token: str | None = None,
                 agent_caps: int = 0) -> None:
        self.token = token if token is not None else os.environ.get("TANYAO_MOCK_TOKEN", "tanyao-dev-token")
        self.agent_caps = agent_caps
        self.generation = 1
        self.start_time = time.monotonic()
        self.memory = FakeMemory()
        self._build_world()
        self._scan_job: "MockScanJob | None" = None
        self._scan_seq = 0
        self._scan_lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(4)
        self.port = self._srv.getsockname()[1]
        self._active_conn: socket.socket | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    # -- world -----------------------------------------------------------------

    def _build_world(self) -> None:
        # module exec map at BASE: real ELF64 header with PT_LOAD1 sized to 0x2000
        exec_map = self.memory.add(BASE, 0x2000, build_elf64()[:0x2000])
        struct.pack_into("<IIQQQQQQ", exec_map, 64, 1, 5, 0, 0, 0x2000, 0x2000, 0, 0x1000)
        data_map = self.memory.add(BASE + 0x2000, 0x1000)
        for i in range(0x400 // 4):
            struct.pack_into("<I", data_map, i * 4, 1000 + i * 7)
        heap = self.memory.add(HEAP_START, 0x10000)
        # pointer chain for tests: HEAP_START+0x100 -> HEAP_START+0x400
        struct.pack_into("<Q", heap, 0x100, HEAP_START + 0x400)
        # ... -> +0x40 -> value u32 0xDEADBEEF at +0x8
        struct.pack_into("<Q", heap, 0x440, HEAP_START + 0x480)
        struct.pack_into("<I", heap, 0x488, 0xDEADBEEF)
        # scattered u32 values for scan tests
        struct.pack_into("<I", heap, 0x1000, 1337)
        struct.pack_into("<I", heap, 0x2000, 1337)
        struct.pack_into("<I", heap, 0x3004, 1337)  # unaligned to 4 relative to heap start
        struct.pack_into("<I", heap, 0x4000, 424242)
        # P1 regression world: a [vvar]-like poisoned hole INSIDE the heap range
        # (1 page at heap+0x8000..0x9000) plus extra hits behind it — verifies
        # bisection skip keeps scanning and preserves later hits
        self.memory.poison = [(HEAP_START + 0x8000, HEAP_START + 0x9000)]
        struct.pack_into("<I", heap, 0xA000, 1337)  # hit AFTER the hole
        # P2-2 regression world: -w-p tail mapping with file-offset drift
        # (vaddr BASE+0x3000..0x4000 = file offset 0x2000..0x3000)
        self.memory.add(BASE + 0x3000, 0x1000, bytes(range(256)) * 16)
        self.wtail_vaddr, self.wtail_file_off = BASE + 0x3000, 0x2000
        # toolchain regression world: decodable A64 prologue at BASE+0x800 and
        # ASCII strings for strings() inside the module image
        #   stp x29, x30, [sp, #-16]!
        #   mov x0, #1337        (movz)
        #   bl +0x400
        #   cbz x0, +8
        #   ret
        prologue = struct.pack("<5I",
                               0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                               0xD280A720,  # mov x0, #0x539
                               0x94000100,  # bl +0x400
                               0xB4000040,  # cbz x0, +8
                               0xD65F03C0)  # ret
        exec_map[0x800:0x800 + len(prologue)] = prologue
        marker = b"tanyao_mock_engine\x00"
        exec_map[0x900:0x900 + len(marker)] = marker
        marker2 = b"Java_icu_nullptr_test\x00"
        exec_map[0x940:0x940 + len(marker2)] = marker2
        # strings marker in the heap (outside module) for window-mode tests
        hmarker = b"TANYAO_STRINGS_WINDOW_MARKER\x00"
        heap[0xB000:0xB000 + len(hmarker)] = hmarker

        # Canonical target_maps snapshot shared by cmd 22 and the device scan
        # engine presets (same table a real agent gets from the kernel).
        self.target_maps = [
            {"start": BASE, "end": BASE + 0x2000, "file_offset": 0,
             "flags": 1 | 4 | 8, "path": MODULE_PATH},
            {"start": BASE + 0x2000, "end": BASE + 0x3000, "file_offset": 0x2000,
             "flags": 1 | 2 | 8, "path": MODULE_PATH},
            {"start": BASE + 0x3000, "end": BASE + 0x4000, "file_offset": 0x2000,
             "flags": 2 | 8, "path": MODULE_PATH},
            {"start": HEAP_START, "end": HEAP_START + 0x10000, "file_offset": 0,
             "flags": 1 | 2 | 8 | 32, "path": ""},
        ]

    # -- networking ----------------------------------------------------------------

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._srv.accept()
            except OSError:
                return
            if self._active_conn is not None:
                # tolerate teardown races: wait briefly for a dying connection
                deadline = time.monotonic() + 0.25
                while self._active_conn is not None and time.monotonic() < deadline:
                    if self._active_is_dead(self._active_conn):
                        self._active_conn = None
                        break
                    time.sleep(0.01)
            if self._active_conn is not None:
                try:
                    self._send(conn, 0, CMD_HELLO, {"error": "busy"},
                               FLAG_RESPONSE | FLAG_ERROR)
                except OSError:
                    pass
                conn.close()
                continue
            self._active_conn = conn
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    @staticmethod
    def _active_is_dead(conn: socket.socket) -> bool:
        """True if the peer has closed (EOF) or the socket is broken."""
        try:
            conn.settimeout(0)
            try:
                return conn.recv(1) == b""
            except BlockingIOError:
                return False  # alive, nothing to read
            except OSError:
                return True
        except OSError:
            return True
        finally:
            try:
                conn.settimeout(60)
            except OSError:
                pass

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(60)
            challenge = os.urandom(32).hex()
            hello = {
                "agent": "tanyao-agent",
                "version": "0.1.0-mock",
                "generation": self.generation,
                "challenge": challenge,
            }
            if self.agent_caps:
                # v1.0 agents omit the field entirely; host treats absent as 0.
                hello["capabilities"] = hex(self.agent_caps)
            self._send(conn, 0, CMD_HELLO, hello, 0)
            decoder_buffer = bytearray()
            authed = False
            expected_seq = 0
            while not self._stop.is_set():
                frame = self._recv(conn, decoder_buffer)
                if frame is None:
                    break
                seq, cmd, _flags, payload = frame
                if not authed:
                    if cmd == CMD_AUTH:
                        proof = payload.get("proof", "")
                        want = hashlib.sha256((self.token + challenge).encode()).hexdigest()
                        if hmac_equal(proof, want):
                            authed = True
                            expected_seq = seq  # auth consumes a sequence number too
                            self._send(conn, seq, cmd, {"ok": True}, FLAG_RESPONSE)
                            continue
                        self._send(conn, seq, cmd, {"ok": False, "error": "auth_failed"},
                                   FLAG_RESPONSE | FLAG_ERROR)
                        break
                    self._send(conn, seq, cmd, {"ok": False, "error": "auth_required"},
                               FLAG_RESPONSE | FLAG_ERROR)
                    break
                if seq != expected_seq + 1:
                    # out-of-order sequence: protocol error, drop
                    break
                expected_seq = seq
                try:
                    resp = self._dispatch(cmd, payload)
                    self._send(conn, seq, cmd, resp, FLAG_RESPONSE)
                except ProtocolFail as exc:
                    self._send(conn, seq, cmd, {"ok": False, "error": exc.error, "errno": exc.errno,
                                                "detail": exc.detail}, FLAG_RESPONSE | FLAG_ERROR)
                    if exc.fatal:
                        break
                if cmd == CMD_SHUTDOWN:
                    break
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if self._active_conn is conn:
                self._active_conn = None

    # -- op dispatch ------------------------------------------------------------------

    def _dispatch(self, cmd: int, payload: dict) -> dict:
        def u64(value, field="value"):
            if isinstance(value, str) and value.lower().startswith("0x"):
                return int(value, 16)
            if isinstance(value, int) and value >= 0:
                return value
            raise ProtocolFail("bad_request", detail=f"bad u64 field {field}")

        def hx(v):
            return f"0x{v:x}"

        if cmd == CMD_PING:
            return {"ok": True, "uptime_sec": int(time.monotonic() - self.start_time)}
        if cmd == CMD_SHUTDOWN:
            return {"ok": True}
        if cmd == CMD_BACKEND_INFO:
            caps = CAP_SESSION | CAP_TARGET_HANDLE | CAP_MEM_READ | CAP_MEM_READV | CAP_MEM_WRITE | CAP_MAPS
            return {"abi_major": 1, "abi_minor": 0, "capabilities": hx(caps),
                    "page_size": 4096, "pointer_bits": 64,
                    "max_transfer_size": hx(1 << 20), "max_iov": 64,
                    "backend_flags": hx(0x7), "name": "mock"}
        if cmd == CMD_SESSION_INFO:
            return {"session_id": hx(0xABCD), "capabilities": hx(0x3F)}
        if cmd == CMD_TARGET_OPEN:
            pid = payload.get("pid")
            if pid != DEMO_PID:
                raise ProtocolFail("backend_error", errno=-3, detail=f"no such pid {pid}")
            return {"handle": hx(pid << 8), "start_cookie": hx(0x1234ABCD)}
        if cmd == CMD_TARGET_CLOSE:
            return {}
        if cmd == CMD_TARGET_MAPS:
            handle = u64(payload.get("handle"), "handle")
            if handle != DEMO_PID << 8:
                raise ProtocolFail("bad_request", detail="unknown handle")
            entries = [
                {"start": hx(m["start"]), "end": hx(m["end"]),
                 "file_offset": hx(m["file_offset"]), "flags": m["flags"],
                 "path": m["path"]}
                for m in self.target_maps
            ]
            return {
                "status": 0, "entry_count": len(entries), "total_count": len(entries),
                "target_cookie": hx(0x1234ABCD),
                "maps_source": "target_maps",
                "entries": entries,
            }
        if cmd == CMD_MEM_READ:
            handle = u64(payload.get("handle"), "handle")
            addr = u64(payload.get("addr"), "addr")
            size = u64(payload.get("size"), "size")
            if size > (1 << 20):
                raise ProtocolFail("bad_request", detail="size exceeds max_transfer_size")
            import base64
            try:
                data = self.memory.read(addr, size)
            except MemoryFault:
                return {"status": -14, "result_size": "0x0", "data_b64": ""}
            return {"status": 0, "result_size": hx(len(data)), "data_b64": base64.b64encode(data).decode()}
        if cmd == CMD_MEM_READV:
            handle = u64(payload.get("handle"), "handle")
            import base64
            spans = []
            failed_idx = None
            for i, span in enumerate(payload.get("iov", [])[:64]):
                if failed_idx is not None:
                    # kernel prefix semantics (P2-1): vectors after the first
                    # failure are not attempted and report ECANCELED
                    spans.append({"status": -104, "result_size": "0x0", "data_b64": ""})
                    continue
                try:
                    data = self.memory.read(u64(span["addr"], "addr"), u64(span["size"], "size"))
                    spans.append({"status": 0, "result_size": hx(len(data)),
                                  "data_b64": base64.b64encode(data).decode()})
                except MemoryFault:
                    failed_idx = i
                    spans.append({"status": -14, "result_size": "0x0", "data_b64": ""})
            completed = failed_idx if failed_idx is not None else len(spans)
            total = sum(int(s["result_size"], 16) for s in spans[:completed])
            return {"status": 0, "completed_iov": completed, "total_completed": hx(total), "spans": spans}
        if cmd == CMD_MEM_WRITE:
            handle = u64(payload.get("handle"), "handle")
            addr = u64(payload.get("addr"), "addr")
            import base64
            data = base64.b64decode(payload.get("data_b64", ""))
            try:
                self.memory.write(addr, data)
            except MemoryFault:
                return {"status": -14, "result_size": "0x0"}
            return {"status": 0, "result_size": hx(len(data))}
        if cmd == CMD_PROCESS_FIND:
            name = payload.get("name", "")
            if name == "com.demo.game":
                return {"pid": DEMO_PID}
            raise ProtocolFail("not_found", detail=name)
        if cmd == CMD_PROCESS_LIST:
            return {"pids": [4321, 1, 5000]}
        if cmd == CMD_PROCESS_ALIVE:
            return {"alive": payload.get("pid") == DEMO_PID}
        if cmd == CMD_MODULE_BASE:
            if payload.get("name") == "libdemo.so" and payload.get("pid") == DEMO_PID:
                return {"base": hx(BASE)}
            raise ProtocolFail("not_found")
        if cmd in (CMD_SCAN_START, CMD_SCAN_STATUS, CMD_SCAN_REFINE,
                   CMD_SCAN_RESULTS, CMD_SCAN_CANCEL, CMD_SCAN_CLEAR):
            if not self.agent_caps & AGENT_CAP_SCAN:
                raise ProtocolFail("unsupported_cmd", detail=f"cmd {cmd}")
            if cmd == CMD_SCAN_START:
                return self._scan_start(payload)
            if cmd == CMD_SCAN_STATUS:
                return self._scan_status(payload)
            if cmd == CMD_SCAN_REFINE:
                return self._scan_refine(payload)
            if cmd == CMD_SCAN_RESULTS:
                return self._scan_results(payload)
            if cmd == CMD_SCAN_CANCEL:
                return self._scan_cancel(payload)
            return self._scan_clear(payload)
        if cmd == CMD_SYMBOL_BATCH:
            if not self.agent_caps & AGENT_CAP_SYMBOL_BATCH:
                raise ProtocolFail("unsupported_cmd", detail=f"cmd {cmd}")
            return self._symbol_batch(payload)
        if cmd == CMD_STRINGS_SCAN:
            if not self.agent_caps & AGENT_CAP_STRINGS:
                raise ProtocolFail("unsupported_cmd", detail=f"cmd {cmd}")
            return self._strings_scan(payload)
        if cmd in (CMD_WRITE_TXN,
                   CMD_DUMP_START, CMD_DUMP_STATUS, CMD_DUMP_PULL,
                   CMD_APK_INFO, CMD_DISASSEMBLE, CMD_DUMP_CLEANUP):
            # implemented in later milestones; undeclared-or-unimplemented ops
            # behave exactly like unknown cmds (unsupported_cmd, no disconnect)
            raise ProtocolFail("unsupported_cmd", detail=f"cmd {cmd}")
        raise ProtocolFail("unsupported_cmd", detail=f"cmd {cmd}")

    # -- device-local scan engine (PROTOCOL.md §7 reference implementation) ------

    # -- cmd 61 symbol_batch (v1.2 draft §3.1 reference implementation) -----------

    def _module_groups(self, module):
        """Group exec file-backed maps by basename; explicit module or all
        (ascending base). Returns [(name, first_map, mem_size)]."""
        groups = {}
        for m in self.target_maps:
            if not m["path"] or not (m["flags"] & 4):  # exec only
                continue
            base = m["path"].rsplit("/", 1)[-1].split(" (deleted)")[0]
            if module and base != module:
                continue
            groups.setdefault(base, []).append(m)
        if module and not groups:
            raise ProtocolFail("not_found", detail=f"module {module!r} not found")
        out = []
        for name, maps in sorted(groups.items(), key=lambda kv: min(m["start"] for m in kv[1])):
            first = min(m["start"] for m in maps)
            out.append((name, first, max(m["end"] for m in maps) - first))
        return out

    def _symbol_batch(self, payload):
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise ProtocolFail("bad_request", detail="pid must be a positive integer")
        if pid != DEMO_PID:
            raise ProtocolFail("backend_error", -3, f"no such pid {pid}")
        fmt = payload.get("format", "json")
        if fmt not in ("json", "packed"):
            raise ProtocolFail("bad_request", detail=f"unknown format {fmt!r}")
        if fmt == "packed" and not self.agent_caps & AGENT_CAP_BINARY_FRAMES:
            raise ProtocolFail("bad_request", detail="packed requires BINARY_FRAMES capability")
        max_symbols = payload.get("max_symbols", 65536)
        if not isinstance(max_symbols, int) or max_symbols <= 0:
            raise ProtocolFail("bad_request", detail="max_symbols must be a positive integer")
        filter_re = None
        raw_filter = payload.get("filter")
        if raw_filter:
            try:
                filter_re = re.compile(raw_filter)  # ECMAScript regex_search analogue
            except re.error as exc:
                raise ProtocolFail("bad_request", detail=f"invalid filter regex: {exc}")
        # NOTE: include_undef is accepted but the mock's loader (host symbols.py
        # semantics) always excludes SHN_UNDEF; true matches false here.

        from tanyao.symbols import SymbolError, load_symbols

        collected = []  # (module_name, symbol)
        modules_order = []
        for name, first, mem_size in self._module_groups(payload.get("module")):
            try:
                header = self.memory.read(first, 0x1000)
                syms = load_symbols(self.memory.read, first, mem_size, header)
            except (SymbolError, MemoryFault):
                if payload.get("module"):
                    raise ProtocolFail("not_found", detail=f"no dynamic segment in {name!r}")
                continue  # merged mode: best effort per module
            for sym in syms:
                if filter_re is not None and not filter_re.search(sym.name):
                    continue  # server-side filter precedes max_symbols counting
                if name not in modules_order:
                    modules_order.append(name)
                collected.append((name, sym))

        truncated = len(collected) > max_symbols
        collected = collected[:max_symbols]
        contributing = [n for n in modules_order if any(n == c[0] for c in collected)]
        module_index = {n: i for i, n in enumerate(contributing)}

        if fmt == "json":
            return {
                "count": len(collected),
                "truncated": truncated,
                "modules": contributing,
                "module_indexes": [module_index[n] for n, _s in collected],
                "names": [s.name for _n, s in collected],
                "addresses": [hx(s.address) for _n, s in collected],
                "sizes": [s.size for _n, s in collected],
                "types": [s.kind for _n, s in collected],
            }
        # packed: header + 20B entries + name_blob + module_blob (all big-endian)
        name_blob = bytearray()
        name_offs = []
        for _n, s in collected:
            name_offs.append(len(name_blob))
            name_blob += s.name.encode("utf-8") + b"\x00"
        module_blob = bytearray()
        module_offs = {}
        for n in contributing:
            module_offs[n] = len(module_blob)
            module_blob += n.encode("utf-8") + b"\x00"
        out = bytearray(PACKED_SYMBOL_HEADER.pack(
            len(collected), len(contributing), len(name_blob), len(module_blob)))
        for (n, s), noff in zip(collected, name_offs):
            out += PACKED_SYMBOL_ENTRY.pack(s.address, s.size, noff, module_offs[n])
        out += name_blob
        out += module_blob
        return bytes(out)

    # -- cmd 62 strings_scan (v1.2 draft §3.2 reference implementation) -----------

    STRINGS_SYNC_LIMIT = 256 * 1024 * 1024  # documented threshold

    def _strings_scan(self, payload):
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise ProtocolFail("bad_request", detail="pid must be a positive integer")
        if pid != DEMO_PID:
            raise ProtocolFail("backend_error", -3, f"no such pid {pid}")
        spec = {"pid": pid, "kind": "strings", "preset": "", "module": "",
                "epsilon": 0.0, "alignment": 0}
        min_len = payload.get("min_len", 4)
        max_len = payload.get("max_len", 256)
        max_results = payload.get("max_results", 1024)
        if not isinstance(min_len, int) or not isinstance(max_len, int) or not isinstance(max_results, int):
            raise ProtocolFail("bad_request", detail="min_len/max_len/max_results must be ints")
        spec["min_len"] = min_len
        spec["max_len"] = max_len
        spec["max_results"] = max_results
        regex = payload.get("regex")
        if regex:
            try:
                spec["regex_re"] = re.compile(regex)
            except re.error as exc:
                raise ProtocolFail("bad_request", detail=f"invalid regex: {exc}")
        ranges = []
        if payload.get("preset"):
            spec["preset"] = str(payload["preset"])
            ranges = self._preset_ranges(spec["preset"], "")
        elif payload.get("addr") is not None and payload.get("size") is not None:
            addr = _u64(payload["addr"], "addr")
            size = _u64(payload["size"], "size")
            ranges = [(addr, addr + size)]
        else:
            raise ProtocolFail("bad_request", detail="strings_scan needs preset or addr+size")
        if not ranges:
            raise ProtocolFail("backend_error", 0, "preset matched no readable ranges")
        total = sum(hi - lo for lo, hi in ranges)
        async_run = bool(payload.get("async", False))
        if async_run:
            with self._scan_lock:
                cancelled_old = False
                old = self._scan_job
                if old is not None and old.state == "running":
                    old.cancel.set()
                    old.state = "cancelled"
                    cancelled_old = True
                self._scan_seq += 1
                job = MockScanJob(self._scan_seq, spec, ranges)
                self._scan_job = job
            threading.Thread(target=self._run_scan, args=(job,), daemon=True,
                             name=f"mock-strings-{job.id}").start()
            resp = {"job_id": job.id, "state": "running"}
            if cancelled_old:
                resp["cancelled_old"] = True
            return resp
        if total > self.STRINGS_SYNC_LIMIT:
            raise ProtocolFail("bad_request", 0,
                               f"sync range {total}B exceeds threshold; limit the preset or use async")
        job = MockScanJob(0, spec, ranges)  # transient: synchronous execution
        started = time.monotonic()
        for lo, hi in ranges:
            job.hex_carry = b""
            self._strings_reset(job)
            self._scan_region(job, lo, hi, SCAN_CHUNK)
        self._strings_flush(job)
        return {
            "count": len(job.hits),
            "truncated": job.truncated,
            "scanned_bytes": hx(job.scanned),
            "skipped_bytes": hx(sum(hi - lo for lo, hi in self._merged_skipped(job))),
            "elapsed_sec": round(time.monotonic() - started, 3),
            "results": [{"address": hx(h["address"]), "length": h["length"],
                         "value": h["value"]} for h in job.hits],
        }

    @staticmethod
    def _strings_reset(job):
        # runs never cross VMAs or skipped holes
        job.str_start = None
        job.str_buf = bytearray()
        job.str_total = 0

    def _strings_flush(self, job):
        if job.str_start is None:
            return
        if job.str_total >= job.spec["min_len"]:
            value = bytes(job.str_buf).decode("ascii", "replace")
            regex_re = job.spec.get("regex_re")
            if regex_re is None or regex_re.search(value):
                if len(job.hits) < job.spec["max_results"]:
                    job.hits.append({"address": job.str_start,
                                     "length": job.str_total,  # pre-truncation length
                                     "value": value})
                else:
                    job.truncated = True
        job.str_start = None
        job.str_buf = bytearray()
        job.str_total = 0

    def _preset_ranges(self, preset: str, module: str) -> list[tuple[int, int]]:
        """Range selection per scan_engine.cpp prepare_ranges (device parity)."""
        out: list[tuple[int, int]] = []
        for m in self.target_maps:
            path = m["path"]
            anonymous = (not path) or path.startswith("[")
            if preset == "anon":
                include = anonymous or ((m["flags"] & 2) and not path)
            elif preset == "stack":
                # kernel labels [stack] anonymous; match by address shape
                include = anonymous and (m["flags"] & 2) and m["start"] >= 0x7F0000000000
            elif preset == "all_readable":
                include = True
            elif preset.startswith("module:") or module:
                base = path.rsplit("/", 1)[-1] if path else ""
                base = base.split(" (deleted)")[0]
                include = base == (module or preset[7:])
            else:
                include = True  # unknown preset: all readable (device parity)
            if include:
                out.append((m["start"], m["end"]))
        return out

    def _scan_start(self, payload: dict) -> dict:
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise ProtocolFail("bad_request", detail="pid must be a positive integer")
        if pid != DEMO_PID:
            # agent auto-opens the target; unknown pid fails like target_open
            raise ProtocolFail("backend_error", -3, f"no such pid {pid}")
        kind = payload.get("kind")
        spec: dict = {"pid": pid, "kind": kind, "preset": str(payload.get("preset", "anon")),
                      "module": str(payload.get("module", "")), "epsilon": 0.0, "alignment": 0}
        if kind == "value":
            vtype = payload.get("type")
            if vtype not in SCAN_TYPES:
                raise ProtocolFail("bad_request", detail=f"unknown scan type {vtype!r}")
            value = payload.get("value")
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ProtocolFail("bad_request", detail="value must be a number")
            spec["type"] = vtype
            spec["value"] = float(value) if isinstance(value, float) else int(value)
        elif kind == "hex":
            pattern = payload.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                raise ProtocolFail("bad_request", detail="hex scan requires 'pattern'")
            pbytes, mask = _parse_aob(pattern)
            spec["pattern"], spec["mask"] = pbytes, mask
        else:
            raise ProtocolFail("bad_request", detail=f"unknown scan kind {kind!r}")
        eps = payload.get("epsilon", 0.0)
        if isinstance(eps, (int, float)) and not isinstance(eps, bool):
            spec["epsilon"] = float(eps)
        align = payload.get("alignment", 0)
        if isinstance(align, int) and not isinstance(align, bool) and align > 0:
            spec["alignment"] = align
        ranges = self._preset_ranges(spec["preset"], spec["module"])
        if not ranges:
            raise ProtocolFail("backend_error", 0, "preset matched no readable ranges")

        with self._scan_lock:
            cancelled_old = False
            old = self._scan_job
            if old is not None and old.state == "running":
                old.cancel.set()
                old.state = "cancelled"
                cancelled_old = True
            self._scan_seq += 1
            job = MockScanJob(self._scan_seq, spec, ranges)
            self._scan_job = job
        threading.Thread(target=self._run_scan, args=(job,), daemon=True,
                         name=f"mock-scan-{job.id}").start()
        resp = {"job_id": job.id, "state": "running",
                "total_bytes": hx(job.total), "ranges": len(job.ranges)}
        if cancelled_old:
            resp["cancelled_old"] = True
        return resp

    def _current_job(self, payload: dict) -> "MockScanJob | None":
        with self._scan_lock:
            job = self._scan_job
        if job is None:
            raise ProtocolFail("not_found", detail="no scan job")
        if "job_id" in payload and payload["job_id"] is not None:
            want = _u64(payload["job_id"], "job_id")
            if want != job.id:
                raise ProtocolFail("not_found", detail=f"no scan job {want}")
        return job

    def _scan_status(self, payload: dict) -> dict:
        job = self._current_job(payload)
        elapsed = time.monotonic() - job.started
        out = {
            "job_id": job.id, "state": job.state, "pid": job.spec["pid"],
            "type": job.spec.get("type", ""), "round": job.round,
            "scanned_bytes": hx(job.scanned), "total_bytes": hx(job.total),
            "skipped_bytes": hx(sum(hi - lo for lo, hi in self._merged_skipped(job))),
            "matches": len(job.hits), "truncated": job.truncated,
            "elapsed_sec": round(elapsed, 3), "error": job.error,
        }
        if job.state == "running" and elapsed > 0.2 and job.scanned > 0:
            out["rate_mbps"] = round(job.scanned / elapsed / 1e6, 2)
        if job.spec["kind"] == "strings":
            out["kind"] = "strings"
        return out

    def _scan_refine(self, payload: dict) -> dict:
        job = self._current_job(payload)
        if job.state == "running":
            raise ProtocolFail("bad_request", detail="scan job still running")
        if job.spec["kind"] == "strings":
            raise ProtocolFail("bad_request", detail="refine not supported for strings jobs")
        mode = payload.get("mode")
        modes = ("eq", "neq", "changed", "unchanged", "increased", "decreased")
        if mode not in modes:
            raise ProtocolFail("bad_request", detail=f"unknown refine mode {mode!r}")
        if job.spec["kind"] == "hex" and mode not in ("changed", "unchanged"):
            raise ProtocolFail("bad_request", detail="hex job supports changed/unchanged only")
        eps = payload.get("epsilon", 0.0)
        eps = float(eps) if isinstance(eps, (int, float)) and not isinstance(eps, bool) else 0.0
        value = payload.get("value")
        kept: list[dict] = []
        if job.spec["kind"] == "value":
            fmt, size, is_float = SCAN_TYPES[job.spec["type"]]
            unpack = struct.Struct(fmt).unpack_from
            for hit in job.hits:
                try:
                    data = self.memory.read(hit["address"], size)
                except MemoryFault:
                    continue  # unreadable now -> drop (host parity)
                new = unpack(data)[0]
                old = hit["value"]
                if mode == "eq":
                    ok = value is not None and _mock_match(new, value, eps)
                elif mode == "neq":
                    ok = value is not None and not _mock_match(new, value, eps)
                elif mode == "changed":
                    ok = new != old
                elif mode == "unchanged":
                    ok = new == old
                elif mode == "increased":
                    ok = new > old
                else:
                    ok = new < old
                if ok:
                    kept.append({"address": hit["address"], "value": new,
                                 "raw": _raw8(new, fmt, size)})
        else:
            plen = len(job.spec["pattern"])
            for hit in job.hits:
                try:
                    data = self.memory.read(hit["address"], plen)
                except MemoryFault:
                    continue
                same = data == hit["seg"]
                if (mode == "unchanged" and same) or (mode == "changed" and not same):
                    # kept hits carry the re-read bytes (host refine parity)
                    kept.append({"address": hit["address"],
                                 "value": int.from_bytes(data[:8], "little"),
                                 "raw": data[:8].ljust(8, b"\0"), "seg": bytes(data)})
        job.hits = kept
        job.round += 1
        return {"job_id": job.id, "matches": len(kept), "round": job.round}

    def _scan_results(self, payload: dict) -> dict:
        job = self._current_job(payload)
        offset = int(payload.get("offset", 0))
        limit = int(payload.get("limit", 256))
        begin = min(max(0, offset), len(job.hits))
        end = min(begin + max(0, limit), len(job.hits))
        if job.spec["kind"] == "strings":
            hits = [{"address": hx(h["address"]), "length": h["length"],
                     "value": h["value"]} for h in job.hits[begin:end]]
        else:
            hits = [{"address": hx(h["address"]), "value": h["value"],
                     "value_hex": "0x" + h["raw"].hex()} for h in job.hits[begin:end]]
        return {"job_id": job.id, "count": end - begin, "total": len(job.hits),
                "truncated": job.truncated, "hits": hits}

    def _scan_cancel(self, payload: dict) -> dict:
        job = self._current_job(payload)
        if job.state == "running":
            job.cancel.set()
            job.state = "cancelled"
        return {"ok": True, "state": job.state}

    def _scan_clear(self, payload: dict) -> dict:
        with self._scan_lock:
            job = self._scan_job
        if job is not None:
            if job.state == "running":
                job.cancel.set()
                job.state = "cancelled"
            job.hits = []
            job.skipped = []
            job.round = 0
            job.scanned = 0
            job.truncated = False
        return {"ok": True}

    def _run_scan(self, job: "MockScanJob") -> None:
        try:
            for lo, hi in job.ranges:
                if job.cancel.is_set():
                    break
                job.hex_carry = b""  # matches never cross VMAs
                if job.spec["kind"] == "strings":
                    self._strings_reset(job)
                self._scan_region(job, lo, hi, SCAN_CHUNK)
                if job.truncated:
                    break
            if job.spec["kind"] == "strings":
                self._strings_flush(job)
        except Exception as exc:  # noqa: BLE001
            job.state = "error"
            job.error = f"{type(exc).__name__}: {exc}"
        else:
            if job.state == "running":
                job.state = "done"
        job.finished = time.monotonic()

    def _scan_region(self, job: "MockScanJob", lo: int, hi: int, chunk: int) -> None:
        """Fault-tolerant streaming read+scan (host scan.py _scan_region parity)."""
        pos = lo
        while pos < hi:
            if job.cancel.is_set():
                job.state = "cancelled"
                return
            take = min(chunk, hi - pos)
            try:
                data = self.memory.read(pos, take)
            except MemoryFault:
                eff = job.dead_gran
                if take <= eff:
                    job.skipped.append((pos, pos + take))
                    if job.spec["kind"] == "strings":
                        self._strings_reset(job)
                    pos += take
                    job.dead_gran = min(SCAN_MAX_GRAN, eff * 2)
                    continue
                mid = pos + max(eff, (take // 2 // eff) * eff)
                self._scan_region(job, pos, mid, chunk)
                pos = mid
                job.dead_gran = min(SCAN_MAX_GRAN, eff * 2)
                continue
            job.dead_gran = SCAN_MIN_GRAN
            self._on_chunk(job, pos, data)
            if job.truncated:
                return
            pos += len(data)

    def _on_chunk(self, job: "MockScanJob", pos: int, data: bytes) -> None:
        job.scanned += len(data)
        if job.spec["kind"] == "strings":
            max_len = job.spec["max_len"]
            for i, b in enumerate(data):
                if 0x20 <= b <= 0x7E or b == 0x09:  # printable ASCII + TAB
                    if job.str_start is None:
                        job.str_start = pos + i
                        job.str_buf = bytearray()
                        job.str_total = 0
                    job.str_total += 1
                    if len(job.str_buf) < max_len:
                        job.str_buf.append(b)  # cap the recorded value at max_len
                else:
                    self._strings_flush(job)
            return
        if job.spec["kind"] == "value":
            fmt, size, _is_float = SCAN_TYPES[job.spec["type"]]
            align = job.spec["alignment"] or size
            unpack = struct.Struct(fmt).unpack_from
            want = job.spec["value"]
            eps = job.spec["epsilon"]
            i = (align - (pos % align)) % align
            while i + size <= len(data):
                found = unpack(data, i)[0]
                if _mock_match(found, want, eps):
                    if len(job.hits) < SCAN_MAX_HITS:
                        job.hits.append({"address": pos + i, "value": found,
                                         "raw": _raw8(found, fmt, size)})
                    else:
                        job.truncated = True
                i += align
            return
        # hex AOB with carry; straddling matches must be caught (scan from the
        # carry prefix, skip only matches ending within already-scanned bytes)
        pattern, mask = job.spec["pattern"], job.spec["mask"]
        plen = len(pattern)
        buf = job.hex_carry + data
        base = pos - len(job.hex_carry)
        i = 0
        while i + plen <= len(buf):
            if base + i + plen <= pos:
                i += 1
                continue
            seg = buf[i : i + plen]
            if all((seg[j] & mask[j]) == (pattern[j] & mask[j]) for j in range(plen) if mask[j]):
                if len(job.hits) < SCAN_MAX_HITS:
                    job.hits.append({"address": base + i,
                                     "value": int.from_bytes(seg[:8], "little"),
                                     "raw": seg[:8].ljust(8, b"\0"), "seg": bytes(seg)})
                else:
                    job.truncated = True
            i += 1
        job.hex_carry = buf[len(buf) - (plen - 1):] if plen > 1 else b""

    @staticmethod
    def _merged_skipped(job: "MockScanJob") -> list[tuple[int, int]]:
        if not job.skipped:
            return []
        merged = [job.skipped[0]]
        for lo, hi in sorted(job.skipped)[1:]:
            plo, phi = merged[-1]
            if lo <= phi:
                merged[-1] = (plo, max(phi, hi))
            else:
                merged.append((lo, hi))
        return merged

    # -- framing ------------------------------------------------------------------

    def _send(self, conn: socket.socket, seq: int, cmd: int, payload, flags: int) -> None:
        if isinstance(payload, (bytes, bytearray)):
            # v1.2 draft §2: raw payload responses carry flags bit2
            body = bytes(payload)
            flags |= FLAG_PAYLOAD_BINARY
        else:
            body = json_dumps(payload)
        conn.sendall(HEADER.pack(FRAME_MAGIC, PROTOCOL_VERSION, flags, 0, seq, cmd, len(body)) + body)

    def _recv(self, conn: socket.socket, buffer: bytearray):
        while True:
            if len(buffer) >= HEADER.size:
                magic, version, flags, _r, seq, cmd, length = HEADER.unpack_from(buffer, 0)
                if magic != FRAME_MAGIC or version != PROTOCOL_VERSION:
                    return None
                if len(buffer) >= HEADER.size + length:
                    body = bytes(buffer[HEADER.size : HEADER.size + length])
                    del buffer[: HEADER.size + length]
                    import json
                    return seq, cmd, flags, (json.loads(body) if length else {})
            chunk = conn.recv(65536)
            if not chunk:
                return None
            buffer.extend(chunk)


class ProtocolFail(Exception):
    def __init__(self, error: str, errno: int | None = None, detail: str = "", fatal: bool = False):
        super().__init__(error)
        self.error = error
        self.errno = errno
        self.detail = detail
        self.fatal = fatal


def hmac_equal(a: str, b: str) -> bool:
    return hashlib.compare_digest(a, b) if hasattr(hashlib, "compare_digest") else a == b


def json_dumps(payload: dict) -> bytes:
    import json
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Mock tanyao-agent (PROTOCOL.md v1)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=52730)
    args = parser.parse_args()
    agent = MockAgent(host=args.host, port=args.port)
    agent.start()
    print(f"mock agent listening on {args.host}:{agent.port}", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
