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
import os
import socket
import struct
import threading
import time

# --- protocol constants (mirrors PROTOCOL.md; host code is the canonical copy) ---
FRAME_MAGIC = 0x54594F31
PROTOCOL_VERSION = 1
FLAG_RESPONSE = 0x01
FLAG_ERROR = 0x02
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

CAP_SESSION = 1 << 0
CAP_TARGET_HANDLE = 1 << 1
CAP_MEM_READ = 1 << 2
CAP_MEM_READV = 1 << 3
CAP_MEM_WRITE = 1 << 4
CAP_MAPS = 1 << 5

BASE = 0x7000000000
HEAP_START = 0x7200000000
DEMO_PID = 4321
MODULE_PATH = "/data/app/libdemo.so"


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


class MockAgent:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, token: str | None = None) -> None:
        self.token = token if token is not None else os.environ.get("TANYAO_MOCK_TOKEN", "tanyao-dev-token")
        self.generation = 1
        self.start_time = time.monotonic()
        self.memory = FakeMemory()
        self._build_world()
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
            self._send(conn, 0, CMD_HELLO, {
                "agent": "tanyao-agent",
                "version": "0.1.0-mock",
                "generation": self.generation,
                "challenge": challenge,
            }, 0)
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
            return {
                "status": 0, "entry_count": 4, "total_count": 4,
                "target_cookie": hx(0x1234ABCD),
                "maps_source": "target_maps",
                "entries": [
                    {"start": hx(BASE), "end": hx(BASE + 0x2000), "file_offset": hx(0),
                     "flags": 1 | 4 | 8, "path": MODULE_PATH},
                    {"start": hx(BASE + 0x2000), "end": hx(BASE + 0x3000), "file_offset": hx(0x2000),
                     "flags": 1 | 2 | 8, "path": MODULE_PATH},
                    # P2-2 world: -w-p tail mapping with file-offset drift
                    {"start": hx(BASE + 0x3000), "end": hx(BASE + 0x4000), "file_offset": hx(0x2000),
                     "flags": 2 | 8, "path": MODULE_PATH},
                    {"start": hx(HEAP_START), "end": hx(HEAP_START + 0x10000), "file_offset": hx(0),
                     "flags": 1 | 2 | 8 | 32, "path": ""},
                ],
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
        raise ProtocolFail("unsupported_cmd", detail=f"cmd {cmd}")

    # -- framing ------------------------------------------------------------------

    def _send(self, conn: socket.socket, seq: int, cmd: int, payload: dict, flags: int) -> None:
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
