"""Interop acceptance tool for tanyao-agent (device side).

Run from a machine that can reach the agent (USB-tethered NIC or LAN):

    python3 -m tanyao.interop --host <device-ip> --port 52730 \
        --token <token> --pid <live-pid> [--allow-write]

Exit code 0 = all mandatory checks PASS. This is the tool referenced by
ENGINEER_PROMPT.md as the agent's Definition of Done.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

from .constants import (
    CMD_BACKEND_INFO,
    CMD_MEM_READ,
    CMD_MEM_READV,
    CMD_MEM_WRITE,
    CMD_MODULE_BASE,
    CMD_PING,
    CMD_PROCESS_FIND,
    CMD_SESSION_INFO,
    CMD_TARGET_CLOSE,
    CMD_TARGET_MAPS,
    CMD_TARGET_OPEN,
    FLAG_ERROR,
    FLAG_RESPONSE,
    HEADER_SIZE,
    ProtocolError,
    b64_decode,
    parse_u64,
)
from .connection import AgentConnection, AgentError

_RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, fn) -> bool:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        _RESULTS.append((False, name, f"{type(exc).__name__}: {exc}"))
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        return False
    _RESULTS.append((True, name, ""))
    print(f"PASS {name}")
    return True


def _recv_raw_frame(sock: socket.socket, timeout: float):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < HEADER_SIZE:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("closed before frame")
        buf += chunk
    magic, version, flags, _r, seq, cmd, length = struct.unpack_from(">IBBHIII", buf, 0)
    while len(buf) < HEADER_SIZE + length:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("closed mid-frame")
        buf += chunk
    import json

    payload = json.loads(buf[HEADER_SIZE : HEADER_SIZE + length]) if length else {}
    return flags, seq, cmd, payload


def raw_connect_expect_error(host: str, port: int, want_error: str) -> None:
    sock = socket.create_connection((host, port), timeout=5)
    try:
        flags, _seq, _cmd, payload = _recv_raw_frame(sock, 5)
        if not (flags & FLAG_ERROR):
            raise AssertionError(f"expected ERROR frame, got flags={flags} payload={payload}")
        if payload.get("error") != want_error:
            raise AssertionError(f"expected error={want_error}, got {payload}")
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="tanyao-agent interop acceptance")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=52730)
    parser.add_argument("--token", default=os.environ.get("TANYAO_TOKEN", ""))
    parser.add_argument("--token-file", default=None)
    parser.add_argument("--pid", type=int, required=True, help="a live process pid on the device")
    parser.add_argument("--allow-write", action="store_true", help="include write+readback test")
    args = parser.parse_args()

    token = args.token
    if args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()

    ok = True

    # 1. wrong token must fail cleanly with auth_failed
    def bad_token():
        conn = AgentConnection(args.host, args.port, "definitely-wrong-token")
        try:
            conn.connect()
        except AgentError as exc:
            if exc.error != "auth_failed":
                raise AssertionError(f"expected auth_failed, got {exc.error}")
            return
        raise AssertionError("wrong token was accepted")

    ok &= check("auth: wrong token rejected with auth_failed", bad_token)

    # 2. main connection: hello + auth
    conn = AgentConnection(args.host, args.port, token)
    conn.connect()
    ok &= check("auth: valid token accepted", lambda: None)

    # 3. busy: second connection while first is authenticated
    ok &= check("single-connection: second conn gets busy", lambda: raw_connect_expect_error(args.host, args.port, "busy"))

    # 4. ping
    ok &= check("ping", lambda: (lambda p: (_ for _ in ()).throw(AssertionError("ok missing")) if not p.get("ok") else None)(conn.ping()))

    # 5. backend_info
    backend = {}
    def do_backend_info():
        nonlocal backend
        backend = conn.request(CMD_BACKEND_INFO, {})
        assert int(backend["abi_major"]) == 1, "abi_major != 1"
        assert parse_u64(backend["capabilities"]) != 0, "capabilities == 0"
        assert parse_u64(backend["max_transfer_size"]) > 0
    ok &= check("backend_info", do_backend_info)

    # 6. session_info
    ok &= check("session_info", lambda: parse_u64(conn.request(CMD_SESSION_INFO, {})["session_id"], field="session_id"))

    # 7. target_open
    handle = None
    def do_target_open():
        nonlocal handle
        resp = conn.request(CMD_TARGET_OPEN, {"pid": args.pid})
        handle = parse_u64(resp["handle"], field="handle")
        parse_u64(resp["start_cookie"], field="start_cookie")
    ok &= check("target_open", do_target_open)

    # 8. target_maps
    first_rx_map = None
    first_rw_map = None
    def do_target_maps():
        nonlocal first_rx_map, first_rw_map
        assert handle is not None
        resp = conn.request(CMD_TARGET_MAPS, {"handle": f"0x{handle:x}", "capacity": 4096})
        entries = resp.get("entries", [])
        assert int(resp["entry_count"]) > 0, "no maps returned"
        assert len(entries) == int(resp["entry_count"])
        for entry in entries:
            flags = int(entry["flags"])
            if flags & 1:
                if flags & 4 and first_rx_map is None and entry["path"]:
                    first_rx_map = entry
                if flags & 2 and first_rw_map is None:
                    first_rw_map = entry
        assert first_rx_map is not None, "no readable exec file map found"
    ok &= check("target_maps", do_target_maps)

    # 9. mem_read from first r-x map
    def do_mem_read():
        assert first_rx_map is not None
        start = parse_u64(first_rx_map["start"], field="start")
        resp = conn.request(CMD_MEM_READ, {"handle": f"0x{handle:x}", "addr": f"0x{start:x}", "size": "0x10"})
        assert int(resp["status"]) == 0, f"status={resp['status']}"
        data = b64_decode(resp["data_b64"])
        assert len(data) == 16, f"short read: {len(data)}"
    ok &= check("mem_read 16 bytes", do_mem_read)

    # 10. mem_readv 2 spans
    def do_mem_readv():
        assert first_rx_map is not None
        start = parse_u64(first_rx_map["start"], field="start")
        resp = conn.request(CMD_MEM_READV, {
            "handle": f"0x{handle:x}",
            "iov": [{"addr": f"0x{start:x}", "size": "0x8"},
                    {"addr": f"0x{start+8:x}", "size": "0x8"}],
        })
        assert len(resp["spans"]) == 2
        assert all(int(s["status"]) == 0 for s in resp["spans"])
    ok &= check("mem_readv", do_mem_readv)

    # 11. optional write + readback
    if args.allow_write:
        def do_write():
            assert first_rw_map is not None
            start = parse_u64(first_rw_map["start"], field="start")
            payload_in = bytes(range(16))
            resp = conn.request(CMD_MEM_WRITE, {"handle": f"0x{handle:x}", "addr": f"0x{start:x}",
                                                "data_b64": __import__("base64").b64encode(payload_in).decode()})
            assert int(resp["status"]) == 0
            assert parse_u64(resp["result_size"]) == 16
            back = conn.request(CMD_MEM_READ, {"handle": f"0x{handle:x}", "addr": f"0x{start:x}", "size": "0x10"})
            assert b64_decode(back["data_b64"]) == payload_in, "readback mismatch"
            print(f"     NOTE: wrote 16 test bytes at 0x{start:x} of {first_rw_map.get('path')}")
        ok &= check("mem_write + readback (--allow-write)", do_write)
    else:
        print("SKIP mem_write (no --allow-write)")

    # 12. unknown cmd -> unsupported_cmd, connection stays alive
    def do_unknown():
        try:
            conn.request(0xFE, {})
        except AgentError as exc:
            if exc.error != "unsupported_cmd":
                raise AssertionError(f"expected unsupported_cmd, got {exc.error}")
            return
        raise AssertionError("unknown cmd accepted")
    ok &= check("unknown cmd handling", do_unknown)

    # 13. legacy process_find (best effort: unknown-process must return not_found, not crash)
    def do_legacy():
        try:
            conn.request(CMD_PROCESS_FIND, {"name": "definitely-not-a-real-process-xyz"})
        except AgentError as exc:
            if exc.error != "not_found":
                raise AssertionError(f"expected not_found, got {exc.error}")
    ok &= check("legacy process_find (not_found path)", do_legacy)

    # 14. target_close
    def do_close():
        conn.request(CMD_TARGET_CLOSE, {"handle": f"0x{handle:x}"})
    ok &= check("target_close", do_close)

    conn.close()

    passed = sum(1 for good, _, _ in _RESULTS if good)
    failed = len(_RESULTS) - passed
    print(f"\n{passed} passed, {failed} failed, exit={'0' if failed == 0 else '1'}")
    return 0 if failed == 0 and ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
