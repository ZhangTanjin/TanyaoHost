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
    AGENT_CAP_APK_INFO,
    AGENT_CAP_DISASSEMBLE,
    AGENT_CAP_DUMP_PIPELINE,
    AGENT_CAP_SCAN,
    AGENT_CAP_STRINGS,
    AGENT_CAP_SYMBOL_BATCH,
    CMD_BACKEND_INFO,
    CMD_MEM_READ,
    CMD_MEM_READV,
    CMD_MEM_WRITE,
    CMD_MODULE_BASE,
    CMD_PING,
    CMD_PROCESS_FIND,
    CMD_SESSION_INFO,
    CMD_SYMBOL_BATCH,
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
from .frames import decode_dump_chunk
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

    # -- v1.2 conditional capability checks (draft §7: declared → check,
    #    undeclared → record in skipped_caps and skip) ---------------------------
    skipped_caps: list[str] = []
    caps = conn.agent_capabilities

    if caps & AGENT_CAP_SCAN:
        def do_agent_scan():
            assert first_rx_map is not None
            base = parse_u64(first_rx_map["start"], field="start")
            module = (first_rx_map.get("path") or "").rsplit("/", 1)[-1]
            resp = conn.request(CMD_MEM_READ, {"handle": f"0x{handle:x}",
                                               "addr": f"0x{base + 0x100:x}", "size": "0x4"})
            data = b64_decode(resp["data_b64"])
            pattern = " ".join(f"{b:02X}" for b in data)
            job = conn.request(50, {"pid": args.pid, "kind": "hex", "pattern": pattern,
                                    "preset": f"module:{module}"})
            deadline = time.time() + 60
            status = {"state": "running"}
            while time.time() < deadline:
                status = conn.request(51, {"job_id": job["job_id"]})
                if status.get("state") != "running":
                    break
                time.sleep(0.2)
            assert status.get("state") == "done", f"scan job state={status.get('state')} err={status.get('error')}"
            assert parse_u64(status.get("total_bytes", "0x0"), field="total_bytes") > 0
            results = conn.request(53, {"offset": 0, "limit": 16})
            assert isinstance(results.get("hits"), list), "scan_results missing hits"
            print(f"     NOTE: agent scan '{pattern}' in {module}: "
                  f"{results.get('total', results.get('count'))} hits")
        ok &= check("agent scan (cmd 50/51/53)", do_agent_scan)

        def do_agent_scan_clear():
            resp = conn.request(55, {})
            assert resp.get("ok") is True
        ok &= check("agent scan_clear (cmd 55)", do_agent_scan_clear)
    else:
        skipped_caps.append("scan")

    if caps & AGENT_CAP_SCAN and not caps & AGENT_CAP_SCAN_EXPLICIT_RANGES:
        skipped_caps.append("scan_explicit_ranges")
    if caps & AGENT_CAP_SCAN_EXPLICIT_RANGES:
        def do_agent_scan_ranges():
            assert first_rx_map is not None
            base = parse_u64(first_rx_map["start"], field="start")
            span = 0x1000
            # preset must be ignored when ranges are present (v1.2.1 附录)
            job = conn.request(50, {"pid": args.pid, "kind": "hex",
                                    "pattern": "00 00 00 00",
                                    "preset": "all_readable",
                                    "ranges": [{"addr": f"0x{base:x}",
                                                "size": f"0x{span:x}"}]})
            deadline = time.time() + 60
            status = {"state": "running"}
            while time.time() < deadline:
                status = conn.request(51, {"job_id": job["job_id"]})
                if status.get("state") != "running":
                    break
                time.sleep(0.2)
            assert status.get("state") == "done", f"ranges scan state={status.get('state')}"
            assert parse_u64(status.get("total_bytes", "0x0"), field="total_bytes") == span, \
                f"ranges ignored: total_bytes={status.get('total_bytes')}"
            conn.request(55, {})
        ok &= check("agent scan explicit ranges (cmd 50 ranges, bit9)", do_agent_scan_ranges)

    if caps & AGENT_CAP_SYMBOL_BATCH:
        def do_symbol_batch():
            assert first_rx_map is not None
            module = (first_rx_map.get("path") or "").rsplit("/", 1)[-1]
            resp = conn.request(CMD_SYMBOL_BATCH, {"pid": args.pid, "module": module,
                                                   "format": "json"})
            count = int(resp["count"])
            assert count > 0, "symbol_batch returned zero symbols"
            for field in ("names", "addresses", "sizes", "types"):
                assert len(resp[field]) == count, f"{field} column misaligned"
            if "binds" in resp:
                assert len(resp["binds"]) == count
            print(f"     NOTE: symbol_batch {module}: {count} symbols")
        ok &= check("symbol_batch json (cmd 61)", do_symbol_batch)
    else:
        skipped_caps.append("symbol_batch")

    if caps & AGENT_CAP_STRINGS:
        def do_strings_scan():
            assert first_rx_map is not None
            module = (first_rx_map.get("path") or "").rsplit("/", 1)[-1]
            resp = conn.request(62, {"pid": args.pid, "preset": f"module:{module}",
                                     "min_len": 8, "max_results": 16})
            assert int(resp["count"]) >= 0
            for item in resp.get("results", []):
                assert "address" in item and "value" in item
        ok &= check("strings_scan sync (cmd 62)", do_strings_scan)
    else:
        skipped_caps.append("strings")

    if not caps & AGENT_CAP_DUMP_PIPELINE:
        skipped_caps.append("dump_pipeline")
    else:
        def do_dump_pipeline():
            import hashlib
            import zlib

            assert first_rx_map is not None
            module = (first_rx_map.get("path") or "").rsplit("/", 1)[-1]
            start = conn.request(63, {"pid": args.pid, "module": module})
            dump_id, want_sha = start["dump_id"], start["sha256"]
            hasher = hashlib.sha256()
            offset = 0
            while True:
                frame = conn.request_raw(65, {"dump_id": dump_id,
                                              "offset": f"0x{offset:x}",
                                              "chunk": "0x40000", "compress": True})
                if not isinstance(frame.payload, bytes):
                    raise AssertionError("dump_pull returned a JSON frame")
                chunk = decode_dump_chunk(frame.payload)
                if chunk.offset != offset:
                    raise AssertionError(f"offset drift: {chunk.offset} != {offset}")
                data = chunk.data
                if chunk.is_deflated:
                    data = zlib.decompress(data)
                hasher.update(data)
                offset += len(data)
                if chunk.is_last:
                    break
            assert hasher.hexdigest() == want_sha, "pull sha256 != dump_start sha256"
            conn.request(68, {"dump_id": dump_id})
            print(f"     NOTE: pipeline dump {module}: {offset}B, sha256 verified, cleaned up")
        ok &= check("dump pipeline pull+sha256+cleanup (cmd 63/65/68)", do_dump_pipeline)

    if not caps & AGENT_CAP_APK_INFO:
        skipped_caps.append("apk_info")
    else:
        def do_apk_info():
            try:
                resp = conn.request(66, {"pid": args.pid})
            except AgentError as exc:
                # a target without a base.apk mapping is a clean not_found
                if exc.error == "not_found":
                    print("     NOTE: apk_info: target has no base.apk mapping (ok)")
                    return
                raise
            assert resp.get("package"), "apk_info missing package"
        ok &= check("apk_info (cmd 66)", do_apk_info)

    if not caps & AGENT_CAP_DISASSEMBLE:
        skipped_caps.append("disassemble")
    else:
        def do_disassemble():
            assert first_rx_map is not None
            start = parse_u64(first_rx_map["start"], field="start")
            try:
                resp = conn.request(67, {"pid": args.pid, "addr": f"0x{start + 0x100:x}",
                                         "count": 4})
            except AgentError as exc:
                # declared but built without capstone: declared-unsupported path
                if exc.error == "unsupported":
                    print("     NOTE: disassemble declared but unsupported (no capstone)")
                    return
                raise
            assert int(resp["count"]) == 4 and len(resp["instructions"]) == 4
            for ins in resp["instructions"]:
                assert "address" in ins and "bytes_hex" in ins and "mnemonic" in ins
        ok &= check("disassemble (cmd 67)", do_disassemble)

    conn.close()

    if skipped_caps:
        print(f"skipped_caps: [{', '.join(skipped_caps)}] (capability not declared)")

    passed = sum(1 for good, _, _ in _RESULTS if good)
    failed = len(_RESULTS) - passed
    print(f"\n{passed} passed, {failed} failed, exit={'0' if failed == 0 else '1'}")
    return 0 if failed == 0 and ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
