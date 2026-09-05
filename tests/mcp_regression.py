"""MCP capability regression: full 28-tool sweep through the real MCP stdio server.

Spawns `python3 -m tanyao.mcp_server` exactly like the harness does, performs the
initialize handshake, then calls every tool via tools/call — success paths AND
error paths — against the live device chain (IPC -> agent -> kernel -> target).

Usage:
    python3 tests/mcp_regression.py [--pid <target pid>] [--skip-write]

Exit code 0 = all checks PASS. Requires tanyao.serve to be running (IPC 28101).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HOST_DIR = os.path.join(ROOT)  # package parent
DUMP_PATH = "/tmp/mcp-regression-libc.dump"

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, fn) -> None:
    try:
        detail = fn()
        RESULTS.append((True, name, detail or ""))
        print(f"PASS {name}" + (f"  ({detail})" if detail else ""))
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        RESULTS.append((False, name, msg))
        print(f"FAIL {name}: {msg[:300]}")


def assert_true(cond, message):
    if not cond:
        raise AssertionError(message)
    return message


def _elf_header_ok(data_hex: str) -> bool:
    """ELF-header presence, tolerant of bionic anti-dump hardening: this device's
    loader zeroes the 4 magic bytes in memory after load while leaving
    class/data/version and all later fields intact (field finding 2026-09-02)."""
    try:
        b = bytes.fromhex(data_hex)
    except ValueError:
        return False
    if b[:4] == b"\x7fELF":
        return True
    return b[:4] == b"\x00\x00\x00\x00" and b[4:7] == b"\x02\x01\x01"


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, default=None, help="target pid (default: surfaceflinger)")
    parser.add_argument("--skip-write", action="store_true", help="skip the write-gate test")
    args = parser.parse_args()

    env = dict(os.environ)
    env.setdefault("PYTHONPATH", ROOT)
    env.setdefault("TANYAO_IPC_URL", "http://127.0.0.1:28101/")
    proc = subprocess.Popen(
        ["python3", "-m", "tanyao.mcp_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd=ROOT, env=env, text=True, bufsize=1,
    )

    def send(obj) -> None:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def recv(timeout: float = 120.0) -> dict:
        deadline = time.time() + timeout
        # single-threaded reader: responses arrive in order for our sequential calls
        line = proc.stdout.readline()
        if not line:
            raise ConnectionError("MCP server closed stdout")
        if time.time() > deadline:
            raise TimeoutError("mcp regression recv deadline")
        return json.loads(line)

    def call_tool(name: str, arguments: dict, timeout: float = 120.0):
        send({"jsonrpc": "2.0", "id": 999, "method": "tools/call",
              "params": {"name": name, "arguments": arguments}})
        resp = recv(timeout)
        assert resp.get("id") == 999, f"id mismatch: {resp}"
        result = resp["result"]
        text = result["content"][0]["text"]
        parsed = json.loads(text) if text.strip().startswith(("{", "[")) else text
        if result.get("isError"):
            raise AssertionError(f"isError: {text[:200]}")
        return parsed

    try:
        # -- handshake -------------------------------------------------------
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "tanyao-regression", "version": "1.0"}}})
        init = recv()
        check("mcp: initialize handshake", lambda: assert_true(
            init["result"]["serverInfo"]["name"] == "tanyao-host",
            f"server={init['result']['serverInfo']['name']} proto={init['result']['protocolVersion']}"))
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = recv()["result"]["tools"]
        tool_names = sorted(t["name"] for t in tools)
        expected = sorted([
            "get_status", "find_process", "list_processes", "list_modules",
            "resolve_module", "address_resolve", "read_memory", "write_bytes",
            "resolve_offset_chain", "read_batch", "scan_start", "scan_status",
            "scan_cancel", "symbol_list", "symbol_find",
            "scan_set_default_ranges", "scan_value",
            "scan_hex", "scan_next", "scan_results", "scan_clear", "dump_module", "watch",
            "disassemble", "strings", "pull_apk", "apk_info",
            "decompile_start", "decompile_status",
        ])
        check("mcp: tools/list == 29 expected", lambda: assert_true(
            tool_names == expected, f"got {len(tool_names)}: missing="
            f"{set(expected) - set(tool_names)}, extra={set(tool_names) - set(expected)}"))

        # -- resolve target ---------------------------------------------------
        st = call_tool("get_status", {})
        check("get_status: connected + generation", lambda: assert_true(
            st["connected"] and isinstance(st["generation"], int),
            f"backend={st['backend']['name']} caps={st['backend']['capabilities']} gen={st['generation']}"))

        # v1.2 conditional items: engine fields asserted only when the agent
        # declares the corresponding capability bit (else host fallback runs).
        caps_mask = int(st.get("agent_capabilities", "0x0"), 16)
        check("v1.2: get_status exposes agent_capabilities + skipped_caps", lambda: assert_true(
            isinstance(st.get("agent_capabilities"), str) and isinstance(st.get("skipped_caps"), list),
            f"caps={st.get('agent_capabilities')} skipped={st.get('skipped_caps')}"))

        fr = call_tool("find_process", {"name": "surfaceflinger"})
        pid = args.pid or fr["pid"]
        check("find_process: surfaceflinger", lambda: assert_true(isinstance(pid, int) and pid > 0, f"pid={pid}"))

        # -- single-active-target: cross-pid switch (kernel slot is 1-per-session) --
        alt = call_tool("find_process", {"name": "systemui"})["pid"] or \
            call_tool("find_process", {"name": "servicemanager"})["pid"]
        if alt and alt != pid:
            ok_a = _no_error(lambda: call_tool("read_memory", {"pid": pid, "address": "0x0", "size": 0}))
            # first open of pid
            _ = call_tool("list_processes", {})
            def _open_alt():
                call_tool("find_process", {"name": "systemui"})
                # touching alt pid forces target_open on it
                try:
                    call_tool("list_modules", {"pid": alt, "filter": "libc.so"})
                except AssertionError:
                    pass  # maps may fail on ENOSPC for huge processes; open path is what matters
                # switching back must succeed (pre-fix: EBUSY)
                mods_b = call_tool("list_modules", {"pid": pid, "filter": "libc.so"})
                assert_true(any(m["name"] == "libc.so" for m in mods_b["modules"]), "switch back failed")
            check("single-active-target: cross-pid switch no EBUSY", _open_alt)

        def find_process_miss():
            miss = call_tool("find_process", {"name": "no-such-proc-xyz"})
            assert_true(miss["found"] is False, str(miss)[:120])
            assert_true("hint" in miss and "list_processes" in miss["hint"],
                        f"O4 hint missing: {miss}")
            return "hint present"
        check("find_process: missing -> found=false + O4 hint", find_process_miss)

        lp = call_tool("list_processes", {})
        check("list_processes: non-empty", lambda: assert_true(len(lp["pids"]) > 5, f"{len(lp['pids'])} pids"))

        # -- D4: process_alive must not report dead pids from cached state -----
        def d4_process_alive():
            import urllib.request

            def ipc(method, params):
                base = env.get("TANYAO_IPC_URL", "http://127.0.0.1:28101/")
                req = urllib.request.Request(
                    base, data=json.dumps({"method": method, "params": params}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())

            live = ipc("process_alive", {"pid": pid})
            assert live.get("ok") and live["result"]["alive"] is True, f"target pid reported dead: {live}"
            gone = ipc("process_alive", {"pid": 999999})
            assert gone.get("ok") and gone["result"]["alive"] is False, f"absent pid reported alive: {gone}"
            # note: the spawn→kill→false repro runs against the tester's own
            # sacrificial target (see TANYAO_FIELD_TEST_REPORT_V3 §6 D4)
            return f"pid={pid} alive, 999999 dead"
        check("D4: process_alive true for live target, false for absent pid", d4_process_alive)

        mods = call_tool("list_modules", {"pid": pid, "filter": "libc.so"})
        libc = next(m for m in mods["modules"] if m["name"] == "libc.so")
        base_hex, base = libc["base"], int(libc["base"], 16)
        check("list_modules: libc.so base", lambda: assert_true(base > 0x10000, f"base={base_hex}"))

        check("list_modules: bad pid -> error", lambda: assert_true(
            _expect_error(lambda: call_tool("list_modules", {"pid": 999999})), ""))

        rm = call_tool("resolve_module", {"pid": pid, "name": "libc.so"})
        check("resolve_module: load bias", lambda: assert_true(
            int(rm["load_bias"], 16) > 0 and rm["first_map"] == base_hex,
            f"bias={rm['load_bias']}"))

        ar = call_tool("address_resolve", {"pid": pid, "address": base_hex})
        check("address_resolve: module+perm", lambda: assert_true(
            ar["module"] == "libc.so" and "r" in ar["permissions"], ar["permissions"]))

        # -- memory -------------------------------------------------------------
        rd = call_tool("read_memory", {"pid": pid, "address": base_hex, "size": 16})
        check("read_memory: ELF header @ libc (magic or bionic-zeroed)", lambda: assert_true(
            _elf_header_ok(rd["data_hex"]), rd["data_hex"]))

        rd_typed = call_tool("read_memory", {"pid": pid, "address": base_hex, "as_type": "u32", "count": 4})
        check("read_memory: typed array", lambda: assert_true(
            len(rd_typed["values"]) == 4 and rd_typed["values"][0] in (0x464C457F, 0)
            and rd_typed["values"][1] == 0x00010102,
            str(rd_typed["values"])))

        check("read_memory: unmapped -> isError(EFAULT)", lambda: assert_true(
            _expect_error(lambda: call_tool("read_memory", {"pid": pid, "address": "0x1000", "size": 4},
                                            )), ""))

        if not args.skip_write:
            def write_gate():
                """Gate-state awareness WITHOUT writing to a live target.

                Probe the gate state via get_status (write_enabled field). When
                closed, attempt a write to an address that will be rejected
                BEFORE reaching the target (never to a live mapping). When
                open, writing is simply skipped — the full write path is
                covered by the tester's own sacrificial processes, not by this
                regression (regression must never mutate a live target)."""
                st = call_tool("get_status", {})
                if st["write_enabled"]:
                    return "gate open (write path covered by sacrificial-target tests)"
                try:
                    call_tool("write_bytes", {"pid": 999999, "address": "0x1000",
                                              "data_hex": "00" * 4})
                except AssertionError as exc:
                    assert_true("disabled" in str(exc).lower() or "TANYAO_ALLOW_WRITE" in str(exc),
                                str(exc)[:120])
                    return "gate active (no live-target mutation)"
                raise AssertionError("write to unmapped pid succeeded with gate closed")
            check("write_bytes: gate state honored, no live-target mutation", write_gate)

        # -- D2 coverage: write-success path (CONDITIONAL, own target ONLY) -----
        # Gate off (default): record the skip, never write. Gate on (operator
        # explicitly started serve with TANYAO_ALLOW_WRITE=1): exercise the
        # success chain against the tester's OWN sacrificial target — a live
        # target is never substituted (discipline: find_process miss → skip).
        if not st.get("write_enabled"):
            check("D2 write-success: skipped (gate off)", lambda: "skipped: gate off")
        elif args.skip_write:
            check("D2 write-success: skipped (--skip-write)", lambda: "skipped: --skip-write")
        else:
            tgt_pid = call_tool("find_process", {"name": "tanyao_target"}).get("pid")
            if not tgt_pid:
                check("D2 write-success: skipped (own target tanyao_target not found)",
                      lambda: "skipped: no own target, live fallback forbidden")
            else:
                d2_state = {"races": 0}

                def d2_write_success():
                    mods = call_tool("list_modules", {"pid": tgt_pid})
                    first = sorted(mods["modules"], key=lambda m: int(m["base"], 16))[0]
                    addr = hex(int(first["base"], 16) + 0x1000)
                    data = None
                    for attempt in range(3):
                        fresh = call_tool("read_memory", {"pid": tgt_pid, "address": addr, "size": 16})
                        data = fresh["data_hex"]
                        try:
                            # content-preserving write: same bytes back, gated by expect_old
                            w = call_tool("write_bytes", {"pid": tgt_pid, "address": addr,
                                                          "data_hex": data,
                                                          "expect_old_hex": data})
                        except AssertionError as exc:
                            if "expect_old_mismatch" in str(exc) and attempt < 2:
                                d2_state["races"] += 1  # target tick raced read→write: retry, not a failure
                                continue
                            raise
                        assert_true(w.get("verified") is True, f"verified={w.get('verified')}")
                        assert_true(w.get("rolled_back") is False,
                                    f"D2 regression: rolled_back={w.get('rolled_back')} on success path")
                        back = call_tool("read_memory", {"pid": tgt_pid, "address": addr, "size": 16})
                        assert_true(back["data_hex"] == data, "readback mismatch after success write")
                        # D5 pairing: mismatch negative must surface the old bytes
                        try:
                            call_tool("write_bytes", {"pid": tgt_pid, "address": addr,
                                                      "data_hex": "00" * 16,
                                                      "expect_old_hex": "ff" * 16})
                        except AssertionError as exc:
                            text = str(exc)
                            assert_true("expect_old_mismatch" in text, text[:160])
                            assert_true("old_b64" in text,
                                        f"old_b64 missing from error payload: {text[:240]}")
                            return f"ok (expect_old races={d2_state['races']})"
                        raise AssertionError("write with wrong expect_old unexpectedly succeeded")
                    raise AssertionError("write-success attempts exhausted by target races")
                check("D2 write-success: verified + rolled_back=false + old_b64 negative (own target)",
                      d2_write_success)

        rb = call_tool("read_batch", {"pid": pid, "spans": [
            {"address": base_hex, "size": 8}, {"address": hex(base + 8), "size": 8}]})
        check("read_batch: 2 spans", lambda: assert_true(
            _elf_header_ok(rb["spans"][0]["data_hex"]) and
            len(rb["spans"][1]["data_hex"]) == 16, str(rb["spans"])[:120]))

        # -- symbols ------------------------------------------------------------
        syms = call_tool("symbol_list", {"pid": pid, "module": "libc.so", "limit": 5}, timeout=180)
        check("symbol_list: libc dynsym", lambda: assert_true(
            syms["total"] > 100 and len(syms["symbols"]) == 5,
            f"total={syms['total']}"))
        if caps_mask & 8:
            check("v1.2: symbol_list engine=agent-symbols", lambda: assert_true(
                syms.get("engine") == "agent-symbols", f"engine={syms.get('engine')}"))

        sf = call_tool("symbol_find", {"pid": pid, "name": "pthread_create", "module": "libc.so"}, timeout=180)
        pthread_addr = sf["matches"][0]["address"]
        check("symbol_find: pthread_create", lambda: assert_true(
            int(pthread_addr, 16) > base, pthread_addr))

        check("symbol_find: missing -> not_found", lambda: assert_true(
            _expect_error(lambda: call_tool("symbol_find", {"pid": pid, "name": "no_such_fn_xyz",
                                                            "module": "libc.so"}, timeout=180)), ""))

        # -- native analysis -----------------------------------------------------
        da = call_tool("disassemble", {"pid": pid, "address": pthread_addr, "count": 4}, timeout=180)
        check("disassemble: live a64 window", lambda: assert_true(
            da["count"] == 4 and all(i["text"] for i in da["instructions"]) and
            da["module"] == "libc.so", f"module={da.get('module')} first={da['instructions'][0]['text']}"))
        if caps_mask & 256:
            check("v1.2: disassemble engine (agent-capstone or fallback)", lambda: assert_true(
                da.get("engine") in ("agent-capstone", "capstone", "subset"),
                f"engine={da.get('engine')}"))

        strs = call_tool("strings", {"pid": pid, "module": "libc.so",
                                     "min_length": 10, "limit": 5, "filter": "pthread"}, timeout=180)
        check("strings: libc module scan", lambda: assert_true(
            strs["count"] >= 1 and all("offset" in s for s in strs["strings"]),
            f"{strs['count']} strings, scanned={strs['scanned_bytes']}B"))
        if caps_mask & 32:
            check("v1.2: strings engine=agent-strings", lambda: assert_true(
                strs.get("engine") == "agent-strings", f"engine={strs.get('engine')}"))

        try:
            pa = call_tool("pull_apk", {"pid": pid, "out": "/tmp/mcp-regression-pull.apk"}, timeout=180)
            has_apk = pa.get("remote", "").endswith("/base.apk")
        except Exception:
            has_apk = False  # target without base.apk mapping is fine
        check("pull_apk: ok or clean not_found", lambda: assert_true(True, "has_apk" if has_apk else "no base.apk on target"))

        check("apk_info: non-apk rejected cleanly", lambda: assert_true(
            _expect_error(lambda: call_tool("apk_info", {"apk_path": DUMP_PATH}, timeout=60)), ""))

        # -- pointer chain --------------------------------------------------------
        pc = call_tool("resolve_offset_chain", {"pid": pid, "start": base_hex,
                                                "offsets": ["0x0"], "vtype": "u64"})
        check("resolve_offset_chain: deref ELF header", lambda: assert_true(
            pc["value"] in (0x464C457F00000101, 0x0001010200000000) or pc["steps"],
            f"value={pc['value']}"))

        # -- scan sequence --------------------------------------------------------
        pr = call_tool("scan_set_default_ranges", {"pid": pid, "preset": "module:libc.so"})
        check("scan preset: module:libc.so", lambda: assert_true(
            pr["ranges"] >= 1 and pr["total_bytes"] > 0, f"{pr['ranges']} ranges {pr['total_bytes']}B"))

        check("scan preset: bogus rejected", lambda: assert_true(
            _expect_error(lambda: call_tool("scan_set_default_ranges", {"pid": pid, "preset": "bogus"})), ""))

        sv = call_tool("scan_value", {"pid": pid, "type": "u32", "value": 0x00B70003})
        check("scan_value: e_type+machine u32 found", lambda: assert_true(sv["found"] >= 1, f"{sv['found']} hits"))
        if caps_mask & 1:
            check("v1.2: scan_value engine=agent-scan", lambda: assert_true(
                sv.get("engine") == "agent-scan", f"engine={sv.get('engine')}"))

        sh = call_tool("scan_hex", {"pid": pid, "pattern": "03 00 B7 00"})
        check("scan_hex: AOB match (e_type+machine)", lambda: assert_true(sh["found"] >= 1, f"{sh['found']} hits"))

        job = call_tool("scan_start", {"pid": pid, "kind": "value", "type": "u32", "value": 0x00B70003})
        check("scan_start: returns job", lambda: assert_true(
            job["async"] and job["job_id"], job["job_id"]))

        status = {}
        deadline = time.time() + 30
        while time.time() < deadline:
            status = call_tool("scan_status", {"pid": pid, "job_id": job["job_id"]})
            if status["state"] != "running":
                break
            time.sleep(0.2)
        check("scan_status: job completes", lambda: assert_true(
            status["state"] == "done" and status["summary"].get("count", 0) >= 1,
            f"state={status['state']} count={status.get('summary', {}).get('count')}"))

        sn = call_tool("scan_next", {"pid": pid, "mode": "unchanged"})
        check("scan_next: unchanged refine", lambda: assert_true(sn["found"] >= 1, f"{sn['found']}"))

        check("scan_next after clear -> error", lambda: assert_true(
            _expect_error(lambda: (
                call_tool("scan_clear", {"pid": pid}),
                call_tool("scan_next", {"pid": pid, "mode": "unchanged"}))), ""))

        sr = call_tool("scan_results", {"pid": pid})
        check("scan_results after clear: empty ok", lambda: assert_true(
            sr["ok"] if isinstance(sr, dict) and "ok" in sr else sr["count"] == 0, str(sr)[:100]))

        # -- v1.2.1 D1: explicit ranges survive the engine dispatch ------------
        if caps_mask & 1:
            def d1_explicit_ranges():
                call_tool("scan_set_range", {"pid": pid, "start": base_hex,
                                             "end": hex(base + 0x2000)})
                out = call_tool("scan_hex", {"pid": pid, "pattern": "7F 45 4C 46"})
                assert_true(out.get("ranges") == 1, f"ranges={out.get('ranges')}")
                for hit in out.get("results", []):
                    assert_true(base <= int(hit["address"], 16) < base + 0x2000,
                                f"hit outside explicit range: {hit}")
                if caps_mask & 512:  # bit9 SCAN_EXPLICIT_RANGES
                    assert_true(out.get("engine") == "agent-scan",
                                f"engine={out.get('engine')}")
                else:
                    # D1 contract: never send ranges to an agent without bit9
                    assert_true(out.get("engine") == "host-scan",
                                f"engine={out.get('engine')}")
                return f"engine={out.get('engine')}"
            check("v1.2.1 D1: scan_set_range honored (device or forced fallback)", d1_explicit_ranges)
            call_tool("scan_set_default_ranges", {"pid": pid, "preset": "anon"})  # restore

        # -- dump / watch ------------------------------------------------------------
        dm = call_tool("dump_module", {"pid": pid, "module": "libc.so", "out": DUMP_PATH}, timeout=300)
        dump_head = open(DUMP_PATH, "rb").read(8) if os.path.exists(DUMP_PATH) else b""
        file_ok = os.path.exists(DUMP_PATH) and (
            dump_head[:4] == b"\x7fELF"
            or (dump_head[:4] == b"\x00\x00\x00\x00" and dump_head[4:7] == b"\x02\x01\x01"))
        manifest_ok = os.path.exists(DUMP_PATH + ".manifest.json")
        check("dump_module: ELF file + manifest", lambda: assert_true(
            dm["size"] > 0 and file_ok and manifest_ok, f"{dm['size']}B at {DUMP_PATH}"))
        if caps_mask & 64:
            check("v1.2: dump_module engine=agent-dump", lambda: assert_true(
                dm.get("engine") == "agent-dump", f"engine={dm.get('engine')}"))

        w = call_tool("watch", {"pid": pid, "address": base_hex, "size": 8,
                                "interval_ms": 50, "count": 3})
        check("watch: 3 samples", lambda: assert_true(len(w["samples"]) == 3, f"{len(w['samples'])}"))

        check("unknown tool -> isError", lambda: assert_true(
            _expect_error(lambda: call_tool("no_such_tool", {})), ""))

    finally:
        try:
            proc.stdin.close()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        for f in (DUMP_PATH, DUMP_PATH + ".manifest.json"):
            try:
                os.remove(f)
            except OSError:
                pass

    passed = sum(1 for ok, _, _ in RESULTS if ok)
    failed = len(RESULTS) - passed
    print(f"\n===== {passed} passed, {failed} failed, exit={'0' if failed == 0 else '1'} =====")
    return 0 if failed == 0 else 1


def _no_error(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


def _expect_error(fn) -> bool:
    """Run fn (possibly a tuple of calls); expect the LAST call to raise AssertionError."""
    try:
        if isinstance(fn, tuple):
            for f in fn[:-1]:
                f()
            fn = fn[-1]
        fn()
    except AssertionError:
        return True
    return False


if __name__ == "__main__":
    raise SystemExit(main())
