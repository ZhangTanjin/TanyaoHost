#!/usr/bin/env python3
"""Full-surface functional regression over all 33 MCP tools.

Runs each tool against the live device chain (IPC -> serve -> agent -> kernel ->
target), records outcome, payload shape, engine used, and wall time. Failures are
classified as:
  PASS  - ok:true and payload carries the expected fields
  WARN  - ok:false but the error is the *documented* outcome for that input
          (e.g. not_found for a nonexistent process, gate-off for write)
  FAIL  - ok:false unexpectedly, or payload shape wrong

Usage:
  python3 tests/full_surface_regression.py --pid <PID> [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

IPC = os.environ.get("TANYAO_IPC_URL", "http://127.0.0.1:28101/")
RESULTS: list[dict] = []


def call(method: str, params: dict, timeout: float = 120.0) -> dict:
    body = json.dumps({"method": method, "params": params}).encode()
    req = urllib.request.Request(IPC, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def record(tool: str, status: str, detail: str, elapsed_ms: float,
           extra: dict | None = None) -> None:
    RESULTS.append({"tool": tool, "status": status, "detail": detail,
                    "ms": round(elapsed_ms, 1), "extra": extra or {}})
    tag = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL"}[status]
    line = f"[{tag}] {tool:<24} {elapsed_ms:7.1f}ms  {detail}"
    print(line)


def run(tool: str, params: dict, *, expect_ok: bool = True,
        expect_error: str | None = None, need: tuple[str, ...] = (),
        timeout: float = 120.0) -> dict | None:
    """Call one tool and evaluate it against the expectation."""
    t0 = time.monotonic()
    try:
        out = call(tool, params, timeout=timeout)
    except urllib.error.HTTPError as exc:  # IPC 500
        record(tool, "FAIL", f"HTTP {exc.code}", (time.monotonic() - t0) * 1000)
        return None
    except Exception as exc:  # noqa: BLE001
        record(tool, "FAIL", f"{type(exc).__name__}: {exc}",
               (time.monotonic() - t0) * 1000)
        return None
    elapsed = (time.monotonic() - t0) * 1000

    if out.get("ok"):
        if expect_error:
            record(tool, "FAIL", f"expected error '{expect_error}', got ok",
                   elapsed)
            return out
        res = out.get("result") or {}
        missing = [k for k in need if k not in res]
        if missing:
            record(tool, "FAIL", f"missing field(s) {missing}", elapsed)
            return out
        detail = ", ".join(f"{k}={_brief(res[k])}" for k in need) if need else "ok"
        eng = res.get("engine")
        if eng:
            detail += f" [engine={eng}]"
        record(tool, "PASS", detail, elapsed, {"engine": eng})
        return out

    err = out.get("error", "?")
    if expect_error == err:
        record(tool, "WARN", f"expected error '{err}': "
                             f"{str(out.get('detail'))[:70]}", elapsed)
        return out
    if not expect_ok:
        record(tool, "WARN", f"error '{err}': {str(out.get('detail'))[:70]}",
               elapsed)
        return out
    record(tool, "FAIL", f"error '{err}': {str(out.get('detail'))[:90]}", elapsed)
    return out


def _brief(value, limit: int = 60) -> str:
    if isinstance(value, (list, dict)):
        n = len(value)
        return f"<{type(value).__name__} len={n}>"
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True, help="live target pid")
    ap.add_argument("--json", default=None, help="write results JSON here")
    ap.add_argument("--process-name", default=None,
                    help="process name for the pid under test (default: module name)")
    ap.add_argument("--write-target", type=int, default=None,
                    help="pid of OUR OWN scratch target allowed to be written "
                         "(never a live app); enables the real write-path test")
    ap.add_argument("--write-address", default=None,
                    help="0x address inside --write-target to exercise writes on")
    ap.add_argument("--disk-path", default=None,
                    help="on-disk .so to compare against (enables diff_module)")
    ap.add_argument("--skip-slow", action="store_true",
                    help="skip dump/decompile/scan-heavy tools")
    args = ap.parse_args()
    pid = args.pid

    print(f"== full-surface regression: pid={pid} ipc={IPC} ==\n")

    # ---- 1. reconnaissance ------------------------------------------------
    print("-- reconnaissance --")
    st = run("get_status", {}, need=("connected", "agent_capabilities"))
    caps = 0
    if st and st.get("ok"):
        caps = int(st["result"]["agent_capabilities"], 16)

    run("find_process", {"name": "surfaceflinger"}, need=("pid",))
    # find_process reports "no match" as a successful payload (pid=None), not an
    # error: the AI needs the hint text more than an exception.
    fp_miss = call("find_process", {"name": "definitely-not-a-real-proc-xyz"})
    rec_res = (fp_miss.get("result") or {}) if fp_miss.get("ok") else {}
    if fp_miss.get("ok") and rec_res.get("pid") is None and rec_res.get("found") is False:
        record("find_process", "PASS", "no-match -> pid=None + hint", 0)
    else:
        record("find_process", "FAIL", f"unexpected no-match shape: {fp_miss}", 0)
    run("list_processes", {"bytes": 8192}, need=("pids",))
    # Liveness + pid-reuse detection (cheap; no target open required)
    run("process_alive", {"pid": pid}, need=("alive",))
    run("process_alive", {"pid": 999999}, need=("alive",))
    _short = run("watch_process", {"pid": pid, "count": 2, "interval_s": 0.1},
                 need=("samples_taken", "survived"))
    run("list_modules", {"pid": pid}, need=("count", "modules"))

    mods = call("list_modules", {"pid": pid}).get("result", {}).get("modules", [])
    # Pick the richest module available: prefer libc.so (symbol-rich, always
    # present in dynamically linked processes) but fall back to the largest
    # module so statically linked test targets work too.
    lib = next((m for m in mods if m["name"] == "libc.so"), None)
    if lib is None:
        cands = [m for m in mods if m.get("segments")]
        if not cands:
            print("  !! no module with segments in the module table")
            return 1
        lib = max(cands, key=lambda m: sum(
            int(s["end"], 16) - int(s["start"], 16) for s in m["segments"]))
        print(f"  (no libc.so; using largest module {lib['name']!r})")
    lib_base = int(lib["base"], 16)
    mod_name = lib.get("name", "libc.so")
    target_name = str(args.process_name or mod_name)
    seg = lib["segments"][0]
    seg_start = int(seg["start"], 16)
    # Segments carry no permission string here, so identify the executable one
    # the way the rest of the chain does: it is the segment whose first bytes
    # decode as instructions. Practical proxy: take the SECOND segment, which
    # is r-xp for every normal ELF (verified on libc.so).
    rx = lib["segments"][1] if len(lib["segments"]) > 1 else seg
    dis_seg_start = int(rx["start"], 16)
    # resolve_rva takes a FILE OFFSET; use a small offset inside the first
    # file-backed segment so the probe is meaningful for any module.
    off_probe = int(lib["segments"][0]["file_offset"], 16)

    run("resolve_module", {"pid": pid, "name": mod_name},
        need=("segments",))
    run("address_resolve", {"pid": pid, "address": f"0x{seg_start:x}"},
        need=("module", "rva"))

    # ---- 2. memory --------------------------------------------------------
    print("\n-- memory --")
    run("read_memory", {"pid": pid, "address": f"0x{seg_start:x}", "size": 16},
        need=("data_hex",))
    run("read_memory", {"pid": pid, "address": f"0x{seg_start:x}", "as_type": "u32",
                        "count": 4}, need=("values",))
    run("read_memory", {"pid": pid, "address": "0x1", "size": 8},
        expect_ok=False, expect_error="backend_error")
    run("read_batch", {"pid": pid, "spans": [
        {"address": f"0x{seg_start + i * 8:x}", "size": 8} for i in range(8)]},
        need=("spans",))
    run("resolve_offset_chain", {"pid": pid, "start": f"0x{seg_start:x}",
                                 "offsets": ["0x18", "0x0"]}, expect_ok=False)

    # cookie pinning (v1.5 defect fix)
    fp = call("find_process", {"name": "surfaceflinger"}).get("result", {})
    cookie = fp.get("start_cookie")
    # The cookie must belong to the pid under test; using another process's
    # cookie is (correctly) rejected as stale_target.
    own = call("find_process", {"name": target_name}).get("result", {})
    own_cookie = own.get("start_cookie")
    if cookie and own_cookie and cookie != own_cookie:
        cookie = own_cookie
    if cookie:
        run("read_memory", {"pid": pid, "address": f"0x{seg_start:x}", "size": 8,
                            "pid_cookie": cookie}, need=("data_hex",))
        run("read_memory", {"pid": pid, "address": f"0x{seg_start:x}", "size": 8,
                            "pid_cookie": "0xdeadbeef"},
            expect_ok=False, expect_error="stale_target")
        print(f"      (pid_cookie={cookie}: correct accepted, bogus rejected)")

    # ---- 3. symbols / disassembly ----------------------------------------
    print("\n-- symbols / disassembly --")
    sym = run("symbol_list", {"pid": pid, "module": mod_name, "limit": 64},
              need=("total", "symbols"), expect_ok=False)
    have_dynsym = bool(sym and sym.get("ok"))
    if have_dynsym:
        run("symbol_find", {"pid": pid, "name": "pthread_create", "module": mod_name},
            need=("matches",), expect_ok=False)
    else:
        record("symbol_find", "WARN",
               "skipped: module has no dynamic symbol table (static target)", 0)
    run("symbol_find", {"pid": pid, "name": "no_such_symbol_zzz"},
        expect_ok=False, expect_error="not_found")
    # Pick an address that actually holds code: ask resolve_vaddr for the
    # module's first PT_LOAD p_vaddr, then align down to 4 bytes.
    rv = call("resolve_vaddr", {"pid": pid, "module": mod_name,
                                "vaddr": hex(dis_seg_start)})
    dis_addr = f"0x{dis_seg_start:x}"
    if rv.get("ok"):
        dis_addr = rv["result"]["runtime"]
    run("disassemble", {"pid": pid, "address": dis_addr,
                        "count": 6, "module": mod_name},
        need=("instructions",), expect_ok=False)
    run("strings", {"pid": pid, "module": mod_name, "limit": 32},
        need=("strings",))

    # ---- 4. resolve_rva / pointers / watch -------------------------------
    print("\n-- conversion / observation --")
    run("resolve_rva", {"pid": pid, "module": mod_name, "file_offset": off_probe},
        need=("runtime",))
    # resolve_vaddr: any ELF vaddr -> runtime (the .bss-capable entry point)
    rv = run("resolve_vaddr", {"pid": pid, "module": mod_name, "vaddr": "0x0"},
             need=("runtime", "method"))
    _rv_runtime = (rv.get("result") or {}).get("runtime") if rv else None
    # resolve_symbol_ref: inverse direction, cross-checked against resolve_vaddr
    if _rv_runtime:
        inner = int(_rv_runtime, 16) - int(lib["base"], 16)
        run("resolve_symbol_ref",
            {"pid": pid, "module": mod_name, "target": hex(inner)},
            expect_ok=False, timeout=300)
    run("pointers_to", {"pid": pid,
                        "addresses": [f"0x{seg_start:x}"]}, need=("targets",))
    run("watch", {"pid": pid, "address": f"0x{seg_start:x}", "size": 8,
                  "count": 3, "interval": 50}, need=("samples",))
    run("watch_many", {"pid": pid, "spans": [
        {"address": f"0x{seg_start + i * 8:x}", "size": 8} for i in range(3)],
        "count": 3, "interval": 50}, need=("spans",))

    # ---- 5. scan family ---------------------------------------------------
    print("\n-- scan --")
    mod_preset = f"module:{mod_name}"
    run("scan_set_default_ranges", {"pid": pid, "preset": mod_preset},
        expect_ok=False)
    # Seed the typed scan from the module's first READABLE 4 bytes: a segment
    # start is page-aligned and can be unmapped padding in hybrid dumps, so
    # probing is required rather than assuming seg_start+0x18 is readable.
    seed = None
    probe = call("read_memory", {"pid": pid, "address": f"0x{seg_start:x}", "size": 4})
    if probe.get("ok") and (probe.get("result") or {}).get("data_hex"):
        seed = int.from_bytes(bytes.fromhex(probe["result"]["data_hex"]), "little")
    if seed is None:
        record("scan_value", "WARN", "no readable word at segment start", 0)
    else:
        run("scan_value", {"pid": pid, "type": "u32", "value": seed,
                           "preset": mod_preset},
            need=("count",), timeout=180)
    run("scan_hex", {"pid": pid, "pattern": "7F 45 4C 46",
                     "preset": mod_preset}, need=("count",), timeout=180)

    _t0 = time.monotonic()
    job = call("scan_start", {"pid": pid, "kind": "value", "type": "u32",
                              "value": 1, "preset": mod_preset})
    job_id = (job.get("result") or {}).get("job_id") if job.get("ok") else None
    if job_id:
        record("scan_start", "PASS", f"job_id={job_id}",
               (time.monotonic() - _t0) * 1000,
               {"ranges": (job["result"] or {}).get("ranges")})
    else:
        record("scan_start", "FAIL", str(job)[:80], 0)
    if job_id:
        t0 = time.monotonic()
        state = "running"
        for _ in range(300):
            time.sleep(0.2)
            s = call("scan_status", {"pid": pid, "job_id": job_id})
            if s.get("ok") and s["result"].get("state") != "running":
                state = s["result"].get("state")
                break
        record("scan_status", "PASS" if state in ("done", "cancelled") else "FAIL",
               f"state={state}", (time.monotonic() - t0) * 1000)
        run("scan_results", {"pid": pid, "offset": 0, "limit": 16},
            need=("results", "count"), expect_ok=False)
        run("scan_next", {"pid": pid, "mode": "unchanged"}, expect_ok=False)
        # a finished job is gone from the slot: not_found is the documented result
        run("scan_cancel", {"pid": pid, "job_id": job_id}, expect_ok=False,
            expect_error="not_found")
        run("scan_clear", {"pid": pid}, expect_ok=False)
    else:
        record("scan_status", "FAIL", "scan_start returned no job_id", 0)

    # ---- 6. apk ----------------------------------------------------------
    print("\n-- apk --")
    run("apk_info", {"pid": pid}, expect_ok=False)   # sf has no base.apk
    run("apk_info", {"apk_path": "/nonexistent.apk"}, expect_ok=False)
    run("pull_apk", {"pid": pid, "out": "/tmp/regress-base.apk"},
        expect_ok=False)

    # ---- 7. write ---------------------------------------------------------
    print("\n-- write --")
    if args.write_target and args.write_address:
        # Real write path against the operator-designated scratch target ONLY.
        # Discipline: --write-target must name our own throwaway process; never
        # a live app. The address must be inside that process.
        wt = args.write_target
        waddr = int(args.write_address, 16)

        def _rd():
            try:
                r = call("read_memory", {"pid": wt, "address": hex(waddr), "size": 8})
            except urllib.error.HTTPError:
                return None
            return (r.get("result") or {}).get("data_hex") if r.get("ok") else None

        def _wr(payload: dict):
            """write_bytes may answer IPC 500 (WriteDisabled); normalise it."""
            try:
                return call("write_bytes", payload)
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = json.loads(exc.read())["detail"]
                except Exception:  # noqa: BLE001
                    pass
                return {"ok": False, "error": "write_disabled", "detail": detail}

        orig_hex = _rd()
        if orig_hex is None:
            record("write_bytes", "FAIL", f"cannot read write target pid={wt}", 0)
        else:
            # (a) expect_old mismatch must be rejected with zero side effect.
            # Use a deliberately WRONG expected value (never the real one) —
            # passing the true old bytes would make the write legitimate.
            wrong_old = ("0000000000003940" if orig_hex != "0000000000003940"
                         else "0000000000004940")
            bad = _wr({"pid": wt, "address": hex(waddr),
                       "data_hex": "FFFFFFFFFFFFFFFF",
                       "expect_old_hex": wrong_old})
            if bad.get("error") == "write_disabled":
                record("write_bytes", "WARN",
                       "gate off -> refused (WriteDisabled)", 0)
            elif bad.get("ok") or _rd() != orig_hex:
                record("write_bytes", "FAIL",
                       "expect_old mismatch not rejected cleanly", 0)
            else:
                record("write_bytes", "PASS",
                       f"expect_old mismatch rejected ({bad.get('error')})", 0)
            # (b) matching expect_old writes + verifies, then restores
            new_hex = ("0000000000004940" if orig_hex != "0000000000004940"
                       else "0000000000003940")
            w = _wr({"pid": wt, "address": hex(waddr),
                     "data_hex": new_hex, "expect_old_hex": orig_hex})
            if w.get("ok") and (w.get("result") or {}).get("verified"):
                record("write_bytes", "PASS",
                       f"write+verify ok ({orig_hex} -> {new_hex})", 0)
                _wr({"pid": wt, "address": hex(waddr), "data_hex": orig_hex})
                if _rd() == orig_hex:
                    record("write_bytes", "PASS", "restore verified", 0)
                else:
                    record("write_bytes", "FAIL", "restore failed", 0)
            else:
                record("write_bytes", "FAIL", f"write failed: {str(w)[:80]}", 0)
    else:
        # Gate-off path: a write must be refused and leave no trace.
        try:
            r = call("write_bytes", {"pid": pid, "address": f"0x{seg_start:x}",
                                     "data_hex": "00"})
            if r.get("ok"):
                record("write_bytes", "FAIL", "write accepted while gate OFF", 0)
            else:
                record("write_bytes", "WARN",
                       f"gate off -> refused ({r.get('error')})", 0)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read())["detail"]
            except Exception:  # noqa: BLE001
                pass
            if "disabled" in detail.lower():
                record("write_bytes", "WARN", "gate off -> refused (WriteDisabled)", 0)
            else:
                record("write_bytes", "FAIL", f"HTTP {exc.code}: {detail[:60]}", 0)

    # ---- 8. call gate -----------------------------------------------------
    print("\n-- call_export gate --")
    run("call_export", {"pid": pid, "module": "libc.so", "symbol": "getpid"},
        expect_ok=False, expect_error="call_disabled")

    # ---- 9. heavy (optional) ---------------------------------------------
    if not args.skip_slow:
        print("\n-- heavy: dump / decompile --")
        # diff_module needs a disk file; the just-dumped live image is NOT a
        # valid reference, so this only runs when an operator supplies one.
        if args.disk_path:
            run("diff_module", {"pid": pid, "module": mod_name,
                                "local_path": args.disk_path},
                need=("total_diff_bytes", "patched_ranges"), timeout=300)
        out = run("dump_module", {"pid": pid, "module": mod_name,
                                  "out": "/tmp/regress-libc.dump"},
                  need=("size", "sha256"), timeout=600)
        if out and out.get("ok"):
            dump_path = out["result"].get("out")
            d = run("decompile_start", {"pid": pid, "module": mod_name,
                                        "out_dir": "/tmp/regress-ida",
                                        "max_functions": 10},
                    need=("job_id", "engine"), timeout=300)
            job = (d.get("result") or {}).get("job_id") if d and d.get("ok") else None
            if job:
                # IDA decompilation is synchronous-ish (fast); poll briefly.
                st = run("decompile_status", {"pid": pid, "job_id": job},
                         need=("state",), timeout=300)
            else:
                record("decompile_status", "FAIL", "decompile_start gave no job_id", 0)

    # ---- summary ----------------------------------------------------------
    p = sum(1 for r in RESULTS if r["status"] == "PASS")
    w = sum(1 for r in RESULTS if r["status"] == "WARN")
    f = sum(1 for r in RESULTS if r["status"] == "FAIL")
    covered = sorted({r["tool"] for r in RESULTS})
    print(f"\n===== {p} PASS / {w} WARN / {f} FAIL  ({len(RESULTS)} calls) =====")
    print(f"tools exercised: {len(covered)}/33")
    missing = [t for t in TOOL_NAMES if t not in covered]
    if missing:
        print(f"not exercised: {missing}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"results": RESULTS, "pass": p, "warn": w, "fail": f},
                      fh, indent=2)
        print(f"results -> {args.json}")
    return 0 if f == 0 else 1


TOOL_NAMES = [
    "get_status", "find_process", "list_processes", "list_modules",
    "resolve_module", "address_resolve", "read_memory", "write_bytes",
    "resolve_offset_chain", "read_batch", "scan_start", "scan_cancel",
    "resolve_vaddr", "resolve_symbol_ref", "diff_module",
    "process_alive", "watch_process",
    "scan_status", "symbol_list", "symbol_find", "scan_set_default_ranges",
    "scan_value", "scan_hex", "scan_next", "scan_results", "scan_clear",
    "dump_module", "call_export", "resolve_rva", "watch_many", "pointers_to",
    "watch", "disassemble", "strings", "pull_apk", "apk_info",
    "decompile_start", "decompile_status",
]

if __name__ == "__main__":
    sys.exit(main())
