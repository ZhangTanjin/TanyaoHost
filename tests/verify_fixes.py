#!/usr/bin/env python3
"""Post-fix verification for P2-1 (read_batch span isolation) and P2-2 (dump layout).

P2-1: batch [good, bad, good] must return [data, error, data] (no downstream pollution).
P2-2: dump_module must produce a file whose PT_DYNAMIC parses (readelf -d) with DT_NEEDED.

Usage: python3 tests/verify_fixes.py
Assumes serve on 127.0.0.1:28101, targets pid 6545 (real app) present.
"""
import json
import subprocess
import sys
import urllib.request

URL = "http://127.0.0.1:28101/"
PID = 6545
GOOD1 = "0x7bf0b31658"   # .text: Java_..._check prologue (verified readable)
GOOD2 = "0x7bf0bff000"   # bss guard (verified readable)
BAD = "0x1000"           # unmapped


def rpc(method, params):
    req = urllib.request.Request(
        URL,
        data=json.dumps({"method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        out = json.loads(resp.read().decode())
    if not out.get("ok"):
        raise RuntimeError(f"{method}: {out}")
    return out["result"]


def check_p2_1():
    r = rpc("read_batch", {"pid": PID, "spans": [
        {"address": GOOD1, "size": 8},
        {"address": BAD, "size": 8},
        {"address": GOOD2, "size": 8},
    ]})
    spans = r["spans"]
    assert len(spans) == 3, r
    ok1 = "data_hex" in spans[0] and "error" not in spans[0]
    fail2 = "error" in spans[1]
    ok3 = "data_hex" in spans[2] and "error" not in spans[2]
    print(f"P2-1 batch [good,bad,good] -> [{spans[0].get('error','data')}, "
          f"{spans[1].get('error','data')}, {spans[2].get('error','data')}]")
    if ok1 and fail2 and ok3:
        print("P2-1: PASS (span isolation works, downstream no longer polluted)")
        return True
    print("P2-1: FAIL", json.dumps(r))
    return False


def check_p2_2(out_path):
    # fresh dump of the same module
    r = rpc("dump_module", {"pid": PID, "module": "libnullptr.so", "out": out_path})
    print(f"P2-2 dump: size={r['size']} mappings={r.get('mappings')} skipped={r.get('skipped')}")
    # dynamic section must parse
    res = subprocess.run(["readelf", "-dW", out_path], capture_output=True, text=True)
    dyn = res.stdout
    needed = [ln.split("[", 1)[1].rstrip("]\n") for ln in dyn.splitlines() if "NEEDED" in ln]
    print(f"P2-2 readelf -d: rc={res.returncode}, DT_NEEDED entries={len(needed)}")
    for n in needed[:6]:
        print("   NEEDED:", n)
    ok = res.returncode == 0 and "There is no dynamic section" not in res.stdout and len(needed) > 0
    # PT_DYNAMIC offset should exist in program headers
    res2 = subprocess.run(["readelf", "-lW", out_path], capture_output=True, text=True)
    has_dyn_seg = "DYNAMIC" in res2.stdout
    print(f"P2-2 PT_DYNAMIC segment present: {has_dyn_seg}")
    print("P2-2:", "PASS" if (ok and has_dyn_seg) else "FAIL")
    return ok and has_dyn_seg


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "./libnullptr-dump-v2.so"
    results = [check_p2_1(), check_p2_2(out)]
    print("\nSUMMARY:", "ALL PASS" if all(results) else "FAILURES PRESENT")
    sys.exit(0 if all(results) else 1)
