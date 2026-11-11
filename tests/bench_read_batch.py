#!/usr/bin/env python3
"""Test 3: read_batch (1 round-trip, N spans) vs N x read_memory round-trips.

Runs against the host serve JSON-RPC (127.0.0.1:28101), pid 6545
(icu.nullptr.nativetest), 8 scattered 8-byte spans across code/rodata/rw.
"""
import json
import time
import urllib.request

URL = "http://127.0.0.1:28101/"
PID = 6545
SPANS = [
    {"address": "0x7bf0a06bbb", "size": 8},   # rodata: string area
    {"address": "0x7bf0a0598e", "size": 8},   # rodata
    {"address": "0x7bf0a0828e", "size": 8},   # rodata
    {"address": "0x7bf0b31658", "size": 8},   # .text: Java_..._check prologue
    {"address": "0x7bf0bed2f0", "size": 8},   # .text: ANativeActivity_onCreate
    {"address": "0x7bf0bfb000", "size": 8},   # rw: string descriptor table
    {"address": "0x7bf0bfd470", "size": 8},   # bss
    {"address": "0x7bf0bff000", "size": 8},   # bss: random guard
]
ROUNDS = 100


RETRY_COUNT = {"n": 0}


def rpc(method, params):
    req = urllib.request.Request(
        URL,
        data=json.dumps({"method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.loads(resp.read().decode())
    if not out.get("ok"):
        raise RuntimeError(f"{method} failed: {out}")
    return out["result"]


def rpc_retry(method, params, attempts=4):
    for i in range(attempts):
        try:
            return rpc(method, params)
        except RuntimeError as e:
            if "errno': -14" in str(e) or "errno': -16" in str(e):
                RETRY_COUNT["n"] += 1
                time.sleep(0.05)
                continue
            raise
    raise RuntimeError("retry exhausted")


def main():
    # sanity: batch returns 8 spans, none with per-span errors
    r = rpc("read_batch", {"pid": PID, "spans": SPANS})
    bad = [s for s in r["spans"] if "error" in s]
    assert r["count"] == 8 and not bad, r
    print("sanity batch ok:", json.dumps(r["spans"][0]))

    t0 = time.perf_counter()
    for _ in range(ROUNDS):
        rpc("read_batch", {"pid": PID, "spans": SPANS})
    t_batch = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(ROUNDS):
        for s in SPANS:
            rpc_retry("read_memory", {"pid": PID, "address": s["address"], "size": s["size"]})
    t_single = time.perf_counter() - t0
    print(f"\ntransient EFAULT/EBUSY retries during single-read phase: {RETRY_COUNT['n']}")

    t0 = time.perf_counter()
    for _ in range(ROUNDS * 8):
        rpc("get_status", {})
    t_http = time.perf_counter() - t0

    print(f"\nrounds={ROUNDS} spans={len(SPANS)} (8 bytes each)")
    print(f"read_batch   total {t_batch*1000:8.1f} ms  ({t_batch/ROUNDS*1000:6.2f} ms/round, 1 rpc)")
    print(f"8x read_mem  total {t_single*1000:8.1f} ms  ({t_single/ROUNDS*1000:6.2f} ms/round, 8 rpc)")
    print(f"http control total {t_http*1000:8.1f} ms  ({t_http/(ROUNDS*8)*1000:6.2f} ms/rpc)")
    print(f"speedup (single/batch): {t_single/t_batch:.2f}x")
    print(f"speedup excl. http overhead: {(t_single - t_http)/(t_batch - t_http/8):.2f}x")


if __name__ == "__main__":
    main()
