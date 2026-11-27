#!/usr/bin/env python3
"""read_batch throughput A/B (tanyao vs kitty), same target + same addresses.

Workload: N rounds of one read_batch call with 256 spans x 4096 bytes
(1 MiB per round). This exercises the kernel readv path, which is what the
scan engine uses too, so it is the fairest proxy available through the tool
surface for "scan throughput".

Usage: bench_readv_ab.py <pid> <base_hex> [rounds] [trials]
"""
import json
import sys
import time
import urllib.request

URL = "http://127.0.0.1:28101/"
SPANS_PER_CALL = 256
SPAN_SIZE = 4096


def rpc(method, params):
    body = json.dumps({"method": method, "params": params}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read().decode())


def main():
    pid = int(sys.argv[1])
    base = int(sys.argv[2], 16)
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    trials = int(sys.argv[4]) if len(sys.argv) > 4 else 3

    spans = [{"address": hex(base + i * SPAN_SIZE), "size": SPAN_SIZE}
             for i in range(SPANS_PER_CALL)]

    best = None
    for trial in range(trials):
        t0 = time.monotonic()
        for _ in range(rounds):
            out = rpc("read_batch", {"pid": pid, "spans": spans})
            if not out.get("ok"):
                print("FAIL", out)
                return 2
        dt = time.monotonic() - t0
        mb = rounds * SPANS_PER_CALL * SPAN_SIZE / (1024 * 1024)
        rate = mb / dt
        print(f"trial {trial + 1}: {dt:.3f}s  {rate:.1f} MiB/s  ({mb:.0f} MiB)")
        best = rate if best is None else max(best, rate)
    print(f"BEST {best:.1f} MiB/s")
    return 0


if __name__ == "__main__":
    sys.exit(main())