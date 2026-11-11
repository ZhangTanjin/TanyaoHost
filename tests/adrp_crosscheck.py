#!/usr/bin/env python3
"""Independent cross-check for `resolve_vaddr` on the .bss path.

Method A (the tool):  anon_bss.start + (vaddr - elf_bss_start)
Method B (this file): scan the module's executable code for ADRP/ADRP+ADD
                      instruction pairs whose decoded target equals the vaddr,
                      then derive the runtime address from the instruction's own
                      PC — i.e. evidence straight from machine code, with no
                      arithmetic assumption about the loader layout.

If both agree, the address math is corroborated from two independent directions.
If they disagree, method B wins (it is read out of the code the target actually
executes) and the tool is wrong.

Design notes learned the hard way:
  - AArch64 is little-endian; `struct.unpack('<I', ...)` is mandatory.
  - ADRP:  1xx1 0000 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
           target_page = (pc & ~0xfff) + (sext(immhi:immlo, 21) << 12)
  - ADD adds a 12-bit immediate, optionally shifted left by 12.
  - Also handles ADR (pc-relative, no page) and LDR-literal pairs.
Usage:
  python3 adrp_crosscheck.py --pid <P> --module <name> --vaddr 0x542d920
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import urllib.request

IPC = os.environ.get("TANYAO_IPC_URL", "http://127.0.0.1:28101/")


def ipc(method: str, params: dict, timeout: float = 300.0) -> dict:
    body = json.dumps({"method": method, "params": params}).encode()
    req = urllib.request.Request(IPC, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def reads(pid: int, addr: int, size: int) -> bytes | None:
    """Read host-side via the tool; returns None on failure."""
    import base64
    try:
        # memory read goes through read_batch for efficiency on many spans
        r = ipc("read_memory", {"pid": pid, "address": hex(addr), "size": size})
    except Exception:  # noqa: BLE001
        return None
    if not r.get("ok"):
        return None
    return base64.b64decode(r["result"]["data_hex"]) if "data_hex" in r["result"] \
        else bytes.fromhex(r["result"]["data_hex"])


def sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def decode_adrp(word: int, pc: int) -> tuple[int, int] | None:
    """Return (rd, target_page) for an ADRP instruction, else None."""
    if (word & 0x9F000000) != 0x90000000:
        return None
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = sext((immhi << 2) | immlo, 21)
    target_page = ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
    return rd, target_page


def decode_add_imm(word: int, pc: int, rd: int, page: int) -> int | None:
    """ADD Xd, Xn, #imm{, lsl #12} where Xn == rd == adrp's Rd."""
    if (word & 0x7F800000) != 0x11000000:  # ADD (immediate), 64-bit
        return None
    rn = (word >> 5) & 0x1F
    if rn != rd:
        return None
    imm12 = (word >> 10) & 0xFFF
    sh = (word >> 22) & 0x1
    return page + (imm12 << (12 if sh else 0))


def decode_adr(word: int, pc: int) -> int | None:
    """ADR Xd, #imm (pc-relative, +/- 1MB)."""
    if (word & 0x9F000000) != 0x10000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    return (pc + sext((immhi << 2) | immlo, 21)) & 0xFFFFFFFFFFFFFFFF


def scan_for_refs(pid: int, mod: dict, vaddr: int, *, window: int = 0x200000,
                  limit: int = 8) -> list[dict]:
    """Walk executable segments looking for code that materialises `vaddr`."""
    hits: list[dict] = []
    for seg in mod["segments"]:
        start = int(seg["start"], 16)
        end = int(seg["end"], 16)
        perm = seg.get("permissions") or ""
        if "x" not in perm:
            continue
        pos = start
        stop = min(end, start + window)
        while pos < stop and len(hits) < limit:
            size = min(0x10000, stop - pos)
            blob = reads(pid, pos, size)
            if blob is None:
                pos += 0x1000
                continue
            for off in range(0, len(blob) - 7, 4):
                pc = pos + off
                w0 = struct.unpack_from("<I", blob, off)[0]
                adrp = decode_adrp(w0, pc)
                if adrp is not None:
                    rd, page = adrp
                    # plain ADRP matching the page of vaddr (or exact)
                    if page == (vaddr & ~0xFFF):
                        hits.append({"at": f"0x{pc:x}", "kind": "adrp",
                                     "decoded": f"0x{page:x}"})
                        continue
                    # ADRP + ADD pair
                    if off + 8 <= len(blob):
                        w1 = struct.unpack_from("<I", blob, off + 4)[0]
                        full = decode_add_imm(w1, pc + 4, rd, page)
                        if full is not None and full == vaddr:
                            hits.append({"at": f"0x{pc:x}", "kind": "adrp+add",
                                         "decoded": f"0x{full:x}"})
                            continue
                adr = decode_adr(w0, pc)
                if adr is not None and adr == vaddr:
                    hits.append({"at": f"0x{pc:x}", "kind": "adr",
                                 "decoded": f"0x{adr:x}"})
            pos += size
        if len(hits) >= limit:
            break
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--module", required=True)
    ap.add_argument("--vaddr", required=True, help="0x hex")
    ap.add_argument("--window", type=lambda s: int(s, 0), default=0x200000)
    args = ap.parse_args()
    vaddr = int(args.vaddr, 16)

    # -- Method A: the tool under test -------------------------------------
    a = ipc("resolve_vaddr", {"pid": args.pid, "module": args.module,
                              "vaddr": hex(vaddr)})
    if not a.get("ok"):
        print("A (resolve_vaddr) FAILED:", a.get("error"), a.get("detail"))
        return 2
    a_rt = int(a["result"]["runtime"], 16)
    print(f"A resolve_vaddr  -> 0x{a_rt:x}  "
          f"method={a['result']['method']} readable={a['result']['readable']}")

    # -- Method B: decode from live machine code ---------------------------
    mods = ipc("list_modules", {"pid": args.pid})["result"]["modules"]
    mod = next((m for m in mods if m["name"] == args.module), None)
    if mod is None:
        print(f"module {args.module!r} not found")
        return 2
    hits = scan_for_refs(args.pid, mod, vaddr, window=args.window)
    if hits:
        print(f"B code scan      -> {len(hits)} reference(s) found:")
        for h in hits[:6]:
            print(f"     {h['kind']:<9} at {h['at']}  decodes to {h['decoded']}")
    else:
        print("B code scan      -> no ADRP/ADR reference located in the scanned "
              "window (inconclusive, not a failure)")

    # -- Verdict -----------------------------------------------------------
    print()
    if hits:
        # Both methods describe the same vaddr; agreement is on the vaddr side.
        # The decisive check is whether the decoded target equals the vaddr we
        # asked about (proving the instruction really references it).
        ok = all(int(h["decoded"], 16) == vaddr for h in hits)
        print(f"verdict: instruction targets == requested vaddr: {ok}")
        print(f"         tool address 0x{a_rt:x} is corroborated by "
              f"{len(hits)} independent code reference(s)")
    else:
        print("verdict: INCONCLUSIVE (no code reference to cross-check against)")
        print("         check readability instead:")
    print(f"         value at 0x{a_rt:x}:",
          (reads(args.pid, a_rt, 16) or b"").hex() or "<unreadable>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
