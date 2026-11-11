#!/usr/bin/env python3
"""Unit tests for the instruction decoders behind resolve_symbol_ref.

Compilers pick different instruction sequences depending on address distance
and optimisation, so relying on a live binary to exercise every form is
unreliable (the toolchain kept folding ADRP into ADR here). These tests drive
the decoders with hand-encoded words instead, which is deterministic.

Encodings (AArch64, little-endian instruction word):
  ADRP  Xd, page    1xx1 0000 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
  ADR   Xd, addr    0xx1 0000 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
  ADD   Xd, Xn, #i  1001 0001 00 sh imm12 Rn Rd
  LDR   Xt, #lit    0101 1000 imm19 Rt            (literal, 64-bit)
  LDR   Xt,[Xn,#i]  1111 1001 01 imm12 Rn Rt      (immediate, 64-bit, scaled 8)
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.analysis import AnalysisFacade  # noqa: E402

F = AnalysisFacade


def bits(value: int, hi: int, lo: int) -> int:
    return (value >> lo) & ((1 << (hi - lo + 1)) - 1)


def enc_adrp(pc: int, target: int, rd: int) -> int:
    imm = (target - (pc & ~0xFFF)) >> 12
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return (0x90000000 | (immlo << 29) | (immhi << 5) | rd)


def enc_adr(pc: int, target: int, rd: int) -> int:
    imm = target - pc
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return (0x10000000 | (immlo << 29) | (immhi << 5) | rd)


def enc_add_imm(rd: int, rn: int, imm: int, shift12: bool = True) -> int:
    return (0x91000000 | ((1 if shift12 else 0) << 22)
            | ((imm >> (12 if shift12 else 0)) << 10) | (rn << 5) | rd)


def enc_ldr_imm(rt: int, rn: int, byte_off: int) -> int:
    return 0xF9400000 | ((byte_off >> 3) << 10) | (rn << 5) | rt


def enc_ldr_literal(rt: int, pc: int, target: int) -> int:
    imm19 = (target - pc) >> 2
    return 0x58000000 | ((imm19 & 0x7FFFF) << 5) | rt


def check(name: str, got, want) -> bool:
    ok = got == want
    print(f"[{'PASS' if ok else 'FAIL'}] {name:<44} got={got} want={want}")
    return ok


def main() -> int:
    failures = 0
    pc = 0x21B000

    # ---------------------------------------------------------------- ADRP
    for target, label in ((0x26C000, "page-aligned"),
                          (0x274000, "16K boundary"),
                          (0x21B000, "same page")):
        w = enc_adrp(pc, target, rd=8)
        got = F._decode_adrp(w, pc)
        failures += not check(f"ADRP {label} -> page", got[1] if got else None,
                              target & ~0xFFF)

    # negative offset (target BELOW pc)
    w = enc_adrp(pc, pc - 0x80000, rd=8)
    got = F._decode_adrp(w, pc)
    failures += not check("ADRP negative offset", got[1] if got else None,
                          (pc - 0x80000) & ~0xFFF)

    # rd is preserved
    failures += not check("ADRP preserves Rd", F._decode_adrp(
        enc_adrp(pc, 0x270000, rd=13), pc)[0], 13)

    # ---------------------------------------------------------------- ADR
    for delta, label in ((0x104, "small +"),
                         (-0x104, "small -"),
                         (0x7FFFC, "near +1MB")):
        w = enc_adr(pc, pc + delta, rd=8)
        failures += not check(f"ADR {label}", F._decode_adr(w, pc), pc + delta)

    # ---------------------------------------------------------------- ADRP+ADD
    page = 0x274000
    off = 0x8
    add_w = enc_add_imm(rd=8, rn=8, imm=off, shift12=False)
    failures += not check("ADD imm (no shift) composes",
                          F._decode_add_imm(add_w, 8, page), page + off)
    add_w = enc_add_imm(rd=8, rn=8, imm=0x1000, shift12=True)
    failures += not check("ADD imm lsl#12 composes",
                          F._decode_add_imm(add_w, 8, page), page + 0x1000)
    # wrong source register must be rejected
    add_w = enc_add_imm(rd=8, rn=9, imm=0x10, shift12=False)
    failures += not check("ADD with other Rn rejected",
                          F._decode_add_imm(add_w, 8, page), None)

    # ---------------------------------------------------------------- LDR imm
    got = F._decode_ldr_imm(enc_ldr_imm(rt=8, rn=8, byte_off=0xDC0))
    failures += not check("LDR imm decodes rn/rt/offset", got, (8, 8, 0xDC0))
    got = F._decode_ldr_imm(enc_ldr_imm(rt=2, rn=13, byte_off=0x20))
    failures += not check("LDR imm other regs", got, (13, 2, 0x20))

    # ---------------------------------------------------------------- LDR literal
    lit_target = pc + 0x48
    got = F._decode_ldr_literal(enc_ldr_literal(rt=8, pc=pc, target=lit_target), pc)
    failures += not check("LDR literal forward", got, lit_target)
    back = pc - 0x100
    got = F._decode_ldr_literal(enc_ldr_literal(rt=8, pc=pc, target=back), pc)
    failures += not check("LDR literal backward", got, back)

    # ---------------------------------------------------------------- rejection
    failures += not check("random word decodes as nothing",
                          (F._decode_adrp(0xD65F03C0, pc),
                           F._decode_adr(0xD65F03C0, pc),
                           F._decode_ldr_imm(0xD65F03C0),
                           F._decode_ldr_literal(0xD65F03C0, pc)),
                          (None, None, None, None))

    print()
    if failures:
        print(f"{failures} decoder case(s) FAILED")
        return 1
    print("all decoder cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
