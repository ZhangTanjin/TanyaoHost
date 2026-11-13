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
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.analysis import AnalysisFacade  # noqa: E402

F = AnalysisFacade
PC = 0x21B000


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


class AdrpTest(unittest.TestCase):
    def test_page_targets(self) -> None:
        for target, label in ((0x26C000, "page-aligned"),
                              (0x274000, "16K boundary"),
                              (0x21B000, "same page")):
            with self.subTest(case=label):
                w = enc_adrp(PC, target, rd=8)
                got = F._decode_adrp(w, PC)
                self.assertEqual(got[1] if got else None, target & ~0xFFF)

    def test_negative_offset(self) -> None:
        target = PC - 0x80000
        got = F._decode_adrp(enc_adrp(PC, target, rd=8), PC)
        self.assertEqual(got[1] if got else None, target & ~0xFFF)

    def test_preserves_rd(self) -> None:
        got = F._decode_adrp(enc_adrp(PC, 0x270000, rd=13), PC)
        self.assertEqual(got[0], 13)


class AdrTest(unittest.TestCase):
    def test_relative_offsets(self) -> None:
        for delta, label in ((0x104, "small +"),
                             (-0x104, "small -"),
                             (0x7FFFC, "near +1MB")):
            with self.subTest(case=label):
                w = enc_adr(PC, PC + delta, rd=8)
                self.assertEqual(F._decode_adr(w, PC), PC + delta)


class AddImmTest(unittest.TestCase):
    page = 0x274000

    def test_no_shift_composes(self) -> None:
        w = enc_add_imm(rd=8, rn=8, imm=0x8, shift12=False)
        self.assertEqual(F._decode_add_imm(w, 8, self.page), self.page + 0x8)

    def test_lsl12_composes(self) -> None:
        w = enc_add_imm(rd=8, rn=8, imm=0x1000, shift12=True)
        self.assertEqual(F._decode_add_imm(w, 8, self.page), self.page + 0x1000)

    def test_other_rn_rejected(self) -> None:
        w = enc_add_imm(rd=8, rn=9, imm=0x10, shift12=False)
        self.assertIsNone(F._decode_add_imm(w, 8, self.page))


class LdrImmTest(unittest.TestCase):
    def test_decodes_regs_and_offset(self) -> None:
        self.assertEqual(F._decode_ldr_imm(enc_ldr_imm(rt=8, rn=8, byte_off=0xDC0)),
                         (8, 8, 0xDC0))

    def test_other_regs(self) -> None:
        self.assertEqual(F._decode_ldr_imm(enc_ldr_imm(rt=2, rn=13, byte_off=0x20)),
                         (13, 2, 0x20))


class LdrLiteralTest(unittest.TestCase):
    def test_forward(self) -> None:
        target = PC + 0x48
        w = enc_ldr_literal(rt=8, pc=PC, target=target)
        self.assertEqual(F._decode_ldr_literal(w, PC), target)

    def test_backward(self) -> None:
        target = PC - 0x100
        w = enc_ldr_literal(rt=8, pc=PC, target=target)
        self.assertEqual(F._decode_ldr_literal(w, PC), target)


class RejectionTest(unittest.TestCase):
    """A non-matching word must decode as nothing, not as a plausible value."""

    def test_random_word(self) -> None:
        word = 0xD65F03C0  # `ret`
        self.assertIsNone(F._decode_adrp(word, PC))
        self.assertIsNone(F._decode_adr(word, PC))
        self.assertIsNone(F._decode_ldr_imm(word))
        self.assertIsNone(F._decode_ldr_literal(word, PC))


if __name__ == "__main__":
    unittest.main()
