#!/usr/bin/env python3
"""disassemble_range: batch A64 disassembly with filtering and ADRP resolution.

Field report #13: scanning 11 functions totalling 121,440 B (and a whole 29 MB
library) one `disassemble` call at a time was impossible, so the caller wrote
their own A64 decoder to bypass the tool. That is the demand signal.

The tests pin three things:

  * a range is disassembled in one call, with per-instruction file offsets;
  * a filter narrows by mnemonic and/or immediate value, so the caller can ask
    "every MADD whose multiplier came from MOVZ #imm" without post-processing;
  * ADRP results are resolved to absolute addresses and annotated with whether
    they land in a known mapping.
"""
from __future__ import annotations

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.connection import AgentError  # noqa: E402


# --- A64 instruction builders ------------------------------------------------
# Real encodings, so the test exercises the actual decoder rather than a mock.

def movz(reg: int, imm: int, shift: int = 0) -> bytes:
    """MOVZ Xd, #imm, LSL #shift"""
    hw = (imm >> shift) & 0xFFFF if shift else imm & 0xFFFF
    hw_field = shift // 16
    return struct.pack("<I", 0xD2800000 | (hw_field << 21) | (hw << 5) | reg)


def madd(rd: int, rn: int, rm: int, ra: int) -> bytes:
    """MADD Xd, Xn, Xm, Xa"""
    return struct.pack("<I", 0x9B000000 | (rm << 16) | (ra << 10) | (rn << 5) | rd)


def adrp(rd: int, imm: int) -> bytes:
    """ADRP Xd, #imm (page-relative). imm is in pages, signed 21-bit."""
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x1FFFFF
    return struct.pack("<I", 0x90000000 | (immlo << 29) | (immhi << 5) | rd)


def nop() -> bytes:
    return struct.pack("<I", 0xD503201F)


# A small but real instruction stream:
#   0x1000: MOVZ X0, #0x2AD8        <- the constant the field report hunts
#   0x1004: NOP
#   0x1008: MADD X1, X2, X0, X3     <- multiplier from that MOVZ
#   0x100C: ADRP X4, #0x200         <- page 0x200 above PC page
#   0x1010: NOP
STREAM = movz(0, 0x2AD8) + nop() + madd(1, 2, 0, 3) + adrp(4, 0x200) + nop()
STREAM_BASE = 0x1000


class FakeService:
    def __init__(self, data: bytes, base: int):
        self._data = data
        self._base = base

    def has_agent_cap(self, bit) -> bool:
        return False  # host-side decode, deterministic in tests

    def target_maps(self, pid):
        # One synthetic mapping covering the test stream.
        return [type("M", (), {
            "start": self._base,
            "end": self._base + len(self._data),
            "file_offset": 0,
            "flags": 5,
            "path": "/x/libtest.so",
        })]

    def mem_read(self, pid, addr, size, expected_cookie=None):
        off = addr - self._base
        return self._data[off:off + size]


def make_facade(data: bytes, base: int) -> AnalysisFacade:
    f = AnalysisFacade.__new__(AnalysisFacade)
    f._scans = {}
    f._scan_presets = {}
    f._preset_fresh = {}
    f._explicit_ranges = {}
    f._jobs = None
    f.service = FakeService(data, base)
    return f


class RangeDecodeTest(unittest.TestCase):
    def test_decodes_whole_range_in_one_call(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM))
        self.assertEqual(out["count"], 5)
        self.assertEqual(out["instructions"][0]["text"], "mov x0, #0x2ad8")

    def test_instructions_carry_file_offset(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM))
        ins = out["instructions"][2]
        self.assertEqual(ins["file_offset"], "0x8")


class FilterTest(unittest.TestCase):
    def test_mnemonic_filter(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "madd"})
        self.assertEqual(out["count"], 1)
        self.assertIn("madd", out["instructions"][0]["text"])

    def test_immediate_filter(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "mov", "imm": 0x2AD8})
        self.assertEqual(out["count"], 1)
        self.assertIn("0x2ad8", out["instructions"][0]["text"])

    def test_imm_filter_rejects_other_immediates(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "mov", "imm": 0x9999})
        self.assertEqual(out["count"], 0)

    def test_filter_reports_scanned_and_matched(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "nop"})
        self.assertEqual(out["scanned"], 5)
        self.assertEqual(out["count"], 2)


class AdrpResolutionTest(unittest.TestCase):
    def test_adrp_result_is_resolved(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "adrp"})
        self.assertEqual(out["count"], 1)
        ins = out["instructions"][0]
        # ADRP at 0x100C, imm 0x200 pages: PC page 0x1000 + 0x200*0x1000
        self.assertEqual(ins["resolved_address"], "0x201000")

    def test_adrp_marks_known_mapping(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "adrp"},
                                  known_ranges=[(0x200000, 0x202000)])
        self.assertTrue(out["instructions"][0]["in_known_range"])

    def test_adrp_marks_unknown_mapping(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        out = f.disassemble_range(0, STREAM_BASE, STREAM_BASE + len(STREAM),
                                  filter={"mnemonic": "adrp"},
                                  known_ranges=[(0x500000, 0x502000)])
        self.assertFalse(out["instructions"][0]["in_known_range"])


class ValidationTest(unittest.TestCase):
    def test_backwards_range_rejected(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        with self.assertRaises(AgentError):
            f.disassemble_range(0, STREAM_BASE + 16, STREAM_BASE)

    def test_empty_range_rejected(self) -> None:
        f = make_facade(STREAM, STREAM_BASE)
        with self.assertRaises(AgentError):
            f.disassemble_range(0, STREAM_BASE, STREAM_BASE)


if __name__ == "__main__":
    unittest.main()
