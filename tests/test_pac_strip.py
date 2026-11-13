#!/usr/bin/env python3
"""PAC stripping must be conservative.

Masking the top 16 bits of ANY 64-bit word yields something that "looks like"
an address, so a blind mask silently corrupts non-pointer data. These tests pin
the heuristic that guards it.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.analysis import _looks_like_pointer  # noqa: E402

CASES = [
    # (value, expected, why)
    (0xB40000782510E410, True, "genuine PAC-signed pointer"),
    (0x0000007655039000, True, "plain user pointer"),
    (0x000000792E75B000, True, "observed hook target"),
    (0x000000400000, True, "low static PIE base"),
    (0x54414E59414F0001, False, "64-bit magic constant (ASCII payload)"),
    (0xDEADBEEFCAFEF00D, False, "random data"),
    (0xFFFFFFFFFFFFFFFF, False, "-1 / uninitialised"),
    (0x0000000000000000, False, "NULL"),
    (0x0000000000000001, False, "unaligned value"),
    (0x0000010000000000, False, "beyond user VA range"),
]


class PacGuardTest(unittest.TestCase):
    """One subtest per case so a failure names the offending value."""

    def test_pointer_heuristic(self) -> None:
        for value, want, why in CASES:
            with self.subTest(case=why, value=hex(value)):
                self.assertEqual(_looks_like_pointer(value), want,
                                 f"{why}: {value:#018x}")


if __name__ == "__main__":
    unittest.main()
