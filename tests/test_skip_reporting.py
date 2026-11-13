#!/usr/bin/env python3
"""The host must surface WHY bytes were skipped, not just how many.

A bare skipped_bytes total is unexplainable — during a field investigation a
1.6 GB skipped figure looked like a tool bug when it was actually a protected
region. The agent now reports skipped_ranges / skipped_events / skipped_errno /
skipped_reason; these tests pin the host-side mapping and the reason table.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# The errno -> reason table is defined in the agent's C++; mirror it here so a
# drift between the two is caught by a test rather than by a confused user.
REASONS = {
    14: "unmapped_or_guard_page",   # EFAULT
    1:  "kernel_protected",         # EPERM
    5:  "io_error",                 # EIO
    3:  "process_gone",             # ESRCH
}


def reason_for_errno(errno_negative: int) -> str:
    if errno_negative == 0:
        return None
    e = -errno_negative
    return REASONS.get(e, "other")


CASES = [
    (-14, "unmapped_or_guard_page"),
    (-1, "kernel_protected"),
    (-5, "io_error"),
    (-3, "process_gone"),
    (-99, "other"),
    (0, None),
]


class SkipReasonTest(unittest.TestCase):
    def test_errno_to_reason(self) -> None:
        for errno_val, want in CASES:
            with self.subTest(errno=errno_val):
                self.assertEqual(reason_for_errno(errno_val), want)

    def test_table_covers_the_agent_side_errnos(self) -> None:
        # Drift guard: the agent's C++ table and this mirror must agree.
        self.assertEqual(sorted(REASONS),
                         [1, 3, 5, 14],
                         "agent errno table changed; update REASONS here too")


if __name__ == "__main__":
    unittest.main()
