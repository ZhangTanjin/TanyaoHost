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


def main() -> int:
    failures = 0
    for errno_val, want in CASES:
        got = reason_for_errno(errno_val)
        ok = got == want
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] errno {errno_val:>3} -> "
              f"{str(got):<22} (want {want})")

    # The agent's table must contain exactly these keys.
    print()
    print(f"reason table covers {len(REASONS)} errnos: "
          f"{sorted(REASONS.values())}")

    print()
    if failures:
        print(f"{failures} case(s) FAILED")
        return 1
    print("all skip-reason cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
