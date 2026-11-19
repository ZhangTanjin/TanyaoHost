#!/usr/bin/env python3
"""Scan range transparency and preset lifetime.

Field report #2 is the reason this file exists. A preset left over from an
earlier call was silently reused by a later `scan_hex`, which then read 5.88 GB
and killed the target process. Nothing in the response said what was about to be
scanned, and nothing expired the setting.

The tests below pin three separate guarantees:

  * every scan response says WHAT it scanned, in bytes and segments, and WHERE
    that scope came from (`explicit` / `preset` / `inherited`);
  * a preset set explicitly does not silently outlive its usefulness;
  * a scope too large to be reasonable is refused unless the caller says so.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.connection import AgentError  # noqa: E402
from tanyao.jobs import JobManager  # noqa: E402


class FakeEngine:
    """Minimal scan engine: enough state for range accounting and summaries."""

    def __init__(self) -> None:
        self.state = type("S", (), {
            "pid": 0, "vtype": "u64", "scan_round": 0, "count": 0,
            "ranges": [], "truncated": False, "skipped_ranges": [],
            "skipped_bytes": 0,
        })()

    def set_ranges(self, pid: int, ranges) -> None:
        self.state.pid = pid
        self.state.ranges = list(ranges)

    def summary(self) -> dict:
        return {
            "pid": self.state.pid, "type": self.state.vtype,
            "round": self.state.scan_round, "count": self.state.count,
            "ranges": len(self.state.ranges),
            "truncated": self.state.truncated,
            "skipped_ranges": len(self.state.skipped_ranges),
            "skipped_bytes": self.state.skipped_bytes,
        }

    def scan_hex(self, pid, pattern, mask, **kw):
        self.state.scan_round += 1
        self.state.count = 3
        return 3

    def scan_value(self, pid, vtype, value, **kw):
        self.state.scan_round += 1
        self.state.count = 2
        return 2

    def results(self, limit=32):
        return []


class NoAgentService:
    """No agent capabilities: scans run on the host engine (the path under test)."""

    def has_agent_cap(self, bit) -> bool:
        return False


def make_facade() -> AnalysisFacade:
    f = AnalysisFacade.__new__(AnalysisFacade)
    f._scans = {}
    f._scan_presets = {}
    f._preset_fresh = {}
    f._explicit_ranges = {}
    f._jobs = JobManager()
    f.service = NoAgentService()
    return f


def set_preset(f: AnalysisFacade, pid: int, preset: str) -> None:
    """Mirror what scan_set_default_ranges does: record the preset AND mark it
    fresh. Setting only the dict would model a state the real code never enters."""
    f._scan_presets[pid] = preset
    f._preset_fresh[pid] = True


def attach_engine(f: AnalysisFacade, pid: int, ranges) -> FakeEngine:
    e = FakeEngine()
    e.set_ranges(pid, ranges)
    f._scans[pid] = e
    return e


class ScopeEchoTest(unittest.TestCase):
    """Every scan response must state what it scanned and where the scope came from."""

    def test_preset_scope_is_reported_as_preset(self) -> None:
        f = make_facade()
        attach_engine(f, 100, [(0x1000, 0x2000), (0x3000, 0x4000)])
        set_preset(f, 100, "anon")
        out = f.scan_hex(100, "41 42")
        self.assertEqual(out["range_source"], "preset")
        self.assertEqual(out["scan_bytes"], 0x2000)
        self.assertEqual(out["scan_segments"], 2)

    def test_explicit_scope_is_reported_as_explicit(self) -> None:
        f = make_facade()
        attach_engine(f, 101, [(0x1000, 0x1800)])
        f._explicit_ranges[101] = [(0x1000, 0x1800)]
        out = f.scan_hex(101, "41 42")
        self.assertEqual(out["range_source"], "explicit")
        self.assertEqual(out["scan_bytes"], 0x800)

    def test_no_preset_set_is_reported_as_default(self) -> None:
        # Nothing was ever configured: the engine still has whatever ranges the
        # default path installed, and the caller must be told it was a default.
        f = make_facade()
        attach_engine(f, 102, [(0x1000, 0x2000)])
        out = f.scan_hex(102, "41 42")
        self.assertEqual(out["range_source"], "default")

    def test_scan_value_reports_scope_too(self) -> None:
        f = make_facade()
        attach_engine(f, 103, [(0x1000, 0x3000)])
        set_preset(f, 103, "module:libx.so")
        out = f.scan_value(103, "u64", 1)
        self.assertEqual(out["range_source"], "preset")
        self.assertEqual(out["scan_bytes"], 0x2000)

    def test_effective_ranges_lists_actual_addresses(self) -> None:
        f = make_facade()
        attach_engine(f, 104, [(0x1000, 0x2000), (0x5000, 0x6000)])
        out = f.scan_hex(104, "41 42")
        spans = [(int(a, 16), int(b, 16)) for a, b in out["effective_ranges"]]
        self.assertEqual(spans, [(0x1000, 0x2000), (0x5000, 0x6000)])


class PresetLifetimeTest(unittest.TestCase):
    """A preset must not quietly outlive the call that set it."""

    def test_preset_reused_once_is_flagged_inherited(self) -> None:
        f = make_facade()
        attach_engine(f, 200, [(0x1000, 0x2000)])
        set_preset(f, 200, "anon")
        first = f.scan_hex(200, "41 42")
        self.assertEqual(first["range_source"], "preset")
        # Second scan without re-setting: same ranges, but the caller did not
        # ask for them this time, and that is exactly the accident shape.
        second = f.scan_hex(200, "41 42")
        self.assertEqual(second["range_source"], "inherited")

    def test_explicit_ranges_are_not_marked_inherited(self) -> None:
        f = make_facade()
        attach_engine(f, 201, [(0x1000, 0x2000)])
        f._explicit_ranges[201] = [(0x1000, 0x2000)]
        f.scan_hex(201, "41 42")
        out = f.scan_hex(201, "41 42")
        self.assertEqual(out["range_source"], "explicit")

    def test_setting_preset_resets_inheritance(self) -> None:
        f = make_facade()
        attach_engine(f, 202, [(0x1000, 0x2000)])
        set_preset(f, 202, "anon")
        f.scan_hex(202, "41 42")          # consumed
        f.scan_hex(202, "41 42")          # inherited
        # Re-setting must restore the explicit signal.
        set_preset(f, 202, "anon")
        out = f.scan_hex(202, "41 42")
        self.assertEqual(out["range_source"], "preset")


class LargeScopeGuardTest(unittest.TestCase):
    """An all_readable-class scan must not start without an explicit override."""

    def test_large_scope_is_refused_by_default(self) -> None:
        f = make_facade()
        attach_engine(f, 300, [(0, 11_712_372_736)])
        set_preset(f, 300, "all_readable")
        with self.assertRaises(AgentError) as ctx:
            f.scan_hex(300, "41 42")
        self.assertEqual(ctx.exception.error, "bad_request")
        self.assertIn("allow_large", str(ctx.exception.detail))

    def test_large_scope_proceeds_with_override(self) -> None:
        f = make_facade()
        attach_engine(f, 301, [(0, 11_712_372_736)])
        set_preset(f, 301, "all_readable")
        out = f.scan_hex(301, "41 42", allow_large=True)
        self.assertEqual(out["range_source"], "preset")
        self.assertTrue(out["large_scope"])

    def test_small_scope_is_not_gated(self) -> None:
        f = make_facade()
        attach_engine(f, 302, [(0x1000, 0x2000)])
        set_preset(f, 302, "anon")
        out = f.scan_hex(302, "41 42")     # must not raise
        self.assertEqual(out["scan_bytes"], 0x1000)
        self.assertNotIn("large_scope", out)


if __name__ == "__main__":
    unittest.main()
