"""v1.2 engine-dispatch matrix: caps 0x0 / 0x3 / 0x1ff (DESIGN_V3_HOST §4.1).

Each capability combination must route scan_* tools to the right engine
(`engine` field) with equivalent results, and undeclared v1.2 ops must behave
like unknown cmds (unsupported_cmd, no disconnect). Run:
    python3 -m unittest tests.test_v12_dispatch -v
"""

from __future__ import annotations

import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import (  # noqa: E402
    AGENT_CAP_SCAN,
    BASE,
    DEMO_PID,
    HEAP_START,
    MockAgent,
)
from tanyao.connection import AgentConnection, AgentError  # noqa: E402
from tanyao.analysis import AnalysisFacade  # noqa: E402
from tanyao.constants import CMD_SCAN_START  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

TOKEN = "tanyao-dev-token"


def hx(v: int) -> str:
    return f"0x{v:x}"


class MatrixBase(unittest.TestCase):
    AGENT_CAPS = 0x0

    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN, agent_caps=cls.AGENT_CAPS)
        cls.agent.start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def setUp(self):
        os.environ["TANYAO_ALLOW_WRITE"] = "1"
        self.service = TanyaoService("127.0.0.1", self.agent.port, TOKEN)
        self.facade = AnalysisFacade(self.service)
        self.service.connect()

    def tearDown(self):
        self.service.close()

    def wait_job(self, job_id: str, timeout: float = 10.0) -> dict:
        deadline = time.time() + timeout
        st: dict = {}
        while time.time() < deadline:
            st = self.facade.scan_status(DEMO_PID, job_id)
            if st["state"] != "running":
                return st
            time.sleep(0.02)
        raise AssertionError("job did not finish in time")


class TestCaps0HostEngine(MatrixBase):
    """caps=0 (v1.0 agent, no capabilities field): everything on the host engine."""

    AGENT_CAPS = 0x0

    def test_capabilities_plumbing(self):
        self.assertEqual(self.service.agent_capabilities(), 0x0)
        self.assertFalse(self.service.has_agent_cap(AGENT_CAP_SCAN))

    def test_scan_tools_use_host_engine(self):
        self.facade.scan_set_default_ranges(DEMO_PID)
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, alignment=4)
        self.assertEqual(out["engine"], "host-scan")
        self.assertEqual(out["count"], 4)
        out = self.facade.scan_hex(DEMO_PID, "EF BE AD DE")
        self.assertEqual(out["engine"], "host-scan")
        self.assertEqual(out["found"], 1)
        out = self.facade.scan_next(DEMO_PID, "unchanged")
        self.assertEqual(out["engine"], "host-scan")
        out = self.facade.scan_results(DEMO_PID)
        self.assertEqual(out["engine"], "host-scan")
        out = self.facade.scan_clear(DEMO_PID)
        self.assertEqual(out["engine"], "host-scan")

    def test_undeclared_scan_cmd_is_unsupported(self):
        self.service.close()  # free the single-connection slot
        conn = AgentConnection("127.0.0.1", self.agent.port, TOKEN)
        conn.connect()
        try:
            with self.assertRaises(AgentError) as ctx:
                conn.request(CMD_SCAN_START, {"pid": DEMO_PID, "kind": "value",
                                              "type": "u32", "value": 1})
            self.assertEqual(ctx.exception.error, "unsupported_cmd")
            # connection stays alive per protocol
            self.assertTrue(conn.ping().get("ok"))
        finally:
            conn.close()


class TestCaps3AgentScan(MatrixBase):
    """caps=0x3 (v1.1 agent): scan_* on the device, everything else host."""

    AGENT_CAPS = 0x3

    def test_capabilities_plumbing(self):
        self.assertEqual(self.service.agent_capabilities(), 0x3)
        self.assertTrue(self.service.has_agent_cap(AGENT_CAP_SCAN))

    def test_scan_value_agent_engine_inline(self):
        self.facade.scan_set_default_ranges(DEMO_PID)
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, alignment=4)
        self.assertEqual(out["engine"], "agent-scan")
        self.assertEqual(out["count"], 4)
        self.assertEqual(out["type"], "u32")
        self.assertGreaterEqual(out["round"], 1)
        addrs = {int(r["address"], 16) for r in out["results"]}
        self.assertIn(HEAP_START + 0xA000, addrs)  # hit after the poison hole

    def test_agent_scan_equivalent_to_host_engine(self):
        """Same world must yield the same hits regardless of engine."""
        self.facade.scan_set_default_ranges(DEMO_PID)
        agent_out = self.facade.scan_value(DEMO_PID, "u32", 1337, alignment=4)

        host_agent = MockAgent(port=0, token=TOKEN, agent_caps=0x0)
        host_agent.start()
        try:
            svc = TanyaoService("127.0.0.1", host_agent.port, TOKEN)
            facade = AnalysisFacade(svc)
            svc.connect()
            facade.scan_set_default_ranges(DEMO_PID)
            host_out = facade.scan_value(DEMO_PID, "u32", 1337, alignment=4)
            self.assertEqual(host_out["engine"], "host-scan")
            self.assertEqual(
                {int(r["address"], 16) for r in agent_out["results"]},
                {int(r["address"], 16) for r in host_out["results"]},
            )
            self.assertEqual(agent_out["count"], host_out["count"])
        finally:
            host_agent.stop()

    def test_agent_hex_and_refine_flow(self):
        self.facade.scan_set_default_ranges(DEMO_PID)
        out = self.facade.scan_hex(DEMO_PID, "EF BE AD DE")
        self.assertEqual(out["engine"], "agent-scan")
        self.assertEqual(out["found"], 1)
        self.assertEqual(out["results"][0]["address"], hx(HEAP_START + 0x488))
        out = self.facade.scan_next(DEMO_PID, "unchanged")
        self.assertEqual(out["engine"], "agent-scan")
        self.assertEqual(out["found"], 1)
        self.service.mem_write(DEMO_PID, HEAP_START + 0x488, struct.pack("<I", 0))
        out = self.facade.scan_next(DEMO_PID, "changed")
        self.assertEqual(out["found"], 1)  # only rewritten hit changed
        paged = self.facade.scan_results(DEMO_PID)
        self.assertEqual(paged["engine"], "agent-scan")
        self.assertEqual(paged["results"][0]["address"], hx(HEAP_START + 0x488))
        self.assertEqual(paged["results"][0]["value"], 0)
        # restore the world for later tests in this class (shared mock memory)
        self.service.mem_write(DEMO_PID, HEAP_START + 0x488,
                               bytes.fromhex("EFBEADDE"))
        out = self.facade.scan_clear(DEMO_PID)
        self.assertEqual(out["engine"], "agent-scan")
        after = self.facade.scan_results(DEMO_PID)
        self.assertEqual(after["count"], 0)

    def test_agent_scan_skipped_accounting(self):
        """P1 parity on the device engine: poison hole skipped, later hits kept."""
        self.facade.scan_set_default_ranges(DEMO_PID)
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, alignment=4)
        self.assertEqual(out["count"], 4)
        self.assertGreaterEqual(out["skipped_bytes"], 0x1000)

    def test_agent_async_scan_job_roundtrip(self):
        self.facade.scan_set_default_ranges(DEMO_PID)
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, async_run=True)
        self.assertTrue(out["async"])
        st = self.wait_job(out["job_id"])
        self.assertEqual(st["state"], "done", st.get("error"))
        self.assertEqual(st["summary"]["engine"], "agent-scan")
        self.assertEqual(st["summary"]["count"], 4)
        # cancelling an already-finished job still errors like the host engine
        with self.assertRaises(AgentError):
            self.facade.scan_cancel(DEMO_PID, out["job_id"])

    def test_hex_scan_job_and_wildcard(self):
        self.facade.scan_set_range(DEMO_PID, HEAP_START, HEAP_START + 0x10000)
        out = self.facade.scan_hex(DEMO_PID, "EF BE ?? ??", async_run=True)
        st = self.wait_job(out["job_id"])
        self.assertEqual(st["state"], "done", st.get("error"))
        self.assertEqual(st["summary"]["count"], 1)

    def test_agent_job_unknown_pid_not_found(self):
        with self.assertRaises(Exception):
            self.service.agent_scan_start(999999, kind="value", type="u32", value=1,
                                          preset="anon")


class TestCaps3BSymbolsStrings(MatrixBase):
    """caps=0x3b (bits 0,1,3,4,5): symbols/strings on the device incl. binary
    frames end-to-end (packed symbol_batch goes over a real socket)."""

    AGENT_CAPS = 0x3B

    def test_symbol_list_agent_engine(self):
        out = self.facade.symbol_list(DEMO_PID, "libdemo.so")
        self.assertEqual(out["engine"], "agent-symbols")
        self.assertEqual(out["module"], "libdemo.so")
        names = {s["name"]: s for s in out["symbols"]}
        self.assertIn("demo_start", names)
        self.assertIn("demo_data", names)
        self.assertEqual(names["demo_start"]["address"], hx(BASE + 0x1B40))
        self.assertEqual(names["demo_start"]["type"], "FUNC")
        self.assertIn("bind", names["demo_start"])  # shape key preserved

    def test_symbol_list_filter(self):
        out = self.facade.symbol_list(DEMO_PID, "libdemo.so", filter="^demo_data$")
        self.assertEqual([s["name"] for s in out["symbols"]], ["demo_data"])

    def test_symbol_find_agent_engine(self):
        out = self.facade.symbol_find(DEMO_PID, "demo_start", module="libdemo.so")
        self.assertEqual(out["engine"], "agent-symbols")
        self.assertEqual(out["module"], "libdemo.so")
        self.assertEqual(out["matches"][0]["address"], hx(BASE + 0x1B40))
        with self.assertRaises(AgentError) as ctx:
            self.facade.symbol_find(DEMO_PID, "no_such_symbol_xyz")
        self.assertEqual(ctx.exception.error, "not_found")

    def test_packed_matches_json(self):
        j = self.service.symbol_batch(DEMO_PID, module="libdemo.so")
        p = self.service.symbol_batch(DEMO_PID, module="libdemo.so", format="packed")
        self.assertEqual(p["names"], j["names"])
        self.assertEqual(p["addresses"], j["addresses"])
        self.assertEqual(p["sizes"], j["sizes"])
        self.assertEqual(p["modules"], j["modules"])
        self.assertGreater(len(p["names"]), 0)

    def test_strings_module_mode_agent(self):
        out = self.facade.strings(DEMO_PID, module="libdemo.so", min_length=6)
        self.assertEqual(out["engine"], "agent-strings")
        vals = [s["value"] for s in out["strings"]]
        self.assertIn("tanyao_mock_engine", vals)
        self.assertIn("Java_icu_nullptr_test", vals)
        by_val = {s["value"]: s for s in out["strings"]}
        self.assertEqual(by_val["tanyao_mock_engine"]["offset"], BASE + 0x900)
        self.assertEqual(by_val["tanyao_mock_engine"]["length"], 18)
        self.assertGreater(out["scanned_bytes"], 0)

    def test_strings_window_mode_agent(self):
        out = self.facade.strings(DEMO_PID, address=HEAP_START + 0xAFF0, size=0x40,
                                  min_length=8)
        self.assertEqual(out["engine"], "agent-strings")
        vals = [s["value"] for s in out["strings"]]
        self.assertIn("TANYAO_STRINGS_WINDOW_MARKER", vals)

    def test_strings_regex_and_bad_regex(self):
        out = self.facade.strings(DEMO_PID, module="libdemo.so", min_length=6,
                                  filter="^tanyao")
        self.assertEqual([s["value"] for s in out["strings"]], ["tanyao_mock_engine"])
        with self.assertRaises(AgentError) as ctx:
            self.service.strings_scan(DEMO_PID, preset="module:libdemo.so", regex="([bad")
        self.assertEqual(ctx.exception.error, "bad_request")

    def test_strings_async_job_roundtrip(self):
        out = self.service.strings_scan(DEMO_PID, preset="module:libdemo.so",
                                        min_len=6, async_run=True)
        dev_job = int(out["job_id"])
        st = {}
        deadline = time.time() + 10
        while time.time() < deadline:
            st = self.service.agent_scan_status(dev_job)
            if st.get("state") != "running":
                break
            time.sleep(0.02)
        self.assertEqual(st["state"], "done", st.get("error"))
        self.assertEqual(st.get("kind"), "strings")
        page = self.service.agent_scan_results(0, 32)
        hits = page["hits"]
        self.assertTrue(any(h["value"] == "tanyao_mock_engine" for h in hits))
        self.assertNotIn("value_hex", hits[0])  # strings hits carry length, not value_hex
        self.assertIn("length", hits[0])


if __name__ == "__main__":
    unittest.main()
