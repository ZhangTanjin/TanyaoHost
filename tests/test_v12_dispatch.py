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


if __name__ == "__main__":
    unittest.main()
