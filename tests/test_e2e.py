"""End-to-end tests: host stack against the mock agent. Run: python3 -m unittest tests.test_e2e -v"""

from __future__ import annotations

import json
import os
import struct
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_agent import BASE, DEMO_PID, HEAP_START, MORTAL_PID, MockAgent  # noqa: E402
from tanyao.analysis import AnalysisFacade, WriteDisabled  # noqa: E402
from tanyao.connection import AgentConnection, AgentError  # noqa: E402
from tanyao.ipc import IpcServer  # noqa: E402
from tanyao.mcp_server import handle_request  # noqa: E402
from tanyao.service import TanyaoService  # noqa: E402

TOKEN = "tanyao-dev-token"


def hx(v: int) -> str:
    return f"0x{v:x}"


class TestE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN)
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

    # -- connection ---------------------------------------------------------

    def test_auth_ok_and_backend_info(self):
        info = self.service.backend_info()
        self.assertEqual(info.name, "mock")
        self.assertEqual(info.abi_major, 1)
        self.assertEqual(info.capabilities & 0x3F, 0x3F)
        self.assertEqual(info.max_transfer_size, 1 << 20)

    def test_auth_bad_token_rejected(self):
        self.service.close()  # free the single-connection slot; setUp already connected
        conn = AgentConnection("127.0.0.1", self.agent.port, "wrong-token")
        with self.assertRaises(AgentError) as ctx:
            conn.connect()
        self.assertIn("auth", str(ctx.exception).lower())

    def test_generation_exposed(self):
        self.assertEqual(self.service.generation(), 1)

    # -- process / module ---------------------------------------------------

    def test_process_find(self):
        self.assertEqual(self.facade.find_process("com.demo.game")["pid"], DEMO_PID)
        self.assertFalse(self.facade.find_process("nope")["found"])

    def test_list_modules(self):
        out = self.facade.list_modules(DEMO_PID)
        names = [m["name"] for m in out["modules"]]
        self.assertIn("libdemo.so", names)
        libdemo = next(m for m in out["modules"] if m["name"] == "libdemo.so")
        self.assertEqual(libdemo["base"], hx(BASE))

    def test_module_base(self):
        self.assertEqual(self.service.module_base(DEMO_PID, "libdemo.so"), BASE)

    # -- memory ---------------------------------------------------------------

    def test_read_memory_raw(self):
        out = self.facade.read_memory(DEMO_PID, BASE, 4)
        self.assertEqual(out["data_hex"], "7f454c46")

    def test_read_typed_array(self):
        out = self.facade.read_memory(DEMO_PID, BASE + 0x2000, 0, as_type="u32", count=4)
        self.assertEqual(out["values"], [1000, 1007, 1014, 1021])

    def test_write_verify_and_expect_old(self):
        addr = BASE + 0x2000
        out = self.facade.write_bytes(DEMO_PID, addr, bytes.fromhex("DEADBEEF"), expect_old=bytes.fromhex("E8030000"))
        self.assertTrue(out["verified"])
        back = self.facade.read_memory(DEMO_PID, addr, 4)
        self.assertEqual(back["data_hex"], "deadbeef")
        # wrong expect_old must fail without writing
        with self.assertRaises(AgentError):
            self.facade.write_bytes(DEMO_PID, addr + 4, b"\x00" * 4, expect_old=b"\xff" * 4)

    def test_write_disabled_by_default(self):
        os.environ.pop("TANYAO_ALLOW_WRITE", None)
        try:
            facade = AnalysisFacade(TanyaoService("127.0.0.1", self.agent.port, TOKEN))
            with self.assertRaises(WriteDisabled):
                facade.write_bytes(DEMO_PID, BASE + 0x2000, b"\x00" * 4)
        finally:
            os.environ["TANYAO_ALLOW_WRITE"] = "1"

    def test_mem_readv(self):
        out = self.service.mem_readv(DEMO_PID, [(BASE, 4), (BASE + 0x2000, 8)])
        self.assertEqual(out[0], b"\x7fELF")
        self.assertEqual(len(out[1]), 8)

    # -- module resolve ---------------------------------------------------------

    def test_resolve_module_elf_semantics(self):
        out = self.facade.resolve_module(DEMO_PID, "libdemo.so")
        self.assertEqual(out["first_map"], hx(BASE))
        # min(vaddr - offset) = 0 -> load bias == BASE
        self.assertEqual(out["load_bias"], hx(BASE))
        self.assertIsNone(out["mirror_detected"] or None)  # single exec map: no mirror

    def test_address_resolve_rva(self):
        out = self.facade.address_resolve(DEMO_PID, BASE + 0x1234)
        self.assertEqual(out["module"], "libdemo.so")
        self.assertEqual(out["module_offset"], hx(0x1234))

    # -- pointer chain ------------------------------------------------------------

    def test_resolve_offset_chain(self):
        out = self.facade.resolve_offset_chain(
            DEMO_PID, HEAP_START, [0x100, 0x40, 0x8], vtype="u32"
        )
        # HEAP+0x100 -> HEAP+0x400; deref(0x400+0x40=0x440) -> HEAP+0x480; +0x8 = 0xDEADBEEF
        self.assertEqual(out["value"], 0xDEADBEEF)

    # -- scan -------------------------------------------------------------------

    def test_scan_value_first_and_refine(self):
        self.facade.scan_set_default_ranges(DEMO_PID)
        out = self.facade.scan_value(DEMO_PID, "u32", 1337, alignment=4)
        # 4 aligned hits inside heap (0x1000, 0x2000, 0x3004, 0xA000-after-hole)
        self.assertEqual(out["count"], 4)
        # unchanged refine keeps all
        out = self.facade.scan_next(DEMO_PID, "unchanged")
        self.assertEqual(out["count"], 4)
        # change one value, then "changed" keeps only it
        self.service.mem_write(DEMO_PID, HEAP_START + 0x1000, struct.pack("<I", 1000))
        out = self.facade.scan_next(DEMO_PID, "changed")
        self.assertEqual(out["count"], 1)
        results = self.facade.scan_results(DEMO_PID)["results"]
        self.assertEqual({r["address"] for r in results}, {hx(HEAP_START + 0x1000)})
        self.assertEqual(results[0]["value"], 1000)
        self.facade.scan_clear(DEMO_PID)
        self.assertEqual(self.facade.scan_results(DEMO_PID)["count"], 0)

    def test_scan_hex(self):
        self.facade.scan_set_range(DEMO_PID, HEAP_START, HEAP_START + 0x10000)
        out = self.facade.scan_hex(DEMO_PID, "EF BE AD DE")
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["results"][0]["address"], hx(HEAP_START + 0x488))

    # -- dump ---------------------------------------------------------------------

    def test_dump_module(self):
        out_path = os.path.join(self.agent_dir(), "libdemo.dump")
        out = self.facade.dump_module(DEMO_PID, "libdemo.so", out_path)
        self.assertGreater(out["size"], 0)
        with open(out_path, "rb") as fh:
            head = fh.read(4)
        self.assertEqual(head, b"\x7fELF")
        with open(out_path + ".manifest.json", "rb") as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["module"], "libdemo.so")

    @staticmethod
    def agent_dir():
        return os.path.dirname(os.path.abspath(__file__))

    # -- IPC ------------------------------------------------------------------------

    def test_ipc_end_to_end(self):
        ipc = IpcServer(self.facade, port=0)
        port = ipc._httpd.server_address[1]
        ipc.start()
        try:
            def call(method, params):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/",
                    data=json.dumps({"method": method, "params": params}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req) as resp:
                    return json.loads(resp.read())

            status = call("get_status", {})
            self.assertTrue(status["ok"])
            self.assertTrue(status["result"]["connected"])
            found = call("find_process", {"name": "com.demo.game"})
            self.assertEqual(found["result"]["pid"], DEMO_PID)
            read = call("read_memory", {"pid": DEMO_PID, "address": hx(BASE), "size": 4})
            self.assertEqual(read["result"]["data_hex"], "7f454c46")
            # hardening: Origin rejected
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                data=b'{"method":"get_status","params":{}}',
                headers={"Content-Type": "application/json", "Origin": "http://evil.example"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            ipc.stop()

    # -- MCP --------------------------------------------------------------------------

    def test_mcp_initialize_tools_list(self):
        resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "tanyao-host")
        resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in resp["result"]["tools"]]
        for expected in ("get_status", "read_memory", "scan_value", "resolve_offset_chain", "dump_module"):
            self.assertIn(expected, names)

    def test_mcp_tools_call_via_ipc(self):
        ipc = IpcServer(self.facade, port=0)
        port = ipc._httpd.server_address[1]
        ipc.start()
        try:
            # redirect the MCP module's IPC URL to the ephemeral port
            from tanyao import mcp_server

            mcp_server.IPC_URL = f"http://127.0.0.1:{port}/"
            resp = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": {"name": "read_memory",
                           "arguments": {"pid": DEMO_PID, "address": hx(BASE), "size": 4}},
            })
            self.assertFalse(resp["result"]["isError"])
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertEqual(payload["data_hex"], "7f454c46")
        finally:
            ipc.stop()


class TestProcessAliveD4(unittest.TestCase):
    """Field defect D4: process_alive must report dead targets as false.

    The kernel legacy op (kOpIsAlive → find_get_pid) still answers alive for a
    pid pinned by our own open target; the host corroborates a TRUE against the
    session-independent process table (cmd 41). The mock models both sides:
    `mortal_alive` toggles real liveness, `alive_overreport` makes the legacy
    op lie like the kernel does."""

    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(port=0, token=TOKEN)
        cls.agent.start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def test_alive_dead_and_overreported(self):
        svc = TanyaoService("127.0.0.1", self.agent.port, TOKEN)
        svc.connect()
        try:
            self.assertTrue(svc.process_alive(DEMO_PID))
            self.assertTrue(svc.process_alive(MORTAL_PID))
            self.assertFalse(svc.process_alive(999999))  # never existed

            self.agent.mortal_alive = False  # process got reaped
            self.assertFalse(svc.process_alive(MORTAL_PID))

            # legacy op over-reports like the kernel quirk; corroboration
            # against the process table must flip the answer to false
            self.agent.alive_overreport = True
            self.assertFalse(svc.process_alive(MORTAL_PID))
            self.assertTrue(svc.process_alive(DEMO_PID))  # genuinely alive unaffected
        finally:
            svc.close()


if __name__ == "__main__":
    unittest.main()
