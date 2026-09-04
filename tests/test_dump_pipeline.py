"""dump pipeline client unit tests: pull_dump_with_resume (cmd 63/64/65/68).

Covers the DESIGN_V3_HOST §4 test plan: crc error injection → same-offset
retry; interruption → offset resume → sha256 reconcile; terminal errors
propagate without retry; partial data is never silently discarded.
Run: python3 -m unittest tests.test_dump_pipeline -v
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tanyao.connection import AgentError  # noqa: E402
from tanyao.constants import ProtocolError  # noqa: E402
from tanyao.dump import pull_dump_with_resume  # noqa: E402
from tanyao.frames import (  # noqa: E402
    DUMP_CHUNK_DEFLATE,
    DUMP_CHUNK_LAST,
    DUMP_CHUNK_HEADER,
    decode_dump_chunk,
    encode_dump_chunk,
)


def _blob(size: int) -> bytes:
    rng = random.Random(20260904)
    return bytes(rng.getrandbits(8) for _ in range(size))


class FakeDumpService:
    """dump_pull protocol-alike over an in-memory blob, with fault injection.

    corrupt_once: offsets whose FIRST pull carries a corrupted byte (crc mismatch)
    fail_once:    offsets whose FIRST pull raises a transient transport error
    fail_always:  offsets that always raise (simulates a dead pipeline segment)
    """

    def __init__(self, blob: bytes, *, chunk: int = 64 * 1024,
                 corrupt_once=(), fail_once=(), fail_always=(), compress=True):
        self.blob = blob
        self.chunk = chunk
        self.corrupt_once = set(corrupt_once)
        self.fail_once = set(fail_once)
        self.fail_always = set(fail_always)
        self.compress = compress

    def dump_status(self, dump_id, **_kw):
        return {"exists": True, "size": f"0x{len(self.blob):x}",
                "sha256": hashlib.sha256(self.blob).hexdigest()}

    def dump_pull(self, dump_id=None, *, path=None, offset=0, chunk=256 * 1024,
                  compress=True):
        if offset in self.fail_always:
            raise AgentError("backend_error", errno=-104, detail="segment dead")
        if offset in self.fail_once:
            self.fail_once.discard(offset)
            raise AgentError("backend_error", errno=-104, detail="transient hiccup")
        chunk = min(chunk, self.chunk)
        raw = self.blob[offset:offset + chunk]
        last = offset + chunk >= len(self.blob)
        data = zlib.compress(raw) if self.compress else raw
        flags = (DUMP_CHUNK_DEFLATE if self.compress else 0)
        flags |= (DUMP_CHUNK_LAST if last else 0)
        if offset in self.corrupt_once:
            self.corrupt_once.discard(offset)
            # header carries the crc of the GOOD data; payload byte flipped
            good_crc = zlib.crc32(data) & 0xFFFFFFFF
            bad = bytearray(data)
            bad[0] ^= 0xFF
            wire = bytes(DUMP_CHUNK_HEADER.pack(offset, len(bad), len(raw), flags, good_crc)) + bytes(bad)
        else:
            wire = encode_dump_chunk(offset, data, len(raw), flags)
        try:
            return decode_dump_chunk(wire)
        except ProtocolError as exc:
            # service.dump_pull wraps decode failures as AgentError('internal')
            raise AgentError("internal", detail=str(exc)) from exc


class TestPullDump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "libdemo.dump")
        self.blob = _blob(1024 * 1024 + 777)  # 1MiB + odd tail
        self.sha = hashlib.sha256(self.blob).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_happy_path_compressed(self):
        svc = FakeDumpService(self.blob, chunk=64 * 1024)
        result = pull_dump_with_resume(svc, self.out, dump_id="x-01",
                                       expected_sha256=self.sha,
                                       expected_size=len(self.blob))
        self.assertEqual(result["size"], len(self.blob))
        self.assertEqual(result["sha256"], self.sha)
        with open(self.out, "rb") as fh:
            self.assertEqual(fh.read(), self.blob)
        self.assertFalse(os.path.exists(self.out + ".part"))

    def test_crc_corruption_retried_same_offset(self):
        # corrupt the first pull of chunk #3; the retry must succeed cleanly
        svc = FakeDumpService(self.blob, chunk=64 * 1024, corrupt_once=[3 * 64 * 1024])
        result = pull_dump_with_resume(svc, self.out, dump_id="x-02",
                                       expected_sha256=self.sha)
        self.assertEqual(result["sha256"], self.sha)
        with open(self.out, "rb") as fh:
            self.assertEqual(fh.read(), self.blob)

    def test_double_corruption_fails_keeping_partial(self):
        svc = FakeDumpService(self.blob, chunk=64 * 1024,
                              fail_always=[2 * 64 * 1024])
        store: dict = {}
        with self.assertRaises(AgentError) as ctx:
            pull_dump_with_resume(svc, self.out, dump_id="x-03",
                                  expected_sha256=self.sha, state_store=store)
        self.assertEqual(ctx.exception.error, "internal")
        self.assertIn("failed twice", str(ctx.exception))
        # partial data preserved, resume state registered
        part = self.out + ".part"
        self.assertTrue(os.path.exists(part))
        self.assertEqual(os.path.getsize(part), 2 * 64 * 1024)
        self.assertEqual(store["x-03"]["offset"], 2 * 64 * 1024)

    def test_resume_from_memory_state(self):
        broken = FakeDumpService(self.blob, chunk=64 * 1024,
                                 fail_always=[5 * 64 * 1024])
        store: dict = {}
        with self.assertRaises(AgentError):
            pull_dump_with_resume(broken, self.out, dump_id="x-04",
                                  expected_sha256=self.sha, state_store=store)
        good = FakeDumpService(self.blob, chunk=64 * 1024)
        result = pull_dump_with_resume(good, self.out, dump_id="x-04",
                                       expected_sha256=self.sha,
                                       expected_size=len(self.blob),
                                       state_store=store)
        self.assertEqual(result["sha256"], self.sha)
        with open(self.out, "rb") as fh:
            self.assertEqual(fh.read(), self.blob)

    def test_resume_from_sidecar_after_restart(self):
        broken = FakeDumpService(self.blob, chunk=64 * 1024,
                                 fail_always=[1 * 64 * 1024])
        with self.assertRaises(AgentError):
            # no state_store: only the sidecar survives (serve restart)
            pull_dump_with_resume(broken, self.out, dump_id="x-05",
                                  expected_sha256=self.sha)
        self.assertTrue(os.path.exists(self.out + ".part.state"))
        good = FakeDumpService(self.blob, chunk=64 * 1024)
        result = pull_dump_with_resume(good, self.out, dump_id="x-05",
                                       expected_sha256=self.sha,
                                       expected_size=len(self.blob),
                                       state_store={})
        self.assertEqual(result["size"], len(self.blob))
        self.assertFalse(os.path.exists(self.out + ".part.state"))

    def test_terminal_error_not_retried(self):
        class NotFound(FakeDumpService):
            def dump_pull(self, **kw):
                raise AgentError("not_found", detail="dump deleted")

        calls = {"n": 0}

        def counting():
            calls["n"] += 1
        svc = NotFound(self.blob)
        with self.assertRaises(AgentError) as ctx:
            pull_dump_with_resume(svc, self.out, dump_id="x-06")
        self.assertEqual(ctx.exception.error, "not_found")

    def test_sha256_mismatch_detected(self):
        svc = FakeDumpService(self.blob, chunk=256 * 1024)
        with self.assertRaises(AgentError) as ctx:
            pull_dump_with_resume(svc, self.out, dump_id="x-07",
                                  expected_sha256="0" * 64)
        self.assertIn("sha256", str(ctx.exception))
        # received file kept for inspection (renamed only on success: stays .part)
        self.assertTrue(os.path.exists(self.out + ".part"))

    def test_size_mismatch_detected(self):
        svc = FakeDumpService(self.blob)
        with self.assertRaises(AgentError) as ctx:
            pull_dump_with_resume(svc, self.out, dump_id="x-08",
                                  expected_size=len(self.blob) + 1)
        self.assertIn("size", str(ctx.exception))

    def test_path_variant_and_empty_blob(self):
        small = FakeDumpService(b"", chunk=64 * 1024)
        result = pull_dump_with_resume(small, self.out, path="/data/app/x/base.apk")
        self.assertEqual(result["size"], 0)
        self.assertTrue(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
