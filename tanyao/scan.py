"""Host-side scan engine: first scan / refine / hex-pattern over chunked mem_read.

Scan state lives entirely on the host (design decision D3). The agent only
serves mem_read/mem_readv.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Callable

from .constants import MAP_READ
from .jobs import ScanCancelled

# value type name -> (struct fmt, size, python kind)
TYPES: dict[str, tuple[str, int, str]] = {
    "u8": ("<B", 1, "int"),
    "u16": ("<H", 2, "int"),
    "u32": ("<I", 4, "int"),
    "u64": ("<Q", 8, "int"),
    "i8": ("<b", 1, "int"),
    "i16": ("<h", 2, "int"),
    "i32": ("<i", 4, "int"),
    "i64": ("<q", 8, "int"),
    "f32": ("<f", 4, "float"),
    "f64": ("<d", 8, "float"),
}

MAX_HITS = 200_000
DEFAULT_CHUNK = 1 << 20

PAC_MASK_DEFAULT = 0x0000FFFFFFFFFFFF


@dataclass(slots=True)
class Hit:
    address: int
    value: int | float  # last observed value


@dataclass
class ScanState:
    pid: int | None = None
    ranges: list[tuple[int, int]] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    vtype: str = "u32"
    scan_round: int = 0
    truncated: bool = False
    skipped_ranges: list[tuple[int, int]] = field(default_factory=list)  # unreadable holes

    @property
    def count(self) -> int:
        return len(self.hits)

    @property
    def skipped_bytes(self) -> int:
        return sum(hi - lo for lo, hi in self.skipped_ranges)


def _matches(found: int | float, want: int | float, epsilon: float) -> bool:
    if isinstance(found, float) or isinstance(want, float):
        if epsilon > 0:
            return abs(found - want) <= epsilon
        return math.isclose(found, want, rel_tol=1e-6)
    return found == want


class ScanEngine:
    """One scan state per target process; the service owns lifecycle."""

    def __init__(self, read_fn, max_transfer: int = DEFAULT_CHUNK) -> None:
        # read_fn(pid, address, size) -> bytes ; raises AgentError on failure
        self._read = read_fn
        self._max_transfer = max_transfer
        self._dead_gran = self.MIN_SCAN_CHUNK  # engine-level dead-zone skip granularity
        self.state = ScanState()

    # -- setup -------------------------------------------------------------------

    def set_ranges(self, pid: int, ranges: list[tuple[int, int]]) -> None:
        if self.state.pid != pid:
            self.state = ScanState(pid=pid)
        self.state.ranges = [(start, end) for start, end in ranges if end > start]

    def set_default_ranges(self, pid: int, maps) -> None:
        """Default scan range: readable anonymous + heap-ish writable mappings."""
        ranges = [
            (m.start, m.end)
            for m in maps
            if (m.flags & MAP_READ) and (m.flags & 32 or (m.flags & 2 and not m.path))
        ]
        self.set_ranges(pid, ranges)

    def clear(self) -> None:
        """Clear scan results but KEEP range configuration (field feedback: users
        expect re-scan without re-setting ranges; scan_next still requires a new
        first scan via round reset)."""
        self.state = ScanState(
            pid=self.state.pid, ranges=self.state.ranges, vtype=self.state.vtype
        )

    # -- fault-tolerant chunked reads (P1: special pages like [vvar] PFNMAP) ------

    MIN_SCAN_CHUNK = 4096

    def _scan_region(self, pid: int, lo: int, hi: int, chunk: int, on_chunk) -> None:
        """Fault-tolerant STREAMING read+scan of [lo, hi).

        on_chunk(addr, data) fires as each chunk arrives — reads and scanning
        are interleaved, so host memory stays constant regardless of range
        size (a 10GB range does NOT buffer 10GB) and progress flows live
        (fixes the blocking-job bug: the previous version buffered the whole
        range before scanning, freezing progress_done at 0 and risking OOM).

        On a failed chunk: bisect down to an effective minimum granularity,
        skipping only unreadable leaves (appended to
        self.state.skipped_ranges) instead of aborting. Special pages such as
        [vvar] (VM_PFNMAP) cost ~2 reads per bisection level and are skipped
        cleanly; completed progress is preserved. Dead-zone granularity
        escalates geometrically (4KB -> 64MB cap) via the engine-level
        `self._dead_gran` counter — persists across chunk boundaries and
        recursion levels, resets to MIN_SCAN_CHUNK on next successful read
        (isolated holes keep 4KB precision)."""
        min_take = self._dead_gran
        pos = lo
        while pos < hi:
            take = min(chunk, hi - pos)
            try:
                data = self._read(pid, pos, take)
            except Exception:
                eff = self._dead_gran
                if take <= eff:
                    self.state.skipped_ranges.append((pos, pos + take))
                    pos += take
                    self._dead_gran = min(64 * 1024 * 1024, eff * 2)
                    continue
                mid = pos + max(eff, (take // 2 // eff) * eff)
                self._scan_region(pid, pos, mid, chunk, on_chunk)
                pos = mid
                self._dead_gran = min(64 * 1024 * 1024, eff * 2)
                continue
            # callback runs OUTSIDE the fault handler: a bug in the scan
            # callback must propagate loudly, never masquerade as an EFAULT
            # (this exact masking bug hid scan_hex's NameError for a day)
            self._dead_gran = self.MIN_SCAN_CHUNK  # successful read resets granularity
            on_chunk(pos, data)
            pos += len(data)

    # -- first scan ---------------------------------------------------------------

    def scan_value(
        self,
        pid: int,
        vtype: str,
        value: int | float,
        *,
        epsilon: float = 0.0,
        alignment: int | None = None,
        chunk: int = DEFAULT_CHUNK,
        progress=None,
        cancel_event=None,
    ) -> int:
        fmt, size, _kind = TYPES[vtype]
        align = alignment or size
        want = float(value) if isinstance(value, float) else int(value)
        self.state = ScanState(pid=pid, vtype=vtype, ranges=self.state.ranges if self.state.pid == pid else [])
        if not self.state.ranges:
            raise ValueError("no scan ranges set; call set_ranges/set_default_ranges first")
        hits: list[Hit] = []
        truncated = False
        total = sum(end - start for start, end in self.state.ranges)
        done = 0
        unpack = struct.Struct(fmt).unpack_from

        def on_chunk(addr: int, data: bytes) -> None:
            nonlocal done, truncated
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelled()
            scan_end = len(data) - size
            i = (align - (addr % align)) % align  # alignment from absolute address
            while i <= scan_end:
                found = unpack(data, i)[0]
                if _matches(found, want, epsilon):
                    hits.append(Hit(address=addr + i, value=found))
                    if len(hits) >= MAX_HITS:
                        truncated = True
                        return
                i += align
            done += len(data)
            if progress:
                progress(done, total)

        for start, end in self.state.ranges:
            self._scan_region(pid, start, end, min(chunk, self._max_transfer), on_chunk)
            if truncated:
                break
        self.state.skipped_ranges = self._coalesce(self.state.skipped_ranges)
        self.state.hits = hits
        self.state.truncated = truncated
        self.state.scan_round = 1
        return len(hits)

    def scan_hex(self, pid: int, pattern: bytes, mask: bytes, *, chunk: int = DEFAULT_CHUNK, progress=None, cancel_event=None) -> int:
        """AOB scan. `mask` bytes: 0xFF = must match, 0x00 = wildcard. Same length as pattern."""
        if not pattern or len(pattern) != len(mask):
            raise ValueError("pattern/mask length mismatch")
        plen = len(pattern)
        self.state = ScanState(pid=pid, vtype="bytes", ranges=self.state.ranges if self.state.pid == pid else [])
        if not self.state.ranges:
            raise ValueError("no scan ranges set")
        hits: list[Hit] = []
        truncated = False
        carry = b""      # tail of previous contiguous chunk (straddling matches)
        carry_addr = 0
        done = 0
        total = sum(end - start for start, end in self.state.ranges)

        def on_chunk(addr: int, data: bytes) -> None:
            nonlocal carry, carry_addr, done, truncated
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelled()
            buf = carry + data
            base = addr - len(carry)
            i = 0
            while i + plen <= len(buf):
                seg = buf[i : i + plen]
                if all((seg[j] & mask[j]) == (pattern[j] & mask[j]) for j in range(plen) if mask[j]):
                    hits.append(Hit(address=base + i, value=int.from_bytes(seg[:8], "little")))
                    if len(hits) >= MAX_HITS:
                        truncated = True
                        return
                i += 1
            carry = buf[len(buf) - (plen - 1):] if plen > 1 else b""
            carry_addr = addr + len(data) - len(carry)
            done += len(data)
            if progress:
                progress(done, total)

        for start, end in self.state.ranges:
            self._scan_region(pid, start, end, min(chunk, self._max_transfer), on_chunk)
            carry = b""  # hole skipped: straddling carry is invalid across the gap
            if truncated:
                break
        self.state.skipped_ranges = self._coalesce(self.state.skipped_ranges)
        self.state.hits = hits
        self.state.truncated = truncated
        self.state.scan_round = 1
        return len(hits)

    # -- refine scans ---------------------------------------------------------------

    def refine(
        self,
        pid: int,
        mode: str,
        value: int | float | None = None,
        *,
        epsilon: float = 0.0,
        batch: int = 256,
    ) -> int:
        """Re-read current hits and keep those matching the relation.

        mode: eq | neq | changed | unchanged | increased | decreased
        """
        if self.state.scan_round == 0:
            raise ValueError("no first scan yet")
        _fmt, size, _kind = TYPES[self.state.vtype]

        def read_values(addrs: list[int]) -> list[int | float | None]:
            out: list[int | float | None] = []
            for i in range(0, len(addrs), batch):
                group = addrs[i : i + batch]
                for addr in group:
                    try:
                        data = self._read(pid, addr, size)
                        out.append(struct.unpack(TYPES[self.state.vtype][0], data)[0])
                    except Exception:
                        out.append(None)
            return out

        old = [h.value for h in self.state.hits]
        new = read_values([h.address for h in self.state.hits])
        kept: list[Hit] = []
        for o, n, hit in zip(old, new, self.state.hits):
            if n is None:
                continue  # unreadable now -> drop
            if mode == "eq":
                ok = value is not None and _matches(n, value, epsilon)
            elif mode == "neq":
                ok = value is not None and not _matches(n, value, epsilon)
            elif mode == "changed":
                ok = n != o
            elif mode == "unchanged":
                ok = n == o
            elif mode == "increased":
                ok = n > o
            elif mode == "decreased":
                ok = n < o
            else:
                raise ValueError(f"unknown refine mode {mode!r}")
            if ok:
                kept.append(Hit(address=hit.address, value=n))
        self.state.hits = kept
        self.state.scan_round += 1
        return len(kept)

    # -- results -----------------------------------------------------------------

    def results(self, offset: int = 0, limit: int = 256) -> list[dict]:
        out = []
        for hit in self.state.hits[offset : offset + limit]:
            v = hit.value
            out.append(
                {
                    "address": f"0x{hit.address:x}",
                    "value": v if isinstance(v, float) else int(v),
                }
            )
        return out

    def _coalesce(self, skipped: list[tuple[int, int]]) -> list[tuple[int, int]]:
        """Sort and merge adjacent/overlapping skipped ranges."""
        if not skipped:
            return []
        skipped = sorted(skipped)
        merged = [skipped[0]]
        for lo, hi in skipped[1:]:
            plo, phi = merged[-1]
            if lo <= phi:
                merged[-1] = (plo, max(phi, hi))
            else:
                merged.append((lo, hi))
        return merged

    def summary(self) -> dict:
        return {
            "pid": self.state.pid,
            "type": self.state.vtype,
            "round": self.state.scan_round,
            "count": self.state.count,
            "ranges": len(self.state.ranges),
            "truncated": self.state.truncated,
            "skipped_ranges": len(self.state.skipped_ranges),
            "skipped_bytes": self.state.skipped_bytes,
        }
