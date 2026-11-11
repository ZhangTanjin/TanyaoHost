"""Background scan jobs: async first-scans with progress polling.

Long scans (large anonymous ranges over WiFi) must not block the MCP tool call
until toolCallTimeoutMs. scan_start runs the engine scan in a daemon thread and
returns a job id; scan_status reports progress and promotes results into the
per-pid engine on completion.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable


class ScanCancelled(Exception):
    """Raised inside a scan when a cancellation is requested (job state → cancelled)."""


@dataclass
class ScanJob:
    id: str
    pid: int
    kind: str  # "value" | "hex"
    state: str = "running"  # running | done | error | cancelled
    progress_done: int = 0
    progress_total: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    summary: dict | None = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def to_dict(self, include_summary: bool = True) -> dict:
        elapsed = (self.finished_at or time.time()) - self.started_at
        out = {
            "job_id": self.id,
            "pid": self.pid,
            "kind": self.kind,
            "state": self.state,
            "progress_done": self.progress_done,
            "progress_total": self.progress_total,
            "elapsed_sec": round(elapsed, 3),
        }
        if elapsed > 0 and self.progress_done > 0:
            out["rate_mbps"] = round(self.progress_done / elapsed / 1e6, 2)
        if include_summary and self.summary is not None:
            out["summary"] = self.summary
        if self.error:
            out["error"] = self.error
        return out


class JobManager:
    """Keeps the last N jobs per process; daemon threads run the scans."""

    MAX_JOBS = 32

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def start(self, pid: int, kind: str, run_fn, cancel_event: threading.Event | None = None) -> str:
        job = ScanJob(id=uuid.uuid4().hex[:12], pid=pid, kind=kind,
                      cancel_event=cancel_event or threading.Event())
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.MAX_JOBS:
                old = self._order.pop(0)
                self._jobs.pop(old, None)

        def progress(done: int, total: int) -> None:
            job.progress_done, job.progress_total = done, total

        def runner() -> None:
            try:
                job.summary = run_fn(progress)
                job.state = "done"
            except ScanCancelled:
                job.state = "cancelled"
            except Exception as exc:  # noqa: BLE001
                job.state = "error"
                job.error = f"{type(exc).__name__}: {exc}"
            finally:
                job.finished_at = time.time()

        threading.Thread(target=runner, daemon=True, name=f"tanyao-scan-{job.id}").start()
        return job.id

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        """Request cancellation; the engine checks the event between chunks.
        Returns False when the job is unknown or already finished."""
        job = self._jobs.get(job_id)
        if job is None or job.state != "running":
            return False
        job.cancel_event.set()
        return True

    def list_for(self, pid: int | None = None) -> list[ScanJob]:
        with self._lock:
            jobs = [self._jobs[jid] for jid in self._order if jid in self._jobs]
        if pid is not None:
            jobs = [j for j in jobs if j.pid == pid]
        return jobs
