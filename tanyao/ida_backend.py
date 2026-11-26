"""IDA Pro (idalib) decompilation backend.

Replaces the former headless-Ghidra pipeline. Same job model and output shape,
so `decompile_start` / `decompile_status` keep their MCP contract; only the
engine behind them changes.

Why idalib instead of `analyzHeadless`
--------------------------------------
IDA Pro 9 ships `idalib`, which loads a binary and runs Hex-Rays in-process.
That avoids spawning a JVM, gives us the same auto-analysis quality, and makes
per-function progress reporting trivial (the previous Ghidra path had to infer
progress from log-scraping).

Layout produced under out_dir (unchanged from the Ghidra era, so existing
consumers keep working):
    <module>.dump.so        raw dump pulled from the device (input)
    <module>.c              single concatenated pseudo-C file
    functions/<name>.c      one file per function
    index.json              {module, functions:[{name,address,file}], ...}

Environment:
    TANYAO_IDA_DIR   IDA Pro installation root (default: highest ida-pro-* found
                     under $HOME, /opt, /usr/local — so an in-place upgrade is
                     picked up without editing config)
    TANYAO_IDA_PY    idalib python dir   (default <IDA_DIR>/idalib/python)

If IDA is absent the caller gets a structured `unavailable` error, exactly like
the Ghidra path did — tools never crash, callers can degrade.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

# --- environment discovery ---------------------------------------------------

# IDA ships as `ida-pro-<version>` directories. Hardcoding one version breaks
# silently on upgrade: the host keeps loading the old tree while the operator
# believes they are running the new one. Discover the highest version instead,
# and let TANYAO_IDA_DIR override when a specific tree must be pinned.
_IDA_DIR_PARENTS = (
    os.path.expanduser("~"),
    "/opt",
    "/usr/local",
)
_IDA_DIR_RE = re.compile(r"^ida-pro-(\d+(?:\.\d+)*)$")


def _version_key(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split(".") if part.isdigit())


def discover_ida_root() -> str | None:
    """Highest-versioned ida-pro-* install, or None when none is found."""
    best: tuple[tuple[int, ...], str] | None = None
    for parent in _IDA_DIR_PARENTS:
        try:
            entries = os.listdir(parent)
        except OSError:
            continue
        for name in entries:
            m = _IDA_DIR_RE.match(name)
            if not m:
                continue
            path = os.path.join(parent, name)
            if not os.path.isdir(path):
                continue
            key = _version_key(m.group(1))
            if best is None or key > best[0]:
                best = (key, path)
    return best[1] if best else None


def ida_root() -> str:
    explicit = os.environ.get("TANYAO_IDA_DIR")
    if explicit:
        return explicit
    found = discover_ida_root()
    return found if found else "/home/ufo/data/tools/ida-pro-9.5"


def idalib_python_dir() -> str:
    explicit = os.environ.get("TANYAO_IDA_PY")
    if explicit:
        return explicit
    return os.path.join(ida_root(), "idalib", "python")


def ida_available() -> tuple[bool, str]:
    """Return (ok, detail). Never raises."""
    root = ida_root()
    if not os.path.isdir(root):
        return False, f"IDA Pro not found at {root} (set TANYAO_IDA_DIR)"
    py = idalib_python_dir()
    if not os.path.isdir(os.path.join(py, "idapro")):
        return False, f"idalib python module not found under {py}"
    return True, f"IDA Pro at {root}"


# --- job model ----------------------------------------------------------------


@dataclass
class IdaJob:
    job_id: str
    pid: int
    module: str
    out_dir: str
    state: str = "running"          # running | done | error | cancelled
    started_at: float = field(default_factory=time.monotonic)
    functions_total: int = 0
    functions_done: int = 0
    error: str = ""
    result: dict | None = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def to_dict(self) -> dict:
        out = {
            "job_id": self.job_id,
            "pid": self.pid,
            "module": self.module,
            "state": self.state,
            "engine": "ida",
            "elapsed_sec": round(self.elapsed, 1),
            "out_dir": self.out_dir,
            "functions_done": self.functions_done,
            "functions_total": self.functions_total,
        }
        if self.error:
            out["error"] = self.error
        if self.result:
            out.update(self.result)
        return out

    def cancel(self) -> None:
        self._cancel.set()


# --- the decompiler worker ----------------------------------------------------

# Executed inside the idalib process. Kept as a source string because it must run
# with idalib's own sys.path, not the host process's.
_WORKER = r'''
import json, os, re, sys, time

def main():
    dump_path, out_dir, max_functions, progress_path, cancel_path = sys.argv[1:6]
    max_functions = int(max_functions)

    import idapro
    rc = idapro.open_database(dump_path, run_auto_analysis=True)
    if rc != 0:
        print(json.dumps({"ok": False, "error": f"open_database rc={rc}"}))
        return 1

    import ida_auto, ida_funcs, ida_hexrays, ida_name, ida_nalt, ida_bytes
    import idaapi
    from idaapi import BADADDR

    # Write a helper so a function body can be read as raw bytes when the dump
    # has no segments covering it (common for hybrid dumps).
    try:
        ida_auto.auto_wait()
    except Exception:
        pass

    have_hexrays = False
    try:
        have_hexrays = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        have_hexrays = False

    func_entries = []
    total = ida_funcs.get_func_qty()
    for i in range(total):
        # getn_func() is deprecated in IDA 9.5 (warns on every call, and the
        # deprecation notice names get_func_ea_by_num as the replacement). The
        # pair below is byte-for-byte equivalent on both 9.4 and 9.5, including
        # the out-of-range case where getn_func returns None: get_func_ea_by_num
        # gives BADADDR and get_func(BADADDR) gives None.
        ea = ida_funcs.get_func_ea_by_num(i)
        if ea == BADADDR:
            continue
        f = ida_funcs.get_func(ea)
        if f is None:
            continue
        func_entries.append((f.start_ea, f.end_ea))

    if max_functions > 0:
        func_entries = func_entries[:max_functions]

    os.makedirs(os.path.join(out_dir, "functions"), exist_ok=True)
    index = []
    combined = []
    aborted = False

    def safe(name):
        s = re.sub(r"[^A-Za-z0-9_.$-]", "_", name or "")
        return s[:120] or "sub"

    for n, (ea, end) in enumerate(func_entries):
        if os.path.exists(cancel_path):
            aborted = True
            break
        try:
            raw_name = ida_funcs.get_func_name(ea) or ("sub_%X" % ea)
        except Exception:
            raw_name = "sub_%X" % ea
        text = None
        if have_hexrays:
            try:
                cf = ida_hexrays.decompile(ea)
                if cf is not None:
                    text = str(cf)
            except Exception:
                text = None
        if text is None:
            # Fall back to disassembly so the file always has content.
            lines = []
            cur = ea
            try:
                while cur < end and len(lines) < 4000:
                    line = ida_funcs.get_func_name(cur)
                    d = ida_bytes.generate_disasm_line(cur, 0) or ""
                    lines.append("  %08X  %s" % (cur, d))
                    nxt = ida_bytes.get_item_end(cur)
                    if nxt <= cur:
                        break
                    cur = nxt
            except Exception:
                pass
            text = "// disassembly fallback (no Hex-Rays)\n" + "\n".join(lines)

        fname = "%04d_%s.c" % (n, safe(raw_name))
        with open(os.path.join(out_dir, "functions", fname), "w", encoding="utf-8") as fh:
            fh.write("// %s @ 0x%x\n" % (raw_name, ea))
            fh.write(text)
            fh.write("\n")
        combined.append("// ---- %s @ 0x%x ----\n%s\n" % (raw_name, ea, text))
        index.append({"name": raw_name, "address": "0x%x" % ea, "file": fname})

        # progress heartbeat, read by the host poller
        tmp = progress_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"done": n + 1, "total": len(func_entries)}, fh)
        os.replace(tmp, progress_path)

    mod = os.path.basename(dump_path)
    try:
        ida_version = idaapi.get_kernel_version()
    except Exception:
        ida_version = ""
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump({"module": mod, "engine": "ida", "ida_version": ida_version,
                   "hexrays": have_hexrays,
                   "functions": index, "cancelled": aborted}, fh, indent=2)
    with open(os.path.join(out_dir, mod + ".c"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(combined))

    try:
        idapro.close_database(False)
    except Exception:
        pass
    # Record WHICH IDA produced this output. After an in-place upgrade a stale
    # worker or a pinned TANYAO_IDA_DIR can silently keep using the old engine,
    # and without this the result looks identical either way.
    print(json.dumps({"ok": True, "functions": len(index),
                      "hexrays": have_hexrays, "cancelled": aborted,
                      "ida_version": ida_version}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''


def _worker_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "_ida_worker.py")


def _ensure_worker_file() -> str:
    path = _worker_path()
    try:
        with open(path, encoding="utf-8") as fh:
            if fh.read() == _WORKER:
                return path
    except OSError:
        pass
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_WORKER)
    return path


def start_decompile(
    dump_path: str,
    out_dir: str,
    *,
    max_functions: int,
    job_id: str,
    pid: int,
    module: str,
    on_done: Callable[[IdaJob], None] | None = None,
) -> IdaJob:
    """Spawn the idalib worker for `dump_path` and return the tracked job.

    The caller owns polling; this function only launches and wires progress.
    Raises RuntimeError when IDA is unavailable (callers map that to a
    structured `unavailable` AgentError).
    """
    ok, detail = ida_available()
    if not ok:
        raise RuntimeError(detail)

    worker = _ensure_worker_file()
    progress_path = os.path.join(out_dir, ".progress.json")
    cancel_path = os.path.join(out_dir, ".cancel")
    for stale in (progress_path, cancel_path):
        try:
            os.unlink(stale)
        except OSError:
            pass

    job = IdaJob(job_id=job_id, pid=pid, module=module, out_dir=out_dir)

    def run() -> None:
        import subprocess

        env = dict(os.environ)
        env["PYTHONPATH"] = idalib_python_dir() + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        env.setdefault("DISPLAY", "")
        try:
            proc = subprocess.Popen(
                [sys.executable, worker, dump_path, out_dir,
                 str(max(1, int(max_functions))), progress_path, cancel_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
        except OSError as exc:
            job.state = "error"
            job.error = f"ida worker failed to start: {exc}"
            if on_done:
                on_done(job)
            return

        deadline = time.monotonic() + 3600
        while proc.poll() is None:
            if job._cancel.is_set():
                try:
                    with open(cancel_path, "w", encoding="utf-8") as fh:
                        fh.write("1")
                except OSError:
                    pass
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                job.state = "cancelled"
                if on_done:
                    on_done(job)
                return
            if time.monotonic() > deadline:
                proc.kill()
                job.state = "error"
                job.error = "ida decompile timed out (3600s)"
                if on_done:
                    on_done(job)
                return
            _read_progress(job, progress_path)
            time.sleep(0.5)

        out, err = proc.communicate()
        _read_progress(job, progress_path)
        if proc.returncode != 0:
            job.state = "error"
            job.error = (err or out or "").strip()[-800:] or f"exit {proc.returncode}"
        else:
            job.state = "done"
            # The worker's last stdout line is its JSON verdict; carry the IDA
            # version through so a caller can tell which engine produced this.
            ida_version = ""
            for line in reversed((out or "").strip().splitlines()):
                try:
                    verdict = json.loads(line)
                except ValueError:
                    continue
                if isinstance(verdict, dict) and "ida_version" in verdict:
                    ida_version = str(verdict.get("ida_version") or "")
                break
            job.result = {
                "out_dir": out_dir,
                "ida_version": ida_version,
                "index": os.path.join(out_dir, "index.json"),
                "c_file": os.path.join(out_dir, f"{os.path.basename(dump_path)}.c"),
                "functions": job.functions_done or job.functions_total,
            }
        if on_done:
            on_done(job)

    threading.Thread(target=run, daemon=True).start()
    return job


def _read_progress(job: IdaJob, progress_path: str) -> None:
    try:
        with open(progress_path, encoding="utf-8") as fh:
            data = json.load(fh)
        job.functions_done = int(data.get("done", job.functions_done))
        job.functions_total = int(data.get("total", job.functions_total))
    except (OSError, ValueError):
        pass
