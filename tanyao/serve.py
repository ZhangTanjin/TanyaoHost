"""`serve` entry point: agent address from env/args, connect, run IPC + keepalive.

Usage:
    python3 -m tanyao.serve --host 192.168.42.100 [--port 52730] [--token xxx]
Env:
    TANYAO_AGENT=192.168.42.100:52730   (host[:port])
    TANYAO_TOKEN=<shared secret>
    TANYAO_ALLOW_WRITE=1                (enable memory write tools)
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

from .analysis import AnalysisFacade
from .connection import DEFAULT_PORT
from .ipc import IpcServer
from .service import TanyaoService


def main() -> int:
    parser = argparse.ArgumentParser(prog="tanyao-serve")
    parser.add_argument("--host", default=None, help="device agent address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token", default=None)
    parser.add_argument("--ipc-port", type=int, default=28101)
    parser.add_argument("--no-keepalive", action="store_true")
    args = parser.parse_args()

    host = args.host
    token = args.token
    if host is None:
        env = os.environ.get("TANYAO_AGENT", "")
        if env:
            if ":" in env:
                h, p = env.rsplit(":", 1)
                host, args.port = h, int(p)
            else:
                host = env
    if host is None:
        print("error: no agent address (use --host or TANYAO_AGENT)", file=sys.stderr)
        return 2
    if token is None:
        token = os.environ.get("TANYAO_TOKEN") or None
    # D12: transport label for diagnostics (start-serve.sh sets adb forward for
    # loopback targets; direct TCP otherwise)
    os.environ["TANYAO_TRANSPORT"] = (
        "adb-forward" if host in ("127.0.0.1", "localhost", "::1") else "direct-tcp"
    )

    service = TanyaoService(host, args.port, token)
    facade = AnalysisFacade(service)

    try:
        backend = service.connect()
    except Exception as exc:
        print(f"error: initial connect failed: {exc}", file=sys.stderr)
        # keep serving IPC anyway; MCP clients can retry via connect()
    else:
        print(
            f"connected to agent {host}:{args.port} (gen={service.generation()}, "
            f"backend={backend.name} abi={backend.abi_major}.{backend.abi_minor} "
            f"caps=0x{backend.capabilities:x})",
            file=sys.stderr,
        )

    ipc = IpcServer(facade, port=args.ipc_port)
    ipc.start()
    print(f"IPC listening on 127.0.0.1:{args.ipc_port}", file=sys.stderr)

    stop_event = threading.Event()

    def on_signal(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if not args.no_keepalive:
        def keepalive():
            while not stop_event.wait(10.0):
                try:
                    if service.is_connected():
                        service.ping()
                except Exception:
                    pass  # reconnect happens lazily on next use

        threading.Thread(target=keepalive, daemon=True, name="tanyao-keepalive").start()

    print("ready.", file=sys.stderr)
    try:
        while not stop_event.wait(3600):
            pass
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
