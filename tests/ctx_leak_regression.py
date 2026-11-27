"""ctx 槽泄漏回归：批量开/关目标会话后，用户态 ctx 占用数必须回到基线。

为什么需要它（2026-11-27）
--------------------------
Kitty 用户态库里有两张表：内核 session 表 + 用户态 `g_ctxs`。
**只有 `kitty_close()`** 会把 `g_ctxs` 的槽位置 -1（`alloc_ctx` 只找 `fd < 0`
的槽）。用裸 `::close(fd)` 回收会话时：

- 内核 session 被 `fops_release` 释放，看起来「关掉了」；
- 用户态槽位永久泄漏，`KITTY_MAX_CTX = 64` 用满后 `kitty_open()` 返回
  `-ENOMEM`，agent 再也开不了目标，只能重启；
- 而且 `get_ctx_slot(fd)` 按 fd 线性查，会命中先登记的陈旧槽 →
  可能 `-EBADF`，或**读到别的目标**（静默错数据）。

这个缺陷真实发生过一次（agent 的 5 处 `::close` + 2 处回滚，已修）。它靠人读
代码才发现，运气成分很大 —— 所以固化成会失败的测试。

原理
----
agent 支持一个探针：环境变量 `TANYAO_CTX_PROBE` 指向某个路径时，它在**启动**
和**每个请求处理完之后**把当前占用槽数写进该文件。

本测试分两个阶段，覆盖两条会话路径：

- **阶段 1（控制 fd 路径）**：经 serve 调 `resolve_module` N 轮 —— 每次
  `backend.open_target()` / `close_target()`，走 `kitty_close()`。
- **阶段 2（池 fd 路径）**：直连 agent 发 `TARGET_OPEN` / `TARGET_CLOSE`
  N 轮 —— 每次 `Backend::connect_fd()` 拿一个池 fd，回收走
  `release_target_fd()` / `TargetCtx::close()`。

两阶段各自「读基线 → 跑 → 再读 → 断言回到基线」；泄漏会让数字单调增长。

用法
----
    # 1) agent 必须带探针启动：
    #    TANYAO_CTX_PROBE=/data/local/tmp/.ctx-live \
    #      /data/local/tmp/tanyao-agent-kitty --bind 127.0.0.1 --port 52730 ...
    # 2) 跑测试：
    python3 tests/ctx_leak_regression.py --pid <target pid> [--rounds 100]

退出码 0 = 通过；1 = 泄漏或轮次失败；2 = 环境不满足（探针未启用）。

tanyao 后端（`-DTANYAO_BACKEND=lkm`）没有第二张表，`ctx_live()` 返回 -ENOSYS，
探针会写 -1 —— 此时测试报 SKIP（退出码 0），因为该后端不存在这类泄漏。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request

# 直连 agent（阶段 2）复用 host 自己的连接实现，不重复造帧格式
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DEFAULT_BASE_URL = "http://127.0.0.1:28101/"
DEFAULT_PROBE = "/data/local/tmp/.ctx-live"


def rpc(base_url: str, method: str, params: dict, timeout: float = 60.0):
    body = json.dumps({"method": method, "params": params}).encode()
    req = urllib.request.Request(
        base_url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def read_probe(adb: str, serial: str | None, path: str) -> int | None:
    cmd = [adb] + (["-s", serial] if serial else [])
    cmd += ["shell", f"su -c 'cat {path}'"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = out.stdout.strip()
    if not text:
        return None
    try:
        return int(text.splitlines()[0])
    except ValueError:
        return None


def phase_pool(host: str, port: int, token: str, pid: int, rounds: int,
               probe: int, read: "callable") -> int:
    """阶段 2：直连 agent，反复 target_open/target_close（池 fd 路径）。"""
    from tanyao.connection import AgentConnection
    from tanyao.constants import CMD_TARGET_CLOSE, CMD_TARGET_OPEN

    from tanyao.connection import AgentError

    conn = AgentConnection(host, port, token)
    conn.connect()
    try:
        failures = []
        for index in range(rounds):
            try:
                opened = conn.request(CMD_TARGET_OPEN, {"pid": pid})
                handle = opened.get("handle") if isinstance(opened, dict) else None
                if not handle:
                    failures.append((index, f"open 无 handle: {opened}"))
                else:
                    conn.request(CMD_TARGET_CLOSE, {"handle": handle})
            except AgentError as exc:
                # -ENOMEM 就是槽位耗尽的典型症状（KITTY_MAX_CTX=64）
                failures.append((index, f"{exc}"))
            if len(failures) >= 5:
                break
    finally:
        conn.close()

    final = read()
    print(f"[池 fd] 轮次失败={len(failures)} 完成后占用槽={final}（基线 {probe}）")
    for idx, err in failures:
        print(f"  round {idx}: {err}")
    if failures:
        print("FAIL: 池 fd 路径的开/关有失败")
        return 1
    if final != probe:
        print(
            f"FAIL: 池 fd 路径 ctx 槽从 {probe} 涨到 {final} —— "
            "有路径没走 kitty_close()/release_target_fd"
        )
        return 1
    print("PASS: 池 fd 路径 %d 轮后 ctx 槽回到基线" % rounds)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True, help="目标进程 pid（用来开/关会话）")
    ap.add_argument("--rounds", type=int, default=100, help="开/关循环次数（默认 100，需 > 64）")
    ap.add_argument("--module", default="libc.so", help="每轮解析的模块名")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--probe", default=DEFAULT_PROBE, help="agent 探针文件路径（设备上）")
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--serial", default=os.environ.get("KITTY_DEV") or None)
    ap.add_argument("--agent-host", default="127.0.0.1", help="阶段 2 直连的 agent 地址")
    ap.add_argument("--agent-port", type=int, default=52730)
    ap.add_argument("--token-file", default="/tmp/tanyao_token")
    ap.add_argument("--skip-pool", action="store_true", help="只跑阶段 1")
    args = ap.parse_args()

    status = rpc(args.base_url, "get_status", {})
    if not status.get("ok"):
        print(f"SKIP/FAIL: agent 不可达: {status.get('error')}", file=sys.stderr)
        return 2
    backend = (status.get("result") or {}).get("backend", {}).get("name", "?")

    # 先触发一次请求，确保探针已落盘（启动基线也会写一次）
    warm = rpc(args.base_url, "find_process", {"name": "surfaceflinger"})
    baseline = read_probe(args.adb, args.serial, args.probe)
    if baseline is None:
        print(
            "环境不满足：读不到探针文件 %s\n"
            "  agent 需要以 TANYAO_CTX_PROBE=%s 启动。" % (args.probe, args.probe),
            file=sys.stderr,
        )
        return 2
    if baseline < 0:
        print(f"SKIP: backend={backend} 没有用户态 ctx 表（ctx_live=-1），无此类泄漏")
        return 0

    print(f"backend={backend} 探针基线={baseline} 轮次={args.rounds} pid={args.pid}")

    failures: list[tuple[int, str]] = []
    for index in range(args.rounds):
        out = rpc(
            args.base_url,
            "resolve_module",
            {"pid": args.pid, "name": args.module},
        )
        if not out.get("ok"):
            failures.append((index, str(out.get("error"))))
            if len(failures) >= 5:
                break

    final = read_probe(args.adb, args.serial, args.probe)
    if final is None:
        print("FAIL: 跑完之后读不到探针文件", file=sys.stderr)
        return 1

    print(f"轮次失败={len(failures)} 完成后占用槽={final}（基线 {baseline}）")
    for idx, err in failures:
        print(f"  round {idx}: {err}")

    if failures:
        print("FAIL: 开/关循环有失败 —— 很可能是槽位已耗尽（-ENOMEM）")
        return 1
    if final != baseline:
        print(
            f"FAIL: ctx 槽从 {baseline} 涨到 {final} —— 有路径没走 kitty_close()。\n"
            "  查 agent 里是否有裸 ::close(fd) 回收 kitty 会话（应改 "
            "Backend::release_target_fd）。"
        )
        return 1

    print("PASS: 阶段 1（控制 fd）开/关 %d 轮后 ctx 槽回到基线" % args.rounds)

    if args.skip_pool:
        return 0
    try:
        token = open(args.token_file, encoding="utf-8").read().strip()
    except OSError as exc:
        print(f"SKIP 阶段 2: 读不到 token 文件 {args.token_file}（{exc}）")
        return 0
    return phase_pool(
        args.agent_host, args.agent_port, token, args.pid, args.rounds,
        read_probe(args.adb, args.serial, args.probe),
        lambda: read_probe(args.adb, args.serial, args.probe),
    )


if __name__ == "__main__":
    sys.exit(main())