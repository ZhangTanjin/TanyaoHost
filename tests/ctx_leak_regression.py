"""ctx 槽泄漏回归：会话开/关之后，用户态 ctx 占用数不得随轮数增长。

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

**断言用差分，不用绝对值**
--------------------------
第一版断言 `final == baseline`，复查发现它和 host 的会话缓存耦合：

`resolve_module` 走 `service.target_maps()` → `_require_handle()`，**按 pid
缓存**会话；host 只在槽位满时才 `close_target()`。所以同一个 pid 跑 N 轮
实际只 open 一次，之后一直复用缓存句柄。于是：

| 起始状态 | `final == baseline` 的结果 |
| --- | --- |
| 该 pid 还没缓存 | baseline=1，第一轮后 2 并保持 → **健康 agent 也 FAIL** |
| 该 pid 已有缓存 | baseline=2，跑完仍 2 → **PASS 但根本没经过 open/close** |

改成差分后对缓存天然免疫：

    跑第 1 轮 → 读 e1（此时 = 基线 + 常驻缓存会话）
    再跑 N-1 轮 → 读 eN
    断言 eN == e1（不随轮数增长）

两阶段都用这个口径。阶段 2（池 fd）每轮真的 connect_fd → open_target_on →
release_target_fd，泄漏会表现为 eN 单调增大。

用法
----
    # 1) agent 必须带探针启动：
    #    TANYAO_CTX_PROBE=/data/local/tmp/.ctx-live \
    #      /data/local/tmp/tanyao-agent-kitty --bind 127.0.0.1 --port 52730 ...
    # 2) 跑测试：
    python3 tests/ctx_leak_regression.py --pid <target pid> [--rounds 100]

退出码 0 = 通过；1 = 泄漏或轮次失败；2 = 环境不满足（探针未启用）。

tanyao 后端（`-DTANYAO_BACKEND=lkm`）没有第二张表，`ctx_live()` 返回 -ENOSYS，
探针写 -1 —— 此时报 SKIP（退出码 0），因为该后端不存在这类泄漏。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DEFAULT_BASE_URL = "http://127.0.0.1:28101/"
DEFAULT_PROBE = "/data/local/tmp/.ctx-live"
SENTINEL = -999


def rpc(base_url: str, method: str, params: dict, timeout: float = 60.0):
    body = json.dumps({"method": method, "params": params}).encode()
    req = urllib.request.Request(
        base_url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _adb_cmd(adb: str, serial: str | None, shell: str) -> list[str]:
    return [adb] + (["-s", serial] if serial else []) + ["shell", shell]


def read_probe(adb: str, serial: str | None, path: str,
               attempts: int = 3, delay: float = 0.1) -> int | None:
    """读探针，失败重试。

    写入端已改成 tmp+rename 原子替换，理论上不会读到截断内容；这里仍重试，
    是为了容忍转发侧/文件系统偶发的空读 —— 一次空读不该让测试假失败。
    """
    for attempt in range(attempts):
        try:
            out = subprocess.run(
                _adb_cmd(adb, serial, f"su -c 'cat {path}'"),
                capture_output=True, text=True, timeout=30,
            )
            text = out.stdout.strip()
            if text:
                return int(text.splitlines()[0])
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        if attempt + 1 < attempts:
            time.sleep(delay)
    return None


def write_probe_sentinel(adb: str, serial: str | None, path: str) -> None:
    """把探针文件写成哨兵。

    如果 agent 没有以 TANYAO_CTX_PROBE 启动，文件里会残留上一次测试的值 ——
    那个值通常正好等于基线，断言会**假通过**。先写 -999，发一个请求后再读：
    仍是 -999 就说明探针没在更新，测试必须 SKIP 而不是 PASS。
    """
    subprocess.run(
        _adb_cmd(adb, serial, f"su -c 'echo {SENTINEL} > {path}'"),
        capture_output=True, text=True, timeout=30,
    )


def run_phase(label: str, rounds: int, round_once, read_now) -> int:
    """差分跑一个阶段：第 1 轮后取 e1，再跑 N-1 轮取 eN，断言 eN == e1。"""
    failures: list[tuple[int, str]] = []
    try:
        round_once()
        e1 = read_now()
        if e1 is None:
            print(f"FAIL [{label}]: 第 1 轮后读不到探针", file=sys.stderr)
            return 1
        for index in range(1, rounds):
            try:
                round_once()
            except Exception as exc:  # noqa: BLE001 — 每轮都要单独记账
                failures.append((index, str(exc)))
                if len(failures) >= 5:
                    break
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL [{label}]: 第 1 轮就抛错: {exc}", file=sys.stderr)
        return 1

    en = read_now()
    print(f"[{label}] e1={e1} eN={en} 轮次失败={len(failures)}")
    for idx, err in failures:
        print(f"  round {idx}: {err}")
    if en is None:
        print(f"FAIL [{label}]: 跑完之后读不到探针", file=sys.stderr)
        return 1
    if failures:
        print(f"FAIL [{label}]: 开/关循环有失败（槽位耗尽时就是 -ENOMEM）")
        return 1
    if en != e1:
        print(
            f"FAIL [{label}]: ctx 槽从第 1 轮的 {e1} 涨到 {en}（{rounds} 轮）—— "
            "每有路径没走 kitty_close()/release_target_fd。\n"
            "  查 agent 里是否有裸 ::close(fd) 回收 kitty 会话。"
        )
        return 1
    print(f"PASS [{label}]: {rounds} 轮差分为 0（{e1} → {en}）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True, help="目标进程 pid")
    ap.add_argument("--rounds", type=int, default=100, help="每阶段轮次（默认 100，建议 > 64）")
    ap.add_argument("--module", default="libc.so")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--probe", default=DEFAULT_PROBE, help="agent 探针文件（设备上）")
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--serial", default=os.environ.get("KITTY_DEV") or None)
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=52730)
    ap.add_argument("--token-file", default="/tmp/tanyao_token")
    ap.add_argument("--skip-pool", action="store_true", help="只跑阶段 1")
    args = ap.parse_args()

    status = rpc(args.base_url, "get_status", {})
    if not status.get("ok"):
        print(f"SKIP/FAIL: agent 不可达: {status.get('error')}", file=sys.stderr)
        return 2
    backend = (status.get("result") or {}).get("backend", {}).get("name", "?")

    # 探针活性检测：先写哨兵，再发一个请求看它有没有被更新
    write_probe_sentinel(args.adb, args.serial, args.probe)
    rpc(args.base_url, "find_process", {"name": "surfaceflinger"})
    baseline = read_probe(args.adb, args.serial, args.probe)
    if baseline == SENTINEL:
        print(
            "环境不满足：探针没有被更新（仍是哨兵 %d）。\n"
            "  agent 需要以 TANYAO_CTX_PROBE=%s 启动。" % (SENTINEL, args.probe),
            file=sys.stderr,
        )
        return 2
    if baseline is None:
        print(f"环境不满足：读不到探针文件 {args.probe}", file=sys.stderr)
        return 2
    if baseline < 0:
        print(f"SKIP: backend={backend} 没有用户态 ctx 表（ctx_live={baseline}）")
        return 0

    print(f"backend={backend} 基线={baseline} 轮次={args.rounds} pid={args.pid}")

    read_now = lambda: read_probe(args.adb, args.serial, args.probe)  # noqa: E731

    # 阶段 1：控制 fd 路径（host 有会话缓存，所以必须用差分口径）
    def control_round():
        out = rpc(args.base_url, "resolve_module", {"pid": args.pid, "name": args.module})
        if not out.get("ok"):
            raise RuntimeError(str(out.get("error")))

    rc = run_phase("控制 fd", args.rounds, control_round, read_now)
    if rc != 0 or args.skip_pool:
        return rc

    # 阶段 2：池 fd 路径（每轮真开/真关）
    try:
        token = open(args.token_file, encoding="utf-8").read().strip()
    except OSError as exc:
        print(f"SKIP 阶段 2: 读不到 token 文件 {args.token_file}（{exc}）")
        return 0

    from tanyao.connection import AgentConnection
    from tanyao.constants import CMD_TARGET_CLOSE, CMD_TARGET_OPEN

    conn = AgentConnection(args.agent_host, args.agent_port, token)
    conn.connect()
    try:
        handle_box: dict[str, str] = {}

        def pool_round():
            opened = conn.request(CMD_TARGET_OPEN, {"pid": args.pid})
            handle = opened.get("handle") if isinstance(opened, dict) else None
            if not handle:
                raise RuntimeError(f"open 无 handle: {opened}")
            handle_box["h"] = handle
            conn.request(CMD_TARGET_CLOSE, {"handle": handle})

        return run_phase("池 fd", args.rounds, pool_round, read_now)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())