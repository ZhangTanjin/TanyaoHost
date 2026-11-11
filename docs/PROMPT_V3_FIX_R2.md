# 主机端工程师任务提示词：R2 收尾——回归补强 + interop 三项 + 文档同步

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：R1 修复轮验收完毕（WORKSPACE.md §7），本轮是 v3 收尾的三件小事。
> 当前工作区：`/home/tanjin/phone/tanyao-host/`。

## 任务 1：mcp_regression 写成功路径条件用例段（D2 覆盖盲区收口）

现状：回归断言"写门禁关闭"，而 D2 的写成功断言需要门禁开启——两者不冲突，
用**条件段**解决：

- 脚本启动时读 get_status 的 `write_enabled`：为 false → 维持现状（门禁
  用例照跑，写成功段记 `skipped: gate off`）；
- 为 true（操作员显式带 `TANYAO_ALLOW_WRITE=1` 起 serve）→ 追加写成功段：
  ①`find_process("tanyao_target")` 找不到则整段跳过（纪律：找不到自有靶
  **绝不**换活体目标）；②fresh read → 同值回写（`expect_old_hex`）→
  断言 `verified:true` 且 **`rolled_back:false`** → readback 一致；
  ③expect_old_mismatch 负例 → 断言 isError 且**负载含 `old_b64`**（与
  D5 修配对）；④竞争导致的偶发 mismatch 计数入报告，不算失败。
- 纪律不变：只打自有靶 `tanyao_target`，任何情况不改活体目标。

## 任务 2：interop.py 三项（设备端 R1 实测移交，证据在 WORKSPACE.md §7）

1. `do_agent_scan`（:256 附近）在 check 14 `target_close` 之后仍复用已关
   handle 发 mem_read → 改为扫描检查前重新 `target_open`（或调整 check
   顺序），消除对已关 handle 的依赖。
2. `symbol_batch` 检查打在 `tanyao_target` 上——NDK 静态链接、无
   PT_DYNAMIC，`not_found` 是**正确行为**；检查靶改用带 dynsym 的模块
   （如该进程的 linker 或 libc.so），断言改为"动态段存在时返回非空表"。
3. interop 对 hello/响应 `flags` 字段需容忍 **number 形态**（agent wire
   恒为 number，字符串形态是旧 mock 习惯），解析处统一 `int(x, 0)` 风格
   兼容。

## 任务 3：文档同步

- `README.md` 能力面/测试口径随现状同步：回归 43 项（R2 合并后以实际数为
  准）、v1.2.1 附录提及（cmd 50 `ranges` + bit9 + hello `build`）。
- `TESTER_HANDOFF.md`/`TESTER_HANDOFF_V3.md` 若有与现行协议冲突的旧口径，
  以一句话"以 PROTOCOL.md/PROTOCOL_V1.2.md 为准"收口即可，不重写。

## 纪律与 DoD

- 每个任务一个 commit；不动协议正文；mock 行为变化必须先对齐
  `PROTOCOL.md`。
- DoD：单测全绿（mock 无 bit9 ↔ 显式范围回退、含 bit9 ↔ 设备路径两组
  分派例）；与设备端协调（其 R2 交付 bit9 声明后）真机联跑——
  `mcp_regression.py` 全绿且 D1 用例翻转为 `engine=agent-scan`、interop
  全过；WORKSPACE.md §7 遗留项 2/3 回填关闭。全部完成后在 §7 标记
  **v3 正式收尾**。
