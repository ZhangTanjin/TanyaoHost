# 主机端工程师任务提示词：R6——V1.3 主机半（消费三项 + mock 同步）

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：用户批准推进 V1.3。设备半在 TanyaoCli（capstone bit8 + 三 bit）；
> 你负责主机侧消费与 mock 参考实现。协议唯一依据：
> `docs/PROTOCOL_V1.3_DRAFT.md`。注意：mirror 标注已完成（`156ce27`），
> 与本轮无耦合。

## 任务 1：mock_agent 同步实现（参考实现先行）

`tests/mock_agent.py` 按草案实现三项：cmd 44 `mode=substring`（mock 世界
进程表子串命中+计数）、cmd 50 `values[]`（≤64、value_index）、cmd 61
packed 24B（entry_size 头 + bind 枚举，与 json binds 一致）。金样本：
24B packed 编解码往返、双值扫描归属。

## 任务 2：host 消费

1. **find_process**：IPC/MCP 新增可选 `mode` 透传；工具描述更新（"短名
   用 mode=substring；默认 exact 需完整包名"）。
2. **pointers_to**：bit11 声明时改发单次 `values[]`（≤64 目标一批，
   超出分批），未声明维持现状展开（兼容矩阵照旧只看能力位）；输出增加
   per-target `value_index` 关联。
3. **packed 解码器**：按头部 `entry_size` 分派 20B/24B（字段无则按
   bit12），24B 解出 bind 并入 symbol_list 输出（json binds 路径不变）。
4. **disassemble**：bit8 声明时路由 cmd 67（engine=capstone-device），
   未声明维持主机 capstone（engine=capstone）——双引擎输出形状一致。

## 任务 3：回归与验收

- interop 条件项三项（草案 §4）+ mcp_regression 新用例：substring
  find、pointers_to 多目标单往返（engine=agent-scan 且 ranges 账目为
  1 次扫描）、packed 24B 解码。
- 单测：mock 世界全路径 + 能力位缺失回退（0x2fb 旧 agent 组合行为
  不变）。

## 纪律与 DoD

- mock 先行一个 commit，消费按项各一 commit；协议正文零改动（矛盾上报）。
- DoD：单测全绿 → 与设备端协调部署窗口联跑 interop + mcp_regression
  全绿 + 带宽对照（pointers_to 8 目标单次 vs 展开，记台账）→ 通知架构师
  启动 V1.3 定版。
