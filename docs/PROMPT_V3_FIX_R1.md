# 主机端工程师修复任务提示词：实战缺陷 D1(host 侧) / D3 / D4 / D5（v3 修复轮 R1）

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：v3 全功能实战测试完成（`TANYAO_FIELD_TEST_REPORT_V3.md`，T1–T6
> 全项 PASS），主机端归属缺陷 4 项。分诊与修复设计已定稿：
> `/home/tanjin/phone/WORKSPACE.md` §7「架构师分诊」。
> 协议侧依据已就位：`docs/PROTOCOL.md` §7.2 附录（v1.2.1：cmd 50 `ranges`
> 字段 + 能力位 bit9 SCAN_EXPLICIT_RANGES + hello `build` 字段）。

## 必读（动手前按序）

1. `WORKSPACE.md` §7 缺陷表 + 架构师分诊（D1/D3/D4/D5 四条）
2. `TANYAO_FIELD_TEST_REPORT_V3.md` 各缺陷复现步骤（§T6-3 / §T3 续传 /
   §T4 负例）
3. `docs/PROTOCOL.md` §7.2 附录、§4.7；`docs/DESIGN_V3_HOST.md` §3.1
   （分派器）与 §3.4（apk_info 路由——本轮不动它，作为回退式样参考）

## 任务 1：D1（P2）scan_set_range 在 agent-scan 路径被静默忽略

根因（测试者已定位）：`_agent_scan_start` 只传 `preset`，`scan_set_range`
写的显式范围在设备路径无承载。协议附录已定：cmd 50 新增可选 `ranges`
（≤4096 段，present 时忽略 preset）+ 能力位 bit9。

host 侧三件事：

1. `_agent_scan_start`：用户设了显式范围且 hello 声明 bit9 → 请求携带
   `ranges`（`addr/size` hex 字符串，逐段透传，不跨段合并）。
2. **强制回退规则**：显式范围 + bit9 未声明 → 路由主机引擎
   （`engine:"host-scan"`）。禁止把 `ranges` 发给未声明的 agent——v1.1
   agent 会静默忽略并回落 preset（D1 失败模式）。禁止报错打断用户。
3. `tests/mock_agent.py`（参考实现）同步：声明 bit9、消费 ranges、
   preset 与 ranges 互斥语义；回归补三例——bit9 声明走设备+范围正确、
   bit9 未声明+显式范围回退 host 引擎、ranges 与 preset 同给时 preset
   被忽略。

## 任务 2：D3（P3）pull 断点状态不抗 serve 硬杀

现状：`.part.state` 只在干净失败路径落盘，`kill -9` 后进度丢失（实战
被迫手工补 sidecar 才验证续传）。修复（host 侧最简方案，分诊已定）：

- `.part` 旁每 chunk **原子落盘** `.pull.state`（临时文件 + `os.replace`）：
  `{path, offset, sha256, chunk_size, dump_id}`。
- serve 重启后 pull 客户端优先读 `.pull.state` 恢复 offset，设备端
  sidecar 退化为对账参考（其存在与否不影响续传）。
- 回归：mock 上模拟"传输中中断→重启→续传"（不依赖任何手工 sidecar），
  断言最终 sha256 一致且实际传输字节 ≈ 剩余部分。

## 任务 3：D4（P3）process_alive 对已死 pid 返回 true

现状：查了缓存的会话/handle 状态。修复：`process_alive` 不得依赖缓存
会话——直发 legacy `process_alive`(cmd 42)，或在返回前用 `kill(pid,0)`
旁证复核（任选其一，倾向前者：协议语义原样）。死目标必须如实 `alive:false`。
回归补例：起进程→杀掉→process_alive 为 false（mock 与真机各一）。

## 任务 4：D5（P3）expect_old_mismatch 丢失 old_b64

agent 的 ERROR 帧本就附带 `old_b64`（PROTOCOL §7.5），host 错误透传把它
丢了。修复：MCP 错误响应的 `data`/detail 保留 `old_b64`（以及 errno），
让 AI 能直接拿到旧字节做比对。回归补例：expect_old 不匹配时错误负载含
`old_b64` 且值正确。

## 收尾

- get_status 透传 hello 新增的 `build` 字段（配对设备端任务，字段缺席时
  省略不报错）。
- 提交纪律：每个缺陷一个 commit 系列（消息引用 D1/D3/D4/D5）。
- **DoD**：`python3 -m unittest discover tests` 全绿（含全部新回归例）；
  与设备端协调部署窗口后真机 `tests/mcp_regression.py` 全绿（设备端 R1
  修复已含 bit9/build/1.2.0 版本）；WORKSPACE.md §7 对应行回填状态。

## 协作提醒

- 协议正文（§7.2 附录）为唯一依据，发现矛盾停下上报架构师，不要自行
  发明字段。
- 设备端本轮同时在做 D2/D6/D7（hello build 字段、bit9 声明由其实现），
  mock 与 C++ 实现的语义对齐以 PROTOCOL 为准；D6 的定性结论可能产生新的
  协议补丁（resident_only 开关），在架构师批准前不要预实现。
