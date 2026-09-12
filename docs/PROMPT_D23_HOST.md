# 主机端工程师任务提示词：D23——call_export host 半（V1.4 草案消费）

> 协议唯一依据：`docs/PROTOCOL_V1.4_DRAFT.md`（用户已批准翻转 F3，风险
> 知悉在案）。mock 先行，以草案 §3 安全模型为准。

1. mock_agent：白名单文件加载（合成 allowlist）、cmd 80 参考实现
   （白名单内返回合成值/外拒绝）、`not_in_allowlist/call_timeout/
   call_failed` 三 slug。
2. host/IPC/MCP：`call_export` 工具（第 33 个）——`TANYAO_ALLOW_CALL=1`
   双门禁（镜像 write 门禁），get_status 增 `call_enabled` +
   `call_allowlist_entries`；工具描述含检测/封号风险声明与
   "对活体目标的显式授权操作"警示。
3. 回归：门禁关（默认，工具拒）与开（mock 或真机）两态 + 白名单拒绝
   路径条件项。
4. DoD：单测全绿 + 回归保持 + 与设备端联跑（其 D23 交付后）真机
   getter 链 → WORKSPACE.md §7 回填。
