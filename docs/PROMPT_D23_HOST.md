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

## 附：实施前修订（工程师现场核验输入，V1.4 草案 §5.1）

白名单基线 10→13（+class_from_name/image_get_name/
class_get_field_from_name）；请求可选 `probe_ret:true`（agent 1 字节
探测，响应 `ret_readable`）；DoD 按对方 S0–S9 分步规格执行（S0 dry-run
强制、S8 结构判据、失败如实登记）。设备半注意：probe_ret 在 agent 侧
用自身内存路径实现；host 半注意：工具描述与 mock 同步三新增符号。
