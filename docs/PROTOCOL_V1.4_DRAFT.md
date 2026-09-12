# Tanyao Agent 线协议 v1.4 草案（call_export 受控进程内调用）

> 状态：**草案（2026-09-13，用户批准翻转 F3）**——双端实现 + 真机验收后
> 定版。基线：v1.3。本文为纯增量；除本 op 外一切语义不变。
> 决策记录：坐标目标（lolm）唯一剩余路径；用户已知悉并接受 TP 反作弊
> 检测/封号风险与活体目标操作纪律突破。

## 1. 能力位

| bit | 名称 | 含义 |
| --- | --- | --- |
| 13 | CALL_EXPORT | cmd 80 受控调用（本草案）；实现与声明同提交 |

## 2. cmd 80 `call_export`

请求：

```json
{"pid":1234,"module":"libil2cpp.so","symbol":"il2cpp_class_get_name",
 "args":["0x72990c6590"],"ret_type":"u64"}
```

- `args`：≤8 个，u64 hex 字符串或十进制整数（AAPCS64 x0–x7；超过 8 参
  拒绝——白名单函数均 ≤2 参，余量为类型混淆容错）。
- `ret_type`：`u64|f64|void`（默认 u64）。

响应：`{"ret":"0x...","elapsed_us":812,"audit_id":"<n>"}`

## 3. 安全模型（不可妥协项）

1. **白名单默认拒绝**：agent 启动必须带 `--call-allowlist <file>`（0600，
   行格式 `module:module_basename:symbol_name` 或简化
   `<module_basename>:<symbol>`）才声明 bit13；无白名单文件/空文件 →
   不声明，cmd 80 回 `unsupported`。请求的 (module, symbol) 不在表内 →
   `not_in_allowlist` ERROR（新 slug），**不做通配**。
2. **host 双门禁**：MCP 工具 `call_export` 仅当 serve 以
   `TANYAO_ALLOW_CALL=1` 启动时可用（镜像 write 门禁模式）；关闭时工具
   描述报"disabled"且调用被拒。get_status 增加 `call_enabled` 与
   `call_allowlist_entries`。
3. **执行机制（设备端）**：root 下 ptrace 附着目标线程 → 保存全量
   寄存器 → 布参（x0–x7）→ x8=目标地址、pc 置返回断点 → continue →
   陷阱回收 x0 → **无条件恢复寄存器并 DETACH**（任何异常路径同此，
   finally 语义）。超时 3s（墙钟）视为失败并尽力恢复。
4. **审计强制**：每次调用（含拒绝）append 到
   `/data/local/tmp/tanyao-calls.log`（0600：ts/pid/module/symbol/结果/
   elapsed）。audit_id 为单调序号。
5. **单飞**：同连接同时最多一个 in-flight 调用（并发请求
   `already_running`）。
6. 错误 slug 增补：`not_in_allowlist`、`call_timeout`、`call_failed`
   （附着/陷阱层失败，detail 带 errno）。

## 4. 已知风险（用户已接受，记录在案）

- TracerPid 可被 TP 类反作弊观测 → 检测/封号风险由操作者承担；
- 白名单函数虽纯读，执行仍改变目标线程瞬时状态；超时路径可能留下
  中间态（getter 类函数窗口极小，风险可控但不为零）；
- 本 op 不受"写只打自有靶"纪律约束的豁免——**对活体目标调用属显式
  授权操作**，审计日志为准。

## 5. host 侧

- 工具 `call_export`（第 33 个）+ 门禁 + 描述含风险声明；mock_agent
  白名单化参考实现（合成世界返回定值）；回归条件项（门禁关/开两态 +
  白名单拒绝路径）；audit 透传。

## 6. 验收

- 单测：白名单匹配（含 module 歧义负例）、门禁两态、mock 调用链。
- interop 条件项：bit13 声明依赖 allowlist 文件存在。
- 真机 DoD（逆向工程师执靶）：白名单 10 个 il2cpp 纯读 getter 全通过；
  坐标目标闭环（枚举 image → 定位 ActorVarFixVector3 → 字段偏移 →
  实例读取 → 多点采样）后本草案转正。
