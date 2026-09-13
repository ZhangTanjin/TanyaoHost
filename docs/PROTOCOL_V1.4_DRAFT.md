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

## 5.1 实施前修订（2026-09-13，逆向实战工程师现场核验输入）

1. **白名单基线 10 → 13**（全部纯读，现场地址已核）：
   `il2cpp_class_from_name`（**必需**——否则按名取类退化为 10.5 万类
   暴力枚举，性能与暴露面均不可接受）、`il2cpp_image_get_name`（把
   image 调用面 52→1–3）、`il2cpp_class_get_field_from_name`（直取
   FieldInfo*，免字段数组遍历）。
2. **返回值可读性探针**：请求新增可选 `"probe_ret":true`——agent 对
   u64 返回值做目标地址空间 1 字节探测（经自身内存路径），响应增
   `"ret_readable":true|false`；false 时调用方**必须中止链**不得续用。
3. **domain 悬垂防护（DoD 强制）**：S0 dry-run（仅调
   il2cpp_domain_get + probe_ret 验证即止）；count 合理界（0<count≤1000，
   实测 52）由消费方执行；域不可用须如实报错**不得伪造**。三次独立实测
   （R4/R7/R10，形态各异）证明该槽可用性不可假定。
4. **验证判据修订**：S8 弃用"值变化"判据（英雄静止，R4 教训）——改用
   结构判据（实例 klass 指针 == 目标类指针）+ 数值合理性（平面 0–15000）
   + 指针链回溯稳定基址。S0–S9 分步规格（含就绪探针与失败如实登记）
   以 `archive/reprojet-r5/r5/D23_INPUT_WHITELIST_AND_DOD.md` 为 DoD
   基础文本。

## 6. 验收

- 单测：白名单匹配（含 module 歧义负例）、门禁两态、mock 调用链。
- interop 条件项：bit13 声明依赖 allowlist 文件存在。
- 真机 DoD（逆向工程师执靶）：白名单 10 个 il2cpp 纯读 getter 全通过；
  坐标目标闭环（枚举 image → 定位 ActorVarFixVector3 → 字段偏移 →
  实例读取 → 多点采样）后本草案转正。

## 5.2 kcall（内核态调用引擎，A 路线，2026-09-13 用户拍板）

背景：lolm 场景 vendor/TP 内核静默中和 ptrace（D24 平台发现），用户态
传输不可达。kcall = cmd 80 的内核态传输，**wire 语义零变化**（cmd 80
不变，agent 按内核能力位选传输）。

### 机制（task_work 家族，transport_anon 同源）

1. 新 ioctl `TANYAO_IOC_KCALL`（agent 的 anon fd 上）：入参 target
   handle/函数地址/args x0–x7/超时；内核侧完成三步接管：
2. **劫持**：选目标主线程（tid==tgid，状态可停优先），`task_work_add`
   在其返回用户态路径回调中（current==目标线程）安全改写
   `task_pt_regs(current)`：保存全量原寄存器 → PC=函数、x0–x7=参数、
   LR=蹦床地址。
3. **蹦床**：在目标 mm 安装一页蹦床（task_work 上下文内可操作
   current->mm），内容为 `brk #tanyao-magic`（或非法 svc，实现择优）；
   函数 `ret` 落入蹦床 → 异常进内核。
4. **收网**：kprobe/异常 hook 按（far/编号==magic && tgid==目标）过滤，
   捕获用户态 pt_regs 的 x0（返回值），**恢复全量原寄存器**并抑制该
   异常对目标的可见性（目标零感知），线程回到原执行流。
5. **预算与放弃路径**：超时不硬抢（无法安全强停用户态执行）——迟到
   仍可经蹦床捕获并恢复；白名单函数皆短时，v1 接受"不回收"残余风险
   并如实上报（`call_timeout, recovery=pending`）。
6. **能力位**：内核 backend caps 增 bit `TANYAO_CAP_KCALL`（0x40）；
   agent hello 层不变（cmd 80 语义同），agent 传输选择：内核声明
   kcall → 优先内核路径，ptrace 保留为无 kcall 内核的回退。

### 风险登记（用户已知悉）

内核侧 bug = panic/变砖级。缓解：probe 先行（自有靶 tanyao_probe_kcall
导出确定性函数，全链验证后才上真目标）、CONFIG_KCALL 构建开关（默认
关，显式开）、全或无寄存器保存、异常抑制正确性（目标永不观察 SIGSEGV）
为验收硬项、卸载回滚 = 不加载模块。

### 里程碑

- **K0（内核）**：kcall 实现 + 自有靶 probe 全绿 + full probe 不回退。
- **K1（agent）**：cmd 80 传输选择（kcall 优先/ptrace 回退）+ 自检。
- **K2**：S0 lolm → RE 工程师 S0–S9 → V1.4 定版。
