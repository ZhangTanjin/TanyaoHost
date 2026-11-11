# tanyao-host v3 设计文档：智能层编排（计算下沉版）

> 日期：2026-09-04 ｜ 负责人：架构师（规划）；实现按本文件执行
> 上游依据：`../tanyao-ai-re-architecture.md` §11（v3 架构定稿）
> 协议依据：`docs/PROTOCOL.md`（v1）、`TanyaoCli/docs/AGENT_PROTOCOL_EXTENSIONS.md`
>（v1.1 定版基座）、`docs/PROTOCOL_V1.2_DRAFT.md`（v1.2 增量，本文引用时简称
> "v1.2 草案"）
> 角色定位：host 是**智能层**——AI 入口（MCP）、编排调度、写门禁策略、少量紧凑
> 读、Ghidra 深度反编译。数据密集计算全部下沉设备端（见协议能力位）。

## 1. 背景与目标

v2 全链路真机实测的带宽封顶点：3.21GB 首扫 480s（~6.8MB/s）、symbol_list 1483
符号 33s、dump/apk 为 MB~百 MB 级搬运。v3 把这些操作的计算移到数据旁边
（设备端），host 只收提炼结果。**MCP 工具面（名称/签名/输出形状）保持不变，
AI 工作流与既有回归用例零改动**——变化只发生在工具内部实现与引擎选择。

## 2. 模块变更总览

| 模块 | 变更 | 阶段 |
| --- | --- | --- |
| `frames.py` | 支持 flags bit2 PAYLOAD_BINARY 响应解码；dump_pull 24B 子头编解码；CRC 校验 | M1/M2 |
| `connection.py` | hello `capabilities` 解析为 int 位图；`has_cap(bit)` 查询；断言 version 兼容（1.0/1.1/1.2 均接受） | M0 |
| `service.py` | ① 引擎分派器（按能力位选择设备 op 或 host 本地实现）；② dump 管线客户端（start/status/pull 循环、crc 校验、断点续传、cleanup 编排）；③ apk_info 直连设备 op | M1/M2 |
| `analysis.py` | `symbol_list`/`symbol_find` 优先 cmd 61（host `symbols.py` 降级回退）；`disassemble` 优先 cmd 67（`native.py` 回退） | M1/M3 |
| `scan.py` | **特性冻结**。仅作 v1.0 agent 回退；`scan_*` MCP 工具在 hello 声明 bit0 时全部改走 cmd 50–55 | M0 |
| `dump.py` | Ghidra 消费入口不变（输入=拉取后的本地文件）；新增 `pull_dump_with_resume()`（offset 推进 + crc32 + 失败重发） | M2 |
| `native.py` | 保留为 disassemble 回退，不新增特性 | — |
| `symbols.py` / `elfinfo.py` | 降级回退路径；elfinfo 继续服务 dump 产物的磁盘侧解析 | — |
| `mcp_server.py` | 工具表不变；内部实现分派；输出透传新标准字段（`engine`、`maps_source`、`skipped_caps`） | 随各阶段 |
| `jobs.py` | host 侧异步 job（scan_start/decompile）语义不变；设备端 job 由 agent 负责 | — |
| `interop.py` | 检查项按能力位条件化，未声明能力记录 `skipped_caps` 跳过 | M1 |
| `tests/mock_agent.py` | **实现全部 v1.2 op 作为参考实现**（含二进制帧、packed 符号表、deflate） | M1/M2 |
| `tests/` | 新增二进制帧金样本、packed 解码、crc 错误注入、续传中断恢复用例 | M1/M2 |

## 3. 关键设计

### 3.1 引擎分派器（service.py）

```text
选择规则：只看 hello.capabilities，不做版本号判断（v1.2 草案 §6）。
  bit0 → scan_* 走设备；未声明 → scan.py（冻结基线）
  bit3 → symbol_list/find 走 cmd 61；未声明 → symbols.py
         （映射：`symbol_list(module,filter)` 直传 module/filter；
          `symbol_find(name)` = 省略 module 的全模块请求 + 锚定 filter，
          输出的模块归属由 `modules`/`module_indexes` 填充。见 v1.2 草案 §3.1）
  bit5 → strings 走 cmd 62；未声明 → host 现有窗口扫描实现
  bit6 → dump_module 走 63/64/65 + 68；未声明 → 旧 mem_read 分块重建
  bit7 → apk_info 带 pid 时走 cmd 66；路由细则见 §3.5
  bit8 → disassemble 走 cmd 67；未声明 → native.py 子集解码器
```

分派结果写入每次工具输出的 `engine` 字段（如 `"engine":"agent-scan"` /
`"host-scan"`），排障时可辨。**回退路径不删不改**——它们同时是 v1.0 agent 的
兼容面和 mock 测试的对照基线。

### 3.2 dump 管线客户端（service.py + dump.py）

流程：`dump_start(63)` → 拿 `dump_id/size/sha256` → `dump_pull(65)` 循环
（chunk 默认 256 KiB，`compress:true`）→ 逐块 crc32 校验 → 落盘主机临时目录 →
sha256 全文件比对 → （Ghidra 导入完成后）`dump_cleanup(68)`。

- 断点续传：pull 状态（dump_id + 已收 offset + 目标 sha256）持久化于内存即可；
  serve 重启后凭 `dump_status(64)` 的 size/sha256 对账，从断点 offset 重发。
- 解压失败/CRC 不符：从本块起始 offset 重试一次，再失败报 `internal` 并保留
  已收数据（可续传恢复，不自动清盘）。
- Ghidra 链路（`decompile_start/status`）只改数据来源：dump 产物从"host 分块
  读取重建"换成"dump_pull 产物"，`ghidra_scripts/` 与 job 机制零改动。

### 3.3 带宽验收指标（真机，M1/M2 出数后回填实测值）

| 操作 | v2 实测 | v3 目标 | 过网数据量 |
| --- | --- | --- | --- |
| 3.21GB 全匿名首扫 | 480s | ≤120s（含冷页换入） | 命中列表，KB 级 |
| symbol_list 1483 符号 | 33s | ≤2s | ≤200KB（或 packed 更小） |
| dump_module 1.1MB 模块 | 全量过网 | 仅显式发起；deflate 后 ≤0.6× 原始 | 按需 MB 级 |
| apk_info | 整包拉取 | 零镜像 | ≤10KB |
| watch/diff | 周期读过网 | 设备端采样（远期，走 v1 读即可） | 小 |

### 3.4 apk_info 工具层路由（2026-09-04 裁决，M2 实现依据）

背景：现有 MCP `apk_info(apk_path)` 解析**主机上任意 APK 文件**；v1.2 cmd 66
返回**目标进程的 APK** 元信息（设备端从 maps 定位 base.apk 本地解析）。两者
是不同语义，wire 协议不变，路由在工具层解决：

1. **参数互斥、恰好其一**：`pid`（新增，可选）与 `apk_path`（现有）二选一；
   两者同给或缺任一 → 参数错误（isError，含用法提示）。
2. 仅 `apk_path` → 本机 AXML 解析，行为与 v2 完全一致（兼容面，永不改变）。
3. 仅 `pid` → agent 已声明 bit7 时走 cmd 66；**未声明 bit7 时返回结构化
   错误**，提示改走 `pull_apk` + `apk_info(apk_path)`。**禁止自动回退到
   pull_apk**——那是百 MB 级隐式批量传输，违反 D7"批量必须显式发起"。
4. 输出形状统一：两条路径返回同构字段（`apk_path` 分别为设备解析路径/
   主机给定路径，其余 package/version/permissions 等对齐），调用方无感。

方案 2（隐式沿用当前 target）否决：工具行为依赖 host 隐藏状态，AI 调用
非确定性，且"无 target 回退本机解析"在无 apk_path 时根本无路可走。
方案 3（cmd 66 暂不接入）否决：apk_info 是高频查询，放弃零镜像过网违背
v3 目标，且兼容性问题由方案 1 完整解决，不存在需要绕开的冲突。

### 3.5 写门禁与安全（不变量）

`write_bytes` 双门禁（`TANYAO_ALLOW_WRITE=1` + expect-old→write→verify）语义
不变；M2 起在 agent 声明 bit1 时底层可改走 cmd 60 write_txn（单次往返，
省一半过网往返），门禁策略仍在 host 判定。回归纪律不变：**任何情况不改动
活体目标进程**，写测试只打自有靶进程。

## 4. 测试计划

1. 单测（mock agent，无需设备）：
   - 帧层：PAYLOAD_BINARY 收发金样本；24B 子头边界；MAX_PAYLOAD 越限拒绝；
     `assert _HEADER.size == HEADER_SIZE` 类断言钉死新子头。
   - packed 符号表解码（含 name_blob 偏移越界负例）。
   - dump_pull：crc 错误注入→重试；中断→offset 续传→sha256 对账。
   - 分派器：capabilities 组合矩阵（0x0 / 0x3 / 0x1ff）下每工具的 engine 字段。
2. 回归：现有 61 单测 + 36 项 MCP 回归全部保持绿（v1.0/v1.1 agent 兼容面）。
   新增 v1.2 条件项进 `mcp_regression.py`。
3. interop（设备 DoD 工具）：按能力位条件化（v1.2 草案 §7）。

## 5. 阶段任务（host 侧视角，与 v3 架构 §11.5 对应）

| 阶段 | host 任务 | DoD |
| --- | --- | --- |
| M0 | capability 解析合入；v1.1 定版评审签字（在 TanyaoCli 侧提交后）；`scan_*` 走 cmd 50–55 的分派合入 | 真机：扫描类工具 `engine=agent-scan`，既有回归全绿 |
| M1 | 二进制帧 + cmd 61/62 接入；mock_agent 同步实现；单测/回归扩展 | libc symbol_list ≤2s；回归全绿 |
| M2 | dump 管线（63/64/65/68）+ apk_info(66) 接入；Ghidra 链路切数据源 | 1MB 模块拉取压缩生效且仅显式发起；apk_info 零镜像 |
| M3 | 扫描账目适配内核 PFNMAP 排除（`skipped_bytes` 预期为 0，保留字段兼容旧内核） | 3.21GB 设备端首扫指标达成 |
| M4 | 无 host 侧任务（MB 为独立客户端）；文档更新 | — |

## 6. 明确不做

- 不在 host 重建第二套设备端语义（扫描语义真相源 = agent 实现 + 协议文档，
  host 引擎冻结在 v2 基线）。
- 不新增 MCP 工具数量（28+1 收敛为稳定面）；MCP 输出形状向后兼容，只增字段。
- 不把 Ghidra/capstone/pyelftools 移上设备（capstone 除外——见 agent 设计文档）。
