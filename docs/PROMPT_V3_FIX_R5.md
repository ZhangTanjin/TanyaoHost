# 主机端工程师修复任务提示词：R5——D13/D14/D16/D18 + F1/F2/F4/F5/F6

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：12 轮 lolm 深度实测的三维度工具审查（证据：
> `/home/tanjin/phone/reprojet/r4/`，REPORT_R4 + evidence 19 项；台账
> WORKSPACE.md §7 R5 分诊）。架构师已抽查确认关键缺陷。协议侧唯一变更
> （`already_running` slug）已由架构师写入 `PROTOCOL_V1.2.md` §5 附录
> v1.2.3，你按其消费即可。

## 任务 1：D13 + D14（P0）maps 解析统一——全部地址推断的根基

**D13**：`list_modules` 跨段合并且产出畸形条目（实测 `naanges` 键损坏、
libilzma/libutils 的 end 跨越 311MB 无关映射、与 resolve_module 端点矛盾、
无 path 映射伪造模块名）。**D14**：`address_resolve` 不与 list_modules 共
用解析器，部分区域凭空生成区间（`0x6d00000000-0x6d01000000` 不存在于
模块表）。

修复设计（分诊定稿）：

1. 抽**单一 maps 解析器**（模块级组件）：输入 maps 快照 → 输出按 path
   分组的段列表（每模块 N 段，每段 `[lo,hi) + file_offset + flags`）。
   `list_modules`、`address_resolve`、`resolve_module`、扫描 preset 构建
   全部改走它——**一处真相**。
2. `list_modules` 输出改为逐段返回（每模块 `segments[]`），顶层
   `base = first_map.start`（与 resolve_module 同源），**不再跨段合并
   end**；无 path / `[` 开头伪路径的映射归入 anonymous 段列表，**不伪造
   模块名**；顺手修 `naanges` 键名损坏（应为 ranges，输出组装处）。
3. `address_resolve`：找不到包含映射 → 返回 `unknown`（**禁止构造区间**）；
   命中时给 `module / segment_index / file_offset / rva`（rva 按映射表
   平移，D9 的 helper 复用）。
4. 单测交叉断言：对同一 pid，address_resolve(每模块 base) 的归属 ==
   list_modules 对应模块；随机地址落在模块表外交际必须 unknown。加
   lolm 六段 fixture 用例（D9 已有）扩展到 list_modules 逐段形状。

## 任务 2：D16（P2）strings.offset 字段

实测 `"offset": 481432716827` 是地址的十进制整型（analysis.py:1000）。
修复：字段改名 `address`（保留 hex 字符串形态，与全工具面一致），删除
误导性 offset；输出 breaking 变更需在 README 工具面注明（v1 消费方为零，
直接改）。

## 任务 3：D18（P1）截断必须显性化

`truncated=true` 时：结果尾部强制加 `"truncated": true, "next_offset": <n>`
提示分页；`scan_start` 对 preset 全可读类返回 range 体量预估。不做静默
截断。

## 任务 4：F1 watch_many + F2 pointers_to（两个新 MCP 工具，架构师已批准）

- `watch_many(spans[], interval_ms, count, changes_only)`：host 以
  read_batch（readv）编排多 span 周期采样，零协议改动；输出 per-span
  采样数组（对齐既有 watch 的 samples 形状）。
- `pointers_to(pid, addresses[] | address, module/preset/ranges 可选)`：
  u64 扫描的语义化封装（addresses 展开为多次 u32/u64 扫描或单次扫描后
  按 8 字节解释过滤，取实现更简者），返回每个目标地址的引用位置列表。
  PAC 归一化参数沿用 typed 读的 strip-pac 选项。
- 两工具入 IPC 方法表 + mcp_server 注册（工具面 29→31），README/交接单
  同步。**不做设备端多值批量**（V1.3 候选，见台账）。

## 任务 5：F4 + F5 + F6

- F4：`symbol_list` 加 `fields` 参数（`names_only` 布尔亦可），默认全量。
- F5：`decompile_start` 对 >64MB 模块先做熵采样（读若干页算熵，>7.5
  bits/byte 比例超阈值即警告加密页风险并要求 `force:true`）；进度心跳
  （progress_done/total 定期刷新）；`job_kill`/取消路径修复（实测对
  挂死 job 报 unknown）。17 分钟静默挂死不可接受。
- F6：`scan_set_default_ranges` 返回实际区间摘要（段数/总字节/类别
  分布）；preset 差异写入工具描述（all_readable 含 ART 启动镜像）。

## 纪律与 DoD

- 每任务一个 commit（引用 D13/D14/D16/D18/F1/F2/F4/F5/F6）；maps 解析
  器是本轮核心，先行合入。
- 协议正文除消费 `already_running` 外零改动；发现协议矛盾上报。
- DoD：单测全绿（含 maps 交叉断言、六段 fixture 扩展、watch_many/
  pointers_to 用例）→ 真机回归全绿（新工具两用例入 mcp_regression）→
  用 lolm 实测一次 list_modules 逐段输出与 address_resolve 交叉一致性
  → WORKSPACE.md §7 回填。写进 mock_agent 的行为变化先对齐协议文档。
