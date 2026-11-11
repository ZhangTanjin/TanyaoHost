# 主机端工程师修复任务提示词：R7——D19 mirror 误标与 load_bias 语义（P0）

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：tester 复验发现基址三方不一致（证据
> `archive/reprojet-r5/r5/R7_REVERIFY_AND_DEFECT.md`；分诊与修复设计：
> WORKSPACE.md §7「D19」）。**根因是架构师 9-12 的 mirror 启发式**
> （`156ce27`，mapsview.py `_mark_mirrors`）在多 off-0 重叠布局下误标
> 真实 loader 段——本轮修复以语义纠正为主，不是 tester 的错报。

## 缺陷复现要点（真值锚）

- 真值 load bias = **0x728af3b000**（symbol_find(il2cpp_domain_get)
  0x7290f7109c − RVA 0x3a3609c；disassemble 自报 rva=0x3a3609c 且字节
  逐字一致）。
- resolve_module/address_resolve 现报 **0x728d53b000**（差 0x2600000）；
  用它换算 rva 落到 ASCII "video" 纯数据。
- address_resolve 同响应内 load_bias + rva ≠ address（自相矛盾）。
- 触发条件：同路径存在**多个 off-0 映射**且其中含 EXEC——真实 r--p
  PT_LOAD（小，~58MB+，含 0x3a3609c）被 v1 启发式误标为镜像，锚点跳到
  EXEC 段（192MB，off-0）。

## 任务 1：mirror 启发式 v2（mapsview.py `_mark_mirrors`）

新规则：off-0（页对齐同组）内非 EXEC 段，仅当**文件空间支配**同组其他
成员（`size ≥ max(同组其他成员 size)`）才标 `mirror:true`——整文件完整
性副本的支配特征；真实共载 PT_LOAD 严格更小或文件空间不重叠。

- 用例 A（支配型，维持镜像）：r--p 202MB off-0 + r-xp 192MB off-0
  （R5 lolm 实测布局）→ r--p 标 mirror ✓（既有用例不回退）。
- 用例 B（共载型，**不得误标**）：r--p ~60MB off-0 + r-xp 192MB off-0
  （本轮真值布局）→ r--p 为真实 loader 段，load_base 取其 start =
  0x728af3b000 锚。
- 用例 C：无 off-0 重复——行为不变。

## 任务 2：load_bias 语义降级（resolve_module / address_resolve）

多 bias 模块上单一 load_bias 本质上不成立（D9 以来已知，本轮坐实）：

1. `resolve_module`：返回**全部段** `segments[]`（start/end/file_offset/
   permissions/translation_base/mirror）；非镜像段 translation_base 唯一
   时保留 `load_bias`；不唯一时 `load_bias: null` +
   `"load_bias_ambiguous": true` + hint（"use per-segment translation_base
   or derive base from disassemble self-reported rva"）。
2. `address_resolve`：**自洽断言**——输出 load_bias 前强制校验
   `load_bias + rva == address`（按包含段的 translation_base）；不满足
   即省略 load_bias 并置 `load_bias_ambiguous:true`。**禁止自相矛盾响应**。
3. `load_base`（list_modules 的 base）：v2 启发式修正后自然回到真实
   首个非镜像段；加单测断言 B 布局下 base==0x728af3b000 型锚。

## 任务 3：文档与工具描述（P1）

`disassemble` 工具描述 + README：**自报 `rva` 是运行时↔文件偏移换算的
权威基准**（映射表法产出）；resolve_module 的 load_bias 标注"多 bias
模块上可能为 null/不可用"。R4 勘误口径同步：mirror/多 bias 场景不得以
resolve_module.load_bias 作换算基准。

## 纪律与 DoD

- 任务 1/2/3 各一 commit（引用 D19）；协议零改动（纯 host 语义层）。
- 单测：A/B/C 三布局 fixture + address_resolve 自洽断言正反例 + 真值锚
  （B 布局 translation_base==0x728af3b000…型）全绿；全套单测不回退。
- **真机 DoD（lolm）**：`resolve_module(libil2cpp)` 段表含真实 r--p 段
  （非 mirror）且其 translation_base = 0x728af3b000 型锚（与
  symbol_find−RVA 一致）；`address_resolve(il2cpp_domain_get)` 的
  rva=0x3a3609c 且响应自洽；若多 bias → load_bias 为 null+ambiguous
  标注；支配型镜像（若进程重映射出）仍正确标注。
- 完成后通知 tester 重跑复验①–③（前置已清），架构师终验后
  WORKSPACE.md §7 D19 回填。
