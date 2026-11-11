# 主机端工程师任务提示词：R8——D20 resolve_rva 逆向换算工具 + rva 语义文档

> 背景：R7 复核暴露逆向换算缺口（tester 四候选手算全落空；架构师以逐段
> 包含换算当场重定位 CodeRegistration 佐证正确路径——见 WORKSPACE.md §7
> 「R7 复核回执处理」）。小任务，host 单仓。

## 任务 1：`resolve_rva` 工具（IPC+MCP，第 32 个）

- 入参 `{pid, module, rva?, file_offset?}`（二选一；`rva` 为 vaddr 口径，
  经活体 phdr（p_vaddr→p_offset）换算为文件偏移；`file_offset` 直用）。
- 换算：逐段包含 `runtime = seg.start + (fo − seg.file_offset)`（跳过
  mirror 段；无承载段 → not_found 并列出该模块非镜像段表供判读）。
- 输出：`{runtime, segment:{start,end,file_offset,perms,translation_base},
  used:"vaddr|file_offset"}`。
- mock 用例：六段多 bias 布局下 vaddr 与 file_offset 双入口（差 0x4000
  场景）；支配镜像段不承载；lolm 真机 DoD：
  `resolve_rva(libil2cpp, file_offset=0xbb87538) == 0x72990c6538` 且
  88B 载荷含 5473/1709 计数（本轮回执证据固化）。

## 任务 2：rva 语义文档（口径统一）

- 全工具面 `rva` 字段语义 = **文件偏移**（disassemble/address_resolve/
  dump manifest，与 D15 统一）；README + 工具描述注明：**加法恒等式
  `address == 承载段.translation_base + rva`**——用 load_bias 加法仅当
  其等于承载段 tb（r-xp 恰如此；.data.rel.ro 类多 bias 段会偏）。
- R4 历史 "RVA" 为 vaddr 口径的差异有脚注（复现旧记录时的 0x4000 坑）。

## 纪律与 DoD

- 两任务各一 commit（引用 D20）；协议零改动。
- DoD：单测全绿（新增 ≥4 用例）+ 真机 lolm 上述 DoD + 回归 51/51 保持 →
  WORKSPACE.md §7 D20 回填。完成后通知 tester：复验②③可用 resolve_rva
  正算，不再手推。
