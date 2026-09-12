# 主机端工程师任务提示词：D22——扫描覆盖提示 + manifest 混合性质注记

> 背景：RE 基线代理 R11（archive/reprojet-r5/r5/R11_CONTENT_ANCHOR_VERDICT.md）
> 前两次 scan_hex 因隐式预设不含 module 类区间返回**假 0 命中**（anon
> 1262 区间 vs 全量 4281）；且误读 dump 为纯文件偏移镜像走了弯路。
> 注意：本轮起修复轮弃用 R# 编号（与 RE 代理记录系列解耦）。

## 任务 1：扫描覆盖提示（禁静默假 0）

scan_value/scan_hex/pointers_to 等结果满足「用户未显式设 ranges + 命中
为 0 + 有效预设 ≠ all_readable」时，响应追加
`coverage_hint`：当前预设覆盖的类别摘要 + 未覆盖类别（module 等）+
`retry: all_readable 或 module:<name>` 指引。默认预设不改（性能权衡）。
显式 ranges 或有命中时不加。单测：anon 预设 0 命中出 hint / 有命中不出 /
显式 ranges 不出。

## 任务 2：dump manifest 混合性质注记

manifest 增加常量字段
`"nature": "file-offset layout; data segments contain RUNTIME-RELOCATED
pointers (not file-image values)"`；工具描述同步一句。单测断言字段在位。

## 任务 3：手册条目

TESTER 手册（TESTER_HANDOFF*）新增「双锚互证内容锚定法」条目（R11 路径：
dump 内已知载荷 → scan_hex 全可读扫描 → 唯一命中；字符串内容锚独立验
证；双基址一致判真）——零换算依赖，免疫别名/镜像/多 bias 全部换算陷阱。

## 纪律与 DoD

三任务可合一 commit（引用 D22）；协议零改动；单测全绿 + 回归保持 →
WORKSPACE.md §7 D22 回填。
