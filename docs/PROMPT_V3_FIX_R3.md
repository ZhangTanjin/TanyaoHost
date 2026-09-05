# 主机端工程师任务提示词：R3——O4 短期修复（find_process 短名摩擦）

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：lolm 实战逆向发现 O4（P3）：`find_process("lolm")` 不命中而全包名
> 命中，AI 会话选参摩擦。分诊见 `/home/tanjin/phone/WORKSPACE.md` §7
> 「架构师分诊 R3」。本轮主机端只有这一项小改；D8/O3 在设备端任务书
> （`TanyaoCli/docs/PROMPT_V3_FIX_R3.md`）。

## 任务：O4 短期修复——find_process 工具描述与降级指引

协议约束：`process_find` 的匹配语义在内核 legacy op（F18 长进程名边界已知），
**host 侧无法可靠实现模糊匹配**（process_list 只回 pid 无名字）。因此本轮
零协议改动，做两层：

1. `find_process` 工具 description 补明确指引："name must be the FULL
   package name / process name as shown in /proc/<pid>/cmdline (e.g.
   `com.tencent.lolm`); short names (`lolm`) are NOT matched. If unsure,
   call `list_processes` first"。
2. not_found 响应的 detail 追加一句同义提示（AI 下一步自会改参重试），
   不做自动重试/枚举。

**长期项登记（不在本轮）**：设备端模糊匹配 find（agent root 直读
/proc/*/cmdline 子串匹配）已登记为 V1.3 草案候选（WORKSPACE.md 分诊），
届时走协议流程，本轮不预实现。

## DoD

- `python3 -m unittest discover tests` 全绿；mcp_regression 相应 detail
  断言更新后全绿；README 工具描述同步。
- 一个 commit（引用 O4），WORKSPACE.md §7 O4 行回填"短期已关闭 / 长期
  V1.3 候选"。
