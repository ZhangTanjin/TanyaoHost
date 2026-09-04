# 主机端工程师任务提示词：tanyao-host v3（智能层编排）

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 你负责 `/home/tanjin/phone/tanyao-host` 的 v3 演进：MCP 工具面不变，把
> 数据密集操作的实现切换到设备端 agent（计算下沉），并产出协议 v1.2 的
> Python 参考实现。

## 0. 路径勘误（先读）

当前工作区是 **`/home/tanjin/phone/`**。文档中的 `/home/tanjin/guihua/tanyao-host`、
`/home/tanjin/TanyaoKernel`、`/home/tanjin/TanyaoCli` 均为废弃旧路径，
现路径分别为 `tanyao-host`、`TanyaoKernel`、`TanyaoCli`（同目录下）。

```bash
必读（动手前按序通读）：
1. /home/tanjin/phone/tanyao-host/docs/DESIGN_V3_HOST.md       # 你的设计文档（权威）
2. /home/tanjin/phone/tanyao-host/docs/PROTOCOL_V1.2_DRAFT.md  # 线协议 v1.2 草案
3. /home/tanjin/phone/tanyao-host/tanyao-ai-re-architecture.md 仅读 §11  # 背景
```

## 1. 角色与任务

阶段顺序（详细任务表与 DoD 见设计文档 §2/§5）：

- **M0（可与设备端并行立即开工）**：`connection.py` 解析 hello
  `capabilities` 位图 + `has_cap()`；`service.py` 引擎分派器骨架；
  **`scan_*` 工具在 bit0 声明时改走 cmd 50–55**（v1.1 已在设备端实现，
  本次接入）；未声明能力一律走现有本地实现（回退基线，不许删）。
- **M1**：`frames.py` 支持 flags bit2 二进制载荷帧（含 24B dump 子头编解码
  与 assert 钉死布局）；`tests/mock_agent.py` 实现全部 v1.2 op 作为参考
  实现（json + packed 符号表、deflate、crc32）；cmd 61/62 接入
  `analysis.py`；单测金样本 + 分派矩阵用例。
- **M2**：dump 管线客户端（cmd 63/64/65/68：start/status/pull 循环、crc
  校验、断点续传、sha256 对账、显式 cleanup）；cmd 66 apk_info 直连；
  Ghidra 链路（`decompile_*`）数据源切换为 dump_pull 产物，job 机制不动。
- **M3**：内核 PFNMAP 排除后的账目适配（`skipped_bytes` 期望恒 0，字段
  保留兼容旧内核），配合 3.21GB 首扫指标复测。

## 2. 硬边界（违反即返工）

1. **MCP 工具面零变化**：28+1 个工具的名称、签名、输出形状向后兼容，只增
   字段（`engine`、`maps_source`、`skipped_caps`）；不新增工具数量。
2. `scan.py` / `symbols.py` / `native.py` **特性冻结**，仅作回退路径——
   它们同时是 v1.0 agent 兼容面和回归对照基线。
3. 现有 61 项单测 + 36 项 MCP 回归**必须保持全绿**（v1.0/v1.1 agent 兼容面）。
4. 写门禁不变：`TANYAO_ALLOW_WRITE=1` 双门禁 + expect-old→write→verify；
   agent 声明 bit1 后底层可改走 cmd 60，策略判定仍在 host。
5. **wire 格式以 `PROTOCOL_V1.2_DRAFT.md` 为唯一依据**；发现协议矛盾停下
   上报，不要自行发明。`PROTOCOL.md`（v1 正式版）保持只读，v1.2 转正合并
   由架构师做。
6. 回归纪律：**任何情况不改动活体目标进程**；写测试只打自有靶进程。

## 3. 验收

- `python3 -m unittest discover tests` 全绿（新增：二进制帧金样本、packed
  解码含偏移越界负例、crc 错误注入→重试、中断→续传→sha256 对账、
  capabilities 0x0/0x3/0x1ff 分派矩阵）。
- `python3 tests/mcp_regression.py`（真机链路）36 项保持绿 + v1.2 条件项
  新增；`interop.py` 按能力位条件化（`skipped_caps` 透出）。
- 带宽指标（真机，出数后回填设计文档 §3.3 表）：libc symbol_list ≤2s
  （对照 33s）；`module:` preset strings 秒级；1MB 模块 dump 仅显式发起
  且 deflate 生效；apk_info 零镜像过网。
- mock_agent 作为参考实现与设备端 C++ 实现联调一致（帧对不上时按协议
  草案逐字节核对——v2 帧头 16/18B 变体事故教训在案，架构文档 §10）。

## 4. 协作

- 设备端工程师（TanyaoCli）并行实现同一协议 v1.2；双方都以草案为准。
- Git 卫生：本仓库现有未提交修复与文档随 M0 首个提交一并整理入库
  （`analysis.py/scan.py/service.py` 修改 + 4 份未跟踪文档）。
- 遇设计文档与协议草案冲突：以协议草案为准，同时上报架构师修订设计文档。
