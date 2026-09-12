# TanyaoHost

Tanyao 桌面端（tanyao-host）：面向 TanyaoKernel 的远程逆向分析核心，为
AI 助手（MCP 客户端）与自动化提供对 Android 设备内存的受控访问。

```
AI / MCP 客户端 ──MCP stdio──▶ tanyao.mcp_server (Python)
                                   │ HTTP JSON, 127.0.0.1:28101
                                   ▼
                             TanyaoService（协议层单一真相源）
                             · ELF 解析 / 扫描引擎 / 指针链 / dump
                                   │ TCP + token（WiFi 或 USB 网卡）
                                   ▼
              设备端 tanyao-agent（TanyaoCli 仓库） ──ioctl──▶ TanyaoKernel
```

- 协议唯一真相源：[docs/PROTOCOL.md](docs/PROTOCOL.md)（20B 大端帧头 + JSON
  payload，单槽位 target 语义，挑战-应答鉴权）；v1.2（计算下沉）定版为
  [docs/PROTOCOL_V1.2.md](docs/PROTOCOL_V1.2.md)（与正文同效力）；v1.2.1
  附录（cmd 50 显式 `ranges` + 能力位 bit9 `SCAN_EXPLICIT_RANGES` + hello
  `build` 构建标识）见 PROTOCOL.md §7.2
- 设备端 agent：`ZhangTanjin/TanyaoCli` 仓库（`src/agent/`）

## 能力面（31 个 MCP 工具，v3 按能力位自动分派）

- 侦察：`get_status`（含 `agent_capabilities`/`skipped_caps`）`find_process`
  （name 须为完整包名/cmdline，短名不匹配——O4 短期口径；模糊匹配为 V1.3 候选）
  `list_processes` `list_modules`
  `resolve_module`（ELF load bias/BSS/mirror）`address_resolve`（RVA）
- 内存：`read_memory`（原始/typed）`read_batch`（批量）`write_bytes`
  （双门禁 + expect-old/verify；agent 声明 bit1 时单往返走 cmd 60，门禁仍在 host）
- 扫描：`scan_set_default_ranges`（preset）`scan_value` `scan_hex`
  `scan_start`/`scan_status`（异步）`scan_next` `scan_results` `scan_cancel`
  `scan_clear`
  —— agent 声明 bit0 时走设备端扫描引擎（cmd 50–55，只回传命中），
  否则回退主机引擎（冻结基线）：容错分区读、PFNMAP 自动跳过、死区粒度升级
- 观测/检索（R5 新增）：`watch_many`（多地址批量采样，MEM_READV 编排）
  `pointers_to`（找指向给定地址的指针——u64 扫描语义化封装，strip_pac
  默认掩顶两字节）
- 分析：`resolve_offset_chain`（PAC 剥离）`symbol_list`/`symbol_find`
  （bit3 → cmd 61 设备端 dynsym 批量，否则活内存解析回退）
  `disassemble`（bit8 → 设备端 capstone；否则 capstone/子集 fallback）
  `strings`（bit5 → cmd 62 设备端扫描；行字段为 `address`/`length`/`value`
  ——R5 起不再使用十进制 `offset` 旧字段名）`dump_module`（bit6 → 设备端落盘 +
  压缩分块拉取 + sha256 对账 + 显式清理，否则主机分块读重建）
  `pull_apk`（bit6 时走 dump_pull path 变体）`apk_info`（`pid` 或
  `apk_path` 二选一：pid 走 cmd 66 零镜像过网）`watch`
  `decompile_start`/`decompile_status`（Ghidra headless 异步；dump 数据源
  自动跟随管线）

分派只看 hello `capabilities` 位图，不做版本号判断；所有输出只增字段
（`engine`、`maps_source`、`skipped_caps`），MCP 工具面（名称/签名/形状）
向后兼容。协议 v1.2 增量见 [docs/PROTOCOL_V1.2_DRAFT.md](docs/PROTOCOL_V1.2_DRAFT.md)。

## 快速开始

```bash
# 依赖：Python 3.10+，核心零第三方依赖；可选增强见 pyproject extras
# 1) 设备端就绪（TanyaoCli 仓库构建的 tanyao-agent 在设备上运行）
# 2) 启动主机核心（地址与 token 从环境注入，勿硬编码）
TANYAO_AGENT=<device-ip:52730> TANYAO_TOKEN=<token> ./scripts/start-serve.sh
# 3) MCP 接入（Claude Code / DeepSeek Harness 等）：stdio 拉起
#    python3 -m tanyao.mcp_server   （TANYAO_IPC_URL 默认 127.0.0.1:28101）
```

安全模型：agent 侧挑战-应答鉴权 + 单连接槽位；host 侧 `write_bytes` 双门禁
（`TANYAO_ALLOW_WRITE=1` + expect-old→write→verify 强制链）；回归测试
**永不改动活体目标进程**。

## 测试

```bash
python3 -m unittest discover tests          # 单测（mock agent，无需设备）
python3 tests/mcp_regression.py             # 真机回归，项数随能力位/写门禁条件段浮动
                                            # （2026-09-05 基准 44 项：agent caps=0x2fb、门禁关闭）
python3 -m tanyao.interop --host <ip> --port 52730 --token <token> --pid <pid>
                                            # 设备端 agent 验收（按能力位条件化，含 skipped_caps）
```

## 仓库结构

```
tanyao/            核心包（协议/连接/服务/分析/扫描/ELF/符号/native/ipc/mcp）
tests/             单测（mock agent 内置）+ mcp_regression + interop + 靶进程源码
docs/PROTOCOL.md   双端线协议唯一真相源
scripts/           start-serve.sh
```
