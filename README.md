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
  payload，单槽位 target 语义，挑战-应答鉴权）
- 设备端 agent：`ZhangTanjin/TanyaoCli` 仓库（`src/agent/`）

## 能力面（29 个 MCP 工具）

- 侦察：`get_status` `find_process` `list_processes` `list_modules`
  `resolve_module`（ELF load bias/BSS/mirror）`address_resolve`（RVA）
- 内存：`read_memory`（原始/typed）`read_batch`（批量）`write_bytes`
  （双门禁 + expect-old/verify）
- 扫描：`scan_set_default_ranges`（preset）`scan_value` `scan_hex`
  `scan_start`/`scan_status`（异步）`scan_next` `scan_results` `scan_cancel`
  `scan_clear`
  —— 容错分区读，特殊页（PFNMAP）自动跳过，死区粒度几何升级
- 分析：`resolve_offset_chain`（PAC 剥离）`symbol_list`/`symbol_find`
  （活内存 dynsym）`disassemble`（capstone 主引擎 + 零依赖子集 fallback）
  `strings` `dump_module`（文件布局重建 + 节表清洗）`pull_apk` `apk_info`
  `watch` `decompile_start`/`decompile_status`（Ghidra headless 异步）

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
python3 -m unittest discover tests          # 61 用例（mock agent，无需设备）
python3 tests/mcp_regression.py             # 36 项真机回归（需 serve + 设备）
python3 -m tanyao.interop --host <ip> --port 52730 --token <token> --pid <pid>
                                            # 设备端 agent 验收（TanyaoCli DoD）
```

## 仓库结构

```
tanyao/            核心包（协议/连接/服务/分析/扫描/ELF/符号/native/ipc/mcp）
tests/             单测（mock agent 内置）+ mcp_regression + interop + 靶进程源码
docs/PROTOCOL.md   双端线协议唯一真相源
scripts/           start-serve.sh
```
