# Tanyao AI 逆向工作流架构设计

状态：**v3 方向已确认**（2026-09-04，用户拍板：计算下沉设备端，消除高带宽链路依赖）
版本历史：
- v1：保留 adb 的渐进路线（serve 模式 → adb forward → RNDIS）——已被 v2 取代
- v2：**agent 化 + 运行期脱离 adb + 参考 AMem/AndroidMiniMem 制作电脑端**——agent 化与脱离 adb 继续有效
- v3：**计算下沉设备端（data-local computing）：扫描/符号/字符串/dump 落盘等数据密集操作在设备执行，
  网络只传提炼结果；批量产物仅在显式发起时压缩传输**（当前生效，详见 §11；§5–§9 为 v2 存档）

结论基于对以下代码/资料的实读：
- `TanyaoKernel/src/transport_anon.c`、`transport_socket.c`、`include/uapi/tanyao_abi.h`
- `TanyaoCli/src/main.cpp`（BackendClient、命令分发、--json 覆盖面）
- `TanyaoKernel/docs/WORKSPACE_STATUS.md`（2026-09-02 实测快照）
- https://github.com/niqiuqiux/AMem （dev 分支，README + CLAUDE.md）
- https://github.com/niqiuqiux/AndroidMiniMem （AMem 的精简 monorepo，README）

---

## 1. 目标

让 AI（Claude Code 等 MCP 客户端）安全、低延迟、少出错地驱动 TanyaoKernel
对设备上目标进程做逆向分析（进程/模块枚举、ELF 解析、dump、AOB/typed 扫描、
指针链、受控写入）。运行期不依赖 adb。

## 2. 参考项目分析（AMem / AndroidMiniMem）

两者关系：AMem = Windows ImGui 图形前端；AndroidMiniMem = 精简版 monorepo，
其 `engine/minimem_server` 正是"设备端 agent"角色（root 常驻 socket 服务，
默认端口 52736，CE 协议子集，内核驱动做内存读写）。

### 2.1 照抄的部分

```
AI ──MCP/stdio──▶ Python MCP Server ──HTTP JSON──▶ 核心服务内嵌 IPC (127.0.0.1:28101)
                                                        │
                                                        ▼ TCP（RNDIS 网卡 / WiFi）
                                              设备端 agent（root 常驻）
```

| 照抄 | 出处 |
| --- | --- |
| MCP(stdio) → HTTP IPC → 核心服务 → TCP → 设备 的四层分离 | 两者共同架构 |
| 协议层单一真相源：GUI/Lua/IPC 只经一个 MemService 进协议层 | MiniMem `client_singleton.h` 模式 |
| 连接代际 + 目标 revision + 复合事务 + 统一错误语义 | MiniMem（与我们的 cookie 机制同源） |
| IPC 安全：仅本机、Content-Length 唯一、拒浏览器 CORS、拒 Transfer-Encoding | MiniMem gui IPC |
| MCP 工具命名与粒度 | MiniMem 工具表（见 §7.2） |

### 2.2 不抄的部分

| 不抄 | 原因 |
| --- | --- |
| Windows/DX12 GUI | 主机是 Linux；GUI 后置可选 |
| CE ceserver 协议兼容 | 见 §6 决策 D2 |
| 设备端扫描引擎 | 扫描全部放主机（§7.1） |
| 硬件断点 | TanyaoKernel 无内核断点能力，远期项 |
| Lua 引擎 | 后置可选；主机 Python SDK 本身可编程 |

## 3. 现状链路（保留的优点）

```
现状：AI → adb shell "su -M -c 'tanyao-cli <cmd>'" → CLI 一次性进程
      → syscall(SYS_reboot, MAGIC_A, MAGIC_B) → kprobe(__arm64_sys_reboot)
      → task_work_add(current) 装匿名 fd → ioctl(ABI v1) → access_process_vm()
      → 进程退出，全部释放
```

保留不动：内核只做用户态做不到的事（FOLL_FORCE 写 .text、TARGET_MAPS、隐藏能力）、
重分析留主机、`target_start_cookie` 防 PID 复用、写入护栏、无常驻 daemon 的 stealth 定位。

核心损耗（v2 要解决的）：每命令一次全量冷启动（~100–500ms）、三层引号拼接、
状态靠 AI 上下文搬运、64KiB 输出上限、dump 三步搬运。

## 4. 关键约束（不变量）

**内核连接是一根绑定在设备进程上的匿名 fd，无法跨机。**
fd 由 `task_work_add(current, ...)` 安装进发起 magic reboot 的设备进程
（transport_anon.c:888）；ioctl 只能由设备内核上持有 fd 的进程发起。
推论：设备上必须有一个 root 进程持有 fd 并代为执行 ioctl；能上电脑的只有逻辑。
备选连接：`transport_socket.c` 的 socket transport（PF_DECnet 空槽自定义协议族，
`socket(AF_TANYAO, SOCK_RAW)` 直接换出 session，root+CAP_NET_RAW），
默认关闭、仅 stealth profile——agent 稳定后可作为免 kprobe 的连接方式。

**无 adb 的部署悖论**：首次部署 agent 与 `.ko` 仍需一次 adb/root；
此后运行期 adb 完全退出。这是接受的物理事实。

## 5. 确定的目标架构

```
AI(Claude Code 等) ──MCP stdio──▶ tanyao-mcp (Python)
                                      │ HTTP JSON, 127.0.0.1:28101
                                      ▼
                        tanyao-host 核心 (Python, 协议层单一真相源)
                        · 连接管理/重连/代际, cookie 缓存
                        · ELF 解析, 指针链, 扫描引擎, dump 流
                                      │ TCP + token（RNDIS 网卡优先，WiFi 备选）
                                      ▼
              设备 tanyao-agent（root 常驻, 由 TanyaoCli 简化而来）
              · magic-reboot → anon fd（或 socket transport）持内核连接
              · 帧 → ioctl(ABI v1) → 帧返回；零业务逻辑
                                      ▼
              TanyaoKernel（完全不动）→ access_process_vm() → 目标进程
```

职责边界：

| 位置 | 放什么 | 不放什么 |
| --- | --- | --- |
| 电脑 | AI、MCP、host 核心、全部逆向逻辑（ELF/扫描/指针链/dump）、pyelftools/capstone | 设备依赖 |
| 设备 agent | 内核连接、fd 持有、token 鉴权、帧解析、ioctl 转发、连接代际 | 任何逆向逻辑、任何无鉴权监听 |
| 内核 | 现状全部能力 | — |

## 6. 关键决策记录

| # | 决策 | 理由 |
| --- | --- | --- |
| D1 | 设备端只留 agent；`tanyao-cli` 保留为设备端手动调试工具，两者共存于 TanyaoCli 仓库（`src/agent/` 独立 target） | 复用 BackendClient / tanyao_abi.h；调试兜底 |
| D2 | **自定义二进制协议，不做 CE 兼容** | CE 协议 32 位时代设计、庞杂，与 ABI v1 能力集（TARGET_MAPS/readv/start_cookie/能力位）不对齐；自定义协议每 op 一一映射 ioctl，agent 零翻译、审计面最小；AI 主入口是自研 MCP，GUI 是锦上添花 |
| D3 | 扫描/ELF/指针链全部在主机 | agent 零业务逻辑；增量扫描在主机快照上做，控制 USB 带宽 |
| D4 | 传输走 TCP over RNDIS/NCM USB 网卡（手机"USB 网络共享"→ 主机 usb0/rndis0），WiFi 为备选；运行期无 adb | 控制面（adb 一次性部署）/数据面（TCP 直连）分离；Linux 免驱动 |
| D5 | MCP 工具默认只读；写操作策略在 host 层强制（expect-old → write → verify → rollback），agent 不拦截 | 策略集中、可审计 |
| D6 | GUI 后置可选 | MiniMem gui/ 已验证 Linux 构建可行（GLFW+OpenGL3），需要时再做；GUI 只是 IPC 的又一个客户端 |

## 7. 组件设计

### 7.1 设备端 `tanyao-agent`

- **op = ABI v1 ioctl 一一映射**：`backend_info`、`session_info`、`target_open/close`、
  `mem_read`、`mem_readv`、`mem_write`、`target_maps`；可选 legacy `process find/list/alive`、`module base`。
- **砍掉**（逻辑上移主机）：文本/JSON 格式化、ELF 解析、AOB/typed 搜索、watch/diff、
  dump 落盘、64KiB 终端限制、argv 解析。
- **新增**：TCP 监听、token 鉴权握手、二进制帧协议（定长头 `magic|ver|len|seq|cmd` + payload）、
  连接代际（agent 重启代际 ++，host 自动重开会话）、心跳。
- **监听地址**：优先绑 `rndis0` 接口地址；WiFi 局域网亦可但 token 必选；永不无鉴权绑 0.0.0.0。
- **启动**：adb 一次性 push + `su -M -c` 拉起（默认）；或 KernelSU 模块 boot 脚本常驻（stealth 权衡自担）；或设备上手动拉起。

### 7.2 主机端三层

**核心层 `tanyao-host`（Python 3.10+）**，内嵌 HTTP IPC（127.0.0.1:28101，MiniMem 式加固）：
- 协议层（单一真相源）：连接、鉴权、帧收发、重连、代际、cookie/PID 缓存；
- 上移逻辑：ELF 解析（pyelftools：load bias/RVA/mirror）、指针链（strip-PAC）、
  扫描引擎（首扫分块 mem_read + 主机比较；增量在主机快照；首扫默认限定
  heap/anonymous/模块范围）、dump 流式回传。

**MCP 层 `tanyao-mcp`（stdio）** 工具表（对齐 MiniMem + 本项目增量）：

| 分类 | tools |
| --- | --- |
| 状态 | `get_status` `get_backend_info` `get_architecture` |
| 进程/模块 | `list_processes` `find_process` `open_process` `list_modules` `get_module_base` `resolve_module` |
| 内存 | `read_memory` `read_value`(typed) `read_batch` `write_bytes`(默认禁用，显式开启) |
| 扫描 | `scan_set_range` `scan_value` `scan_hex` `scan_next` `scan_fuzzy` `get_scan_results` `clear_scan` |
| 分析 | `resolve_offset_chain` `dump_module` `watch` `diff` |
| 断点 | 暂缺（需内核断点能力，远期） |

**GUI 层**：可选；ImGui docking + GLFW/OpenGL3 Linux 版或 Web 页面，仅作 IPC 客户端。

### 7.3 帧协议（v1）

- 定长头 + payload；`cmd` 与 ioctl 一一对应；每请求带 `seq`，响应回带；
- 鉴权：连接后先 challenge-response（token），失败即断；
- 大块数据（dump/扫描回传）：meta 帧后跟数据帧流；
- 主机 SDK 传输层可插拔（rndis-tcp / wifi-tcp / 预留 adb-forward 调试通道），帧协议不变。

## 8. 里程碑

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| M0（硬阻塞） | 装 AOSP clang + 6.6.118-android15-8 symvers 重编 `.ko`；full probe 归零；CLI 本机重编核对 hash；记录写回 VALIDATION_LOG | 模块可加载、有验证记录 |
| M1 | `tanyao-agent`（TCP+token+核心 op）+ `tanyao-host` 核心层 | 主机 Python 直连读写成功，运行期无 adb |
| M2 | `tanyao-mcp` + HTTP IPC | AI 经 MCP 完成 进程→模块→读值 全流程 |
| M3 | 扫描引擎 + 指针链 + dump 流 | 首扫→再扫→指针链 全在主机完成 |
| M4 | 稳定性（重连/代际/多目标并发）+ GUI（可选） | — |

## 9. 风险

1. RNDIS/NCM 与 MTK+Android 16 共存需真机实测（tethering 开关是否瞬断 adb）；
2. WiFi 模式暴露面大于 USB 网卡——默认推荐 USB 网络共享；
3. `.ko` 重编是 M1 前置，设备当前无可验证模块（WORKSPACE_STATUS §3）；
4. 主机扫描的全内存首扫受 USB 带宽约束——范围限定 + 增量扫描对冲；
5. agent 长持有 session 期间目标死亡：依赖 cookie 校验报错，host 重查 PID 重开。

## 10. 实施记录

> 注：本节为 2026-09-02 的实施日志，文中 `/home/tanjin/guihua/...` 为当时
> 主机路径；2026-09-04 起工作区统一为 `/home/tanjin/phone/tanyao-host`。

### 2026-09-02 M1/M2/M3 桌面端（tanyao-host）完成

- 语言与分层：桌面端 Python 3.10+（核心零第三方依赖）；设备端 agent 由 TanyaoCli
  工程师用 C++ 实现（`ENGINEER_PROMPT.md` 已交付，含完整协议内嵌、禁止条款、
  验收标准与建议实现顺序）。
- 交付物（`/home/tanjin/guihua/tanyao-host/`）：
  - `docs/PROTOCOL.md` —— 双端唯一真相源：20B 大端帧头（`>IBBHIII`）+ JSON payload、
    16 个 op（6 个 ABI v1 核心 + 4 个 legacy）、SHA256 挑战-应答鉴权、单连接/代际、
    错误 slug 表。
  - `tanyao/` 核心包：`constants.py`（编码/opcode）、`frames.py`（编解码）、
    `connection.py`（hello/auth/一问一答/超时）、`service.py`（单一真相源：重连、
    代际、handle/cookie 缓存、分块读写、写能力检查）、`analysis.py`（门面：typed
    读、写护栏 expect-old+verify、模块 ELF 解析、地址→RVA、指针链 PAC、watch）、
    `scan.py`（首扫/增量/AOB/模糊，主机态）、`elfinfo.py`（零依赖 ELF64/PT_LOAD/
    load bias/BSS/mirror）、`dump.py`（稀疏重建 + manifest + watch）、`ipc.py`
    （HTTP IPC 127.0.0.1:28101，MiniMem 式加固）、`mcp_server.py`（MCP stdio，
    17 个工具，默认只读）、`serve.py`（常驻入口 + keepalive）、`interop.py`
    （设备端验收工具，14 项检查）。
  - `tests/mock_agent.py` —— 协议参考实现（Python 版 mock agent，含合成
    ELF64/多映射/指针链/扫描目标的假想世界）；`tests/test_e2e.py` —— 20 用例端到端。
- 验收证据：
  - `python3 -m unittest tests.test_e2e` → **20/20 OK**（连续 3 次稳定）；
  - `python3 -m tanyao.interop --host 127.0.0.1 --port <mock> --token ... --pid 4321
    --allow-write` → **14 passed / 0 failed / exit 0**（对 mock agent 全绿；
    同一工具即设备端 agent 的 DoD 验收）。
- 排障记录（对端工程师可参考）：帧头结构体曾出现 `>IBBHII`/`>IBBHIHI` 两种错误
  变体（16/18B），与规范的 20B 不符，导致 hello 可达但解码器从错误偏移读 length
  永远凑不齐——表象是"对端 sendall 成功、本端 recv 永久超时"。已统一为
  `>IBBHIII` 并在 `frames.py` 加 `assert _HEADER.size == HEADER_SIZE`。
  **教训：双端帧头格式必须以 PROTOCOL.md §2 为准逐字节核对。**
- 待办移交：
  - 设备端 `tanyao-agent`（TanyaoCli 仓库，按 `ENGINEER_PROMPT.md` 执行，
    M0 的 `.ko` 重编仍是其联调前置）；
  - MCP 接入 Claude Code 实测（`tanyao.mcp_server` 已就绪，等 agent 联调后
    走真实链路验证）；
  - 真机 RNDIS tethering 共存性实测（设计文档 §9 风险 1）。

### 2026-09-02 设备端 agent 交付（TanyaoCli 工程师），双端合龙

- TanyaoCli 仓库提交 `1bb9637`：`src/agent/{agent.hpp,agent_main.cpp,agent_ops.cpp}`、
  `third_party/agent/`（cJSON + 公有领域 SHA-256）、`tanyao-agent` CMake target、
  `scripts/build-agent.sh`；`src/main.cpp` 零改动。
- 真机 DoD 全部达成：interop 14/14（含 --allow-write 写入+回读打在自有测试进程）、
  abi 1.0 / capabilities 0x1003f 双端一致、同地址 16 字节读取与 tanyao-cli 逐字节
  一致、generation 持久化于 `/data/local/tmp/.tanyao-agent-generation`（重启递增，
  host 以变化检测重启——与设计兼容）、全部错误路径、SIGTERM async-signal-safe
  干净退出（工程师实测修复了只写管道不置停止位的问题）、tanyao-cli 构建回归通过。
- 帧头格式争议闭环：工程师报告 host 端 `>IBBHIHI`（18B）与 `HEADER_SIZE=20` 矛盾——
  该 bug 属实，但与本次 mock 联调排障发现的是同一处，**已在本日修复**（全仓统一
  `>IBBHIII`，`frames.py` 加 `assert _HEADER.size == HEADER_SIZE`）；工程师侧
  interop 14/14 通过本身即证明其运行的是修复后版本（16/18B 解码器不可能对上
  规范实现的 agent）。新增 `tests/test_frames.py` 6 个金样本回归测试将 20B 布局
  钉死，任何未来漂移会在 CI 第一时间爆炸。全仓 26/26 OK。
- 设备当前状态：agent 产物在机（`/data/local/tmp/tanyao-agent` + token 文件 0600 +
  generation 计数文件），adb 已断开，agent 走设计内 SIGTERM 干净退出（exit 0）；
  重连后重启 agent generation 将为 5，host 端按设计检测重启并重建会话。
- 下一步：设备重连 → 重启 agent → 复跑 interop → `tanyao.serve` + MCP 接入
  Claude Code 真链路验证。

### 2026-09-02 设备重连，全链路真机贯通（M1/M2 真机验收完成）

- 真机 interop 复跑 **14/14 exit 0**（agent gen=4 运行中，绑 192.168.1.34:52730，
  内核模块 Live）。写回读用例在 surfaceflinger 上返回 EFAULT（SELinux 域隔离，
  属预期），改打自有 root `sleep` 进程后逐字节回读一致——**写入测试目标必须是
  自有进程**，已记为操作纪律。
- `tanyao.serve` 常驻接入真机：IPC get_status / find_process(surfaceflinger pid
  1370) / list_modules(libc.so base 0x7dd2e55000) / read_memory(ELF magic
  7f454c46…) / resolve_module(load bias) / address_resolve 全部经
  IPC→agent→内核→目标进程真链路通过。
- MCP stdio 层真链路通过：initialize / tools/list(17) / tools/call
  find_process+read_memory 返回正确，isError=False。
- 扫描引擎真机冒烟：surfaceflinger 匿名区共 356 个 range（target_maps 0.3s）；
  全匿名区首扫为分钟级（WiFi 带宽，符合 §9 风险 4 预期，AI 工作流应默认
  scan_set_range 限定模块/小范围）；libc 8KB 范围内 ELF magic 首扫 0.01s 命中
  且地址精确。
- 运维脚本：`scripts/start-serve.sh`（setsid 脱离终端，日志 /tmp/tanyao-serve.log；
  注意 pkill 模式勿含自身命令行）。
- 剩余：Claude Code MCP 配置接入实测；全匿名区首扫的性能对策（限range/二进制帧/
  后端 readv 摊薄）。

### 2026-09-02 MCP 接入 DeepSeek Harness（M2 闭环）

- 配置方式：`/root/.dsh/profiles/web/cordis.patch.yml` 增加 patch 插入行
  （`PatchOptions.insert`），挂载 `@deepseek-ai/dsh-mcp-client`
  （serverName=`tanyao`，stdio，`python3 -m tanyao.mcp_server`，cwd=
  `/home/tanjin/guihua/tanyao-host`，env 注入 PYTHONPATH 与
  `TANYAO_IPC_URL=http://127.0.0.1:28101/`，toolCallTimeoutMs=600000，
  failOnStartupError=false）。
- `mcp_server.py` 相应支持 `TANYAO_IPC_URL` 环境变量覆盖 IPC 地址。
- 验证链：`dsh --profile web --dump-config` 组合校验通过（mcp-tanyao 行在位、
  零告警）；web profile 为 `patchReload: live`，**补丁写入后运行中的 harness
  进程热重载并自行 spawn 了 MCP server**（进程树：dsh web → tanyao.mcp_server）；
  harness 式 spawn 模拟握手（initialize 回显 2025-06-18 / tools/list 17 工具 /
  tools/call get_status+find_process）全部返回真实数据；IPC 链路
  connected=True generation=4。
- 工具命名：`mcp__tanyao__<tool>`（如 `mcp__tanyao__read_memory`、
  `mcp__tanyao__scan_value`）。热重载前已开启的会话工具表可能不含新工具，
  **新会话必定可见**；重启 `tanyao.serve` 后 MCP 子进程经重连策略自动恢复。
- 运维速查：链路三层各自独立——设备 agent（重启用 adb su 一条命令）、
  `tanyao.serve`（`scripts/start-serve.sh`）、MCP 子进程（harness 托管，
  随补丁/重启自动管理）。

### 2026-09-02 P1 功能补齐（对齐 AMem 差距，17→22 工具）

全部桌面端闭环，协议与 agent 零改动。新增：

1. **`read_batch`**（暴露既有 MEM_READV）：一次拉多个不连续 span，per-span
   data_hex/error。真机 2 spans 0.01s。
2. **扫描异步化**：新增 `scan_start`（后台任务，daemon 线程）+ `scan_status`
   （轮询进度 done/total 字节数 + 完成后 summary/results）；估算 >64MB 自动转
   async；运行中禁止 scan_next 防状态竞争。解决全匿名区扫描阻塞到 MCP 超时的
   最大痛点。
3. **符号解析**（MiniMem symbol_find/list 对齐）：`symbols.py` 从**活内存**解析
   PT_DYNAMIC → DT_SYMTAB/STRTAB/DT_HASH/GNU_HASH（bionic 把 DT_* 重写为绝对
   地址，兼容 raw/absolute 两种形态；GNU hash 走 bucket→chain 计数）。
   `symbol_list`（含 filter）、`symbol_find`（跨可执行模块自动搜索）。
   真机 libc.so：1483 符号 33s（WiFi 逐 symtab 读；后续可用 dump 产物
   解析优化到秒级）；`pthread_create` @ 0x7dd2ef1160，地址处读回 ARM64
   prologue（ff 43 04 d1 = stp x31,x30,[sp,#-64]!）交叉验证通过。
4. **扫描范围 preset**：`scan_set_default_ranges` 增加 preset 参数
   （anon | stack | module:<name> | all_readable）。真机 module:libc.so
   = 4 ranges 1.1MB 0.1s。
5. mock ELF 升级为含 PT_DYNAMIC + dynsym/dynstr/DT_HASH 的完整镜像，
   符号路径全程可测；`tests/test_p1.py` 15 用例，全仓 **41/41 OK**。

实测运维发现：agent 单连接槽位 + 内核会话表在 host 非优雅重连后可能返回
EBUSY(-16) target_open；处置 = 重启 serve（或 agent）。gen 4→5 的重启检测
按设计生效。

### 2026-09-02 MCP 能力回归（31 项全绿）

新增 `tests/mcp_regression.py`：按 harness 方式 spawn MCP server，走完整
stdio 握手，**22 个工具逐个 tools/call**（成功路径 + 错误路径），对真设备
链路（IPC→agent→内核→surfaceflinger）执行。31 项检查全部 PASS：
- 协议层：initialize 握手（协议版本回显）、tools/list 恰为 22 预期工具、未知工具 isError；
- 侦察：get_status / find_process（含未命中非错误语义）/ list_processes(1080 pids) /
  list_modules（含坏 pid ESRCH）/ resolve_module(load bias) / address_resolve；
- 内存：read 原始+typed 数组、未映射 EFAULT isError、**write 门禁默认关闭**、
  read_batch 双 span；
- 符号：symbol_list(libc 1483 符号) / symbol_find(pthread_create
  0x7dd2ef1160) / 未命中 not_found；
- 扫描：preset module / bogus 拒绝 / scan_value / scan_hex / **scan_start→
  scan_status 异步完成（count=1）** / scan_next unchanged / clear 后 next 报错；
- 产物：dump_module 1.13MB ELF + manifest 落盘校验；watch 3 采样。

回归揪出并修复 1 个真实缺陷：`scan_start` 遗漏注册到 IPC 方法表
（MCP→IPC 转发报 unknown_method）——正是回归测试存在的意义。
已修复并复跑全绿。单测 41/41 保持 OK。

### 2026-09-02 EBUSY 事件闭环（跨端协作第一例）

**现象**：8 个 target 类工具全部 EBUSY(-16)；只有进程枚举类正常。
**根因**（工程师定位，我方探针佐证）：内核会话单 target 槽位
（`transport_anon.c:167` `session->target` 非空即 EBUSY），fd 跨客户端连接
存活，泄漏的 open target 占槽直到 agent 退出。独立 CLI 会话可正常打开
同一 pid ⇒ 锁在会话不在全局。
**三层处置**：
1. agent（工程师 `57f5891`）：每连接 target 列表 + 连接终止自动补发
   TARGET_CLOSE——防泄漏复发（协议零改动，纯连接生命周期管理）；
2. agent 重启恢复（gen 4→5），nohup 方式脱离 adb 会话生命周期；
3. host（架构师）：`service.py` 实装**单活动 target 策略**——打开新 pid 前
   自动 close 旧 target；EBUSY 时 close-all+重试一次。MCP 回归新增
   "cross-pid 切换无 EBUSY" 用例。**32/32 全绿**。
**残留（待工程师）**：TARGET_MAPS 对 >4096 映射的进程（systemui 实测 6466 条）
返回 ENOSPC——需 agent 侧 `/proc/<pid>/maps` 回退 op（tanyao-cli 既有语义）。
host 侧已做 ENOSPC 重试与清晰报错。协议 §4.5 已补单槽位语义说明。

### 2026-09-02 遗留两项闭环（agent a81d824），MCP 回归保持 32/32

1. **TARGET_MAPS ENOSPC 回退**（工程师实现，与 tanyao-cli 语义对齐）：内核
   -ENOSPC 且 total_count > 4096 时读 /proc/<pid>/maps 返回同结构 entries，
   响应新增 `maps_source` 标准字段（"target_maps"/"proc_maps"）；伪路径
   ([heap]/[stack]/[anon:*]/[vdso]/[vvar]) 置 ANONYMOUS。已补进
   PROTOCOL.md §4.7；host 侧 `service.maps_source()` 透传至 `list_modules`
   输出。真机验证：surfaceflinger=target_maps，systemui=proc_maps（6504 条）。
2. **幂等 target_open**：对本连接已持有的同 pid 直接返回既有
   handle/cookie（范围刻意收窄于本连接——内核单槽位下跨 pid 旧 handle 已死，
   跨 pid 切换仍走 host 的"先 close 再 open"策略，职责边界正确）。真机验证：
   serve 重启（host 缓存丢失）后首触同 pid 直接成功，不再需要重启 agent。
3. **generation 语义提醒（工程师）已确认**：gen 在 agent 每次重启时 +1，
   host 的"gen 变化→清 handles 缓存"逻辑本来就以变化为准，无需改动；
   此语义已写入 PROTOCOL.md §6（原文允许重启后重置，现在统一为持久递增）。
4. MCP 回归 32/32、单测全绿。EBUSY 事件全链闭环，无遗留。

### 2026-09-02 实战测试收官反馈闭环（P1/P2/P3 全部修复，真机验证）

实战逆向工程师全功能测试 8 项：7 PASS + 1 定位根因（报告
`TANYAO_FIELD_TEST_REPORT.md`，含靶进程源码 `tests/tanyao_target.c`）。
按报告修复并真机复测：

**P1 大扫描 fail-fast（已修，真机验证）**
- 根因（工程师实证）：内核 target_maps 把 [vvar]（VM_PFNMAP）纳入可读匿名
  段，GUP 读必 EFAULT，引擎 fail-fast 丢弃全部进度（两次独立运行同偏移
  3,202,273,280 确定性失败）。
- host 修复：`scan.py` 容错分区读——失败块二分下探，只跳过不可读叶（记录
  skipped ranges），命中保留；引擎级死区粒度几何升级（4KB→64MB，成功回 4KB），
  死区代价 ~30 次失败读而非 ~8 万次。
- 真机复测（同一目标 pid 6545，3.21GB / 547 段）：**done, 4 hits,
  skipped_ranges=1 (8192B = vvar+vdso), 480s**——修复前两次 8.5 分钟全损。
- 残留慢段（350s 零进度）为冷页 page-in 开销（GUP 首触换入），设备侧行为，
  非缺陷；内核侧排除 PFNMAP 仍值得做（消掉 skipped 概念）。
- 单测：`tests/test_field.py` 8 用例（毒洞二分跳过、hit 保留、账目、
  span 隔离、文件布局 dump、clear 保范围），全仓 52/52。

**P2-1 read_batch 批次污染（已修）**
- 内核 readv 是"连续前缀"语义：首个失败 iov 后的全部向量报 ECANCELED。
- host 修复：`service.mem_readv` 检测 completed_iov 短报/首个失败位，对
  失败位之后的 span 逐个独立重读——坏 span 隔离，后续 span 照常返回数据。
- 真机验证：[good, bad, good] → [data, error, data]。

**P2-2 dump PT_DYNAMIC 截断（已修，真机验证）**
- 双根因：① host 按 MAP_READ 过滤丢掉 -w-p 尾段（实测 FOLL_FORCE 可读）；
  ② 映射 vaddr 与 file offset 页漂移（-w-p: vaddr 0x1FA000 = file 0x1F9000），
  按 vaddr 推导输出偏移必然错位。
- host 修复：dump 改为**文件布局重建**——file-backed 映射一律写入其
  file_offset（不再按 vaddr 推导），包含无读权限映射，不可读段按映射跳过
  并记 manifest。
- 真机验证：libnullptr dump 2,084,864B（3 映射），PT_DYNAMIC
  (0x1fbb68+0x1f0) 完整可解析（DT_NEEDED 可见）；修复前截断于 0x1FA120。

**P3 全部顺手修**：scan_value 内联 results（一致化）；symbol_list 过滤
SHN_UNDEF 导入符号（92 个 st_value=0 噪声消失）；scan_clear 保留范围配置。

**域矩阵勘误（采纳）**：root agent 对 untrusted_app 可写（verified），
仅 system 域 EFAULT——TESTER_HANDOFF 第 3 节已更正。

性能基准（工程师实测）：read_batch 7.91×（10.23 vs 80.95ms/轮）；
全匿名区扫描 ~6.8MB/s（WiFi）。

### 2026-09-02 RE 工程师两阻塞修复（A1 hex 崩溃 / A2 大范围无进度）+ 新增 scan_cancel

**A1（已修，真机验证）**：`scan_start kind=hex` 立即 IndexError——根因是
`scan_start` 的 hex 分支只传 `pattern`（1 参数），而 job runner 期望
`(pattern_bytes, mask_bytes)`。修复：抽取 `_parse_aob()` 单源解析器，
两个入口共用；job runner 的 hex 分支同时接 progress。
真机验证：工程师原 pattern（AF 1B B1 FA 1F 00 00 00，2GB anon 范围）
完整跑完 done、0 hits（该值本就少）、skipped=1(8KB)、速率稳定 1.86→1.94MB/s。

**A2（已修，真机验证）**：大范围扫描 2 分钟无进度且疑似卡死——根因是 P1
容错重构把"读"与"扫"分离，`_read_region` 先把整个范围读进内存列表再迭代
扫描：进度恒 0 + 10GB 范围直接 OOM。修复：`scan_value/scan_hex` 重构为
**流式**架构（`_scan_region` + on_chunk 回调，读一块扫一块，内存恒定），
job runner 注入 progress 与 cancel_event。
真机验证：3.21GB 扫描进度曲线平滑（每 10s +1.9%）。

**附带修复**：`scan_hex` 签名漏 `cancel_event/progress` 参数（闭包 NameError
被 _scan_region 误判为 EFAULT → 全范围被跳过的静默故障）——由此引入**关键
架构分离**：`_scan_region` 中"读故障"（引擎处理：跳过/二分）与"回调错误"
（直接传播，大声失败）严格分离，杜绝同类伪装。

**新增 `scan_cancel`（第 29 工具）**：jobs 增加取消事件 + cancelled 状态；
引擎每 chunk 检查事件、抛 ScanCancelled（_scan_region 直通）。起因：验证
期间意外残留 3 个并发 hex job 抢占同一 agent 连接，互相爬行且无法取消。
IPC/MCP/regression 同步。**协议无改动。**

**运维发现（非缺陷，已记录）**：目标进程死亡时全量读 EFAULT，引擎按死区
快速跳过会"done 但全 skipped"——验证 6545 已死（15277 为活靶）。跳过全部
即目标已死的行为符合设计，但 host 可加"连续 skipped > 阈值 → 显式报
target-dead"（待办，非阻塞）。

### 2026-09-02 工具链收官（22→28 工具，capstone/Ghidra 外接架构）+ 反 dump 硬化发现

**架构纠正（工程师主导，架构师建议）**：自写 A64 子集解码器实测真机覆盖率
94%（15 条 .long），继续补指令=重造 capstone。纠正为外接为主、自写降级：
- 会话内反汇编：capstone 4.0.2 主引擎（全 ISA）+ native.py 子集 fallback
  （无 capstone 环境自动切换），输出带 engine 字段；真机 253 条指令 100% 覆盖。
- 全函数反编译：Ghidra 12.1.3 headless（/opt/ghidra，JDK 21），
  `decompile_start`/`decompile_status` 异步 job；真机 47s 反编译 5009 函数。
- 新工具：`disassemble` `strings` `pull_apk` `apk_info`（AXML 解析）
  `decompile_start` `decompile_status`（26→28）。
- strings 首战即获目标情报：root 检测扩展至 io.github.vvb2060.magisk /
  me.weishu.kernelsu 包名 + procfs 一致性比对。

**工具链深坑发现与修复（工程师）**：内存 dump 的 ELF 头携带悬空 e_shoff
（指向未捕获的磁盘节表），Ghidra 导入器静默跳过 dynsym 符号加载（3 万符号
无名）。修复：dump_module 输出清零 e_shoff/e_shnum/e_shstrndx，
manifest.sanitized 记录；修复后 Ghidra 符号全数恢复（函数名产出 C 伪代码）。

**反 dump 硬化发现（架构师，回归排障）**：该设备 bionic loader 加载后把内存
ELF 头 magic 4 字节清零（class/data/version/e_type/phdr 完好），内存扫
magic 全部落空。修复：`elfinfo.parse_elf64(allow_zero_magic=True)`（内存模式
按其余字段放行，dump 磁盘校验仍严格）；回归 8 处 magic 断言改为幸存字段
（e_type+machine = `03 00 B7 00`）。**对实战的含义：目标设备有反 dump
硬化，dump 产物首 4 字节为零，Ghidra 导入需手动补 magic。**

**回归安全化（架构师自查）**：原 write-gate 用例会向活体 surfaceflinger
libc 基址写 4 字节（恰好落在已清零 magic 区无害，但设计危险）。改为
get_status 探测门禁状态、关闭时仅写不存在的 pid、**任何情况不改动活目标**。

**最终验证**：MCP 回归 36/36（28 工具+错误路径，含新 6 工具）；单测 61/61
（双解码引擎路径）。链路 UP（gen=9）。RE 全链就绪：find→dump→Ghidra
decompile→strings/disassemble→scan→chain→write。

---

## 11. v3 架构：计算下沉设备端（2026-09-04 定稿）

### 11.1 动机——v2 实测暴露的带宽封顶

v2 的 D3（"扫描/ELF/指针链全部在主机"）在真机实测中被证伪为性能瓶颈。
凡是"把原始内存搬到主机再算"的操作，速率都被链路封顶，与计算本身无关：

| 操作 | v2 实测 | 瓶颈 |
| --- | --- | --- |
| 全匿名区首扫 3.21GB | 480s（~6.8MB/s，WiFi） | 3.21GB 原始内存过网 |
| symbol_list 1483 符号 | 33s | 逐符号读内存过网 |
| dump/decompile | MB 级镜像过网 + base64 +33% 体积 | 镜像搬运 |
| pull_apk | 百 MB 级 APK 过网 | 仅为看包信息 |

结论：**计算必须移到数据旁边**。设备本地读内存是 GB/s 级（内存带宽/冷页换入
UFS 速率），比过网高两个数量级。TanyaoCli v1.1 扫描扩展（cmd 50–55，设备端
本地扫描、只回传命中）已经验证了这条路线的正确性——v3 就是把同一原则推广到
全部数据密集操作。

### 11.2 v3 目标架构

```
AI(Claude Code 等) ──MCP stdio──▶ tanyao-host (Python)
                                   · MCP 工具面（不变）/编排/重连代际/写门禁
                                   · 指针链与 typed 读（少量小读，KB 级）
                                   · Ghidra 深度反编译（唯一显式批量消费方）
                                   │ TCP + token（帧协议演进，新增二进制载荷帧）
                                   ▼
              设备 tanyao-agent（角色升级：纯转发器 → 设备端分析引擎）
              · 本地扫描引擎（v1.1 已实现：cmd 50–55，命中回传）
              · dynsym 批量解析（bit3 SYMBOL_BATCH）、strings 扫描
              · apk 中央目录 + AXML 解析（apk_info 零镜像过网）
              · 会话内反汇编（capstone 交叉编译到设备，可选）
              · dump 本地落盘（含 e_shoff 清洗）+ 按需压缩分块拉取
              · 同机 loopback 服务 TanyaoMB（设备端 GUI，不占外网带宽）
              │ ioctl（ABI v1，不变）
              ▼
              TanyaoKernel（小幅增强：PFNMAP 排除等，见 §11.6）
              → access_process_vm() → 目标进程
```

**带宽分级（v3 核心约束）**：

| 级别 | 操作 | 过网数据量 |
| --- | --- | --- |
| 零镜像（本地算，只回结果） | 扫描、watch/diff、strings 过滤、apk_info、符号批量/检索、反汇编 | 命中/结果列表，KB 级 |
| 紧凑 | 进程/模块枚举、typed 读、指针链、dump 元数据 | KB 级 |
| 显式批量（唯一例外） | dump 镜像拉取（供 Ghidra）、pull_apk | 压缩后 MB 级，必须显式发起、分块、可续传 |

### 11.3 决策修订与新增

| # | 决策 | 内容 |
| --- | --- | --- |
| D3-修订 | 扫描引擎主力换位 | 设备端引擎为主（数据在旁）；主机 `scan.py` 冻结特性，仅作旧 agent 能力回退与 mock 参考实现。MCP 工具按 hello capabilities 自动选择引擎，AI 工作流与回归用例零改动 |
| D7（新） | 计算靠近数据 | 默认只有提炼结果过网；任何批量产物必须：显式发起 + 压缩传输 + 分块可续传 + 设备侧落盘带清理策略 |
| D8（新） | 反汇编下沉、反编译保留主机 | agent 链接 capstone（C 库，NDK 可交叉编译）提供会话内反汇编；Ghidra 全函数反编译保留主机，成为唯一 sanctioned 批量操作（需先显式拉取压缩镜像） |
| D9（新） | 批量通道不新增常驻链路 | 批量产物走同一 TCP（压缩+分块+续传）；调试期允许临时 adb pull 兜底，但不构成运行期依赖，帧协议不因此分叉 |

不变量继续有效：ABI v1 不动；帧协议 20B 头不动（只扩展 flags 位与 cmd 号）；
鉴权/单槽位/代际语义不动；写门禁（双门禁 + expect-old→write→verify）不动；
无 adb 运行期不动。

### 11.4 协议演进（v1.2 草案方向）

基座：v1.1 扩展（AGENT_SCAN bit0、WRITE_TXN bit1、cmd 50–55/60）**定版并入
PROTOCOL.md**。在此之上：

| 项 | 能力位/op | 说明 |
| --- | --- | --- |
| 二进制载荷帧 | flags bit2 BINARY | 大块数据不再 base64（-25~33% 体积 + 编解码 CPU）；meta(JSON) 帧 + 二进制数据帧 |
| 符号批量 | bit3 SYMBOL_BATCH → `symbol_batch` | 设备端解析 PT_DYNAMIC→dynsym/dynstr 一次性回传（支持设备侧 name 过滤）；替代主机逐符号读（33s → 秒级） |
| strings 扫描 | `strings_scan` | 设备端分块容错扫 + 正则过滤，只回命中 |
| apk 元信息 | `apk_info` 下沉 | 设备端 zip 中央目录 + AXML 解析，零镜像过网；`pull_apk` 改走 dump_pull 同机制 |
| dump 管线 | `dump_start`/`dump_status`/`dump_pull` | 设备端按文件布局落盘（含 e_shoff/e_shnum/e_shstrndx 清洗与 manifest）→ 按需压缩分块拉取，offset 续传 |
| 会话反汇编 | `disassemble`（可选） | capstone on device，读本地内存直接出文本，替代主机按窗口拉字节 |

语义单一真相源随实现移到设备端 + PROTOCOL.md；`tests/mock_agent.py` 同步实现
全部新 op，继续充当参考实现与回归基座；interop 按新能力位扩展为条件验收
（能力不齐只跑对应子集）。

### 11.5 里程碑（v3）

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| M0 | 定版并提交 v1.1（扫描扩展 + write_txn，代码已在 TanyaoCli 工作区） | 双仓 git 干净；interop/单测/MCP 回归全绿；PROTOCOL.md 并入 v1.1 |
| M1 | 协议 v1.2：二进制帧 + symbol_batch + strings_scan；host MCP 工具按能力位选引擎 | libc 1483 符号 list <2s（对照 33s）；回归全绿 |
| M2 | dump 落盘管线 + dump_pull 压缩续传 + apk_info 下沉 | 1MB 模块镜像过网 ≤0.6MB 且仅显式发起；apk_info 零镜像过网 |
| M3 | 内核 PFNMAP 排除（vvar/vdso 类不再可读上报） | 设备端 3.21GB 首扫分钟级以内、零 skipped、账目精确 |
| M4 | TanyaoMB 以 loopback 客户端接入 agent（设备端 GUI 层） | UI 功能全流程不产生对 PC 流量 |

### 11.6 内核侧配套（小幅、可选、独立验证）

- **PFNMAP VMA 排除**（M3）：TARGET_MAPS 不再上报 vvar/vdso 类 PFNMAP 映射为
  可读匿名段——`skipped` 概念整体消失，引擎无需死区预算；改动收敛在
  `src/process.c`/`proc.c` 上报过滤，按 VALIDATION_LOG §6 规则重跑 full probe。
- 远期可选（非承诺）：内核态扫描原语（range+pattern ioctl，内核内存速度）。
  仅当 agent 用户态扫描实测不足时再评估；默认不做，避免把业务逻辑推进内核。

### 11.7 风险与对策

1. **agent 复杂度上升**（纯转发器 → 分析引擎）：扫描/符号/dump 均单 job 串行 +
   能力位协商；扫描线程低优先级（nice/SCHED_IDLE）+ 分块 pacing，避免与游戏抢
   CPU/IO；断连自动 cancel 既有语义沿用。
2. **双引擎语义漂移**（设备 vs mock）：匹配语义（对齐、epsilon、carry、死区二分）
   在 PROTOCOL.md 钉死 + mock 金样本回归；主机引擎冻结后不再双头演化。
3. **命中集过大**：MAX_HITS=200000 既有上限之上，设备侧先做 refine/过滤再回传，
   `scan_results` 分页不变。
4. **设备落盘占用**：dump 文件落 `/data/local/tmp`，dump_status 暴露大小，host
   在 Ghidra 导入完成后显式 cleanup；agent 不做静默清理（可审计）。
5. **Ghidra 仍是批量例外**：文档明示"深度反编译前会拉取一次压缩镜像"，这是
   接受的物理事实；会话内分析路径（符号/字符串/反汇编/扫描/指针链）不受影响。
6. **冷页换入成本不因下沉消失**（v2 实测 350s 慢段为 page-in）：本地换入走
   UFS 速率而非网络速率，量级改善；扫描 pacing 参数留可调。

### 11.8 设计文档分发（2026-09-04）

v3 详细设计已按项目下发，实现以各项目文档为准，本文保留方向与决策记录：

| 项目 | 文档 | 覆盖内容 |
| --- | --- | --- |
| tanyao-host | `docs/PROTOCOL_V1.2_DRAFT.md` | v1.2 协议草案（双端唯一 wire 依据：能力位、二进制帧、cmd 61–68） |
| tanyao-host | `docs/DESIGN_V3_HOST.md` | 智能层：引擎分派、dump 管线客户端、mock 参考、验收指标 |
| TanyaoCli | `docs/DESIGN_V3_AGENT.md` | 设备端分析引擎：v1.1 定版入库、RegionReader 抽取、61–68 实现、capstone |
| TanyaoKernel | `docs/DESIGN_V3_KERNEL.md` | TARGET_MAPS 排除 PFNMAP（唯一变更点）、验证纪律、明确不做清单 |
| TanyaoMB | `docs/DESIGN_V3_MB.md` | 设备端 GUI 层：loopback 独立 agent 实例、只读功能面、工程治理 |

里程碑主线：M0（v1.1 定版入库）→ M1（二进制帧+符号+strings）→
M2（dump 管线+apk 下沉）→ M3（内核 PFNMAP 排除）→ M4（MB loopback 接入）。
