# 主机端工程师任务提示词：R9——D21 映射别名标注（resolve_rva candidates）

> 背景：tester 复验发现同模块非镜像段文件空间重叠（lolm 实测
> file_offset=0xc620000 对应 0x7299dbf000 与 0x7299dc3000 双区间）——
> 文件偏移→运行时非单射，resolve_rva 单值返回在此拓扑下可能错选。
> 证据：`/home/tanjin/phone/archive/reprojet-r5/r5/R10_POSTRESTART_REVERIFY.md`。

## 任务：别名检测与 candidates 返回（mapsview + resolve_rva + list_modules）

1. mapsview：同模块非镜像段两两计算文件区间
   `[file_offset, file_offset+size)` 重叠 → 标注 `file_overlap: true` +
   同组 `alias_group: <n>`。
2. resolve_rva：目标偏移落在别名组 → 返回
   `{"candidates":[{runtime, segment{…}}, …]}`（按段序）而非单值；无别名
   → 维持现有单值形状（向后兼容，MCP 描述注明）。list_modules 段表带
   file_overlap/alias_group。
3. mock 用例：别名组双 candidates（含 lolm 六 bias 尾段双 off=0xc620000
   形态）；非别名不回退。真机 DoD：lolm resolve_rva(file_offset=0xc620000
   附近) 返回双 candidates。
4. 单 commit（引用 D21）；协议零改动；单测全绿 + 回归 52/52 保持 →
   WORKSPACE.md §7 回填。
