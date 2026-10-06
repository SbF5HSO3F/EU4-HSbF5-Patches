# scripts/

逆向与校验工具。多数是**一次性研究脚本**（按当时的机器与存档写就），
少数是可复用的离线校验器与 IDB 辅助工具。

下表说明由**各脚本自身的注释/文档**自动提取，未逐个人工修订。

## 环境变量

脚本里的路径写成占位符（`%EU4_GAME_DIR%` 等），**不会自动展开**。运行前请设置：

| 变量 | 含义 |
|---|---|
| `EU4_REPO_ROOT` | 本仓库根目录 |
| `EU4_GAME_DIR` | 游戏安装目录（含 `eu4.exe`） |
| `EU4_USER_DIR` | 用户数据目录（存档、mod），默认 `%USERPROFILE%\Documents\Paradox Interactive\Europa Universalis IV` |
| `VCVARS64` | MSVC 的 `vcvars64.bat`（用于构建源码） |

一键设置当前 PowerShell 会话（会自动推断仓库根、用户目录，并用 `vswhere` 找 `vcvars64.bat`）：

```powershell
. .\scripts\set-env.ps1
. .\scripts\set-env.ps1 -GameDir "D:\Steam\steamapps\common\Europa Universalis IV"
```

## 脚本索引

| 脚本 | 说明 |
|---|---|
| `_list_dyn_names.py` | 列出 wu / jianghuai 两个文化的 dynasty_names（逐条，含长度）。 |
| `add_site_counters.py` | 给 9 个 handler 的开头插入站点计数（一次性，2026-10-05）。 |
| `add_site_guards.py` | 把 9 个 handler 的业务调用包进 SEH 守卫（一次性，2026-10-05）。 |
| `analyze_crash_1004.py` | 针对 2026-10-05 10:04 那次崩溃的专项分析。 |
| `analyze_disp_form2.py` | 解析 disp 现场，逐字段还原 out / 两个字段的字节账。 |
| `analyze_disp_hex.py` | 把 disp 的 hex 现场逐字节对上，确定「真实串」在 out 里的起点与组成。 |
| `analyze_marker_scene.py` | 对照 dbf=0 / dbf=1 两类现场，检查 nlen/dlen/olen 的关系。 |
| `analyze_mnp_log.py` | 分析 MonarchNameFix.log —— 汇总探针、找 shandong_culture 的踪迹。 |
| `analyze_p11_p8.py` | 统计 P11（生成期重排）的成败分布，以及 P8 的 +0x120 回退内容。 |
| `analyze_p11.py` | 统计 MonarchNameFix.log 里 P11 的余量与形态分布，找潜在越界风险。 |
| `decode_eu4_name_encoding.py` | EU4 特殊双字节编码的解码器（依 bruceCzK 的 specialEscape 方案反推）。 |
| `deploy.ps1` | MonarchNameFix 部署 / 卸载 / 状态检查 |
| `dump_check_stack.py` | 检查 minidump 里是否包含崩溃线程的栈内存，并列出所有线程的栈范围。 |
| `dump_mem.py` | 从 minidump 里读任意虚拟地址的内存，并 dump 栈上的返回地址。 |
| `dump_monarch_fields.py` | 核对 CMonarch 的 name / dynasty 两个字段在存档里的位置。 |
| `dump_stack.py` | 更严谨地解析 EU4 minidump 的崩溃线程栈，还原调用链。 |
| `encode_eu4_special.py` | EU4 特殊编码的**正向**转码器（specialEscape）—— 回答一个二元问题。 |
| `find_ruler_culture_in_save.py` | 在存档里定位【统治者/继承人】块，看它们的 culture 到底是什么。 |
| `find_ruler.py` | 在存档里定位指定 tag 的统治者 / 继承人记录，打印其 name= 与 dynasty=。 |
| `find_save_culture_usage.py` | 从存档里找出 shandong_culture 的【真实用途】，以及它对应的国家。 |
| `fix_duplicate_0h.py` | 修正 交接-按文化决定姓名顺序.md 里 §0-H 的重复编号。 |
| `fix_log_tags_after_rename.py` | 修正上一遍留下的问题：日志串里不该出现"带对齐空格的显示名"（一次性）。 |
| `ida_dump_bytes.py` | (无自述注释) |
| `ida_scan_r12.py` | 在 EffectImpl_CreateGeneral (create_general) 内扫描 r12 的所有写入与使用，确认 r12 在 |
| `list_name_key_users.py` | 列出使用 $MONARCHNAME$ / $FULLMONARCHNAME$ 的具体本地化键。 |
| `move_guard_block.py` | 把「站点异常守卫」宏块移到日志设施之后（一次性，2026-10-05）。 |
| `parse_dump.py` | 解析 EU4 崩溃的 minidump：取异常记录 + 寄存器上下文，并尝试手工走栈。 |
| `remove_regent_guards.py` | 撤掉「摄政期 / 空位期 ⇒ 不重排」的两道守卫（用户要求，2026-10-06）。 |
| `rename_internal_vars_by_function.py` | 内部变量按功能组重命名（一次性，2026-10-05）。 |
| `rename_patch_symbols.py` | 把补丁站点的符号名从 `p1/p2/...` 改成带动作名的形式（一次性维护脚本）。 |
| `rename_pn_references.py` | 把注释/日志/脚本里的旧 "PN" 文字改成新的功能组名（一次性，2026-10-05）。 |
| `rename_site_display_names.py` | 把 kSites[] 的显示名从 "PN 动作名" 改成 "功能组 动作名"（一次性，2026-10-05）。 |
| `rename_sites_by_function.py` | 站点按【功能】重命名（一次性脚本，2026-10-05）。 |
| `reorder_stubs_asm.py` | 把 stubs.asm 里的 trampoline 按【逻辑执行顺序】重排。 |
| `restore_form2_after_encoding_fix.py` | 把 P8 的 form2 从"一律原样返回"改回真正的重排（一次性，2026-10-05）。 |
| `scan_localisation_name_keys.py` | 统计模组/游戏数据里 $MONARCHNAME$ 与 $FULLMONARCHNAME$ 的使用。 |
| `scan_save_cultures.py` | 扫描存档里【实际存在的国家文化】，用来解释"为什么某个文化从不出现在日志里"。 |
| `scan_save.py` | 从国家 tag 入手分析存档：找 SDA / FJF 的文化与统治者名字。 |
| `set-env.ps1` | 设置本仓库脚本所需的环境变量（当前会话）。用法： . .\scripts\set-env.ps1 |
| `splice_newlogblock.py` | 把新的日志基础设施整块换进 monarchnamefix.cpp（一次性，2026-10-05）。 |
| `stat_monarch_dynasty_fields.py` | 统计：存档里的 monarch 块，name / dynasty 两个字段的并存情况。 |
| `stats_form2_size.py` | 统计 form2（带标记）现场的 size 与 nlen+sur_len 是否一致。 |
| `strip_dead_switches.py` | 删除因旧补丁表移除而失去用途的诊断开关。 |
| `strip_legacy.py` | 按【精确行区间】删除 monarchnamefix.cpp 里的历史残留代码。 |
| `strip_nameorder_builders.py` | 删除 nameorder.h 里的 buildP* 桩构造器（"机械拼字节"时代的遗产）。 |
| `verify_bf_lead_byte.py` | 穷举验证两件事（回答"会不会有字的码以 0xBF 开头"）： |
| `verify_culture_offsets.py` | verify_culture_offsets.py — 静态核对 CCulture 的字段偏移常量与反汇编证据一致。 |
| `verify_monarch_name_composition.py` | 逐字节确认 CMonarch 里存的是【name + dynasty 两个字段】还是【拼好的全名】。 |
| `verify_nameorder_stub.py` | verify_nameorder_stub.py — 逐条核对 P4/P5 动态桩的机器码语义（纯静态、确定性）。 |
| `verify_nameorder_target.py` | verify_nameorder_target.py — 把 monarchnamefix.cpp 里的整张补丁表逐条对着 eu4.exe 校验 |
| `verify_newhook.py` | 验证 install.cpp 里那 6 个站点的模式 + RVA 筛选能否唯一定位。 |
| `verify_patch_targets.py` | MonarchNameFix 补丁目标离线校验器 |
| `verify_site_order.py` | 校验五个文件里的站点排列顺序是否一致。 |
| `verify_trampoline_stack.py` | 校验 stubs.asm 里 MNP_ENTER / MNP_EXIT 的栈平衡。 |
| `watch_crash.py` | 崩溃监控：盯着 EU4 的 crashes 目录与 MonarchNameFix.log，一有新崩溃就产出定位报告。 |

## 关于校验类脚本

`verify_*.py` 是**离线静态校验**：不启动游戏、不修改任何文件，
只在补丁源码与 `eu4.exe` 之间做交叉核对（签名命中 RVA、站点原字节、回跳点等）。
