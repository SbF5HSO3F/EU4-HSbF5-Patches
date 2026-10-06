# -*- coding: utf-8 -*-
"""按【精确行区间】删除 monarchnamefix.cpp 里的历史残留代码。

这些残留是"机械拼字节 / 机械重放"时代的产物，已被新钩子层取代：
  - sig_t / sig_parse / sig_scan       -> bytepattern.hpp 的 Pattern
  - patch_t / g_patches[] / stubP*     -> install.cpp 的 kSites[]
  - alloc_near / prepare_one / hook_one -> hooks.hpp
  - buildP*dll / buildP6               -> stubs.asm 的 trampoline
  - p7_prepend_dynasty / p7_reorder_at_exit / p10_reorder_if_sf / p5_transform
                                       -> 已废弃方案，无调用者

★ 安全机制：每个待删区间都会先扫描【必须保留的顶层定义】。一旦发现
  区间里混进了要保留的函数（这是实际踩过的坑：pe_info、cult_name_capture、
  p6_capture_culture 都被误删过），立刻拒绝执行并列出冲突行号。

用法： python scripts\\strip_legacy.py            # 只报告
       python scripts\\strip_legacy.py --apply    # 真正删除
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

# (起始行, 结束行, 说明) —— 1-based，含两端
CUTS = [
    (2414, 2568, "prepare_one + hook_one（被 hooks.hpp::install_hook 取代）"),
    (2400, 2412, "slot_t（含注释；被 hooks.hpp 的槽管理取代）"),
    (2335, 2370, "alloc_near（被 hooks.hpp::alloc_near_module 取代）"),
    (2333, 2333, "NPATCH 宏"),
    (2153, 2331, "g_patches[] 旧补丁表（被 install.cpp::kSites[] 取代）"),
    (2116, 2151, "stubP1/P2/P3 静态桩字节数组"),
    (1734, 1771, "buildP6 桩构造器"),
    (1408, 1647, "p5_transform + buildP4dll..buildP10blankdll（被 stubs.asm 取代）"),
    (1083, 1183, "p10_reorder_if_sf（废弃的 P10 方案）"),
    (474,  613,  "p7_prepend_dynasty / p7_reorder_at_exit（废弃的 P7 方案）"),
    (223,  243,  "「补丁描述」注释块 + patch_t 结构"),
    (187,  221,  "sig_parse + sig_scan（被 bytepattern.hpp 取代）"),
    (171,  177,  "SIG_MAX + sig_t 类型"),
]

# 出现在任何待删区间里就说明区间划错了 —— 这些都是【仍在使用的业务逻辑】
KEEP = [
    "pe_info", "cult_name_capture", "p6_capture_culture",
    "cc_init", "cc_scan_dir", "cc_scan_enabled_mods", "cc_handle_file",
    "derive_game_root", "derive_user_dir", "dlc_load_open", "mod_read_path",
    "do_fix", "DllMain", "newhook_", "mnp_h_",
    "p4_transform", "p8_monarch_reorder", "p10_save_surlen", "p11_reorder",
    "p7_prepend_if_sf", "p4_dump_allow", "p4_dump_one",
    "w_join", "w_len", "file_read_all", "cc_lazy_ready",
    "dll_region_ok", "dll_read", "dll_read_bytes", "log_bytes",
]


def find_definitions(lines, a, b):
    """在 [a,b] 区间内找出【顶层定义】的名字。

    ★ 只认行首、非缩进的函数/变量定义 —— 不能只按字符串出现判断：
      被删的 buildP4dll 里就写着 `&p4_transform`（引用），
      那是"引用要保留的函数"，属于正常情况，删掉它引用也就没了。
    """
    pat = re.compile(r'^(?:static\s+)?(?:[A-Za-z_][\w:<>,\*&\s]*?[\s\*&])?([A-Za-z_]\w*)\s*\(')
    out = []
    for i in range(a - 1, b):
        l = lines[i]
        if not l or l[0] in ' \t/#':        # 缩进、空行、注释、预处理 都跳过
            continue
        m = pat.match(l)
        if m:
            out.append((i + 1, m.group(1), l.strip()[:78]))
    return out


def main():
    apply = "--apply" in sys.argv
    text = io.open(CPP, encoding="utf-8", newline="").read()
    lines = text.split("\n")
    before = len(lines)
    total = 0

    print("目标: %s" % CPP)
    print("原始行数: %d\n" % before)

    keep_set = set(KEEP)
    bad = False
    for a, b, why in CUTS:
        if a < 1 or b > before or a > b:
            print("  [!! 越界] %d..%d  %s" % (a, b, why))
            bad = True
            continue

        defs = find_definitions(lines, a, b)
        clashes = [d for d in defs if d[1] in keep_set]
        total += b - a + 1

        tag = "冲突" if clashes else "删除"
        print("  [%s] %5d..%-5d (%4d 行)  %s" % (tag, a, b, b - a + 1, why))
        print("         区间内顶层定义: %s" % (", ".join(d[1] for d in defs) or "（无）"))
        if clashes:
            bad = True
            for ln, name, txt in clashes:
                print("         ⚠ 需保留的 `%s` -> 第 %d 行: %s" % (name, ln, txt))

    print("\n合计删除 %d 行，剩余约 %d 行" % (total, before - total))

    if bad:
        print("\n[x] 区间划分有问题，未做任何修改")
        return 1

    if not apply:
        print("\n(这是 dry-run；加 --apply 才真正删除)")
        return 0

    for a, b, why in sorted(CUTS, key=lambda x: -x[0]):
        del lines[a - 1:b]

    io.open(CPP, "w", encoding="utf-8", newline="").write("\n".join(lines))
    print("\n[ok] 已写回，剩余 %d 行" % len(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
