# -*- coding: utf-8 -*-
"""把注释/日志/脚本里的旧 "PN" 文字改成新的功能组名（一次性，2026-10-05）。

★ 这是【第三遍】改名，也是最后一遍：
  ① rename_sites_by_function.py      改符号（mnp_hook_pN_* → mnp_hook_<组>_<动作>）
  ② rename_internal_vars_by_function.py  改内部变量（g_pN_* → g_<组>_*）
  ③ 本脚本                            改剩下的文字（注释 / 日志串 / 测试 / 脚本表）

替换规则（按长度降序，避免 P1 命中 P10/P11 的前缀）：
  "P10" → "gen     surn_len"   等，见 MAP。

⚠️ 只替换【独立出现】的 PN：用 (?<![A-Za-z0-9_])P10(?![0-9]) 这类边界，
   避免伤到 "P10_DUMP_STRIDE" 这种宏名（宏名单独在 MAP2 里改）。
"""
import io
import os
import re
import sys

# 站点显示名：与 install.cpp 的 kSites[] 完全一致，便于日志互相对照
MAP = [
    ("P10", "gen     surn_len"),
    ("P11", "gen     reorder"),
    ("P1",  "modfix  pick_idx"),
    ("P2",  "modfix  pick_cult"),
    ("P3",  "modfix  pick_modidx"),
    ("P4",  "gen     exit_fallback"),
    ("P6",  "gen     entry_culture"),
    ("P7",  "gen     loop_decide"),
    ("P8",  "disp    ruler_name"),
]

# 宏名 / 标识符里的编号（这些不是"独立出现"，上面那条抓不到）
MAP2 = [
    ("P4_DUMP_PER_CULT",  "GEN_EXIT_DUMP_PER_CULT"),
    ("P4_DUMP_STRIDE",    "GEN_EXIT_DUMP_STRIDE"),
    ("P4_DUMP_CULT_MAX",  "GEN_EXIT_DUMP_CULT_MAX"),
]

FILES = [
    "src/monarchnamefix/install.cpp",
    "src/monarchnamefix/stubs.asm",
    "src/monarchnamefix/stubs.hpp",
    "src/monarchnamefix/hookvars.cpp",
    "src/monarchnamefix/monarchnamefix.cpp",
    "src/monarchnamefix/hooks.hpp",
    "src/monarchnamefix/bytepattern.hpp",
    "src/monarchnamefix/nameordertest.cpp",
    "src/monarchnamefix/cultureconfigtest.cpp",
    "scripts/verify_site_order.py",
    "scripts/verify_newhook.py",
    "scripts/verify_patch_targets.py",
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.stdout.reconfigure(encoding="utf-8")
    for rel in FILES:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            print("  [skip] %s" % rel)
            continue
        s = io.open(p, encoding="utf-8", errors="surrogateescape").read()
        orig = s
        tot = 0
        for old, new in MAP2:
            c = s.count(old)
            if c:
                s = s.replace(old, new)
                tot += c
        for old, new in MAP:
            pat = re.compile(r"(?<![A-Za-z0-9_])" + old + r"(?![0-9])")
            s, n = pat.subn(new, s)
            tot += n
        if s != orig:
            io.open(p, "w", encoding="utf-8", errors="surrogateescape",
                    newline="").write(s)
        print("  %-46s %d 处" % (rel, tot))


if __name__ == "__main__":
    main()
