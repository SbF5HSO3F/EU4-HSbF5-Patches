# -*- coding: utf-8 -*-
"""把 kSites[] 的显示名从 "PN 动作名" 改成 "功能组 动作名"（一次性，2026-10-05）。

新显示名用来在日志里标识站点，格式固定：
    "<组>  <动作名>"          组宽 6、动作名宽 13

  组      含义
  ──────  ──────────────────────────────────────────
  modfix  取模缺陷修复（三个站点 = 同一个 bug 的三处）
  gen     生成期姓前名后（BuildFullName_Impl 内五个站点 = 一条流水线）
  disp    显示期统治者姓名（CMonarch_GetFullName）

★ 动作名按字典序 = 流水线执行顺序：
    entry_culture → exit_fallback → loop_decide → reorder → surn_len
  （不追求"按顺序排列"的字面观感；需要顺序时看安装位置，看名字能知道"在哪一步"）
"""
import io
import os
import re
import sys

MAP = [
    ("P1  runmask    PickByRandomIndex prologue (mask 21 bits)",
     "modfix  pick_idx       PickByRandomIndex prologue (mask 21 bits)"),
    ("P2  modulo     PickNameFromCultureLists (unsigned fix)",
     "modfix  pick_cult      PickNameFromCultureLists (unsigned fix)"),
    ("P3  modulo     WeightedNameList_GetByModIndex (unsigned fix)",
     "modfix  pick_modidx    WeightedNameList_GetByModIndex (unsigned fix)"),
    ("P6  culture    BuildFullName_Impl entry (capture culture name)",
     "gen     entry_culture  BuildFullName_Impl entry (capture culture name)"),
    ("P7  decide     BuildFullName_Impl loop prelude (surname-first?)",
     "gen     loop_decide    BuildFullName_Impl loop prelude (surname-first?)"),
    ("P10 surnlen    BuildFullName_Impl (record surname length)",
     "gen     surn_len       BuildFullName_Impl (record surname length)"),
    ("P11 reorder    BuildFullName_Impl (surname + sep + given)",
     "gen     reorder        BuildFullName_Impl (surname + sep + given)"),
    ("P4  fallback   BuildFullName_Impl exit (last-resort reorder)",
     "gen     exit_fallback  BuildFullName_Impl exit (last-resort reorder)"),
    ("P8  display    CMonarch_GetFullName (ruler/heir/consort)",
     "disp    ruler_name     CMonarch_GetFullName (ruler/heir/consort)"),
]

FILES = [
    "src/monarchnamefix/install.cpp",
    "src/monarchnamefix/stubs.hpp",
    "src/monarchnamefix/hookvars.cpp",
    "src/monarchnamefix/monarchnamefix.cpp",
    "scripts/verify_site_order.py",
    "scripts/verify_newhook.py",
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
        for old, new in MAP:
            c = s.count(old)
            if c:
                s = s.replace(old, new)
                tot += c
        if s != orig:
            io.open(p, "w", encoding="utf-8", errors="surrogateescape",
                    newline="").write(s)
        print("  %-46s %d 处" % (rel, tot))


if __name__ == "__main__":
    main()
