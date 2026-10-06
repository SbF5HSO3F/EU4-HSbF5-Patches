# -*- coding: utf-8 -*-
"""修正上一遍留下的问题：日志串里不该出现"带对齐空格的显示名"（一次性）。

上一遍 rename_pn_references.py 把注释和**日志字符串**一起替换了，
于是 `LOGS("[d] P8 cm=")` 变成了 `LOGS("[d] disp    ruler_name cm=")` ——
  ① 带 4 个空格，日志难看；
  ② 破坏所有按 "P8"/"disp" 搜日志的分析脚本与既有笔记。

约定（本次定稿）：
  · 注释、kSites[] 的 name 字段 → 用**对齐显示名**（"gen     reorder"），
    因为它同时出现在安装日志的 "[+] newhook: <name> ..." 行里，对齐便于阅读；
  · 日志字符串（LOGS/printf 里） → 用**紧凑标签**（"gen/reorder"），
    便于 grep，也不再依赖 P 编号。
"""
import io
import os
import re
import sys

# 紧凑日志标签
TAG = {
    "modfix  pick_idx":     "modfix/idx",
    "modfix  pick_cult":    "modfix/cult",
    "modfix  pick_modidx":  "modfix/modidx",
    "gen     entry_culture": "gen/entry",
    "gen     loop_decide":  "gen/decide",
    "gen     surn_len":     "gen/len",
    "gen     reorder":      "gen/reorder",
    "gen     exit_fallback": "gen/fallback",
    "disp    ruler_name":   "disp",
}

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
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.stdout.reconfigure(encoding="utf-8")
    for rel in FILES:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            print("  [skip] %s" % rel)
            continue
        lines = io.open(p, encoding="utf-8", errors="surrogateescape").read().split("\n")
        tot = 0
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            # ★ 关键：kSites[] 的 name 字段（形如 `{ "modfix  pick_idx  说明…",`）
            #   必须保留"对齐显示名"格式 —— 它会出现在安装日志
            #   "[+] newhook: <name> site=…" 那一行里，对齐便于人读。
            #   所以这里排除掉所有以 { " 开头的结构体初始化行。
            if stripped.startswith('{ "'):
                continue
            # 只处理真正的日志调用行
            if not ("LOGS(" in ln or "printf(" in ln or "log(" in ln):
                continue
            new = ln
            for disp, tag in TAG.items():
                if disp in new:
                    new = new.replace(disp, tag)
                    tot += 1
            lines[i] = new
        s = "\n".join(lines)
        io.open(p, "w", encoding="utf-8", errors="surrogateescape",
                newline="").write(s)
        print("  %-46s %d 行" % (rel, tot))


if __name__ == "__main__":
    main()
