# -*- coding: utf-8 -*-
"""内部变量按功能组重命名（一次性，2026-10-05）。

与站点符号同步：站点前缀改了，内部变量也必须改 ——
否则日志/代码里 `g_p8_*` 与站点 `disp_ruler_name` 对不上号，读代码时又要靠猜。

映射：
  g_p8_*   → g_disp_*              （显示期统治者姓名）
  g_p7_*   → g_gen_loop_*          （生成期 · 循环前决定）
  g_p4_*   → g_gen_exit_*          （生成期 · 出口兜底）
  g_p11_*  → g_gen_reorder_*       （生成期 · 拼接后重排）
  g_no_p10 → g_no_surn_len         （已废弃的开关，连同注释一起改）
  g_p8_probe → g_disp_probe        （已在 P8 里删除，这里只清理注释文字）
"""
import io
import os
import sys

MAP = [
    # ---- 显示期（disp）----
    ("g_p8_cultprobe_left",   "g_disp_cultprobe_left"),
    ("g_p8_dump_left",        "g_disp_dump_left"),
    ("g_p8_form2_seen_left",  "g_disp_form2_seen_left"),
    ("g_p8_nosur_seen_left",  "g_disp_nosur_seen_left"),
    ("g_p8_last_tag",         "g_disp_last_tag"),
    ("g_p8_probe",            "g_disp_probe"),
    # ---- 生成期 · 循环前（gen_loop）----
    ("g_p7_calls",            "g_gen_loop_calls"),
    ("g_p7_logged",           "g_gen_loop_logged"),
    ("g_p7_prev_act",         "g_gen_loop_prev_act"),
    ("g_p7_prev_cult",        "g_gen_loop_prev_cult"),
    # ---- 生成期 · 出口（gen_exit）----
    ("g_p4_dump_cult",        "g_gen_exit_dump_cult"),
    ("g_p4_dump_used",        "g_gen_exit_dump_used"),
    ("g_p4_dump_n",           "g_gen_exit_dump_n"),
    ("g_p4_calls",            "g_gen_exit_calls"),
    # ---- 生成期 · 重排（gen_reorder）----
    ("g_p11_calls",           "g_gen_reorder_calls"),
    # ---- 废弃开关 ----
    ("g_no_p10",              "g_no_surn_len"),
]

FILES = [
    "src/monarchnamefix/monarchnamefix.cpp",
    "src/monarchnamefix/hookvars.cpp",
    "src/monarchnamefix/stubs.hpp",
    "src/monarchnamefix/stubs.asm",
    "src/monarchnamefix/install.cpp",
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
