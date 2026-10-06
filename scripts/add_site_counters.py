# -*- coding: utf-8 -*-
"""给 9 个 handler 的开头插入站点计数（一次性，2026-10-05）。

目的：长时间稳定性测试时，心跳与退出统计要能回答
      "崩溃/卡死之前，最后在跑哪个站点、各站点各被调用了多少次"。

做法：在每个 `static void mnp_h_<站点>(mnp::reg_pack &r)` 的 `{` 之后插入
      `stat_bump(ST_xxx);`。这是纯增量，不改任何现有逻辑。

先备份为 monarchnamefix.cpp.bak4。
"""
import io
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

# 站点函数名 -> 计数器枚举
MAP = {
    "mnp_h_modfix_pick_idx":     "ST_MODFIX_IDX",
    "mnp_h_modfix_pick_cult":    "ST_MODFIX_CULT",
    "mnp_h_modfix_pick_modidx":  "ST_MODFIX_MODIDX",
    "mnp_h_gen_entry_culture":   "ST_GEN_ENTRY",
    "mnp_h_gen_loop_decide":     "ST_GEN_DECIDE",
    "mnp_h_gen_surn_len":        "ST_GEN_SURNLEN",
    "mnp_h_gen_reorder":         "ST_GEN_REORDER",
    "mnp_h_gen_exit_fallback":   "ST_GEN_EXIT",
    "mnp_h_disp_ruler_name":     "ST_DISP",
}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(SRC, encoding="utf-8").read()
    shutil.copyfile(SRC, SRC + ".bak4")
    n = 0
    for fn, st in MAP.items():
        # 匹配函数头 + 紧跟的换行与 '{'
        pat = re.compile(r"(static void " + re.escape(fn) +
                         r"\(mnp::reg_pack &r\)\s*\n\{\n)")
        new = (r"\1    stat_bump(" + st + ");   /* 站点计数：心跳/退出时打印 */\n")
        s2, k = pat.subn(new, s, count=1)
        if k == 0:
            print("  [x] 未匹配: %s" % fn)
        else:
            n += k
        s = s2
    io.open(SRC, "w", encoding="utf-8", newline="").write(s)
    print("  插入 %d 处计数（原文件备份为 monarchnamefix.cpp.bak4）" % n)
    return 0 if n == len(MAP) else 1


if __name__ == "__main__":
    sys.exit(main())
