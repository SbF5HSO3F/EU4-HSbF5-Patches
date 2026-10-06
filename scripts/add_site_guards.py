# -*- coding: utf-8 -*-
"""把 9 个 handler 的业务调用包进 SEH 守卫（一次性，2026-10-05）。

每个 handler 形如：

    static void mnp_h_xxx(mnp::reg_pack &r)
    {
        stat_bump(ST_XXX);
        <业务调用…>
    }

改成：

    static void mnp_h_xxx(mnp::reg_pack &r)
    {
        stat_bump(ST_XXX);
        MNP_SITE_GUARD_BEGIN
        <业务调用…>
        MNP_SITE_GUARD_END("站点名")
    }

★ 守卫包住的只是**业务调用**；`stat_bump` 留在外面（它绝不会抛异常）。
★ 泛型 handler 本脚本不处理（见下方 GENERIC_SKIP），那些函数体很长，
   由人工单独加，避免脚本误伤。

先备份为 monarchnamefix.cpp.bak5。
"""
import io
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

# 站点函数名 -> 日志里显示的站点名（与 kSites 显示名一致）
SITES = {
    "mnp_h_modfix_pick_idx":    "modfix/pick_idx",
    "mnp_h_modfix_pick_cult":   "modfix/pick_cult",
    "mnp_h_modfix_pick_modidx": "modfix/pick_modidx",
    "mnp_h_gen_entry_culture":  "gen/entry_culture",
    "mnp_h_gen_loop_decide":    "gen/loop_decide",
    "mnp_h_gen_surn_len":       "gen/surn_len",
    "mnp_h_gen_reorder":        "gen/reorder",
    "mnp_h_gen_exit_fallback":  "gen/exit_fallback",
    "mnp_h_disp_ruler_name":    "disp/ruler_name",
}

# 这些 handler 函数体太长/多语句，脚本不碰，由人工处理
GENERIC_SKIP = {"mnp_h_gen_reorder", "mnp_h_disp_ruler_name"}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(SRC, encoding="utf-8").read()
    shutil.copyfile(SRC, SRC + ".bak5")
    n = 0
    for fn, site in SITES.items():
        if fn in GENERIC_SKIP:
            print("  [skip] %s（人工处理）" % fn)
            continue
        # 匹配：函数头 { \n  stat_bump(...);\n  之后到函数末尾的单个 '}' 行
        pat = re.compile(
            r"(static void " + re.escape(fn) + r"\(mnp::reg_pack &r\)\s*\n"
            r"\{\s*\n"
            r"\s*stat_bump\([A-Z_]+\);[^\n]*\n)"      # 组1：函数头 + stat_bump
            r"(.*?)"                                   # 组2：业务体
            r"\n\}\n",                                 # 函数收尾
            re.S)
        m = pat.search(s)
        if not m:
            print("  [x] 未匹配: %s" % fn)
            continue
        body = m.group(2)
        # 业务体按行加缩进保持不变，只是前后插守卫
        rep = (m.group(1) +
               "    MNP_SITE_GUARD_BEGIN\n" +
               body + "\n" +
               "    MNP_SITE_GUARD_END(\"" + site + "\")\n}\n")
        s = s[:m.start()] + rep + s[m.end():]
        n += 1
    io.open(SRC, "w", encoding="utf-8", newline="").write(s)
    print("  已加守卫 %d 处（原文件备份为 monarchnamefix.cpp.bak5）" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
