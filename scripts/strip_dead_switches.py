# -*- coding: utf-8 -*-
"""删除因旧补丁表移除而失去用途的诊断开关。

旧开关（.nop1/.nop2/.nop3/.nop4/.noorder/.nop7/.nop10/.only1/.farcave/.oldhook）
都只对 prepare_one / hook_one 那条"逐条挂补丁"的路径有意义 ——
新钩子层是"要么全挂、要么不挂"，没有任何代码再读它们，留着只会误导。

用法： python scripts\\strip_dead_switches.py [--apply]
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

# 这些开关的"文件常量名" —— 找到 lstrcatW(ncp, XXX) 就删掉整组 4 行
DEAD_FILES = [
    "NOP4_FILE_NAME", "NOORDER_FILE_NAME", "NOP1_FILE_NAME", "NOP2_FILE_NAME",
    "NOP3_FILE_NAME", "FARCAVE_FILE_NAME", "ONLY1_FILE_NAME",
]
# 这些全局变量只剩声明，直接删单行
DEAD_VARS = [
    "g_no_p4", "g_no_order", "g_no_p1", "g_no_p2", "g_no_p3",
    "g_only1", "g_far_cave", "g_no_p7", "g_no_p10",
    "g_use_old_hook", "g_p7_active", "g_src_order_active", "g_src_order_half",
]


def main():
    apply = "--apply" in sys.argv
    lines = io.open(CPP, encoding="utf-8", newline="").read().split("\n")
    before = len(lines)
    kill = set()

    # ① 诊断开关块：lstrcatW(ncp, XXX) 那一行 + 前 1 行 + 后 2 行
    for i, l in enumerate(lines):
        for f in DEAD_FILES:
            if ("lstrcatW(ncp, " + f) in l:
                lo = max(0, i - 1)
                hi = min(len(lines) - 1, i + 2)
                print("  块 %s -> 删 %d..%d" % (f, lo + 1, hi + 1))
                for k in range(lo, hi + 1):
                    kill.add(k)

    # ② 只剩声明的全局变量
    for i, l in enumerate(lines):
        m = re.match(r'^static\s+int\s+(\w+)\s*=', l)
        if m and m.group(1) in DEAD_VARS:
            print("  变量 %s -> 删第 %d 行" % (m.group(1), i + 1))
            kill.add(i)
        # 处理 "static int g_p8_probe = 0;static int g_no_p10 = 0;" 这种粘连写法
        for v in DEAD_VARS:
            if re.search(r';\s*static\s+int\s+' + v + r'\s*=', l):
                print("  粘连变量 %s 在第 %d 行（需手工处理）" % (v, i + 1))

    print("\n合计删除 %d 行，剩余约 %d 行" % (len(kill), before - len(kill)))
    if not apply:
        print("(dry-run；加 --apply 才真正删除)")
        return 0

    out = [l for i, l in enumerate(lines) if i not in kill]
    io.open(CPP, "w", encoding="utf-8", newline="").write("\n".join(out))
    print("[ok] 已写回，剩余 %d 行" % len(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
