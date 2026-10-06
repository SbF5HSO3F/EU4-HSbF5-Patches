# -*- coding: utf-8 -*-
"""把「站点异常守卫」宏块移到日志设施之后（一次性，2026-10-05）。

原因：宏块原本定义在 9 个 handler 之后，而 handler 里要用它 ⇒ C2065 未声明。
      守卫依赖 stat_bump / ST_EXCEPTION / log_stamp / LOGS / log_hex，
      这些都在日志设施段里定义，所以插到 `log_crash_tail(` 之前最合适
      （那里上述符号全部可见，且远在 handler 之前）。

先备份为 monarchnamefix.cpp.bak6。
"""
import io
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

BLOCK_HEAD = "/* ==================================================================== */\n/* 站点异常守卫"
BLOCK_TAIL = "LOGS(\"（已接住，本站点本次放弃）\\r\\n\");"
ANCHOR     = "/* 崩溃/退出收尾：停机 + 冲刷 + 回捞最后若干行。"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(SRC, encoding="utf-8").read()

    a = s.find(BLOCK_HEAD)
    if a < 0:
        print("[x] 找不到守卫块起始")
        return 1
    # 块尾：从 TAIL 往后找到宏的收尾 '}' 及其后的换行
    t = s.find(BLOCK_TAIL, a)
    if t < 0:
        print("[x] 找不到守卫块结尾")
        return 1
    e = s.find("    }", t)          # 宏最后那个 `    }`
    if e < 0:
        print("[x] 找不到宏收尾")
        return 1
    e = s.find("\n", e) + 1

    block = s[a:e]
    rest  = s[:a] + s[e:]

    k = rest.find(ANCHOR)
    if k < 0:
        print("[x] 找不到锚点")
        return 1

    shutil.copyfile(SRC, SRC + ".bak6")
    out = rest[:k] + block + "\n" + rest[k:]
    io.open(SRC, "w", encoding="utf-8", newline="").write(out)
    print("  已把 %d 字节的守卫块移到锚点之前（备份 monarchnamefix.cpp.bak6）" % len(block))
    return 0


if __name__ == "__main__":
    sys.exit(main())
