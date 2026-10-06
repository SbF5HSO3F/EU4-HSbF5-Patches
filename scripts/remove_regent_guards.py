# -*- coding: utf-8 -*-
"""撤掉「摄政期 / 空位期 ⇒ 不重排」的两道守卫（用户要求，2026-10-06）。

背景：用户实测确认 **摄政期间姓名本来就是正常显示的**，所以那两道守卫
      拦错了对象（它们会把本来正确的显示改成"不处理"）。
      两道守卫都是同一批推测改动，一起撤。

保留（同一批里**有实质依据**的那项）：王朝对象的完整性校验 —— 它是
      "垃圾字节"的防线，与"摄政是否重排"无关，用户未要求撤。

做法：删掉从 `/* ★★★ 2026-10-06 修复「摄政的姓名被当作王朝」。` 起，
      到空位期守卫结束 `}`（含）为止的整段。
      结束位置用其后紧跟的 `dlen = dobj ?` 行定位（该行必须保留）。

先备份为 monarchnamefix.cpp.bak7。
"""
import io
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

HEAD = "        /* ★★★ 2026-10-06 修复「摄政的姓名被当作王朝」。"
TAIL = "        dlen = dobj ? *(const size_t *)(const void *)((const char *)dobj + 0x18) : 0;"

REPL = """        /* ★ 2026-10-06：此处原本有两道守卫（`cm+0x78` 摄政非空 / `cm+0x07` 空位期
         *   ⇒ 不重排），**已按用户实测结论撤除** ——
         *   用户确认：**摄政期间姓名本来就是正常显示的**，那两道守卫拦错了对象，
         *   只会把本来正确的显示改成"不动手"。
         *
         *   （撤除的是"是否该重排"的推测判据；同一批里的
         *     「王朝对象完整性校验」是"垃圾字节"防线，与此无关，予以保留。） */

"""


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(SRC, encoding="utf-8").read()
    i = s.find(HEAD)
    j = s.find(TAIL)
    if i < 0 or j < 0 or j <= i:
        print("[x] 定位失败: head=%d tail=%d" % (i, j))
        return 1
    old = s[i:j]
    if "摄政期(cm+78=" not in old or "空位期(cm+07=" not in old:
        print("[x] 范围里没找到两道守卫的日志串，拒绝改动")
        return 1
    shutil.copyfile(SRC, SRC + ".bak7")
    s = s[:i] + REPL + s[j:]
    io.open(SRC, "w", encoding="utf-8", newline="").write(s)
    print("  已删除 %d 字节的两道守卫（备份 monarchnamefix.cpp.bak7）" % len(old))
    return 0


if __name__ == "__main__":
    sys.exit(main())
