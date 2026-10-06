# -*- coding: utf-8 -*-
"""在存档里定位指定 tag 的统治者 / 继承人记录，打印其 name= 与 dynasty=。

存档骨架是 ASCII，字符串值是内嵌 UTF-16LE。
只读。
"""
import io
import re
import sys

SAVE = (r"%EU4_USER_DIR%"
        r"\save games\观察者1492_12_04.eu4")


def u16(d, pos, lim=200):
    """从 pos 起按 UTF-16LE 读到 ASCII 的 " 0x22 00 为止。"""
    j = pos
    buf = bytearray()
    while j + 1 < len(d) and len(buf) < lim:
        if d[j] == 0x22 and d[j + 1] == 0x00:
            break
        buf += bytes((d[j], d[j + 1]))
        j += 2
    return buf.decode("utf-16-le", errors="replace")


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "FJF"
    d = io.open(SAVE, "rb").read()
    print("存档 %d 字节, 目标 tag %s" % (len(d), tag))
    print()

    # 该 tag 的统治者通常在形如  monarch={ ... } 或 ruler={ ... } 的块里，
    # 且块内带 country="TAG"。这里以 country="TAG" 为锚，向前后各看一段。
    anchor = ('country="%s"' % tag).encode()
    pat = re.compile(rb'(name|dynasty|monarch_name|heir_name|consort_name)="')
    seen = 0
    i = 0
    while seen < 8:
        j = d.find(anchor, i)
        if j < 0:
            break
        # 向前 400 字节找块类型，向后 1200 字节找字段
        pre = d[max(0, j - 400):j].decode("latin1")
        blk = "?"
        for kw in ("monarch", "ruler", "heir", "consort", "leader", "advisor",
                   "general", "admiral", "explorer", "conquistador"):
            if kw in pre:
                blk = kw
        seg = d[max(0, j - 400):j + 1400]
        base = max(0, j - 400)
        fields = []
        for km in pat.finditer(seg):
            v = u16(d, base + km.end())
            fields.append("%s=%r" % (km.group(1).decode(), v))
        if fields:
            seen += 1
            print("[%d] block~%s" % (seen, blk))
            for f in fields:
                print("     ", f)
        i = j + 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
