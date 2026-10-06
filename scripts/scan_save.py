# -*- coding: utf-8 -*-
"""从国家 tag 入手分析存档：找 SDA / FJF 的文化与统治者名字。

存档是二进制（头 EU4t），骨架文本是 ASCII，字符串值内嵌 UTF-16LE。
本脚本只读。
"""
import io
import re
import sys

SAVE = (r"%EU4_USER_DIR%"
        r"\save games\观察者1492_12_04.eu4")
TAGS = ["SDA", "FJF"]


def utf16_at(d, pos):
    """从 pos 起按 UTF-16LE 读到 ASCII 引号 (22 00) 为止。"""
    j = pos
    buf = bytearray()
    while j + 1 < len(d) and len(buf) < 256:
        if d[j] == 0x22 and d[j + 1] == 0x00:
            break
        buf += bytes((d[j], d[j + 1]))
        j += 2
    return buf.decode("utf-16-le", errors="replace"), j


def main():
    d = io.open(SAVE, "rb").read()
    print("存档 %d 字节" % len(d))
    print()

    for tag in TAGS:
        print("=" * 60)
        print("国家 tag %s" % tag)
        print("=" * 60)

        # ① 该国家块里出现的 culture="..."
        #    存档里国家定义形如  TAG={ ... culture="xxx" ... }
        pat_tag = re.compile((r'(\b%s\s*=\s*\{)').encode() % tag.encode())
        blocks = [m.start() for m in pat_tag.finditer(d)]
        print("  形如 %s={ 的块: %d 处" % (tag, len(blocks)))

        # 用 ASCII 正则直接抓该 tag 附近的 culture / religion / government
        for m in pat_tag.finditer(d):
            seg = d[m.start():m.start() + 3000]
            cm = re.search(rb'culture="([a-z_]+)"', seg)
            rm = re.search(rb'religion="([a-z_]+)"', seg)
            gm = re.search(rb'government="([a-z_]+)"', seg)
            if cm:
                print("     culture=%s  religion=%s  government=%s"
                      % (cm.group(1).decode(),
                         rm.group(1).decode() if rm else "?",
                         gm.group(1).decode() if gm else "?"))
                break

        # ② 该 tag 的统治者 / 继承人 / 将领块里的 name= 与 dynasty=
        #    这些块里的字符串是 UTF-16LE，所以先定位 name=" 的 ASCII 骨架
        print("  含该 tag 的记录里出现的 name/dynasty（前 12 组）：")
        n = 0
        for m in re.finditer(re.escape(('country="%s"' % tag).encode()), d):
            seg = d[m.start():m.start() + 1200]
            for km in re.finditer(rb'(name|dynasty|monarch_name|heir_name)="', seg):
                s = m.start() + km.end()
                val, _ = utf16_at(d, s)
                if val and all(0x20 <= ord(c) < 0x3000 or ord(c) > 0x2E80 for c in val):
                    print("     %-14s = %r" % (km.group(1).decode(), val))
                    n += 1
                    if n >= 12:
                        break
            if n >= 12:
                break
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
