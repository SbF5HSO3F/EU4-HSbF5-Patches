# -*- coding: utf-8 -*-
"""在存档里定位【统治者/继承人】块，看它们的 culture 到底是什么。

为什么要看统治者而不是省份：BuildFullName_Impl（P4/P7 站点所在）在
「君主 / 继承人 / 顾问」的姓名生成链路上被调用；省份的 culture 不生成人名。
如果某个文化只有省份在用、没有任何统治者/顾问用它，那么日志里就永远不会出现
这个文化的 P4 行 —— 那不是补丁失效，而是这个文化根本没有名字要生成。

本脚本只读。
"""
import io
import re
import sys

SAVE = (sys.argv[1] if len(sys.argv) > 1 else
        r"%EU4_USER_DIR%"
        r"\save games\autosave.eu4")


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    d = io.open(SAVE, "rb").read()
    out.write("save %s (%d bytes)\n\n" % (SAVE, len(d)))

    # 存档里 "monarch={...}" / "heir={...}" 块，以及 country 引用
    for kind in (b"monarch", b"heir"):
        pat = re.compile(kind + rb'\s*=\s*\{')
        n = 0
        cults = {}
        samples = []
        for m in pat.finditer(d):
            # 块内找 culture= ；块长度取 3000 字节内
            seg = d[m.start():m.start() + 3000]
            # 该块的结束用第一个 "}" 之后一段；粗暴取 culture= 第一次出现即可
            cm = re.search(rb'culture="?([a-z_0-9]+)"?', seg)
            dm = re.search(rb'dynasty="', seg)
            n += 1
            c = cm.group(1).decode() if cm else "(no culture field)"
            cults[c] = cults.get(c, 0) + 1
            if len(samples) < 6:
                # 抓 name= 的 UTF-16LE 值
                nm = re.search(rb'name="', seg)
                val = ""
                if nm:
                    pos = m.start() + nm.end()
                    buf = bytearray()
                    j = pos
                    while j + 1 < len(d) and len(buf) < 120:
                        if d[j] == 0x22 and d[j + 1] == 0x00:
                            break
                        buf += bytes((d[j], d[j + 1]))
                        j += 2
                    val = buf.decode("utf-16-le", errors="replace")
                samples.append((c, val, bool(dm)))
        out.write("== %s blocks: %d ==\n" % (kind.decode(), n))
        for c, k in sorted(cults.items(), key=lambda x: -x[1])[:20]:
            out.write("   culture=%-22s %d\n" % (c, k))
        out.write("   samples (culture, name, has_dynasty):\n")
        for s in samples:
            out.write("     %s\n" % (s,))
        out.write("\n")

    # 统治者文化里有没有 shandong_culture？
    out.write("== 含 shandong_culture 的 monarch/heir 块数 ==\n")
    for kind in (b"monarch", b"heir"):
        pat = re.compile(kind + rb'\s*=\s*\{')
        cnt = 0
        for m in pat.finditer(d):
            seg = d[m.start():m.start() + 3000]
            cm = re.search(rb'culture="?([a-z_0-9]+)"?', seg)
            if cm and cm.group(1) == b"shandong_culture":
                cnt += 1
        out.write("   %s: %d\n" % (kind.decode(), cnt))

    # 顾问块（给个对照）
    out.write("\n== advisor 块总数 ==\n")
    n = len(re.findall(rb'advisor\s*=\s*\{', d))
    out.write("   advisor blocks: %d\n" % n)
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
