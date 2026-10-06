# -*- coding: utf-8 -*-
"""统计 form2（带标记）现场的 size 与 nlen+sur_len 是否一致。

若 size == nlen + (dlen - dbf)，说明重排输出长度 = 名长度 + 姓长度，
即"名没有被截断"，标记也被剥掉了 —— 那 form2 的输出在**长度**上是自洽的。
只读。
"""
import io
import re
from collections import Counter

LOG = (r"%EU4_GAME_DIR%"
       r"\plugins\MonarchNameFix.log")

pat = re.compile(r"disp cm=\S+ dobj=\S+ nlen=(\d+) dlen=(\d+) dbf=(\d+) "
                 r"olen=(\d+) ocap=(\d+) expect=(\d+)")


def main():
    L = io.open(LOG, encoding="utf-8", errors="replace").read().split("\n")
    c = Counter()
    for i, ln in enumerate(L):
        m = pat.search(ln)
        if not m:
            continue
        nlen, dlen, dbf, olen, ocap, exp = (int(m.group(k)) for k in range(1, 7))
        if dbf == 0:
            continue
        if olen != nlen + (dlen - dbf):
            continue
        sur = dlen - dbf
        for j in range(i, min(len(L), i + 10)):
            d = re.search(r"disp done form=(\d+) size=(\d+)", L[j])
            if d:
                c[("form" + d.group(1), int(d.group(2)), nlen + sur, olen)] += 1
                break
    print("dbf>=1 且 form2 命中： (form, size, nlen+sur_len, olen) -> 次数")
    print("-" * 62)
    for k, v in c.most_common(12):
        mark = "OK" if k[1] == k[2] else "  << size != nlen+sur_len"
        print("  %-6s size=%-4d nlen+sur=%-4d olen=%-4d  %4d 次  %s"
              % (k[0], k[1], k[2], k[3], v, mark))


if __name__ == "__main__":
    main()
