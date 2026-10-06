# -*- coding: utf-8 -*-
"""统计 P11（生成期重排）的成败分布，以及 P8 的 +0x120 回退内容。

只用你的日志，只读。
"""
import io
import re
import sys
from collections import Counter

LOG = (sys.argv[1] if len(sys.argv) > 1 else
       r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log")


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    txt = io.open(LOG, "rb").read().decode("utf-8", "replace")

    # P11 行：看 size / sur / take / need / cap / sep
    p11 = re.findall(
        r'\[d\] P11 #(\d+) cult="([a-z_0-9]+)" size=(\d+) sur=(\d+) nbf=(\d+) '
        r'deff=(\d+) nlen=(\d+) take=(\d+) folded=(\d+) sep=(\d+) .*? need=(\d+) cap=(\d+)',
        txt)
    out.write("P11 行数: %d\n" % len(p11))
    bycult = Counter()
    sizes = Counter()
    for (idx, cult, size, sur, nbf, deff, nlen, take, folded, sep, need, cap) in p11:
        bycult[cult] += 1
        sizes[int(size)] += 1
    out.write("\n== P11 按文化的次数（前 30）==\n")
    for k, v in bycult.most_common(30):
        out.write("  %-20s %d\n" % (k, v))

    out.write("\n== P11 里 size 的分布（前 20）==\n")
    for k, v in sorted(sizes.items())[:20]:
        out.write("  size=%-4d %d\n" % (k, v))

    # P11 参数一致性：need 是否等于 size（成功重排应相等或 ±sep）
    bad = 0
    for (idx, cult, size, sur, nbf, deff, nlen, take, folded, sep, need, cap) in p11:
        need, size, sep = int(need), int(size), int(sep)
        if not (size - 1 + sep <= need <= size + sep):
            bad += 1
    out.write("\nP11 里 need 与 size 不自洽的行数: %d\n" % bad)

    # P8 偏移回退：+0x120 读到什么
    fb = re.findall(r'P8 cult \u504f\u79fb\u56de\u9000: \+48 len=(\d+) .*?\+120 len=(\d+) ci=(\d+) "([^"]*)"', txt)
    out.write("\n== P8 偏移回退 %d 条，+0x120 的读取结果分布 ==\n" % len(fb))
    c = Counter()
    for (l48, l120, ci2, s) in fb:
        c["+120_len=%s ci=%s" % (l120, ci2)] += 1
    for k, v in c.most_common(20):
        out.write("  %-28s x%d\n" % (k, v))

    # P8 成功重排的文化
    done = re.findall(r'P8 done form=(\d+) size=(\d+) sep_len=(\d+)', txt)
    out.write("\n== P8 done %d 条，form/sep_len 分布 ==\n" % len(done))
    c2 = Counter("%s|sep=%s" % (f, s) for (f, _, s) in done)
    for k, v in c2.most_common():
        out.write("  form|sep=%-8s x%d\n" % (k, v))

    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
