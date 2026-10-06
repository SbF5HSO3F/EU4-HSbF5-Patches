# -*- coding: utf-8 -*-
"""统计 MonarchNameFix.log 里 P11 的余量与形态分布，找潜在越界风险。"""
import io
import re
import collections

LOG = r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log"

PAT = re.compile(
    r'P11 #(\d+) cult="([^"]*)" size=(\d+) sur=(\d+) nbf=(\d+) deff=(\d+) '
    r'nlen=(\d+) take=(\d+) folded=(\d+) sep=(\d+) sepb0=(\d+) need=(\d+) cap=(\d+)')


def main():
    recs = []
    for line in io.open(LOG, encoding="utf-8", errors="replace"):
        m = PAT.search(line)
        if m:
            g = m.groups()
            recs.append(dict(n=int(g[0]), cult=g[1], size=int(g[2]), sur=int(g[3]),
                             nbf=int(g[4]), deff=int(g[5]), nlen=int(g[6]), take=int(g[7]),
                             folded=int(g[8]), sep=int(g[9]), need=int(g[11]), cap=int(g[12])))
    print("P11 记录数 = %d" % len(recs))
    if not recs:
        return
    print("编号范围   = #%d .. #%d" % (recs[0]["n"], recs[-1]["n"]))

    margins = [r["cap"] - r["need"] for r in recs]
    print("\n余量 cap-need:  min=%d  max=%d  平均=%.1f" %
          (min(margins), max(margins), sum(margins) / len(margins)))
    print("  余量 = 0（刚好填满）: %d 次" % sum(1 for m in margins if m == 0))
    print("  余量 <= 1           : %d 次" % sum(1 for m in margins if m <= 1))
    print("  余量 <= 2           : %d 次" % sum(1 for m in margins if m <= 2))

    # need 是否恒 <= size（我们的"只许变短"不变式）
    bad = [r for r in recs if r["need"] > r["size"]]
    print("\n★ need > size 的记录（应为 0）: %d 次" % len(bad))
    for r in bad[:5]:
        print("   #%d %s size=%d need=%d" % (r["n"], r["cult"], r["size"], r["need"]))

    fc = collections.Counter(r["folded"] for r in recs)
    print("\nfolded 分布（0=形态A未折叠, 1=形态B已折叠）: %s" % dict(fc))

    bf = [r for r in recs if r["nbf"] > 0]
    print("\n含 0xBF 的记录: %d 次" % len(bf))
    if bf:
        print("  文化: %s" % dict(collections.Counter(r["cult"] for r in bf).most_common(8)))

    print("\nsize 最大 6 条:")
    for r in sorted(recs, key=lambda x: -x["size"])[:6]:
        print("  #%-5d %-14s size=%-3d sur=%-3d deff=%-3d nlen=%-3d need=%-3d cap=%-3d folded=%d" %
              (r["n"], r["cult"], r["size"], r["sur"], r["deff"], r["nlen"],
               r["need"], r["cap"], r["folded"]))

    print("\nsur 最大 6 条（多词姓）:")
    for r in sorted(recs, key=lambda x: -x["sur"])[:6]:
        print("  #%-5d %-14s size=%-3d sur=%-3d deff=%-3d nlen=%-3d need=%-3d cap=%-3d" %
              (r["n"], r["cult"], r["size"], r["sur"], r["deff"], r["nlen"], r["need"], r["cap"]))

    c = collections.Counter(r["cult"] for r in recs)
    print("\n涉及文化 %d 个; 次数 top10: %s" % (len(c), dict(c.most_common(10))))
    print("只出现 1 次的文化: %s" % [k for k, v in c.items() if v == 1][:12])


if __name__ == "__main__":
    main()
