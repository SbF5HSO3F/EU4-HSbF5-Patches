# -*- coding: utf-8 -*-
"""分析 MonarchNameFix.log —— 汇总探针、找 shandong_culture 的踪迹。

只读。
"""
import io
import os
import re
import sys
from collections import Counter, defaultdict

LOG = (sys.argv[1] if len(sys.argv) > 1 else
       r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log")


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    d = io.open(LOG, "rb").read()
    txt = d.decode("utf-8", "replace")
    lines = txt.split("\n")
    out.write("log %d bytes / %d lines\n" % (len(d), len(lines)))
    out.write(lines[0] + "\n\n")

    def cnt(pat):
        return len(re.findall(pat, txt))

    out.write("== 探针计数 ==\n")
    for name, pat in [
        ("CULTRAW P6", r"CULTRAW P6:"),
        ("CULTRAW P8", r"CULTRAW P8:"),
        ("CULTRAW 回退", r"P8 cult \u504f\u79fb\u56de\u9000"),
        ("[i] P8 TAG", r"\[i\] P8 TAG"),
        ("[d] P8 cm=", r"\[d\] P8 cm="),
        ("[d] P8 cult", r"\[d\] P8 cult "),
        ("P8 done", r"P8 done"),
        ("P8 形态不符", r"P8 \u5f62\u6001\u4e0d\u7b26"),
        ("P8 提前放手", r"P8 \u63d0\u524d\u653e\u624b"),
        ("偏移回退", r"\u504f\u79fb\u56de\u9000"),
        ("culture HIT", r"culture HIT"),
        ("CULTSEEN", r"CULTSEEN #"),
        ("P7 SET", r"P7 SET"),
        ("P11", r"\[d\] P11 #"),
        ("P4 in", r"\[d\] P4 in"),
    ]:
        out.write("  %-14s %d\n" % (name, cnt(pat)))

    out.write("\n== P8 各条 exit 的原因分布 ==\n")
    reasons = Counter()
    for ln in lines:
        if "P8 cult \u504f\u79fb\u56de\u9000" in ln:
            reasons["偏移回退"] += 1
        elif "P8 \u5f62\u6001\u4e0d\u7b26" in ln:
            reasons["形态不符"] += 1
        elif "P8 \u63d0\u524d\u653e\u624b" in ln:
            reasons["提前放手"] += 1
        elif "P8 done" in ln:
            reasons["done"] += 1
        elif "cm+0x60 = NULL" in ln:
            reasons["cu=NULL"] += 1
    for k, v in reasons.most_common():
        out.write("  %-12s %d\n" % (k, v))

    out.write("\n== P8 见过的 tag 分布（[i] P8 TAG 与 [d] P8 cult 都算）==\n")
    tags = Counter()
    for m in re.finditer(r"P8 cult cu=\S+ tag=(\S+) ", txt):
        tags[m.group(1)] += 1
    for m in re.finditer(r"\[i\] P8 TAG (\S+) ", txt):
        tags[m.group(1)] += 1
    for k, v in tags.most_common(40):
        out.write("  [%s] x%d\n" % (k, v))

    out.write("\n== P8 读到的文化名分布 ==\n")
    cults = Counter()
    for m in re.finditer(r'P8 cult cu=\S+ tag=\S+ name@cu\+48=\S+ len=\d+ name="([^"]*)" ci=(\d+)', txt):
        cults["%s|ci=%s" % (m.group(1), m.group(2))] += 1
    for k, v in cults.most_common(40):
        out.write("  %-34s x%d\n" % (k, v))

    out.write("\n== CULTRAW P6 里 ci 有效的（命中配置）==\n")
    hit = []
    for m in re.finditer(r'CULTRAW P6: n=(\d+) cb=(\d+) ci=(\d+)', txt):
        if m.group(3) != "4294967295":
            hit.append((m.group(1), m.group(3)))
    out.write("  条数 %d: %s\n" % (len(hit), ", ".join("n=%s/ci=%s" % h for h in hit)))

    out.write("\n== 任何含 shandong 的行 ==\n")
    for i, ln in enumerate(lines):
        if "shandong" in ln:
            out.write("  L%d: %s\n" % (i + 1, ln[:200]))

    out.write("\n== [i] P8 TAG 全部 ==\n")
    for i, ln in enumerate(lines):
        if "[i] P8 TAG" in ln:
            out.write("  L%d: %s\n" % (i + 1, ln[:200]))

    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
