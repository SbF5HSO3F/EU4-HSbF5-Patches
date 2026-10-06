# -*- coding: utf-8 -*-
"""列出 wu / jianghuai 两个文化的 dynasty_names（逐条，含长度）。

目的：验证「3 字姓」是否来自姓名表本身（例如表里混进了地名条目）。
只读。
"""
import io
import re
import sys

P = (r"%EU4_GAME_DIR%"
     r"\common\cultures\00_cultures.txt")
WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(P, encoding="utf-8", errors="replace").read()
    for cult in ("wu", "jianghuai"):
        i = s.find("\n\t%s = {" % cult)
        if i < 0:
            i = s.find("%s = {" % cult)
        if i < 0:
            print("%s 未找到" % cult)
            continue
        j = s.find("dynasty_names", i)
        k = s.find("}", j)
        seg = s[j + len("dynasty_names"):k]
        words = [w for w in WORD.findall(seg)]
        print("=== %s ===" % cult)
        print("  dynasty_names 共 %d 条" % len(words))
        # 按长度分组
        from collections import Counter
        c = Counter(len(w) for w in words)
        print("  长度分布: %s" % ", ".join("%d字:%d条" % (n, c[n]) for n in sorted(c)))
        print("  全部: %s" % " ".join(words))
        print()


if __name__ == "__main__":
    main()
