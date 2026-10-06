# -*- coding: utf-8 -*-
"""扫描存档里【实际存在的国家文化】，用来解释"为什么某个文化从不出现在日志里"。

背景：MonarchNameFix 的 P6/P4 只在游戏为该文化的角色生成姓名时才被调用。
若某文化在存档里没有任何国家使用（也不是任何省份/统治者的文化），
那么它的配置条目虽然被正确读入，日志里却永远不会出现它的 P4/P7 行 ——
这不是"配置没读到"，而是"这个文化根本没有名字要生成"。

本脚本只读。
"""
import collections
import io
import re
import sys

SAVE = sys.argv[1] if len(sys.argv) > 1 else (
    r"%EU4_USER_DIR%"
    r"\save games\autosave.eu4")

# 想特别确认的文化（配置里有、但日志里从没出现过）
WATCH = {"shandong_culture", "sino_miao", "sino_yi", "sino_bai", "tibetan_new",
         "manchu_new", "khalkha", "altaic_new", "korean_new", "kyushuan",
         "sino_japanese", "vietnamese_new", "sino_khmer"}


def main():
    d = io.open(SAVE, "rb").read()
    print("存档 %s (%d 字节)" % (SAVE, len(d)))
    print()

    # 国家定义里的 culture="xxx"（ASCII 骨架 + ASCII 文化名）
    cults = collections.Counter()
    for m in re.finditer(rb'culture="([a-z_0-9]+)"', d):
        cults[m.group(1).decode()] += 1

    print("存档里出现的文化字符串共 %d 种（含省份文化等）" % len(cults))
    print()

    print("== 关注的文化的出现次数 ==")
    for w in sorted(WATCH):
        c = cults.get(w, 0)
        flag = "OK  " if c else "NONE"
        print("  [%s] %-18s %d" % (flag, w, c))
    print()

    # 国家块里的 culture= —— 国家块形如  TAG={ ... }
    print("== 国家块（TAG={...}）里的 culture ==")
    tag_cult = {}
    for m in re.finditer(rb'\b([A-Z]{3})\s*=\s*\{', d):
        tag = m.group(1).decode()
        seg = d[m.start():m.start() + 4000]
        cm = re.search(rb'culture="([a-z_0-9]+)"', seg)
        if cm and tag not in tag_cult:
            tag_cult[tag] = cm.group(1).decode()

    used = collections.Counter(tag_cult.values())
    print("  有 culture 的国家 %d 个，使用 %d 种文化" % (len(tag_cult), len(used)))
    for c, n in used.most_common():
        mark = "  <== 关注" if c in WATCH else ""
        print("    %-18s %3d 国%s" % (c, n, mark))
    if "SDA" in tag_cult:
        print("  SDA 的文化 = %s" % tag_cult["SDA"])
    else:
        print("  SDA 不在国家块里（该 tag 在此存档中不存在/未启用）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
