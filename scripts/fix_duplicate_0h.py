# -*- coding: utf-8 -*-
"""修正 交接-按文化决定姓名顺序.md 里 §0-H 的重复编号。

问题：文档里有两个 0-H：
  · line 1351  ### 0-H. 架构性结论：P7 无法实现"姓前名后"   ← 三级，实际在 §0-G 之下
  · line 1461  ## 0-H. 统治者/继承人/配偶：第二条独立链路     ← 二级
两者连子节编号都重叠（都有 0-H.1 … 0-H.6），引用时会歧义。

修法：把第一个（含其全部子节）改名为 0-G2 系列 —— 它确实是 §0-G 的延续
      （讲的是 P7/P8 第二次失败后的架构性结论）。第二个保持 0-H 不变。

只改第一个区间的行，且只替换行首标题里的编号，不动正文里的其它引用。

用法： python scripts\\fix_duplicate_0h.py [--apply]
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "notes", "交接-按文化决定姓名顺序.md")


def main():
    apply = "--apply" in sys.argv
    lines = io.open(DOC, encoding="utf-8", newline="").read().split("\n")

    # 定位两个 0-H 标题
    first = second = None
    for i, l in enumerate(lines):
        if re.match(r"^#{2,3} 0-H\.\s", l):
            if first is None:
                first = i
            elif second is None:
                second = i
                break
    if first is None or second is None:
        print("[x] 找不到两个 0-H 标题（first=%s second=%s）" % (first, second))
        return 1

    print("第一个 0-H 在第 %d 行: %s" % (first + 1, lines[first][:70]))
    print("第二个 0-H 在第 %d 行: %s" % (second + 1, lines[second][:70]))
    print()

    changed = 0
    for i in range(first, second):          # 只改第一个区间的行
        new = re.sub(r"^(#{2,3} )0-H(\.\d+)?", lambda m: m.group(1) + "0-G2" + (m.group(2) or ""), lines[i])
        if new != lines[i]:
            print("  %5d: %s" % (i + 1, new[:76]))
            lines[i] = new
            changed += 1

    print("\n改动 %d 个标题" % changed)
    if not apply:
        print("(dry-run；加 --apply 才写回)")
        return 0

    io.open(DOC, "w", encoding="utf-8", newline="").write("\n".join(lines))
    print("[ok] 已写回")
    return 0


if __name__ == "__main__":
    sys.exit(main())
