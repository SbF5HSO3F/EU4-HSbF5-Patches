# -*- coding: utf-8 -*-
"""统计：存档里的 monarch 块，name / dynasty 两个字段的并存情况。

动机：P8（CMonarch_GetFullName）只对【有王朝对象】的统治者做「姓前名后」。
而实测发现 SDA 的统治者块里**只有 name、没有 dynasty**。
如果中国这批 tag 的统治者普遍没有 dynasty，那"姓"根本不在 CMonarch 里
（它可能完全来自 common\cultures 的 dynasty_names，只在生成期用一次），
⇒ P8 这条路对它们天然无效。

本脚本只读。
"""
import io
import re
import sys
from collections import Counter

SAVE = (sys.argv[1] if len(sys.argv) > 1 else
        r"%EU4_USER_DIR%"
        r"\save games\autosave.eu4")

TARGETS = [b"SDA", b"SDD", b"SDG", b"SDQ", b"MNG", b"QIC", b"LJA", b"JIB"]


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    d = io.open(SAVE, "rb").read()
    out.write("save %s\n\n" % SAVE)

    stat = Counter()
    examples = {}

    for m in re.finditer(rb'monarch\s*=\s*\{', d):
        seg = d[m.start():m.start() + 2000]
        cm = re.search(rb'culture=([a-z_0-9]+)', seg)
        ctm = re.search(rb'country="([A-Z0-9]{3})"', seg)
        has_name = re.search(rb'\bname="', seg) is not None
        has_dyn = re.search(rb'\bdynasty="', seg) is not None
        tag = ctm.group(1) if ctm else b"???"
        cult = cm.group(1) if cm else b"?"

        key = ("name+dyn" if (has_name and has_dyn) else
               "name only" if has_name else
               "dyn only" if has_dyn else "neither")
        stat[key] += 1

        if tag in TARGETS and tag not in examples:
            examples[tag] = (cult.decode(), key)

    out.write("== 全部 monarch 块：字段并存情况 ==\n")
    for k, v in stat.most_common():
        out.write("  %-12s %d\n" % (k, v))
    out.write("\n== 关心的 tag ==\n")
    for t in TARGETS:
        e = examples.get(t)
        out.write("  %-4s %s\n" % (t.decode(),
                                   ("culture=%s  %s" % e) if e else "(无 monarch 块)"))
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
