# -*- coding: utf-8 -*-
"""统计模组/游戏数据里 $MONARCHNAME$ 与 $FULLMONARCHNAME$ 的使用。

为什么查这个：
  eu4.exe 里 0x1402E9AB0 往"国家文本参数块"里塞了两个不同的名字段——
      MONARCHNAME       ← 直接读 CMonarch+0x28 字段，**只有名**
      FULLMONARCHNAME   ← 调 CMonarch_GetFullName，**名 + 王朝名**
  朴丁 P8 只挂在 CMonarch_GetFullName 上 ⇒ 只有用 $FULLMONARCHNAME$ 的文本
  才会被处理。用 $MONARCHNAME$ 的文本连姓都不显示。

  所以"某个界面里姓前名后没生效"到底是哪种，看它用什么键就知道。
本脚本只读。
"""
import io
import os
import re
import sys
from collections import Counter, defaultdict

ROOTS = [
    r"%EU4_USER_DIR%\mod",
    r"%EU4_GAME_DIR%",
]

PAT = re.compile(r"\$(FULL)?MONARCHNAME\$")
EXTS = (".yml", ".txt", ".csv")


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    hits = Counter()
    files = defaultdict(list)
    scanned = 0

    for root in ROOTS:
        if not os.path.isdir(root):
            out.write("(skip, not found) %s\n" % root)
            continue
        for dp, dn, fn in os.walk(root):
            for f in fn:
                if not f.lower().endswith(EXTS):
                    continue
                p = os.path.join(dp, f)
                try:
                    s = io.open(p, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                scanned += 1
                for m in PAT.finditer(s):
                    k = "$FULLMONARCHNAME$" if m.group(1) else "$MONARCHNAME$"
                    hits[k] += 1
                    if len(files[k]) < 12:
                        files[k].append(p)

    out.write("扫描文件数: %d\n\n" % scanned)
    if not hits:
        out.write("两个键都没有被任何数据文件使用。\n")
        out.write("⇒ 说明这两个键只被游戏内硬编码文本使用（或只在硬编码本地化里）。\n")
    for k, v in hits.most_common():
        out.write("%-20s %d 处\n" % (k, v))
        for p in files[k]:
            out.write("     %s\n" % p)
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
