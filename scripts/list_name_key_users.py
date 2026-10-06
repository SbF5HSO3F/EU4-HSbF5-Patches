# -*- coding: utf-8 -*-
"""列出使用 $MONARCHNAME$ / $FULLMONARCHNAME$ 的具体本地化键。

用途：确定"玩家在界面上看到的统治者名字"到底用的是哪个键 ——
  $MONARCHNAME$     ⇒ 只有名（字段直读，不经过 CMonarch_GetFullName）
  $FULLMONARCHNAME$ ⇒ 名 + 王朝名（经过 CMonarch_GetFullName，补丁 P8 处理）
本脚本只读。
"""
import io
import os
import re
import sys
from collections import defaultdict

ROOTS = [
    r"%EU4_GAME_DIR%\localisation",
    r"%EU4_USER_DIR%\mod",
]
KEYS = ("$MONARCHNAME$", "$FULLMONARCHNAME$")
LINE = re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*:\s*\d*\s*"(.*)"\s*$')


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    per = defaultdict(lambda: defaultdict(list))

    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            for f in fn:
                if not f.lower().endswith(".yml"):
                    continue
                p = os.path.join(dp, f)
                # 只看英文（避免同一键在 4 种语言里重复出现）
                if "_l_english" not in f and not f.startswith("EU4_l_english"):
                    continue
                try:
                    lines = io.open(p, encoding="utf-8", errors="replace").read().split("\n")
                except Exception:
                    continue
                for ln in lines:
                    if not any(k in ln for k in KEYS):
                        continue
                    m = LINE.match(ln)
                    key = m.group(1) if m else "(未识别行)"
                    for k in KEYS:
                        if k in ln:
                            per[k][key].append(os.path.basename(p))

    for k in KEYS:
        out.write("=" * 70 + "\n%s  共 %d 个不同键\n" % (k, len(per[k])))
        for key in sorted(per[k]):
            out.write("   %-40s  <- %s\n" % (key, ", ".join(sorted(set(per[k][key])))))
        out.write("\n")
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
