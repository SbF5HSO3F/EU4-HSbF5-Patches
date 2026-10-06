# -*- coding: utf-8 -*-
"""从存档里找出 shandong_culture 的【真实用途】，以及它对应的国家。

问题：配置里 shandong_culture 明明读到了（CFGENTRY #13），但整份日志里
P4/P7（按文化改姓名顺序的那两个站点）从来没有 cult="shandong_culture"。
两种可能：
  ① 这个文化根本没有统治者/继承人/将领/顾问在生成姓名（全是省份文化）；
  ② 生成姓名时 a3+0x48 读出来的名字不是 "shandong_culture"。

本脚本只读，只做 ASCII 骨架上的定位 + 上下文打印。
"""
import io
import re
import sys

SAVE = (sys.argv[1] if len(sys.argv) > 1 else
        r"%EU4_USER_DIR%"
        r"\save games\autosave.eu4")
WANT = sys.argv[2].encode() if len(sys.argv) > 2 else b"shandong_culture"


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    d = io.open(SAVE, "rb").read()
    out.write("save %s (%d bytes)\n\n" % (SAVE, len(d)))

    hits = list(re.finditer(re.escape(WANT), d))
    out.write("occurrences of %s: %d\n\n" % (WANT.decode(), len(hits)))

    # 每一处：往前找最近的 ASCII 键名，判断它是 province 的 culture= 还是别的
    for i, m in enumerate(hits):
        s = max(0, m.start() - 120)
        seg = d[s:m.end() + 40]
        # 提取可打印 ASCII 骨架
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in seg)
        out.write("[%2d] @0x%x  ...%s\n" % (i, m.start(), txt))
    out.write("\n")

    # 关键判据：国家块 TAG={ ... culture=... } 里有没有它
    out.write("== 国家块里 culture=WANT 的？==\n")
    n_country = 0
    for m in re.finditer(rb'\b([A-Z]{3})\s*=\s*\{', d):
        seg = d[m.start():m.start() + 6000]
        cm = re.search(rb'culture="([a-z_0-9]+)"', seg)
        if cm and cm.group(1) == WANT:
            out.write("  TAG %s\n" % m.group(1).decode())
            n_country += 1
    out.write("  国家块数 = %d\n\n" % n_country)

    # 省份块：形如  - culture="xxx" 之类
    out.write("== 上下文里紧跟的键名统计（判断用途）==\n")
    kinds = {}
    for m in hits:
        s = max(0, m.start() - 60)
        seg = d[s:m.start()]
        km = re.findall(rb'([a-z_]{3,20})\s*=\s*"?$', seg)
        k = km[-1].decode() if km else "?"
        kinds[k] = kinds.get(k, 0) + 1
    for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
        out.write("  %-20s %d\n" % (k, v))
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
