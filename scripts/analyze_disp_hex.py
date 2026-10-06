# -*- coding: utf-8 -*-
"""把 disp 的 hex 现场逐字节对上，确定「真实串」在 out 里的起点与组成。

现场形如：
  [d] disp 字节 olen=11 nlen=8 dlen=4 dbf=1 ocap=15
        out  = 10 2E 96 10 C1 89 10 F1 6D 20 49 00 00 00 00
        名字段 = 10 C1 89 10 F1 6D 20 49
        姓字段 = BF 10 2E 96
只读。
"""
import io
import re
import sys

LOG = (sys.argv[1] if len(sys.argv) > 1 else
       r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log")


def hx(s):
    return [int(x, 16) for x in s.split()]


def find_sub(hay, needle):
    """返回 needle 在 hay 中所有出现位置"""
    out = []
    n = len(needle)
    for i in range(len(hay) - n + 1):
        if hay[i:i + n] == needle:
            out.append(i)
    return out


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    L = io.open(LOG, encoding="utf-8", errors="replace").read().split("\n")

    print("逐字节分析（只列前 8 组）\n" + "=" * 96)
    n = 0
    for i, ln in enumerate(L):
        if "disp 字节" not in ln:
            continue
        m = re.search(r"olen=(\d+) nlen=(\d+) dlen=(\d+) dbf=(\d+) ocap=(\d+)", ln)
        if not m or i + 3 >= len(L):
            continue
        olen, nlen, dlen, dbf, ocap = (int(x) for x in m.groups())
        mo = re.search(r"out  = ([0-9A-F ]+)", L[i + 1])
        mn = re.search(r"名字段 = ([0-9A-F ]+)", L[i + 2])
        md = re.search(r"姓字段 = ([0-9A-F ]+)", L[i + 3])
        if not (mo and mn and md):
            continue
        out, name, dyn = hx(mo.group(1)), hx(mn.group(1)), hx(md.group(1))

        print("L%-6d olen=%-3d nlen=%-3d dlen=%-3d dbf=%d ocap=%-3d" %
              (i + 1, olen, nlen, dlen, dbf, ocap))
        print("   out  (%2d) = %s" % (len(out), " ".join("%02X" % b for b in out)))
        print("   名字段(%2d) = %s" % (len(name), " ".join("%02X" % b for b in name)))
        print("   姓字段(%2d) = %s" % (len(dyn), " ".join("%02X" % b for b in dyn)))

        # 王朝字段（去掉首字节 0xBF）在 out 里的位置
        d_wo = dyn[1:] if dyn and dyn[0] == 0xBF else dyn
        pos = find_sub(out, d_wo)
        print("   ⇒ 姓字段(去0xBF) 在 out 中的位置: %s  (长度 %d)" % (pos, len(d_wo)))
        for p in pos:
            # 该位置前一个字节
            prev = out[p - 1] if p > 0 else None
            print("        起于 out[%d]，前一字节 = %s%s" %
                  (p, "--" if prev is None else "%02X" % prev,
                   "  ← 是 0xBF" if prev == 0xBF else ""))
        # 名字段在 out 里的位置
        posn = find_sub(out, name)
        print("   ⇒ 名字段 整段 在 out 中的位置: %s" % posn)
        # 名字段去掉尾部 2 字节
        if len(name) > 2:
            posn2 = find_sub(out, name[:-2])
            print("   ⇒ 名字段(去尾2) 在 out 中的位置: %s" % posn2)
        print()
        n += 1
        if n >= 8:
            break


if __name__ == "__main__":
    main()
