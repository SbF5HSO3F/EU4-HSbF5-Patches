# -*- coding: utf-8 -*-
"""对照 dbf=0 / dbf=1 两类现场，检查 nlen/dlen/olen 的关系。

目的：L7844（dbf=1）出现
    nlen=5 dlen=4 olen=8
    名字段 = 10 0B 68 20 49   （1 个字 + 空格 + 'I'）
    姓字段 = BF 11 6A 67      （标记 + 1 个字）
⇒ 若 nlen 真的等于"名在 out 里占的字节数"，则 out 应为 名(5) + 姓(3) = 8 —— 恰好等于 olen。
   但这样的话 form2 的公式 olen == nlen + (dlen - nbf) 也成立，取姓 = out[5..8) = `11 6A 67`，
   名 = out[0..5) = `10 0B 68 20 49`，拼出来 = `11 6A 67 10 0B 68 20 49`（8 字节）。
   而日志里 `disp done size=8 s="h I.jg.."` —— 也是 8 字节！只是我看不出内容。
只读。
"""
import io
import re
import sys

LOG = (sys.argv[1] if len(sys.argv) > 1 else
       r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log")

pat = re.compile(r"disp cm=\S+ dobj=\S+ nlen=(\d+) dlen=(\d+) dbf=(\d+) "
                 r"olen=(\d+) ocap=(\d+) expect=(\d+)")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    L = io.open(LOG, encoding="utf-8", errors="replace").read().split("\n")

    for want in ("0", "1"):
        print("=== dbf=%s 的现场 ===" % want)
        n = 0
        for i, ln in enumerate(L):
            m = pat.search(ln)
            if not m or m.group(3) != want:
                continue
            nlen, dlen, dbf, olen, ocap, exp = (int(m.group(k)) for k in range(1, 7))
            f1 = (olen == nlen + 1 + dlen)
            f2 = (olen == nlen + (dlen - dbf))
            print("  L%-6d nlen=%-3d dlen=%-3d olen=%-3d  form1 %s   form2 %s"
                  % (i + 1, nlen, dlen, olen,
                     "OK" if f1 else "NO", "OK" if f2 else "NO"))
            n += 1
            if n >= 8:
                break
        print()

    # 把 L7844 那类现场的 out / done 一起打出来，便于逐字节核对
    print("=== dbf=1 且 form2 命中的现场（前 3 组，含 out 与 done）===")
    n = 0
    for i, ln in enumerate(L):
        m = pat.search(ln)
        if not m or m.group(3) != "1":
            continue
        nlen, dlen, dbf, olen, ocap, exp = (int(m.group(k)) for k in range(1, 7))
        if olen != nlen + (dlen - dbf):
            continue
        for j in range(i, min(len(L), i + 10)):
            s = L[j]
            if any(k in s for k in ("disp 字节", "out  =", "名字段", "姓字段",
                                    "disp done", "无姓可排", "原样保留")):
                print("  %5d| %s" % (j + 1, s[:170]))
        print("  ---")
        n += 1
        if n >= 3:
            break


if __name__ == "__main__":
    main()
