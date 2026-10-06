# -*- coding: utf-8 -*-
"""解析 disp 现场，逐字段还原 out / 两个字段的字节账。

目的：确定 form2（0xBF 折叠形态）里「名」与「姓」的**真实边界**。
背景：日志显示
    nlen=5 dlen=4 dbf=1 olen=8   din="~..."   sout="....Cg I"
    done: size=8 s="g I....C"
其中 din 有前导 0xBF、而 sout 与输出里都没有 0xBF ⇒
"名在 out 里到底占几字节" 成了唯一未知量，必须算准才能切对。
只读。
"""
import io
import re
import sys

LOG = (sys.argv[1] if len(sys.argv) > 1 else
       r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    L = io.open(LOG, encoding="utf-8", errors="replace").read().split("\n")

    cm = re.compile(
        r"\[d\] disp cm=(\S+) dobj=(\S+) nlen=(\d+) dlen=(\d+) dbf=(\d+) "
        r"olen=(\d+) ocap=(\d+) expect=(\d+) din=\"([^\"]*)\" sout=\"([^\"]*)\"")

    print("%-6s %-40s %s" % ("行号", "字段", "值"))
    print("-" * 100)
    n = 0
    for i, ln in enumerate(L):
        m = cm.search(ln)
        if not m:
            continue
        if m.group(5) == "0":          # 只看 dbf>=1（0xBF 形态）
            continue
        _, _, nlen, dlen, dbf, olen, ocap, exp, din, sout = m.groups()
        nlen, dlen, dbf, olen, exp = (int(x) for x in (nlen, dlen, dbf, olen, exp))
        # 找紧随其后的 done 行
        done = None
        for j in range(i, min(len(L), i + 8)):
            if "disp done" in L[j]:
                done = L[j]
                break
        dm = re.search(r"form=(\d+) size=(\d+) sep_len=(\d+) s=\"([^\"]*)\"", done or "")
        print("L%-5d nlen=%-3d dlen=%-3d dbf=%-2d olen=%-3d expect=%-3d" %
              (i + 1, nlen, dlen, dbf, olen, exp))
        print("       din  = %r  (%d 字符)" % (din, len(din)))
        print("       sout = %r  (%d 字符)" % (sout, len(sout)))
        if dm:
            print("       done : form=%s size=%s sep=%s s=%r (%d 字符)" %
                  (dm.group(1), dm.group(2), dm.group(3), dm.group(4), len(dm.group(4))))
            # 关键推导
            sur = dlen - dbf
            print("       ⇒ sur_len = dlen-dbf = %d" % sur)
            print("       ⇒ 若按【名 = olen-sur_len】 : 名长 %d, 姓起于 out[%d]"
                  % (olen - sur, olen - sur))
            print("       ⇒ 若按【名 = nlen】        : 名长 %d, 姓起于 out[%d]"
                  % (nlen, nlen))
            print("       ⇒ out 前 %d 字节 = %r" % (len(sout), sout))
            # 用 done 的 s 校验两种假设能否把姓还原成 din 的尾部
            s = dm.group(4)
            if len(s) == olen:
                a_name, a_sur = s[:olen - sur], s[olen - sur:]
                b_name, b_sur = s[:nlen], s[nlen:]
                print("       A(名=olen-sur) : 名=%r 姓=%r" % (a_name, a_sur))
                print("       B(名=nlen)     : 名=%r 姓=%r" % (b_name, b_sur))
                print("       din 尾 %d 字节（应≈姓）= %r" % (dlen - dbf, din[dlen - (dlen - dbf):]))
        print()
        n += 1
        if n >= 6:
            break


if __name__ == "__main__":
    main()
