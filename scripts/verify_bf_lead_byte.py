# -*- coding: utf-8 -*-
"""穷举验证两件事（回答"会不会有字的码以 0xBF 开头"）：

① 编码器结构性结论
   转码器（specialEscape）只有两条分支：
     · cp < 256          ⇒ **原样返回**，编码 = [cp]（1 字节）
     · cp >= 256         ⇒ 编码 = [escape][low][high]，escape ∈ {0x10,0x11,0x12,0x13}
   ⇒ **只有 U+00BF 自己会产出"以 0xBF 开头"的码**（1 字节 0xBF）。
     所有 >=256 的字符首字节必然是 0x10..0x13，不可能是 0xBF。
   ⇒ 所以"码以 0xBF 开头" ⟺ "这个字符就是 ¿" ⟺ 它就是标记。

② 日志实测
   把日志里每个含 0xBF 的现场取出来，看**前一个字节**是什么，
   验证"前一个是 escape" 与 "前一个是空格/串首" 是否已经覆盖全部情形。
只读。
"""
import io
import os
import re
import sys
from collections import Counter

LOG_DEFAULT = (r"%EU4_GAME_DIR%"
               r"\plugins\MonarchNameFix.log")


def exhaustive():
    """穷举所有 Unicode 码点，看哪些字符的编码以 0xBF 开头。"""
    INTERNAL = {0x00, 0x0A, 0x0D, 0x20, 0x22, 0x24, 0x40, 0x5B, 0x5C,
                0x7B, 0x7D, 0x7E, 0x80, 0xA3, 0xA4, 0xA7, 0xBD,
                0x3B, 0x5D, 0x5F, 0x3D, 0x23}

    def enc(cp, low_off=15):
        if cp < 256:
            return [cp]
        low, high = cp & 0xFF, (cp >> 8) & 0xFF
        esc = 0x10
        if high in INTERNAL:
            esc += 2
        if low in INTERNAL:
            esc += 1
        nl, nh = low, high
        if low in INTERNAL:
            nl = (low + low_off) & 0xFF
        if high in INTERNAL:
            nh = (high - 9) & 0xFF
        return [esc, nl, nh]

    lead_bf = []
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        e = enc(cp)
        if e[0] == 0xBF:
            lead_bf.append(cp)
    return lead_bf


def log_scan(path):
    """统计日志里 0xBF 的前一字节分布。"""
    if not os.path.exists(path):
        return None
    L = io.open(path, encoding="utf-8", errors="replace").read().split("\n")
    prev = Counter()
    n = 0
    for i, ln in enumerate(L):
        if "disp 字节" not in ln:
            continue
        # 后面三行：out / 名字段 / 姓字段（hex）
        for k in (1, 2, 3):
            if i + k >= len(L):
                continue
            m = re.search(r"=\s*((?:[0-9A-F]{2}\s*)+)", L[i + k])
            if not m:
                continue
            b = [int(x, 16) for x in m.group(1).split()]
            for j, v in enumerate(b):
                if v == 0xBF:
                    n += 1
                    prev["串首(无前一字节)" if j == 0 else "%02X" % b[j - 1]] += 1
    return n, prev


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("=" * 74)
    print("① 穷举：哪些字符的编码**以 0xBF 开头**？")
    print("=" * 74)
    r = exhaustive()
    print("  共 %d 个：%s" % (len(r), ", ".join("U+%04X(%s)" % (c, chr(c)) for c in r)))
    print()
    print("  ⇒ 只有 U+00BF（¿）自己。原因：cp<256 原样返回 ⇒ 单字节 0xBF；")
    print("     而 cp>=256 的字符首字节恒为 escape(0x10..0x13)，不可能等于 0xBF。")
    print()
    print("  ★ 所以「某个字的码以 0xBF 开头」⟺「那个字就是 ¿」⟺「它就是标记」。")
    print("     不存在「某个汉字恰好以 0xBF 开头」的可能。")
    print()

    print("=" * 74)
    print("② 日志实测：0xBF 的前一字节分布")
    print("=" * 74)
    res = log_scan(LOG_DEFAULT)
    if not res:
        print("  (找不到日志)")
        return
    n, prev = res
    print("  日志里共 %d 个 0xBF，前一字节分布：" % n)
    for k, v in prev.most_common():
        tag = ""
        if k in ("10", "11", "12", "13"):
            tag = "  ← escape ⇒ 字符内部（保留）"
        elif k == "20":
            tag = "  ← 空格 ⇒ 独立标记（删除）"
        elif k == "串首(无前一字节)":
            tag = "  ← 串首 ⇒ 独立标记（删除）"
        else:
            tag = "  ← ★ 既非 escape 也非空格！需要判断"
        print("      前一字节 %-18s %4d 次%s" % (k, v, tag))
    print()


if __name__ == "__main__":
    main()
