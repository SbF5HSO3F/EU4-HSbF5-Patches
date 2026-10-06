# -*- coding: utf-8 -*-
"""EU4 特殊双字节编码的解码器（依 bruceCzK 的 specialEscape 方案反推）。

编码（每字符 3 字节）：[escape][low][high]
    low,high = UTF-16 code point 的低/高字节
    escape 初值 0x10；若 low/high 命中"内部字符表"则 +1/+2
    另外：命中时 low += 15（lowByteOffset，EU4 1.26+ 为 14） 或 high += -9

本脚本做**逆运算**：给 3 字节，还原成 UTF-16 code point 与字符。
用途：从 MonarchNameFix.log 的 hex 现场里把"某个名字到底是哪几个字"读出来，
      从而判断 P8 的 0xBF 处理是不是把某个字的字节吃掉了。

只读。
"""
import io
import sys

INTERNAL = [
    0x00, 0x0A, 0x0D,
    0x20,
    0x22, 0x24,
    0x40, 0x5B, 0x5C,
    0x7B, 0x7D, 0x7E, 0x80,
    0xA3, 0xA4, 0xA7, 0xBD,
    0x3B,  # ;
    0x5D,  # ]
    0x5F,  # _
    0x3D,  # =
    0x23,  # #
]

LOW_OFFSET = 15
HIGH_OFFSET = -9


def decode3(b0, b1, b2, low_off=LOW_OFFSET):
    """把 [escape][low][high] 解成 (codepoint, char, note)。失败返回 None。"""
    esc = b0
    if esc not in (0x10, 0x11, 0x12, 0x13):
        return None
    low, high = b1, b2
    low_esc = bool(esc & 0x01)      # escapeChr++ 表示 low 被转过
    high_esc = bool(esc & 0x02)     # escapeChr += 2 表示 high 被转过
    note = []
    if low_esc:
        low = (low - low_off) & 0xFF
        note.append("low-=%d" % low_off)
    if high_esc:
        high = (high - HIGH_OFFSET) & 0xFF      # high += -9 ⇒ 还原要 -(-9)
        note.append("high+=9")
    cp = (high << 8) | low
    try:
        ch = chr(cp)
    except Exception:
        ch = "?"
    return cp, ch, ",".join(note) or "-"


def scan(name, data):
    """把一段字节按 3 字节字符切开解码；返回可读串 + 逐字符说明。"""
    out = []
    i = 0
    while i < len(data):
        b = data[i]
        if b in (0x10, 0x11, 0x12, 0x13) and i + 2 < len(data):
            r = decode3(data[i], data[i + 1], data[i + 2])
            if r:
                cp, ch, note = r
                out.append("%s(U+%04X%s)" % (ch, cp, "" if note == "-" else " " + note))
                i += 3
                continue
        if b == 0x20:
            out.append("<SP>")
        elif 0x21 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append("<%02X>" % b)
        i += 1
    print("  %-10s %s" % (name, " ".join(out)))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("EU4 双字节编码解码验证（lowByteOffset=%d）\n" % LOW_OFFSET)

    # LJA 的实测字节
    print("LJA（用户说：姓=线、名=军）")
    scan("名字段", [0x10, 0x9B, 0x51])
    scan("姓字段", [0x12, 0xBF, 0x75])
    scan("out",    [0x10, 0x9B, 0x51, 0x20, 0x12, 0xBF, 0x75])
    print()

    # 用户期望的两个字，各自编码是什么？
    print("用户期望的两个字（反推其编码）")
    for ch in ("线", "军"):
        cp = ord(ch)
        low, high = cp & 0xFF, (cp >> 8) & 0xFF
        esc = 0x10
        if high in INTERNAL:
            esc += 2
        if low in INTERNAL:
            esc += 1
        nl, nh = low, high
        if low in INTERNAL:
            nl = (low + LOW_OFFSET) & 0xFF
        if high in INTERNAL:
            nh = (high + HIGH_OFFSET) & 0xFF
        print("  %s U+%04X  原始 low=%02X high=%02X  → esc=%02X low=%02X high=%02X  (in INTERNAL: low=%s high=%s)"
              % (ch, cp, low, high, esc, nl, nh, low in INTERNAL, high in INTERNAL))
    print()

    # 其他现场：验证编码一致性
    print("其他现场（来自日志的 hex）")
    scan("L141 out",  [0x10, 0x1D, 0x60, 0x10, 0xFB, 0x4E, 0x10, 0xD5, 0x6C])
    scan("L141 名",   [0x10, 0xFB, 0x4E, 0x10, 0xD5, 0x6C])
    scan("L141 姓",   [0xBF, 0x10, 0x1D, 0x60])
    scan("L12125 out", [0x10, 0xCF, 0x82, 0x12, 0xFF, 0x52, 0x10, 0x96, 0x5A])
    print()
    print("★ 注意 L141 的「姓字段」= BF 10 1D 60 —— **开头那个 BF 是单独的标记**，")
    print("  后面 10 1D 60 才是一个完整字符（escape=0x10）。")
    print("  而 LJA 的「姓字段」= 12 BF 75 —— 0x12 是 escape，BF 是这个字的 low 字节。")
    print("  ⇒ **两种布局的 0xBF 含义完全不同**：一个是标记，一个是字符字节。")


if __name__ == "__main__":
    main()
