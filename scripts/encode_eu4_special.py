# -*- coding: utf-8 -*-
"""EU4 特殊编码的**正向**转码器（specialEscape）—— 回答一个二元问题。

问题：`¿`(U+00BF) 与 `线`(U+7EBF) 过一遍转码器后各是什么字节？
      这决定了 P8/nameorder 里「0xBF 该留还是该删」。

方案出处：bruceCzK 的 gist（移植自 matanki-saito/EU4SpecialEscape）：
    module.exports = function specialEscape(char, toUtf8, newVersion) {
      if (char.codePointAt(0) < 256) return char        // ★ 关键：<256 直接返回
      let low  = cp & 0xFF
      let high = cp >> 8
      let lowByteOffset = 15            // EU4 1.26+ 用 14
      const highByteOffset = -9
      const internalChars = [0x00,0x0A,0x0D,0x20,0x22,0x24,0x40,0x5B,0x5C,
                             0x7B,0x7D,0x7E,0x80,0xA3,0xA4,0xA7,0xBD,
                             0x3B,0x5D,0x5F,0x3D,0x23]
      let escapeChr = 0x10
      if (internalChars.includes(high)) escapeChr += 2
      if (internalChars.includes(low))  escapeChr++
      switch (escapeChr) {
        case 0x11: low += lowByteOffset; break
        case 0x12: high += highByteOffset; break
        case 0x13: low += lowByteOffset; high += highByteOffset; break
        default: break
      }
      return [escapeChr, low, high]
    }
"""
import sys

INTERNAL = [
    0x00, 0x0A, 0x0D, 0x20, 0x22, 0x24, 0x40, 0x5B, 0x5C,
    0x7B, 0x7D, 0x7E, 0x80, 0xA3, 0xA4, 0xA7, 0xBD,
    0x3B, 0x5D, 0x5F, 0x3D, 0x23,
]


def encode(ch, low_off=15, verbose=True):
    cp = ord(ch)
    if cp < 256:
        if verbose:
            print("  %s U+%04X  →  **<256，转码器直接返回原字符**，编码 = [%02X]（1 字节）"
                  % (ch, cp, cp))
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
        nh = (high + (-9)) & 0xFF
    if verbose:
        print("  %s U+%04X  low=%02X high=%02X | in表: low=%s high=%s | escape=%02X"
              % (ch, cp, low, high, low in INTERNAL, high in INTERNAL, esc))
        print("              →  编码 = [%02X %02X %02X]  (%d 字节)"
              % (esc, nl, nh, 3))
    return [esc, nl, nh]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("=" * 78)
    print("① 转码「¿」U+00BF —— 它是标记字符吗？")
    print("=" * 78)
    r1 = encode("\u00bf")
    print()

    print("=" * 78)
    print("② 转码「线」U+7EBF —— 与日志里的 12 BF 75 对得上吗？")
    print("=" * 78)
    r2 = encode("\u7ebf")
    print()

    print("=" * 78)
    print("③ 转码「军」U+519B —— 与日志里的 10 9B 51 对得上吗？")
    print("=" * 78)
    r3 = encode("\u519b")
    print()

    print("=" * 78)
    print("④ 转码「朱」U+6731（单元测试用例里的字）")
    print("=" * 78)
    r4 = encode("\u6731")
    print()

    print("=" * 78)
    print("结论")
    print("=" * 78)
    if r1 == [0xBF]:
        print("  ★ 「¿」<256 ⇒ 转码器**直接返回单字节 0xBF**。")
        print("    ⇒ 「裸 0xBF」**就是**「¿」的编码！它是一个货真价实的 1 字节字符。")
    else:
        print("  「¿」编码 = %s（不是单字节 0xBF）" % " ".join("%02X" % b for b in r1))
    print()
    print("  对照日志实测：")
    print("    线 编码 = %s   | 日志实测 12 BF 75  %s"
          % (" ".join("%02X" % b for b in r2),
             "✓ 一致" if r2 == [0x12, 0xBF, 0x75] else "✗ 不一致"))
    print("    军 编码 = %s   | 日志实测 10 9B 51  %s"
          % (" ".join("%02X" % b for b in r3),
             "✓ 一致" if r3 == [0x10, 0x9B, 0x51] else "✗ 不一致"))


if __name__ == "__main__":
    main()
