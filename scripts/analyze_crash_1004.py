# -*- coding: utf-8 -*-
"""针对 2026-10-05 10:04 那次崩溃的专项分析。

已确认的事实（来自 minidump + 反汇编）：
  崩溃点   RVA 0x28ABA9   `mov 0x38(%rax),%rcx`  读地址 0xFFFFFFFFFFFFFFFF
  函数起点 RVA 0x28AB40   `void f(This *t)`，元素大小 0x48
  循环     r14 从 0 每次 += 0x48，元素数 = (end-begin)/8*0x8e38e38e38e38e39
  崩溃时   r14 = 0x16F50 ⇒ 第 1306 个元素
           rax = [rsi+r14] = 0x1a4020c510000000
           r15 = this      = 0x0000021a4020c510
           rsi = [r15+0x18] = 0x0000021a46ff2940

本脚本把 this 的关键字段读出来，验证
    rax == (r15 & 0xFFFFFFFF) << 32
这个"低 32 位被抬高"的形态是否成立 —— 它指向"某处把 64 位指针按 32 位处理"。
"""
import io
import struct
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from dump_mem import MiniDump


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    md = MiniDump(sys.argv[1])
    regs = md.registers()

    this = regs["R15"]
    rsi = regs["Rsi"]
    r14 = regs["R14"]
    rax = regs["Rax"]

    print("this (r15) = %#x" % this)
    print("rsi        = %#x" % rsi)
    print("r14        = %#x  (%d)" % (r14, r14))
    print("rax        = %#x   ← 崩溃时 [rsi+r14] 的值" % rax)
    print()

    # 1) 验证"低 32 位抬高"的形态
    lo32 = this & 0xFFFFFFFF
    pred = lo32 << 32
    print("=== 形态验证 ===")
    print("  (r15 & 0xFFFFFFFF) << 32 = %#x" % pred)
    print("  实际 rax                 = %#x   %s"
          % (rax, "★ 完全吻合" if pred == rax else "不吻合"))
    print()

    # 2) 读 this 的关键字段
    print("=== this 的字段 ===")
    buf = md.read(this, 0x60)
    for off in range(0, 0x60, 8):
        v = struct.unpack_from("<Q", buf, off)[0]
        tag = ""
        if off == 0x18:
            tag = "  ← begin（循环里 rsi 就取自这里）"
        elif off == 0x20:
            tag = "  ← end"
        print("  [%#04x] %#018x%s" % (off, v, tag))

    begin = struct.unpack_from("<Q", buf, 0x18)[0]
    end = struct.unpack_from("<Q", buf, 0x20)[0]
    print()
    print("  begin = %#x   end = %#x" % (begin, end))
    print("  与循环里的 rsi 一致: %s" % (begin == rsi))
    if begin and end > begin:
        n = (end - begin) // 0x48
        print("  元素数 = %d   （r14 对应第 %d 个）" % (n, r14 // 0x48))
        if r14 // 0x48 < n:
            print("  ★ 索引在范围内 —— 不是越界读，而是【元素本身是坏值】")
        else:
            print("  ★ 索引越界！r14 超出了 begin..end")
    print()

    # 3) 读第 1306 个元素处（如果 dump 里有）
    target = rsi + r14
    print("=== [rsi+r14] = %#x ===" % target)
    b = md.read(target, 0x48)
    if b[:2] == b"\xee\xee":
        print("  （minidump 未包含该页，无法直接读）")
    else:
        for off in range(0, 0x48, 8):
            v = struct.unpack_from("<Q", b, off)[0]
            print("  [+%#04x] %#018x" % (off, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
