# -*- coding: utf-8 -*-
"""删除 nameorder.h 里的 buildP* 桩构造器（"机械拼字节"时代的遗产）。

这些函数的产物是 cave 里的一段字节流，末尾还必须凑出 `90 90 90 E9 rel32`。
新钩子层用 stubs.asm 的 trampoline 之后，它们不再有任何调用者。

保留：name_order_apply / name_order_apply_cfg / name_order_apply_struct
      以及所有共用类型与常量 —— 那是真正的业务逻辑。

用法： python scripts\\strip_nameorder_builders.py [--apply]
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HDR = os.path.join(ROOT, "src", "monarchnamefix", "nameorder.h")

# 要整体删除的 #if 0 遗迹块（用起止注释标记定位）
DEAD_BLOCKS = [
    ("/* ============================================================================",
     "#endif /* 已废弃的 P7/P8旧/P9/P10 遗迹结束"),
    ("/* ============================================================================",
     "#endif /* P9 / P10 废弃遗迹结束 */"),
]


def find_func_end(lines, start):
    """从 start（函数签名行，0-based）起，按花括号配平找函数结尾，返回结尾行索引。"""
    depth = 0
    seen = False
    for i in range(start, len(lines)):
        l = re.sub(r'/\*.*?\*/', '', lines[i])
        l = re.sub(r'//.*', '', l)
        # 去掉字符串与字符字面量里的括号（本文件里很少，但保险）
        l = re.sub(r'"(\\.|[^"\\])*"', '""', l)
        l = re.sub(r"'(\\.|[^'\\])*'", "''", l)
        for ch in l:
            if ch == '{':
                depth += 1
                seen = True
            elif ch == '}':
                depth -= 1
        if seen and depth == 0:
            return i
    return len(lines) - 1


def main():
    apply = "--apply" in sys.argv
    lines = io.open(HDR, encoding="utf-8", newline="").read().split("\n")
    before = len(lines)

    kill = set()

    # 1) 所有 buildP* 函数（含其上方紧邻的注释块）
    for i, l in enumerate(lines):
        if re.match(r'^static uint32_t buildP\w+\s*\(', l):
            end = find_func_end(lines, i)
            # 往上吃掉紧邻的注释行
            s = i
            while s > 0 and (lines[s - 1].strip().startswith(('/*', '*', '//')) or
                             lines[s - 1].strip() == ''):
                s -= 1
                if lines[s].strip().startswith('/*') and lines[s].strip().endswith('*/') and s + 1 == i:
                    break
            print("  buildP: %5d..%-5d  %s" % (s + 1, end + 1, lines[i].strip()[:70]))
            for k in range(s, end + 1):
                kill.add(k)

    # 2) 两段 #if 0 遗迹（先定位，再整体加入）
    for i, l in enumerate(lines):
        if l.startswith('#if 0'):
            for j in range(i, len(lines)):
                if lines[j].startswith('#endif'):
                    print("  #if0  : %5d..%-5d  %s" % (i + 1, j + 1, lines[i + 1].strip()[:60] if i + 1 < len(lines) else ''))
                    for k in range(i, j + 1):
                        kill.add(k)
                    break

    print("\n合计删除 %d 行，剩余约 %d 行" % (len(kill), before - len(kill)))

    if not apply:
        print("(dry-run；加 --apply 才真正删除)")
        return 0

    out = [l for i, l in enumerate(lines) if i not in kill]
    io.open(HDR, "w", encoding="utf-8", newline="").write("\n".join(out))
    print("[ok] 已写回，剩余 %d 行" % len(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
