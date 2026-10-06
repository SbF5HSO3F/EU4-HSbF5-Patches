# -*- coding: utf-8 -*-
"""把 stubs.asm 里的 trampoline 按【逻辑执行顺序】重排。

顺序（与 install.cpp 的 kSites[] 一致）：
    组 1 取模修复        P1 / P2 / P3
    组 2 生成期姓名顺序  P6 / P7 / P10 / P11 / P4
    组 3 统治者链        P8

每个 trampoline 的块 = 从它上方那段 `; ----...` 注释分隔线开始，
到对应的 `mnp_hook_pN ENDP` 为止（含尾随空行）。

用法： python scripts\\reorder_stubs_asm.py [--apply]
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASM = os.path.join(ROOT, "src", "monarchnamefix", "stubs.asm")

ORDER = ["p1", "p2", "p3", "p6", "p7", "p10", "p11", "p4", "p8"]


def main():
    apply = "--apply" in sys.argv
    text = io.open(ASM, encoding="utf-8", newline="").read()
    lines = text.split("\n")

    # 找每个 PROC 块的边界：起点往上吃到最近的 `; ----` 分隔线
    blocks = {}
    for i, l in enumerate(lines):
        m = re.match(r"^(mnp_hook_p\w+)\s+PROC\b", l)
        if not m:
            continue
        name = m.group(1)
        # 找 ENDP
        end = None
        for j in range(i, len(lines)):
            if re.match(r"^%s\s+ENDP\b" % re.escape(name), lines[j]):
                end = j
                break
        if end is None:
            print("[x] %s 找不到 ENDP" % name)
            return 1
        # 起点：往上吃注释与空行，直到遇到 `; ====` 的大分隔或文件头
        s = i
        while s > 0:
            prev = lines[s - 1]
            if prev.strip().startswith(";") or prev.strip() == "":
                if prev.startswith("; ====") and "组" in prev:
                    break
                s -= 1
                if prev.startswith("; ===="):
                    break
            else:
                break
        blocks[name] = (s, end)

    print("找到 %d 个 trampoline 块：" % len(blocks))
    for k in ORDER:
        nm = "mnp_hook_" + k
        if nm in blocks:
            s, e = blocks[nm]
            print("   %-14s 行 %d..%d" % (nm, s + 1, e + 1))
        else:
            print("   %-14s [缺失]" % nm)
            return 1

    # 按 ORDER 重排，但【必须保留】头部（EXTERN 声明 + MNP_ENTER/MNP_EXIT 宏）
    # 与尾部（END）
    first = min(s for s, _ in blocks.values())
    last = max(e for _, e in blocks.values())
    head = lines[:first]
    tail = lines[last + 1:]

    new_lines = list(head)
    for k in ORDER:
        s, e = blocks["mnp_hook_" + k]
        new_lines.extend(lines[s:e + 1])
        # 块间只保留一个空行（若块本身已以空行结尾就不再补）
        if new_lines and new_lines[-1].strip() != "":
            new_lines.append("")
    # 去掉尾部块多出来的空行，让 tail（END）紧接其后
    while len(new_lines) > 1 and new_lines[-1].strip() == "" and tail and tail[0].strip() == "":
        new_lines.pop()
    new_lines.extend(tail)

    out = "\n".join(new_lines)
    print("\n头部 %d 行 + 9 个块 + 尾部 %d 行 ⇒ 共 %d 行（原 %d 行）"
          % (len(head), len(tail), len(out.split("\n")), len(lines)))

    if not apply:
        print("(dry-run；加 --apply 才写回)")
        return 0

    io.open(ASM, "w", encoding="utf-8", newline="").write(out)
    print("[ok] 已写回")
    return 0


if __name__ == "__main__":
    sys.exit(main())
