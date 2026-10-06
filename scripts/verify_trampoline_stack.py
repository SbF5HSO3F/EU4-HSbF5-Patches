# -*- coding: utf-8 -*-
"""校验 stubs.asm 里 MNP_ENTER / MNP_EXIT 的栈平衡。

为什么需要它：
  这两个宏的净效果必须精确为 0 —— 桩执行完回到游戏时，rsp 必须与进入时
  逐字节一致，否则"重放原指令"会写到错误的栈位置，表现为进游戏直接闪退
  且不留崩溃信息（栈被破坏后 ret 跳到非法处，游戏自己的异常处理也拿不到）。

  已经踩过的两个坑：
    ① 用 `pop rsp` 想"跳过 rsp 槽" —— 它的语义是 rsp = [rsp]，
       会把 rsp 设成栈上那个值（S-104），而不是跳过 8 字节；
    ② `add qword ptr [rsp+18h], 120` —— push rsp 压的是【递减前】的值，
       正确修正量是 (S+8) - (S-104) = 112 = 0x70。

用法： python scripts\\verify_trampoline_stack.py
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASM = os.path.join(ROOT, "src", "monarchnamefix", "stubs.asm")


def read_macro(lines, name):
    """取出 MNP_xxx macro ... endm 之间的行。"""
    out, inside = [], False
    for l in lines:
        if re.match(r"^%s\s+macro\b" % name, l, re.I):
            inside = True
            continue
        if inside:
            if re.match(r"^\s*endm\b", l, re.I):
                break
            out.append(l)
    return out


def parse_imm(s):
    """MASM 立即数：0xNN / NNh 都是十六进制，纯数字才是十进制。"""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if s.lower().endswith("h"):
        return int(s[:-1], 16)      # ★ NNh 是十六进制，不是十进制
    return int(s)


def net_effect(body):
    """按 push/pop/add rsp/sub rsp 统计净栈位移（字节）。"""
    delta = 0
    events = []
    for l in body:
        s = re.sub(r";.*$", "", l).strip()
        if not s:
            continue
        m = re.match(r"^push\s+(\S+)", s, re.I)
        if m:
            delta -= 8
            events.append(("push " + m.group(1), -8, delta))
            continue
        if re.match(r"^pushfq\b", s, re.I):
            delta -= 8
            events.append(("pushfq", -8, delta))
            continue
        m = re.match(r"^pop\s+(\S+)", s, re.I)
        if m:
            reg = m.group(1).lower()
            if reg == "rsp":
                # 致命：pop rsp 是"赋值"而非"跳过一个槽"
                events.append(("pop rsp  <== 致命", None, None))
                return None, events
            delta += 8
            events.append(("pop " + m.group(1), +8, delta))
            continue
        if re.match(r"^popfq\b", s, re.I):
            delta += 8
            events.append(("popfq", +8, delta))
            continue
        m = re.match(r"^add\s+rsp\s*,\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+h|\d+)", s, re.I)
        if m:
            v = parse_imm(m.group(1))
            delta += v
            events.append(("add rsp,%#x" % v, +v, delta))
            continue
        m = re.match(r"^sub\s+rsp\s*,\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+h|\d+)", s, re.I)
        if m:
            v = parse_imm(m.group(1))
            delta -= v
            events.append(("sub rsp,%#x" % v, -v, delta))
            continue
    return delta, events


def main():
    lines = io.open(ASM, encoding="utf-8", errors="replace").read().split("\n")

    ok = True
    total = 0
    for name in ("MNP_ENTER", "MNP_EXIT"):
        body = read_macro(lines, name)
        if not body:
            print("[x] 找不到宏 %s" % name)
            ok = False
            continue
        delta, events = net_effect(body)
        print("=== %s ===" % name)
        for desc, step, cur in events:
            if step is None:
                print("   %-22s  <== 危险指令" % desc)
            else:
                print("   %-22s %+4d  =>  %+d" % (desc, step, cur))
        if delta is None:
            print("   [x] 含 pop rsp：它的语义是 rsp=[rsp]（赋值），不是跳过 8 字节")
            ok = False
        else:
            print("   净位移 = %+d 字节" % delta)
            total += delta
        print()

    # ★ 关键判据：ENTER 与 EXIT 必须互为逆运算（各自不必为 0 ——
    #   ENTER 里的 sub rsp,20h 是给 call 用的 shadow space，
    #   它由 EXIT 里的 add rsp,20h 抵消）。
    print("=== 合成效果 ===")
    print("   MNP_ENTER + MNP_EXIT = %+d 字节   %s"
          % (total, "OK（rsp 逐字节复原）" if total == 0 else "[x] 不平衡！"))
    if total != 0:
        ok = False

    # 检查 rsp 槽修正量
    ent = "\n".join(read_macro(lines, "MNP_ENTER"))
    m = re.search(r"add\s+qword\s+ptr\s+\[rsp\+18h\]\s*,\s*([0-9a-fA-F]+)h", ent, re.I)
    print("=== reg_pack::rsp 修正量 ===")
    if not m:
        print("   [x] 找不到 `add qword ptr [rsp+18h], NNNh`")
        ok = False
    else:
        v = int(m.group(1), 16)
        # `push rsp` 是第 14 条 push，执行前 rsp = S-104，所以槽里存的是 S-104。
        # 要让槽值 + 修正量 == S（站点处真实 rsp），修正量必须正好是 104。
        #
        # ★ 这个值是 2026-10-05 由实机【定标】出来的，不是纯推理：
        #   P11CHK 自检 64 次样本全部显示 rbp-rsp = 0xF8，
        #   而序言可证 rbp-rsp 应为 0x100 ⇒ rsp 偏大 8 ⇒ 原值 112 要减 8。
        #   同一份日志里 sp(=rsp+0x30) 与 &Src(=rbp-0xD0) 也正好差 +8，双重印证。
        #   那个 8 字节偏差导致 P11 读局部 CString 时整体错位：buf 取到 SSO
        #   缓冲区中间（垃圾堆指针）、cap 越界读成 48 ⇒ 误判堆串 ⇒ 写坏堆
        #   ⇒ 三次实机崩溃（含 ntdll!RtlFreeHeap 那次）。
        want = 104
        print("   实际 = %d (%#x)   应为 = %d (%#x)   %s"
              % (v, v, want, want, "OK" if v == want else "[x] 不匹配"))
        if v != want:
            ok = False

    print()
    print("ALL OK" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
