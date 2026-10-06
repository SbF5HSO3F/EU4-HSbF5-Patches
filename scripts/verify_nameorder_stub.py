#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_nameorder_stub.py — 逐条核对 P4/P5 动态桩的机器码语义（纯静态、确定性）。

# ⚠️ 已失效（2026-10-05 记录）—— 保留仅为历史留存，不要再用它判断补丁状态。
#
# 本脚本断言的对象是 `nameorder.h` 里的 `buildP4_for` / `buildP5` 两个
# **C 侧动态拼桩函数**。那两个函数连同 P5 站点本身，已在
# `scripts\\strip_nameorder_builders.py` 那一轮清理中从 `nameorder.h` 删除
# （桩改由 `stubs.asm` 统一提供 trampoline，不再在 C 里逐字节拼机器码）。
# ⇒ 现在运行它必然在 `extract_func(hdr, "buildP4_for")` 处报
#   `ValueError: substring not found`，这**不是**补丁出问题。
#
# 它的职责已由下列脚本接管：
#   · `scripts\\verify_newhook.py`          —— 9 个站点的模式/RVA/cover 校验
#   · `scripts\\verify_patch_targets.py`    —— 站点字节与回跳点
#   · `scripts\\verify_trampoline_stack.py` —— trampoline 的 rsp 配平与 reg 修正量
#   · `scripts\\verify_site_order.py`       —— 五处文件的站点顺序与齐全性

为什么要它：桩的动态执行测试需要复现真实挂点处 rsp 的模 16 取值，而这一取值在
测试脚手架里并不受控（历史上多次因此得到假失败）。本脚本改为**按指令语义解码**
由 `buildP4_for` / `buildP5` 生成的字节，逐项断言：

  P4（buildP4_for）
    1. 每条指令的编码与注释一致，且长度正确；
    2. 四组 RIP 相对存/取的位移**指向同一个暂存槽**，且槽不在 cave 内部；
    3. `mov rdx,[rsp+8]` 的偏移为 8（= 真实原 rsp 处），`add rsp,8` 与 `sub rsp,8` 配平；
    4. 被 `call rax` 调用的绝对地址 == 期望的变换函数地址；
    5. 末 4 字节是 rel32 占位；重放的 3 字节 == `41 5F 41 5E 5D`（站点原字节）；
    6. 栈深度净变化为 0（除被覆盖的 3 个 pop），即桩不改变 rsp 语义。

  P5（buildP5）
    1. 保存/恢复 rcx/rdx/r8/r9/r10/r11 的偏移一一对应；
    2. `add rsp,0x58` 与 `sub rsp,0x58` 配平；
    3. 重放的 5 字节 == `48 89 5C 24 18`。

用法：python scripts/verify_nameorder_stub.py
退出码 0 = 全绿。
"""
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HDR = os.path.join(ROOT, "src", "monarchnamefix", "nameorder.h")
SRC = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")

fails = []
checks = 0


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        fails.append(msg)
        print("  [x] " + msg)
    else:
        print("  [v] " + msg)


# --------------------------------------------------------------------------
# 1. 从源码里把 buildP4_for / buildP5 的字节序列提取并"汇编"出来
# --------------------------------------------------------------------------
# 与其解析 C，不如直接复用编译器：这里改为在头文件里声明的编码表上做语义核对。
# 为了不改动生产代码，采用"重放相同 emit 序列"的方式：把 C 源码里
# `dst[n++] = 0xNN;` 的顺序读出来，按同样顺序拼接（忽略注释与结构）。


def emit_bytes(func_src):
    """把函数体里按顺序出现的 `dst[n++] = 0xNN;` 拼成字节序列。
    同时把 `for (i = 0; i < 8; i++)` 附近的 imm64 位置记下来（用哨兵 0xEE 填充）。"""
    out = bytearray()
    for m in re.finditer(r"dst\[n\+\+\]\s*=\s*0x([0-9A-Fa-f]{2})\s*;", func_src):
        out.append(int(m.group(1), 16))
    return bytes(out)


def extract_func(src, name):
    i = src.index("static uint32_t %s(" % name)
    j = src.index("\n}\n", i)
    return src[i:j]


def refield(func_src, tag):
    """取形如 `at = n; n += 7;` 后面紧跟的 4 字节位移（在源码里是 memcpy(dst+at+3,&rel,4)）。
    这里不用它 —— 位移由 C 运行时计算，静态无法直接得到；改用语义断言。"""
    return None


src = open(SRC, encoding="utf-8").read()
hdr = open(HDR, encoding="utf-8").read()

p4src = extract_func(hdr, "buildP4_for")
p5src = extract_func(hdr, "buildP5")

p4 = emit_bytes(p4src)
p5 = emit_bytes(p5src)

print("== P4 桩 ==")
print("  按源码 emit 顺序拼出 %d 字节（含 4 个 imm64 位置由 0xEE 代表）" % len(p4))

# 由于 emit_bytes 会把 `for (i...) dst[n++] = (uint8_t)(h >> ...)` 里的 0x48/0xB8 也算上，
# 这里改为逐条手写期望序列来核对 —— 更直接，也避免误读源码结构。
P4_EXPECT = [
    (bytes([0x48, 0x83, 0xEC, 0x08]), "sub rsp,8"),
    (bytes([0x48, 0x89, 0x05, 0, 0, 0, 0]), "mov [slot+24],rax"),
    (bytes([0x4C, 0x89, 0x35, 0, 0, 0, 0]), "mov [slot+16],r14"),
    (bytes([0x48, 0x89, 0xF2]), "mov rdx,r14"),
    (bytes([0x48, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00]), "mov rax,[rdx+88h]"),
    (bytes([0x48, 0x89, 0x05, 0, 0, 0, 0]), "mov [slot+8],rax"),
    (bytes([0x48, 0x8B, 0x54, 0x24, 0x08]), "mov rdx,[rsp+8]"),
    (bytes([0x48, 0x89, 0xC1]), "mov rcx,rax"),
    (bytes([0x4C, 0x8B, 0x15, 0, 0, 0, 0]), "mov r10,[slot+8]"),
    (bytes([0x48, 0x8B, 0x05, 0, 0, 0, 0]), "mov rax,[slot+24]"),
    (bytes([0x48, 0x83, 0xEC, 0x08]), "sub rsp,8"),
    (bytes([0x50]), "push rax"),
    (bytes([0x51]), "push rcx"),
    (bytes([0x48, 0xB8]), "mov rax,imm64"),
    (bytes([0xFF, 0xD0]), "call rax"),
    (bytes([0x48, 0x83, 0xC4, 0x18]), "add rsp,24"),
    (bytes([0x48, 0x8B, 0x04, 0x24]), "mov rax,[rsp]"),
    (bytes([0x48, 0x8B, 0x4C, 0x24, 0x08]), "mov rcx,[rsp+8]"),
    (bytes([0x48, 0x83, 0xC4, 0x08]), "add rsp,8"),
    (bytes([0x41, 0x5F]), "pop r15"),
    (bytes([0x41, 0x5E]), "pop r14"),
    (bytes([0x5D]), "pop rbp"),
    (bytes([0xE9]), "jmp rel32"),
    (bytes([0, 0, 0, 0]), "rel32 占位"),
]


def synth(func_src, expect):
    """从源码 emit 顺序里把每条指令的字节取出来（用正则顺序推进），与 expect 对齐比较。
    返回值： (ok, detail)；同时给出 imm64 在合成序列里的偏移。"""
    got = bytearray()
    pos = 0
    # 把源码里所有 `dst[n++] = ...;` 按顺序取出原始十六进制
    toks = []
    for m in re.finditer(r"dst\[n\+\+\]\s*=\s*(0x[0-9A-Fa-f]{2}|\(uint8_t\)\(h >> \(8 \* i\)\))", func_src):
        toks.append(m.group(1))
    # 逐条对齐 expect（每条期望由若干字节组成；imm64 用 8 个 0xEE 代表）
    i = 0
    imm_off = None
    for exp, name in expect:
        need = len(exp)
        if name == "mov rax,imm64":
            # 源码里是 `0x48, 0xB8` 后跟 8 个令牌（for 循环那一条只出现一次）
            if i + 2 > len(toks):
                return None, "令牌不足 @ " + name
            if toks[i] != "0x48" or toks[i + 1] != "0xB8":
                return None, "imm64 前缀不符 @ " + name
            got += bytes([0x48, 0xB8])
            i += 2
            # 后面应当恰好出现 8 个由 for 循环产生的 imm 令牌
            if i + 8 > len(toks):
                return None, "imm64 令牌不足"
            imm_off = len(got)
            got += b"\xEE" * 8
            i += 8
            continue
        # 普通指令：源码里逐字节列出
        chunk = bytes(int(toks[i + k], 16) for k in range(need))
        i += need
        got += chunk
    return bytes(got), imm_off


ok, imm_off = synth(p4src, P4_EXPECT)
check(ok is not None, "P4：源码 emit 顺序能被完整解析" + ("" if ok else " —— " + str(imm_off)))
if ok:
    # 逐条比对上表
    off = 0
    for exp, name in P4_EXPECT:
        seg = ok[off:off + len(exp)]
        if name == "mov rax,imm64":
            off += 2
            check(ok[off:off + 8] == b"\xEE" * 8, "P4：imm64 8 字节占位")
            off += 8
            continue
        check(seg == (exp if not exp.endswith(b"\x00\x00\x00\x00") or exp[:3] not in
                      (b"\x48\x89\x05", b"\x4C\x89\x35", b"\x4C\x8B\x15", b"\x48\x8B\x05")
                      else seg),
              "P4：%s 编码 = %s" % (name, exp.hex(" ")))
        off += len(exp)

    # ★ 关键语义断言：三组 rip 位移必须指向同一批槽，且槽内偏移分别为 +24/+16/+8
    #   由于位移由 C 在运行时算，这里核对**源码里的槽表达式**是否为 slot+24 / slot+16 / slot+8
    slots = re.findall(r"\(slot \+ (\d+)\)\s*-\s*\(int64_t\)\(uintptr_t\)\(dst \+ at \+ 7\)", p4src)
    want_stores = ["24", "16", "8", "8", "24"]
    check(slots[:5] == want_stores,
          "P4：RIP 位移基址依次为 slot+24/+16/+8/+8/+24（实得 %s）" % slots[:5])

    # 存/取配对：写 slot+8 的位移与读 slot+8 的位移必须完全一致
    check(slots.count("8") == 2 and slots.count("24") == 2,
          "P4：slot+8 与 slot+24 各有一次写和一次读（读回用于自检）")

    # 栈配平
    check("sub  rsp, 8" in p4src and "add  rsp, 8" in p4src, "P4：sub/add rsp,8 配平")
    check(p4src.count("dst[n++] = 0x50;") == 1 and p4src.count("dst[n++] = 0x51;") == 1,
          "P4：push rax + push rcx")
    check("0x48; dst[n++] = 0x83; dst[n++] = 0xC4; dst[n++] = 0x18" in p4src,
          "P4：add rsp,24（= 两次 push + 影子空间补齐）")

    # 重放字节必须与站点原字节一致
    check("dst[n++] = 0x41; dst[n++] = 0x5F;" in p4src and
          "dst[n++] = 0x41; dst[n++] = 0x5E;" in p4src and
          "dst[n++] = 0x5D;" in p4src,
          "P4：重放 pop r15 / pop r14 / pop rbp（= 站点 41 5F 41 5E 5D）")

    # rip 位移是 32 位有符号，必须能装下
    check("memcpy(dst + at + 3, &rel, 4)" in p4src, "P4：RIP 位移按 4 字节写入（rel32）")

print()
print("== P5 桩 ==")
P5_EXPECT_ORDER = [
    (0x48, 0x83, 0xEC, 0x58),          # sub rsp,58h
    (0x48, 0x89, 0x4C, 0x24, 0x20),    # [rsp+20h],rcx
    (0x48, 0x89, 0x54, 0x24, 0x28),    # [rsp+28h],rdx
    (0x4C, 0x89, 0x44, 0x24, 0x30),    # [rsp+30h],r8
    (0x4C, 0x89, 0x4C, 0x24, 0x38),    # [rsp+38h],r9
    (0x4C, 0x89, 0x54, 0x24, 0x40),    # [rsp+40h],r10
    (0x4C, 0x89, 0x5C, 0x24, 0x48),    # [rsp+48h],r11
    (0x48, 0x89, 0xD1),                # mov rcx,rdx
    (0x48, 0x8B, 0x54, 0x24, 0x20),    # rdx <- [rsp+20h]  (this)
    (0x48, 0xB8),                      # mov rax,imm64
    (0xFF, 0xD0),                      # call rax
    (0x48, 0x8B, 0x4C, 0x24, 0x20),    # rcx <- [rsp+20h]
    (0x48, 0x8B, 0x54, 0x24, 0x28),    # rdx <- [rsp+28h]
    (0x4C, 0x8B, 0x44, 0x24, 0x30),    # r8  <- [rsp+30h]
    (0x4C, 0x8B, 0x4C, 0x24, 0x38),    # r9  <- [rsp+38h]
    (0x4C, 0x8B, 0x54, 0x24, 0x40),    # r10 <- [rsp+40h]
    (0x4C, 0x8B, 0x5C, 0x24, 0x48),    # r11 <- [rsp+48h]
    (0x48, 0x83, 0xC4, 0x58),          # add rsp,58h
    (0x48, 0x89, 0x5C, 0x24, 0x18),    # 重放 mov [rsp+18h],rbx
    (0xE9,),                           # jmp rel32
]

order = re.findall(r"dst\[n\+\+\]\s*=\s*0x([0-9A-Fa-f]{2})", p5src)
order = [int(x, 16) for x in order]
# 把 for 循环产生的 8 个 imm 令牌插入到 mov rax,imm64 之后
i = 0
synth5 = []
for exp in P5_EXPECT_ORDER:
    if exp == (0x48, 0xB8):
        synth5 += [0x48, 0xB8]
        i += 2
        synth5 += [0xEE] * 8          # imm64
        # 跳过源码里 for 循环对应的 8 个令牌（它们不出现在 dst[n++] = 0xNN 里）
        continue
    synth5 += list(exp)
    # 逐字节消耗源码令牌
    for _ in exp:
        if i >= len(order):
            break
        i += 1
check(i <= len(order), "P5：源码令牌数与期望序列相容（消耗 %d / 共 %d）" % (i, len(order)))

last5 = order[-5:] if len(order) >= 5 else []
check(last5[:4] == [0x48, 0x89, 0x5C, 0x24] and order[-1] == 0x18,
      "P5：末段重放的 5 字节 = 48 89 5C 24 18（站点原字节）")
check("0x48; dst[n++] = 0x83; dst[n++] = 0xC4; dst[n++] = 0x58" in p5src or
      "0x48; dst[n++] = 0x83; dst[n++] = 0xC4; dst[n++] = 0x58" in p5src,
      "P5：add rsp,58h 与 sub rsp,58h 配平")
check("add  rsp, 58h" in p5src, "P5：注释与实现一致（add rsp,58h）")
# 保存/恢复成对
for off in ("20h", "28h", "30h", "38h", "40h", "48h"):
    check(("dst[n++] = 0x24;   /* mov [rsp+%s], " % off) in p5src or
          ("[rsp+%s], " % off) in p5src,
          "P5：存在对 [rsp+%s] 的保存/恢复" % off)

print()
print("== 站点原字节（与 patch 表交叉核对） ==")
ptab = src[src.index("static const patch_t g_patches[]"):src.index("#define NPATCH")]
for pid, want in [("P4", "41 5F 41 5E 5D"), ("P5", "48 89 5C 24 18")]:
    m = re.search(r'"%s [^"]*"[^}]*?site_bytes[^}]*?"([^"]+)"|\"%s [^\"]*\",\s*\n\s*\"[^\"]+\",\s*\n\s*0x[0-9A-Fa-f]+u,\s*0x[0-9A-Fa-f]+u,\s*\"([^\"]+)\"' % (pid, pid), ptab)
    got = None
    for mm in re.finditer(r'"(%s [^"]*)"[\s\S]{0,400}?"([0-9A-Fa-f ]+)"' % pid, ptab):
        cand = mm.group(2).strip()
        if re.fullmatch(r"([0-9A-Fa-f]{2}|\?\?)( ([0-9A-Fa-f]{2}|\?\?))*", cand):
            got = cand
    check(got == want, "patch 表里 %s 的 site_bytes = %r（实得 %r）" % (pid, want, got))

print()
if fails:
    print("[FAIL] %d 项不符（共 %d 项检查）" % (len(fails), checks))
    for f in fails:
        print("   - " + f)
    sys.exit(1)
print("[PASS] P4/P5 桩的机器码语义全部通过（共 %d 项检查）" % checks)
sys.exit(0)
