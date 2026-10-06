#!/usr/bin/env python3
"""
verify_nameorder_target.py — 把 monarchnamefix.cpp 里的整张补丁表逐条对着 eu4.exe 校验

动机：P4/P5 曾因两个 bug 在实机上装不上 ——
  ① 护栏拿"签名前 5 字节"比对站点，而签名里带 ?? 通配时 `!s.mask[i]` 必然判失败；
  ② site 直接取签名命中处，而 P4 的签名在函数开头、站点却在函数唯一出口。
这两个 bug 离线可见却被漏掉，因为此前只手工查过单个站点的字节。
本脚本改为**从源码解析整张表**，对每条补丁同时校验：
  - 签名在 .text 中命中，且命中 RVA == rva          （确认是同一个函数/同一处）
  - site_rva 处的原始字节与 site_bytes 逐字节相符     （确认站点没变）
  - resume_rva 处是 C3 (retn)                        （确认回跳点是返回指令）
  - cover >= 5（要放得下 E9 rel32）
本脚本只读文件，不做任何修改。
"""
import re
import struct
import sys
import pathlib
import hashlib

EXE = pathlib.Path(r"%REPO_ROOT%\binaries\eu4.exe")
SRC = pathlib.Path(r"%REPO_ROOT%\src\monarchnamefix\monarchnamefix.cpp")
SRC_DLL = pathlib.Path(r"%REPO_ROOT%\src\monarchnamefix\MonarchNameFix.dll")
DIST_DLL = pathlib.Path(r"%REPO_ROOT%\dist\MonarchNameFix.dll")

IMG_SIZE_EXPECT = 0x025E0000
IMG_TS_EXPECT = 1727949497


def sig_parse(tokens):
    b, m = [], []
    for t in tokens:
        if t in ("?", "??"):
            b.append(0); m.append(0)
        else:
            b.append(int(t, 16)); m.append(1)
    return bytes(b), bytes(m)


def sig_scan(data, pat, msk):
    n = len(pat)
    last = len(data) - n
    for i in range(last + 1):
        ok = True
        for k in range(n):
            if msk[k] and data[i + k] != pat[k]:
                ok = False
                break
        if ok:
            return i
    return None


def parse_patch_table(text):
    """从 g_patches[] 初始化列表里抽出每条补丁的关键字段。"""
    start = text.index("static const patch_t g_patches[]")
    body = text[start:]
    body = body[body.index("{"):]
    entries = []
    for m in re.finditer(r'\{\s*"([^"]+)"(.*?)\}\s*,', body, re.S):
        chunk = m.group(0)
        strs = re.findall(r'"([^"]*)"', chunk)
        hexu = re.findall(r'0x([0-9A-Fa-f]+)u', chunk)
        if len(strs) < 3 or len(hexu) < 3:
            continue
        rid, sig, site_bytes = strs[0], strs[1], strs[2]
        rva = int(hexu[0], 16)
        site_rva = int(hexu[1], 16)
        mm = re.search(r'0x([0-9A-Fa-f]+)u\s*,\s*(\d+)\s*,', chunk)
        if not mm:
            continue
        resume_rva = int(mm.group(1), 16)
        cover = int(mm.group(2))
        entries.append((rid, sig, rva, site_rva, site_bytes, resume_rva, cover))
    return entries


def stub_bytecode(text, comment_prefix):
    """从 nameorder.h 里抽出 P4/P5 桩构造器写出的【字节序列】。

    只按这两个函数实际使用的几种写法取值（不做通用解析，避免猜错）：
      - `dst[n++] = 0xNN;` / `dst[at] = 0xNN;` / `dst[at+K] = 0xNN;`  ⇒ 一个字节
      - `for (i = 0; i < 8; i++) ...`                                ⇒ 8 字节占位
      - `memcpy(dst+at+3, &rel, 4);`                                 ⇒ 4 字节占位
    位置敏感的写法（`dst[at]=0x4C; ... memcpy(dst+at+3,...,4)`）在同一行里
    先收 3 个字面量再补 4 个占位，顺序与真实产物一致。
    """
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if comment_prefix in l and "static uint32_t" in l)
    vals = []
    stopped = False
    for l in lines[start:]:
        if "return n;" in l:
            stopped = True
            break
        if "for (i = 0; i < 8; i++)" in l:
            vals.extend([0] * 8)
            continue
        # 同一行里的字面量赋值（`dst[n++] = 0xNN;` 或 `dst[at+1] = 0xNN;`）
        lits = re.findall(r"dst\[[^\]]+\]\s*=\s*0x([0-9A-Fa-f]{2});", l)
        vals.extend(int(x, 16) for x in lits)
        # 同一行/下一行的 disp32 占位
        if "memcpy(" in l:
            vals.extend([0] * 4)
    if not stopped:
        raise AssertionError("没能解析 %s 的字节序列" % comment_prefix)
    return bytes(vals)


def rsp_balance(stub, entry_rsp, trace=False):
    """对生成的桩字节做一次只跟踪 rsp 的小模拟，返回 (跳回时的 rsp, 调用点偏移, 失败原因)。

    只识别桩里实际用到的这几条形态（其余指令不影响 rsp）；任何未知形态都直接报错，
    以免"看不懂就当通过"。

    entry_rsp = **桩入口处**的 rsp 取值：
      - P4 挂在 BuildFullName_Impl 的出口、由我们自己的 `jmp` 进入 ⇒ 入口 rsp 就是
        被挂钩函数此刻的 rsp，实测 ≡ 0 (mod 16)；
      - P5 挂在 CLeader_SetName 的**入口**、由游戏的 `call` 进入 ⇒ 入口 rsp ≡ 8 (mod 16)。
    两条不变量：
      ① 桩内 `call <变换函数>` 处 rsp ≡ 0 (mod 16)
         （这样被调用者入口看到 ≡ 8，符合 x64 ABI）；
      ② 跳回 resume 时 rsp == entry_rsp（一分不多一分不少）。

    【坑】不要把 rsp 当无符号数去 `& 0xFFFF...`：一旦变成负数，Python 的 `%` 会掩盖
    错位。直接用有符号整数累加，最后比 rsp % 16 即可。"""
    rsp = entry_rsp
    call_off = None
    i = 0
    n = len(stub)
    while i < n:
        b = stub[i]
        if trace:
            print("    +%-3d %02X%02X rsp%%16=%d" % (i, b, stub[i + 1] if i + 1 < n else 0,
                                                    rsp % 16))
        # 41 50..57 : push r8..r15
        if b == 0x41 and 0x50 <= stub[i + 1] <= 0x57:
            rsp -= 8
            i += 2
            continue
        # 41 58..5F : pop r8..r15
        if b == 0x41 and 0x58 <= stub[i + 1] <= 0x5F:
            rsp += 8
            i += 2
            continue
        # 50..57 : push r64（单字节形态，必须放在 0x41 前缀判断【之后】）
        if b in (0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57):
            rsp -= 8
            i += 1
            continue
        # 5B/5D/5E/5F : pop rbx/rbp/rsi/rdi
        if b in (0x5D, 0x5F, 0x5E, 0x5B):
            rsp += 8
            i += 1
            continue
        # 48 83 EC ib : sub rsp, imm8
        if b == 0x48 and stub[i + 1] == 0x83 and stub[i + 2] == 0xEC:
            rsp -= stub[i + 3]
            i += 4
            continue
        # 48 83 C4 ib : add rsp, imm8
        if b == 0x48 and stub[i + 1] == 0x83 and stub[i + 2] == 0xC4:
            rsp += stub[i + 3]
            i += 4
            continue
        # FF D0 : call rax（桩内唯一一次调用，检查调用点对齐）
        if b == 0xFF and stub[i + 1] == 0xD0:
            if rsp % 16 != 0:
                return None, None, "call 处 rsp≡%d (mod 16)，应为 0" % (rsp % 16)
            call_off = i
            i += 2
            continue
        # E9 rel32 : jmp resume
        if b == 0xE9:
            i += 5
            continue
        # 48 B8 imm64 : mov rax, imm64
        if b == 0x48 and stub[i + 1] == 0xB8:
            i += 10
            continue
        # 48/4C 8D /r : lea r64, m  —— 只要识别出「mov [rip+d], r64」（mod=00,rm=101）
        if b in (0x48, 0x4C) and stub[i + 1] == 0x8D and (stub[i + 2] >> 6) == 0 \
                and (stub[i + 2] & 7) == 5:
            i += 7
            continue
        # 48/4C 89/8B + ModRM
        if b in (0x48, 0x4C) and stub[i + 1] in (0x89, 0x8B):
            modrm = stub[i + 2]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 3:
                i += 3                       # mov r64, r64
            elif mod == 0 and rm == 5:
                i += 7                       # mov [rip+d], r64 / mov r64, [rip+d]
            elif mod == 2:
                i += 7                       # mov r64, [reg+disp32]（无 SIB，如 [rdx+88h]）
            elif mod == 0 and rm == 4:
                i += 4                       # [rsp]（有 SIB，无位移）——本桩用不到
            elif mod == 1 and rm == 4:
                i += 5                       # [rsp+disp8]（SIB）——本桩用不到
            else:
                return None, None, "未识别的 ModRM %02X @+%d" % (modrm, i)
            continue
        return None, None, "遇到未识别的字节 %02X @+%d" % (b, i)

    return rsp, call_off, None


def load_stub_fixture():
    """读取 src\\monarchnamefix\\stubbytes.txt（由 build_stubdump.bat 用**真正的
    桩构造器**生成）。返回 {tag: bytes}。

    为什么不解析 nameorder.h：那要复现 `dst[n++]=...` / `dst[at+K]=...` /
    `memcpy` 占位 / imm64 循环四种写法，极易错位——本仓库真实发生过两次
    （漏掉 disp32 的 4 字节、把 imm64 循环体里的 0x8 当成一个字节），
    结果把"栈收支"误判成不平衡。用真构造器的产物当基准最可靠。"""
    p = pathlib.Path(r"%REPO_ROOT%\src\monarchnamefix\stubbytes.txt")
    if not p.exists():
        return None
    out = {}
    lines = [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    i = 0
    while i < len(lines):
        tag, length = lines[i].split()
        body = lines[i + 1].split()
        assert int(length) == len(body), "stubbytes.txt 中 %s 的长度与字节数不符" % tag
        out[tag] = bytes(int(b, 16) for b in body)
        i += 2
    return out


def stub_actions(stub):
    """把桩的字节序列拆成 [(偏移, 动作)]。

    动作 ∈ {"push", "pop", "subN", "addN", "call", "other"}。
    只认桩里实际会出现的形态；任何别的字节立刻报错——**不做通用反汇编**：
    手写模拟器的出错概率比被测代码还高（这个教训在 p4stubtest 上真实发生过）。
    """
    out = []
    i = 0
    n = len(stub)
    while i < n:
        b = stub[i]
        nxt = stub[i + 1] if i + 1 < n else 0
        if b in (0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57):
            out.append((i, "push")); i += 1; continue
        if b in (0x58, 0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F):
            out.append((i, "pop")); i += 1; continue
        if b == 0x41 and 0x50 <= nxt <= 0x57:
            out.append((i, "push")); i += 2; continue
        if b == 0x41 and 0x58 <= nxt <= 0x5F:
            out.append((i, "pop")); i += 2; continue
        if b == 0x48 and nxt == 0x83 and stub[i + 2] == 0xEC:
            out.append((i, "sub%d" % stub[i + 3])); i += 4; continue
        if b == 0x48 and nxt == 0x83 and stub[i + 2] == 0xC4:
            out.append((i, "add%d" % stub[i + 3])); i += 4; continue
        if b == 0xFF and nxt == 0xD0:
            out.append((i, "call")); i += 2; continue
        if b == 0xE9:
            out.append((i, "other")); i += 5; continue
        # ★ 条件跳转 rel32（0F 80..8F）—— P7 要在 cave 里重放 `jle 0x314285`
        #   （站点 0x314228 覆盖了它）。它不改 rsp，故归入 "other"。
        if b == 0x0F and 0x80 <= nxt <= 0x8F:
            out.append((i, "other")); i += 6; continue
        # 条件跳转 rel8（70..7F）—— 同样不改 rsp
        if 0x70 <= b <= 0x7F:
            out.append((i, "other")); i += 2; continue
        # nop（0x90）—— P10 的 jmp 后填充用到
        if b == 0x90:
            out.append((i, "other")); i += 1; continue
        # mov r/m32, imm32（B8+rd，无 REX）—— 5 字节
        if 0xB8 <= b <= 0xBF:
            out.append((i, "other")); i += 5; continue
        # mov r64, imm64（REX.W + B8+rd）—— 10 字节（P7 新增 `49 B8` = mov r8, imm64）
        if b in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= nxt <= 0xBF:
            out.append((i, "other")); i += 10; continue
        if b == 0x85 and (nxt >> 6) == 3:
            out.append((i, "other")); i += 2; continue
        # xor r/m32, r32（寄存器形式）—— P8 重放 `xor ebx,ebx` / `xor esi,esi`
        #   （33 /r 与 31 /r 语义等价，编译器选了 33）
        if b in (0x31, 0x33) and (nxt >> 6) == 3:
            out.append((i, "other")); i += 2; continue
        if b == 0x48 and nxt == 0xB8:
            out.append((i, "other")); i += 10; continue
        if b in (0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D, 0x4E, 0x4F) and nxt == 0x8D:
            modrm = stub[i + 2]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 0 and rm == 5:
                out.append((i, "rip_lea")); i += 7; continue
            if rm == 4:
                # SIB 形式：mod=1 → disp8（5 字节），mod=2 → disp32（8 字节）
                #   ★ mod=0 也常见（如 P7 的 `49 8D 14 18` = lea rdx,[r8+rbx]，
                #     共 4 字节）；此时 SIB.base==5 才表示 disp32（无基址）。
                if mod == 0:
                    base = stub[i + 3] & 7
                    out.append((i, "other")); i += (8 if base == 5 else 4); continue
                if mod == 1:
                    out.append((i, "other")); i += 5; continue
                if mod == 2:
                    out.append((i, "other")); i += 8; continue
            # ★ 非 SIB 的 disp8/disp32 形式（P8 的 `44 8D 6E FF` = lea r13d,[rsi-1]，
            #   ModRM=0x6E ⇒ mod=1, rm=6）
            if mod == 1:
                out.append((i, "other")); i += 4; continue
            if mod == 2:
                out.append((i, "other")); i += 7; continue
            return None, "未识别的 lea ModRM %02X @+%d" % (modrm, i)
        # ★ RIP 相对【写】内存（mov [rip+d], r64 / mov [rip+d], r32）
        #   桩的代码页在安装期被 VirtualProtect 成 PAGE_EXECUTE_READ，不可写，
        #   所以这类指令必然在实机触发 ACCESS_VIOLATION —— 2026-10-03 崩溃根因。
        #   标成 RIP_WRITE 让 check_stub_stack 一眼发现。
        if b in (0x48, 0x49, 0x4C, 0x4D) and nxt in (0x89, 0x88) and (stub[i + 3 - 1] & 0xC7) == 0x05:
            out.append((i, "RIP_WRITE")); i += 7; continue
        if b in (0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D, 0x4E, 0x4F) and nxt in (0x89, 0x8B):
            modrm = stub[i + 2]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 3:
                ln = 3
            elif mod == 0 and rm == 5:
                ln = 7
            elif mod == 2:
                ln = 7
            elif mod == 0 and rm == 4:
                ln = 4
            elif mod == 1 and rm == 4:
                ln = 5
            elif mod == 1:
                ln = 4                       # ★ rbp/r13 + disp8（P8 的 mov rcx,[rbp-58h]）
            else:
                return None, "未识别的 ModRM %02X @+%d" % (modrm, i)
            out.append((i, "other")); i += ln; continue
        # ★ `0F 10/11 /r` = movups/movsd xmm, xmm/m —— P10 重放的 `0F 10 44 24 30`
        #   （ModRM 0x44 ⇒ mod=1, reg=0, rm=4=SIB；SIB 0x24 ⇒ base=rsp；disp8 = 0x30）
        if b == 0x0F and nxt in (0x10, 0x11):
            modrm = stub[i + 2]
            mod = modrm >> 6
            rm = modrm & 7
            # 长度 = 2(0F xx) + 1(ModRM) [+1 SIB] [+disp8/4]
            if mod == 3:
                ln = 3
            elif mod == 0 and rm == 4:
                ln = 4
            elif mod == 0 and rm == 5:
                ln = 7
            elif mod == 0:
                ln = 3
            elif mod == 1 and rm == 4:
                ln = 5                       # ★ 0F 10 44 24 30（P10 重放的那条）
            elif mod == 1:
                ln = 4
            elif mod == 2 and rm == 4:
                ln = 8
            elif mod == 2:
                ln = 7
            else:
                ln = 3
            out.append((i, "other")); i += ln; continue
        # ★ `83 /7 ib` = cmp r/m32, imm8 —— P10 的 `83 38 00` = cmp dword ptr [rax], 0
        if b == 0x83:
            modrm = stub[i + 1]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 3:
                ln = 3
            elif mod == 1:
                ln = 4
            elif mod == 2:
                ln = 7
            elif rm == 4:
                ln = 4 if mod == 0 else 5
            elif rm == 5 and mod == 0:
                ln = 7
            else:
                ln = 3                       # mod=0 且 rm != 4/5
            out.append((i, "other")); i += ln; continue
        # ★ REX 前缀 + xor（P10 的 `45 31 C0` = xor r8d, r8d）
        if b in (0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                 0x4C, 0x4D, 0x4E, 0x4F) and nxt in (0x31, 0x33):
            out.append((i, "other")); i += 3; continue
        # ★ `C7 /0 id` = mov r/m32, imm32 —— P8 重放的那条被覆盖指令
        #   `C7 45 B0 01 00 00 00` = mov dword ptr [rbp-50h], 1
        #   （ModRM 0x45 ⇒ mod=1, reg=0, rm=5=rbp ⇒ disp8 + imm32 = 7 字节）
        if b == 0xC7:
            modrm = stub[i + 1]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 1:
                out.append((i, "other")); i += 7; continue    # disp8  + imm32
            if mod == 2:
                out.append((i, "other")); i += 10; continue   # disp32 + imm32
            if mod == 0 and rm == 5:
                out.append((i, "other")); i += 10; continue   # RIP + imm32
            if mod == 0 and rm == 4:
                out.append((i, "other")); i += 7; continue    # SIB + imm32
            if mod == 0:
                out.append((i, "other")); i += 6; continue    # disp0 + imm32
            if mod == 3:
                out.append((i, "other")); i += 6; continue    # reg + imm32
            return None, "未识别的 C7 ModRM %02X @+%d" % (modrm, i)
        return None, "遇到未识别的字节 %02X @+%d" % (b, i)
    return out, None


def check_stub_stack(text):
    """静态核对 P4/P5 动态桩的「调用点栈对齐」与「跳回时栈位置」。

    动机（只看打完补丁的二进制发现不了）：
      桩在 `sub rsp,8` 与 `call` 之间还会 push 参数，回收时必须与压入一一对应，
      否则**调用点 rsp 就对不齐 16 字节**（被调用者入口会看到错的模值，一旦它用
      movaps 碰栈立刻崩），末尾重放的 3 个 pop 也会取到错误的值。

    判定用两条，都由桩自身的字节算：
      ① 桩内 `call <变换函数>` **执行前** rsp ≡ 0 (mod 16)。
         x64 ABI 要求"被调用者入口 rsp ≡ 8 (mod 16)"，等价于 call 前 rsp ≡ 0；
         call 压入的返回地址由被调用者的 ret 收回，净影响为 0。
      ② 跳回 resume 时 rsp 比入口**高 24 字节**（仅 P4）。
         桩末尾重放的 pop r15 / pop r14 / pop rbp 吃掉的是被挂钩函数留在出口处的
         3 个值（24 字节），所以它**回不到**入口值；这个 +24 是设计的一部分。
         真正要防的是它变成 +32（多回收 8 ⇒ 重放与回读全错）。

    桩入口 rsp 取决于是"怎么进来的"：
      - P4 挂在 BuildFullName_Impl 的**出口**、由我们自己的 `jmp` 进入 ⇒ 入口 rsp
        就是该函数此刻的 rsp。该函数入口 ≡ 8，序言 sub 48h(−8) + 3 个 push(−24)
        ⇒ 出口处 ≡ 0 (mod 16)。
      - P5 挂在 CLeader_SetName 的**入口**、由游戏的 `call` 进入 ⇒ 入口 ≡ 8。
    """
    print()
    print("== 动态桩的调用点对齐与跳回栈位置（P4 / P5） ==")
    fixtures = load_stub_fixture()
    if not fixtures:
        print("  [x] 找不到 src\\monarchnamefix\\stubbytes.txt")
        print("      （请先运行 src\\monarchnamefix\\build_stubdump.bat 生成它）")
        return False

    bad = 0
    for name, entry_rsp, want_delta, how in (
            # 期望的"跳回时 rsp − 入口 rsp"：
            #   P4 = 24：站点在 BuildFullName_Impl 的**函数出口**，桩末尾连做
            #            3 个 `pop`（r15/r14/rbp）吃掉入口处的 3 个槽，正好 +24。
            #            24 是"恰好"值 —— 曾因多一条 `add rsp,8` 变成 32，
            #            写回槽位整体偏移并污染 r14/rbp，实机跳到野地址。
            #   P5 = 0 ：sub/add rsp 严格对称，不重放任何 pop。
            ("P4", 0, 24, "自己的 jmp 进入（BuildFullName_Impl 出口，重放 3 个 pop 并归还结果）"),
            ("P5", 8, 0, "游戏的 call 进入（CLeader_SetName 入口）"),
            #   P8 = 0 ：站点在 CMonarch_GetFullName（0x140A4B2C0）里 `call StringAppend`
            #            刚返回处；序言为 `mov [rsp+..],reg`×2（不动 rsp）+ 3 push +
            #            mov rbp,rsp + sub rsp,70h ⇒ 入口 ≡8，3 push 后 ≡0，
            #            sub 112(≡0) 后仍 ≡0；桩是 8 push + 8 pop 严格对称。
            #   （P7/P10 已重新启用为"生成阶段两套逻辑"方案，见下方说明。）
            #   P7 = 0 ：站点在 BuildFullName_Impl 循环【之前】；序言 3 push + sub rsp,110h
            #            ⇒ 入口 ≡8、3 push 后 ≡0、sub 272(≡0) 后仍 ≡0；桩是 8 push + 8 pop。
            ("P7", 0, 0, "自己的 jmp 进入（BuildFullName_Impl 循环前，按文化先写姓）"),
            #   P10 = 0：站点在 `call StringAppend` 之前（0x3142F2）；同一函数、同一栈状态；
            #            桩是 4 push + 4 pop（32 ≡ 0），只把 r8（姓字节数）交给 C 侧。
            ("P10", 0, 0, "自己的 jmp 进入（BuildFullName_Impl 里，存下姓的字节数）"),
            #   P11 = 0：站点在 StringAppend 刚返回处（0x3142FC），把 Src 重排成「姓+sep+名」。
            ("P11", 0, 0, "自己的 jmp 进入（BuildFullName_Impl 里，按文化重排）"),
            ("P8", 0, 0, "自己的 jmp 进入（CMonarch_GetFullName 里，统治者/继承人/配偶）")):
        stub = fixtures.get(name)
        if stub is None:
            print("  [x] stubbytes.txt 里没有 %s" % name)
            bad += 1
            continue
        acts, err = stub_actions(stub)
        if err:
            print("  [x] %s 桩解析失败（%d 字节）：%s" % (name, len(stub), err))
            bad += 1
            continue

        # ① 硬约束：桩不得 RIP 相对写内存（代码页是 PAGE_EXECUTE_READ，
        #    写了就 ACCESS_VIOLATION —— 这正是 2026-10-03 实机崩溃的根因）
        rip_writes = [o for o, a in acts if a == "RIP_WRITE"]
        if rip_writes:
            print("  [x] %s 桩含 %d 处 RIP 相对【写】内存（偏移 %s）——"
                  "代码页在安装期被设成 PAGE_EXECUTE_READ，实机必然 ACCESS_VIOLATION"
                  % (name, len(rip_writes), [hex(x) for x in rip_writes]))
            bad += 1
            continue

        rsp = entry_rsp
        call_off = None
        call_bad = None
        for off, act in acts:
            if act == "push":
                rsp -= 8
            elif act == "pop":
                rsp += 8
            elif act.startswith("sub"):
                rsp -= int(act[3:])
            elif act.startswith("add"):
                rsp += int(act[3:])
            elif act == "call":
                call_off = off
                if rsp % 16 != 0:
                    call_bad = rsp % 16
        if call_bad is not None:
            print("  [x] %s 桩：`call` @+%d **执行前** rsp≡%d (mod 16)，应为 0"
                  "（被调用者入口必须是 8）" % (name, call_off, call_bad))
            bad += 1
        elif rsp - entry_rsp != want_delta:
            print("  [x] %s 桩：跳回时 rsp 比入口高 %d 字节，应为 %d"
                  "（24 个字节来自桩重放的 3 个 pop；再 +8 是"
                  "`mov [rsp]/[rsp+8]` 把结果与文化交还给被挂钩函数所需"
                  "——它等价于重放第 4 个 pop，不多不少）"
                  % (name, rsp - entry_rsp, want_delta))
            bad += 1
        else:
            n_push = sum(1 for _o, a in acts if a == "push")
            n_pop = sum(1 for _o, a in acts if a == "pop")
            if call_off is None:
                # 纯跳转桩（如 P10：桩体就是一条 E9 jmp，不调用任何东西）
                print("  [v] %s 桩（%d 字节，%s）：不含 `call`（纯跳转）、"
                      "跳回时 rsp 与入口一致（净变化 0）、push×%d / pop×%d"
                      % (name, len(stub), how, n_push, n_pop))
            else:
                print("  [v] %s 桩（%d 字节，%s）：`call` @+%d 执行前 rsp≡0 (mod 16)、"
                      "跳回时比入口高 %d 字节（符合设计）、push×%d / pop×%d"
                      % (name, len(stub), how, call_off, rsp - entry_rsp, n_push, n_pop))
    return bad == 0


def main():
    for p, what in ((EXE, "eu4.exe"), (SRC, "monarchnamefix.cpp")):
        if not p.exists():
            print("[x] 找不到 %s" % what)
            return 2

    # ★ 产物一致性：src\ 里刚编译出来的 DLL 与 dist\ 里准备部署的必须同一个二进制。
    #   踩过的坑：一次链接失败（LNK1104，DLL 被占用）让 `Copy-Item src->dist` 没执行，
    #   之后重跑构建却忘了同步 —— 我照旧把 src 当作"已部署"，于是拿旧 dist 的
    #   cover=8 去实机跑，回跳落进 lea 内部又崩一次。这里直接比 SHA256。
    if SRC_DLL.exists() and DIST_DLL.exists():
        a = hashlib.sha256(SRC_DLL.read_bytes()).hexdigest()
        b = hashlib.sha256(DIST_DLL.read_bytes()).hexdigest()
        if a != b:
            print("[x] src\\ 与 dist\\ 的 MonarchNameFix.dll 不是同一个二进制！")
            print("    src  = %s" % a)
            print("    dist = %s" % b)
            print("    => 先在 src\\monarchnamefix 跑 build.bat，再 Copy-Item 到 dist\\，然后重新校验")
            return 2
        print("[OK] src\\ 与 dist\\ 的 DLL 一致（%s…）" % a[:16])
    else:
        print("[!] 跳过产物一致性检查（src 或 dist 的 DLL 不存在）")

    d = EXE.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    size_of_image = struct.unpack_from("<I", d, opt + 0x38)[0]
    timestamp = struct.unpack_from("<I", d, pe + 0x08)[0]
    secs = []
    for i in range(nsec):
        o = opt + osz + i * 40
        nm = d[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, pr = struct.unpack_from("<IIII", d, o + 8)
        secs.append((nm, va, vs, rs, pr))

    # ★ 这个 eu4.exe 构建里，段头的 PointerToRawData / SizeOfRawData 是**互换存放**的
    #   （.text 写成 raw=0x1b64e00, rawsize=0x400）。若按标准语义读，所有 RVA 换算
    #   都会错位几百字节，校验结果全是假的（曾据此误判 0x31432b 不是 `mov rax,rdi`）。
    #   这里用"段起点是否像 PE 镜像"来自动判定两种语义，选对的那个。
    def looks_like_image(start):
        return 0 <= start <= len(d) - 2 and d[start:start + 2] == b"MZ"

    tname, tva, tvs, trs, tpr = next(s for s in secs if s[0] == ".text")
    # 标准语义：raw=trs, rawsize=tpr ；互换语义：rawsize=trs, raw=tpr
    std_ok = looks_like_image(trs)
    swap_ok = looks_like_image(tpr)
    if swap_ok and not std_ok:
        swapped = True
    elif std_ok and not swap_ok:
        swapped = False
    else:
        # 两个都像/都不像时，用"哪一对更像镜像大小"兜底：rawsize 应 ≈ 0x1b64e00
        swapped = (trs > 0x1000000 and tpr < 0x1000000)
    print("段头语义：%s（.text raw=%#x rawsize=%#x）"
          % ("PointerToRawData/SizeOfRawData 互换" if swapped else "标准",
             tpr if swapped else trs, trs if swapped else tpr))

    def raw_of(sec):
        nm, va, vs, rs, pr = sec
        return (pr, rs) if swapped else (rs, pr)

    raw, rawsize = raw_of((tname, tva, tvs, trs, tpr))
    if rawsize < tvs:
        print("[x] .text 段声明大小 %#x < 虚拟大小 %#x，映射可疑" % (rawsize, tvs))

    print("eu4.exe  SizeOfImage=%#x  TimeDateStamp=%d  .text raw=%#x rawsize=%#x"
          % (size_of_image, timestamp, raw, rawsize))
    if size_of_image != IMG_SIZE_EXPECT or timestamp != IMG_TS_EXPECT:
        print("[x] 构建指纹不匹配 —— 放弃")
        return 1
    print("[OK] 构建指纹匹配\n")

    def at_rva(r, n):
        off = raw + (r - tva)
        return d[off:off + n]

    entries = parse_patch_table(SRC.read_text(encoding="utf-8"))
    print("从源码解析到 %d 条补丁\n" % len(entries))

    ok_all = True
    print("%-40s %-11s %-11s %-6s %s" % ("补丁", "签名命中", "站点RVA", "cover", "结论"))
    print("-" * 100)
    for rid, sig, rva, site_rva, site_bytes, resume_rva, cover in entries:
        notes = []
        good = True

        pat, msk = sig_parse(sig.split())
        hit = sig_scan(d[raw:raw + min(rawsize, len(d) - raw)], pat, msk)
        hit_rva = (tva + hit) if hit is not None else None
        # ★★ 判据修正（2026-10-04）：
        #   原判据要求"sig 的【首次】命中恰好落在 rva"，但某些模式在 exe 里天然重复
        #   （例如 P10 的 `lea rcx,[rsp+30] E8 ??.. 0F 10 44 24 30`），首次命中可能在别处，
        #   而被挂钩的那个站点本身完全正常。
        #   正确语义是：**期望的 rva 处必须匹配 sig**。所以改为从 rva 起扫，
        #   要求偏移 0 命中；同时仍保留"整段命中必须存在"的检查。
        if hit is None:
            notes.append("签名未命中"); good = False
        else:
            off_at_rva = rva - tva
            if off_at_rva < 0 or off_at_rva + len(pat) > len(d) - raw:
                notes.append("签名命中 RVA %#x != 期望 %#x（期望处越界）"
                             % (hit_rva, rva)); good = False
            else:
                at = sig_scan(d[raw + off_at_rva:raw + off_at_rva + len(pat) + 64], pat, msk)
                if at != 0:
                    notes.append("期望站点 RVA %#x 处不匹配签名（首次命中在 %#x）"
                                 % (rva, hit_rva if hit_rva is not None else 0))
                    good = False

        sb, sm = sig_parse(site_bytes.split())
        actual = at_rva(site_rva, max(cover, len(sb)))
        # ★ 硬断言：site_bytes 的字节数必须 >= cover。
        #   实机 prepare_one 的护栏循环是 `for (i = 0; i < pt->cover; i++)`，
        #   拿 sb.bytes[i] 逐字节比。若字符串比 cover 短，就会**越界读未初始化的
        #   栈内存**，护栏随机性地把正确站点判成"original bytes mismatch"。
        #   实际踩过：P4 cover=11 而字符串只有 10 字节、P5 cover=6 而只有 5 字节 ——
        #   实机日志出现 "[!] original bytes mismatch: P4 site=0x31432b"、4/5 applied。
        #   （本验证器此前用 min(cover, len(sb)) 静默容忍了它，所以没能提前发现。）
        if len(sb) < cover:
            notes.append("site_bytes 只有 %d 字节 < cover=%d —— 实机护栏会越界读！"
                         % (len(sb), cover))
            good = False
        for k in range(min(cover, len(sb))):
            if sm[k] and actual[k] != sb[k]:
                notes.append("站点第 %d 字节 %02X != %02X" % (k, actual[k], sb[k]))
                good = False
                break

        # ★ 回归断言：resume 必须落在【真实指令边界】上，且跳转不能落进被覆盖指令的中间。
        #   踩过的两个坑：
        #     ① 安装代码曾用 `resume = base + resume_rva`。P1-P3/P5 的 resume_rva 恰好
        #        等于「cave 内位移」，base 加出来碰巧落在 cave 里；而 P4 的 resume_rva 是
        #        函数内真实 RVA（0x314330），base + 0x314330 = 0x7ff7bb6b4330 —— 飞出去了。
        #        桩末尾的 E9 一跳即崩（实机报 cave+0x307，即 jmp 之后的位置）。
        #     ② 改成 `resume = site + cover` 后，P4 的 cover=5 让 resume 落进 `lea` 的
        #        disp32 中间（0x314330 = 9C 24 …）—— 指令被劈成两半，跳进去是垃圾指令流。
        #        所以 cover 必须是 8（覆盖整条 lea），resume = 0x314336（mov rbx 起点）。
        #   现在的判据：resume_rva ∈ [site_rva+cover, site_rva+cover+7]，且必须是
        #   一个合法指令的起点（用独立边界表核对，见下）。
        lo = site_rva + cover
        # （P7/P10 已废弃移除，"跳跃式 resume"的例外也随之取消 —— 现在所有在用补丁
        #   的 resume 都落在 [site+cover, +7] 内。P8 的 resume 就是 site+cover。）
        if not (lo <= resume_rva <= lo + 7):
            notes.append("resume_rva(%#x) 不在 [site+cover, +7] = [%#x, %#x] 内"
                         % (resume_rva, lo, lo + 7))
            good = False

        # 回跳点判据：
        #  - 出口型站点（补丁打在函数尾部、覆盖 pop/ret）⇒ 回跳点必须是 retn；
        #  - P4 现在挂在**函数体内**的 `mov rax,rdi`（0x31432B），回跳点是
        #    `lea r11,[rsp+110h]`（尾声开头）⇒ 用它的真实字节单独校验；
        #  - 其余站点在函数中间/入口 ⇒ 只要求它仍落在同一函数附近。
        rb = at_rva(resume_rva, 4)
        if rid.startswith("P4"):
            # 回跳点 = 0x31434E，原 `retn`（出口型站点）
            if rb[0] != 0xC3:
                notes.append("P4 回跳点应为 retn(C3)，实为 %02X" % rb[0])
                good = False
        elif site_rva != rva and rb[0] != 0xC3:
            notes.append("出口型站点但回跳处 %02X 非 C3" % rb[0]); good = False
        if abs(resume_rva - rva) > 0x1000:
            notes.append("回跳点距签名命中处 %#x 过远" % abs(resume_rva - rva)); good = False

        # ★ cover 必须 >= 5：hook_one 写的是 `E9 rel32`（5 字节）。
        #   曾经放宽到 4，结果 P10（覆盖的 lea 是 5 字节）只护住前 4 字节 ⇒
        #   第 5 字节未改写 ⇒ E9 的 rel32 残缺 ⇒ 实机 C000001D @ RVA 0x3142F6。
        if cover < 5:
            notes.append("cover<5（放不下 E9 rel32）"); good = False

        print("%-40s %-11s %-11s %-6d %s" % (
            rid[:40],
            ("%#x" % hit_rva) if hit_rva is not None else "—",
            "%#x" % site_rva, cover,
            "OK" if good else "FAIL: " + "; ".join(notes)))
        ok_all = ok_all and good

    print()
    if ok_all:
        ok_all = check_stub_stack(pathlib.Path(
            r"%REPO_ROOT%\src\monarchnamefix\nameorder.h"
        ).read_text(encoding="utf-8"))
    print()
    print("[PASS] 补丁表全部条目通过静态校验" if ok_all else "[FAIL] 存在未通过条目")
    return 0 if ok_all else 1

if __name__ == "__main__":
    sys.exit(main())
