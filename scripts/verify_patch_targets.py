#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MonarchNameFix 补丁目标离线校验器

复刻 MonarchNameFix.dll 内部的同款逻辑（PE 解析 / 签名扫描 / RVA 交叉校验 /
原字节校验 / 跳转位移计算），在【不启动游戏】的前提下验证补丁定义是否仍然有效。

用法：
    python verify_patch_targets.py [目标 exe 路径]
默认目标：%EU4_GAME_DIR%\\eu4.exe
"""
import struct
import sys

DEFAULT_EXE = r"%EU4_GAME_DIR%\eu4.exe"

# 必须与 monarchnamefix.cpp 中保持一致
IMG_SIZE_EXPECT = 0x025E0000
IMG_TS_EXPECT = 1727949497
MASK_VALUE = 0x001FFFFF
CAVE_SIM_RVA = 0x03000000          # 仅用于模拟 rel32 计算

PATCHES = [
    dict(
        id="modfix_pick_idx WeightedNameList_PickByRandomIndex entry",
        sig="49 8B F8 8B F2 4C 8B D1 83 F8 01 75 ??",
        rva=0x00DA989B,
        resume_rva=0x00DA98A0,
        stub_len=16,
        stub_hex=(
            "49 8B F8"                    # mov rdi, r8
            " 81 E2 FF FF 1F 00"          # and edx, 001FFFFFh
            " 8B F2"                      # mov esi, edx
            " E9 00000000"                # jmp resume (placeholder)
        ),
    ),
    dict(
        id="modfix_pick_cult PickNameFromCultureLists modulo",
        sig="8B C7 99 41 F7 F8 3B D1 7D ??",
        rva=0x00280274,
        resume_rva=0x0028027A,
        stub_len=17,
        stub_hex=(
            "8B C7"                       # mov eax, edi
            " 25 FF FF 1F 00"             # and eax, 001FFFFFh
            " 31 D2"                      # xor edx, edx
            " 41 F7 F0"                   # div r8d
            " E9 00000000"
        ),
    ),
    dict(
        id="modfix_pick_modidx WeightedNameList_GetByModIndex modulo",
        sig="8B C2 99 41 F7 F8 48 8D 04 92 49 8D 04 C1 C3",
        rva=0x00DA9A82,
        resume_rva=0x00DA9A88,
        stub_len=17,
        stub_hex=(
            "8B C2"                       # mov eax, edx
            " 25 FF FF 1F 00"
            " 31 D2"
            " 41 F7 F0"
            " E9 00000000"
        ),
    ),
]


def parse_sig(text):
    b, m = [], []
    for tok in text.split():
        if tok == "??":
            b.append(0); m.append(0)
        else:
            b.append(int(tok, 16)); m.append(0xFF)
    return b, m


def scan(data, start, end, pat, mask):
    n = len(pat)
    last = end - n
    i = start
    while i <= last:
        j = 0
        while j < n:
            if mask[j] and data[i + j] != pat[j]:
                break
            j += 1
        if j == n:
            return i
        i += 1
    return None


def pe_parse(data):
    if data[:2] != b"MZ":
        raise SystemExit("not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("bad PE signature")
    machine, nsec, ts = struct.unpack_from("<HHI", data, e_lfanew + 4)
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    secs = []
    base = opt + opt_size
    for k in range(nsec):
        o = base + k * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vad, rsize, praw = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append(dict(name=name, vsize=vsize, vad=vad, rsize=rsize,
                         praw=praw, chars=chars))
    return dict(machine=machine, ts=ts, size_of_image=size_of_image,
                magic=magic, secs=secs)


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EXE
    with open(exe, "rb") as f:
        data = f.read()

    info = pe_parse(data)
    print("target   : %s" % exe)
    print("size     : %d bytes" % len(data))
    print("machine  : 0x%04X %s" % (info["machine"],
          "AMD64" if info["machine"] == 0x8664 else "?"))
    print("magic    : 0x%04X %s" % (info["magic"],
          "PE32+" if info["magic"] == 0x20B else "PE32"))
    print("TimeStamp: %d" % info["ts"])
    print("SizeOfImage: 0x%08X" % info["size_of_image"])

    fatal = []
    if info["machine"] != 0x8664:
        fatal.append("machine is not AMD64")
    if info["size_of_image"] != IMG_SIZE_EXPECT:
        fatal.append("SizeOfImage mismatch (want 0x%08X)" % IMG_SIZE_EXPECT)
    if info["ts"] != IMG_TS_EXPECT:
        fatal.append("TimeDateStamp mismatch (want %d)" % IMG_TS_EXPECT)

    text = [s for s in info["secs"] if s["chars"] & 0x20000000]
    if not text:
        fatal.append("no executable section")
    if fatal:
        print("\n[FAIL] fingerprint:")
        for f in fatal:
            print("   - %s" % f)
        return 2
    print("\n[OK] build fingerprint matches")

    # 文件偏移 <-> 虚拟地址（.text 的 raw/virtual 通常等值，仍按通用方式换算）
    def rva_to_off(rva):
        for s in info["secs"]:
            if s["vad"] <= rva < s["vad"] + max(s["vsize"], s["rsize"]):
                return s["praw"] + (rva - s["vad"])
        return None

    rc = 0
    for pt in PATCHES:
        print("\n--- %s" % pt["id"])
        pat, mask = parse_sig(pt["sig"])
        sec = text[0]
        start = sec["praw"]
        end = start + sec["vsize"]
        hit = scan(data, start, end, pat, mask)
        if hit is None:
            print("   [FAIL] pattern not found in %s" % sec["name"])
            rc = 1
            continue
        hit_rva = hit - sec["praw"] + sec["vad"]
        print("   found at file 0x%08X -> RVA 0x%08X" % (hit, hit_rva))
        if hit_rva != pt["rva"]:
            print("   [FAIL] RVA mismatch: got 0x%08X want 0x%08X" % (hit_rva, pt["rva"]))
            rc = 1
            continue
        print("   [OK] RVA matches")

        # 原字节校验（覆盖 5 字节）
        site = data[hit:hit + 5]
        want = bytes(pat[:5])
        if site != want:
            print("   [FAIL] site bytes %s != %s" % (site.hex(" "), want.hex(" ")))
            rc = 1
            continue
        print("   [OK] site bytes = %s" % site.hex(" "))

        # 模拟 stub 与两处跳转位移
        stub = bytes.fromhex(pt["stub_hex"].replace(" ", ""))
        if len(stub) != pt["stub_len"]:
            print("   [FAIL] stub_len %d != %d" % (len(stub), pt["stub_len"]))
            rc = 1
            continue
        cave_rva = CAVE_SIM_RVA
        # site: E9 rel32 -> cave
        rel1 = (cave_rva) - (pt["rva"] + 5)
        # stub tail jmp: E9 rel32 -> resume
        jmp_off = pt["stub_len"] - 5
        rel2 = pt["resume_rva"] - (cave_rva + jmp_off + 5)
        ok = (-0x80000000 <= rel1 <= 0x7FFFFFFF) and (-0x80000000 <= rel2 <= 0x7FFFFFFF)
        print("   stub (%d bytes): %s" % (len(stub), stub.hex(" ")))
        print("   jmp site->stub  rel32 = %d  (%s)" % (rel1, "in range" if ok else "OUT OF RANGE"))
        print("   jmp stub->resume rel32 = %d" % rel2)
        print("   resume RVA = 0x%08X" % pt["resume_rva"])
        rb = data[rva_to_off(pt["resume_rva"]):rva_to_off(pt["resume_rva"]) + 8]
        print("   resume bytes = %s" % rb.hex(" "))
        if not ok:
            print("   [FAIL] displacement out of range")
            rc = 1

    print("\n%s" % ("[PASS] all patch targets verified" if rc == 0
                    else "[FAIL] see above"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
