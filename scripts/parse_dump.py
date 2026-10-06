# -*- coding: utf-8 -*-
"""解析 EU4 崩溃的 minidump：取异常记录 + 寄存器上下文，并尝试手工走栈。

用法：python parse_dump.py <minidump路径>
"""
import struct
import sys

STREAM_NAMES = {
    3: "ThreadListStream",
    4: "ModuleListStream",
    5: "MemoryListStream",
    6: "ExceptionStream",
    7: "SystemInfoStream",
    9: "Memory64ListStream",
    11: "MiscInfoStream",
    12: "MemoryInfoListStream",
    13: "ThreadInfoListStream",
    16: "HandleDataStream",
    17: "UnloadedModuleListStream",
}


def main(path):
    data = open(path, "rb").read()
    print("dump 大小 = %d 字节" % len(data))

    sig, ver, nstreams, dirrva = struct.unpack_from("<4sIII", data, 0)
    print("signature=%r  version=%#x  streams=%d  dir=%#x" % (sig, ver, nstreams, dirrva))

    streams = []
    for i in range(nstreams):
        t, sz, rva = struct.unpack_from("<III", data, dirrva + i * 12)
        streams.append((t, sz, rva))

    print("\n=== 流列表 ===")
    for t, sz, rva in streams:
        print("  type=%-3d %-26s size=%-9d rva=%#x" % (t, STREAM_NAMES.get(t, "?"), sz, rva))

    # ---- 异常流 ----
    exc = [s for s in streams if s[0] == 6]
    if not exc:
        print("\n没有 ExceptionStream")
        return
    _, _, rva = exc[0]
    tid, _align = struct.unpack_from("<II", data, rva)
    (code, flags, rec, addr, nparam, _u) = struct.unpack_from("<IIQQII", data, rva + 8)
    print("\n=== 异常 ===")
    print("  ThreadId        = %#x" % tid)
    print("  ExceptionCode   = %#x" % code)
    print("  ExceptionAddress= %#x" % addr)
    print("  NumberParams    = %d" % nparam)
    info = struct.unpack_from("<15Q", data, rva + 8 + 40)
    kinds = ["读", "写", "执行"]
    for i in range(min(nparam, 15)):
        label = kinds[info[0]] if (info[0] < 3 and i == 0) else ""
        print("    info[%d] = %#x %s" % (i, info[i], label))

    csz, crva = struct.unpack_from("<II", data, rva + 8 + 152)
    print("  Context: size=%d rva=%#x" % (csz, crva))
    if csz < 0x100:
        print("  上下文不可用")
        return
    ctx = data[crva:crva + csz]
    names = ["Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip"]
    regs = {}
    off = 0x78
    for n in names:
        (v,) = struct.unpack_from("<Q", ctx, off)
        regs[n] = v
        off += 8
    print("\n=== 寄存器 ===")
    for n in names:
        print("  %-4s = %#018x" % (n, regs[n]))

    # ---- 找栈内存 ----
    ranges = []          # (start, end, file_offset)
    for t, sz, s_rva in streams:
        if t == 5:       # MemoryListStream
            (n,) = struct.unpack_from("<I", data, s_rva)
            for i in range(n):
                st, msz, mrva = struct.unpack_from("<QII", data, s_rva + 4 + i * 16)
                ranges.append((st, st + msz, mrva))
        elif t == 9:     # Memory64ListStream
            n, base = struct.unpack_from("<QQ", data, s_rva)
            cur = s_rva + 16
            for i in range(n):
                st, msz = struct.unpack_from("<QQ", data, cur)
                cur += 16
                ranges.append((st, st + msz, base))
                base += msz
    print("\n=== 内存范围 %d 段 ===" % len(ranges))
    for st, en, fo in ranges[:25]:
        print("  %#x .. %#x  (%d 字节)" % (st, en, en - st))

    def read(addr, n):
        for st, en, fo in ranges:
            if st <= addr and addr + n <= en:
                return data[fo + (addr - st): fo + (addr - st) + n]
        return None

    # ---- 手工走栈：RSP 处逐 8 字节找"像代码地址"的值 ----
    rsp = regs["Rsp"]
    print("\n=== 从 RSP=%#x 起扫描栈（找指向 .text 的返回地址）===" % rsp)
    blob = read(rsp, 0x400)
    if blob is None:
        print("  栈内存不在 dump 里")
        return
    imgbase = 0x140000000
    for i in range(0, len(blob) - 8, 8):
        (v,) = struct.unpack_from("<Q", blob, i)
        if imgbase <= v < imgbase + 0x25E0000:
            print("  [rsp+%#04x] = %#018x   RVA=%#x" % (i, v, v - imgbase))

    # ---- 也扫 RBP 链 ----
    rbp = regs["Rbp"]
    print("\n=== 从 RBP=%#x 起走帧链 ===" % rbp)
    cur = rbp
    for depth in range(24):
        pair = read(cur, 16)
        if pair is None:
            print("  [%d] 读不到 %#x" % (depth, cur))
            break
        nxt, ret = struct.unpack_from("<QQ", pair, 0)
        tag = "  RVA=%#x" % (ret - imgbase) if imgbase <= ret < imgbase + 0x25E0000 else ""
        print("  [%2d] frame=%#x  ret=%#018x%s" % (depth, cur, ret, tag))
        if nxt <= cur or nxt - cur > 0x100000:
            break
        cur = nxt


if __name__ == "__main__":
    main(sys.argv[1])
