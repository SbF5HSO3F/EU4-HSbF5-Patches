# -*- coding: utf-8 -*-
"""更严谨地解析 EU4 minidump 的崩溃线程栈，还原调用链。

关键点：
  * 内存段有 847 个且可能重叠，必须选【最小包含段】而不是第一个匹配。
  * 栈上的返回地址应落在 eu4.exe 的 .text 内，也可能是 cave（base-0x10000 附近）。
"""
import struct
import sys

IMGBASE = 0x140000000
IMGSIZE = 0x025E0000


def main(path):
    data = open(path, "rb").read()
    sig, ver, nstreams, dirrva = struct.unpack_from("<4sIII", data, 0)
    streams = []
    for i in range(nstreams):
        t, sz, rva = struct.unpack_from("<III", data, dirrva + i * 12)
        streams.append((t, sz, rva))

    # 收集内存段 (start, end, file_off)
    ranges = []
    for t, sz, s_rva in streams:
        if t == 5:
            (n,) = struct.unpack_from("<I", data, s_rva)
            for i in range(n):
                st, msz, mrva = struct.unpack_from("<QII", data, s_rva + 4 + i * 16)
                ranges.append([st, st + msz, mrva])
        elif t == 9:
            n, base = struct.unpack_from("<QQ", data, s_rva)
            cur = s_rva + 16
            for i in range(n):
                st, msz = struct.unpack_from("<QQ", data, cur)
                cur += 16
                ranges.append([st, st + msz, base])
                base += msz
    ranges.sort(key=lambda r: (r[0], r[1] - r[0]))

    def read(addr, n):
        """取包含 addr 的【最小】段来读。"""
        best = None
        for st, en, fo in ranges:
            if st <= addr < en and (best is None or (en - st) < (best[1] - best[0])):
                best = (st, en, fo)
        if best is None:
            return None
        st, en, fo = best
        avail = en - addr
        return data[fo + (addr - st): fo + (addr - st) + min(n, avail)]

    # 异常线程
    exc_tid = None
    regs = {}
    for t, sz, rva in streams:
        if t == 6:
            (exc_tid,) = struct.unpack_from("<I", data, rva)
            csz, crva = struct.unpack_from("<II", data, rva + 8 + 152)
            ctx = data[crva:crva + csz]
            names = ["Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
                     "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip"]
            off = 0x78
            for nm in names:
                (regs[nm],) = struct.unpack_from("<Q", ctx, off)
                off += 8
    if "Rsp" not in regs:
        print("没有异常上下文")
        return

    rsp, rbp, rip = regs["Rsp"], regs["Rbp"], regs["Rip"]
    print("tid=%#x  RIP=%#x  RSP=%#x  RBP=%#x" % (exc_tid, rip, rsp, rbp))
    print()

    blob = read(rsp, 0x800)
    print("栈可读 = %s (%s 字节)" % (blob is not None, len(blob) if blob else 0))
    if blob:
        print("栈前 32 字节: %s" % blob[:32].hex(" "))

    print("\n=== 扫描栈上所有落在 eu4.exe 模块内的值（候选返回地址）===")
    if blob:
        for i in range(0, len(blob) - 8, 8):
            (v,) = struct.unpack_from("<Q", blob, i)
            if IMGBASE <= v < IMGBASE + IMGSIZE:
                print("  [rsp+%#05x] = %#018x   RVA=%#x" % (i, v, v - IMGBASE))
            # 也看 cave 区（模块基址下方 0x20000 内）
            elif IMGBASE - 0x20000 <= v < IMGBASE:
                print("  [rsp+%#05x] = %#018x   ★CAVE (base%+#x)" % (i, v, v - IMGBASE))

    print("\n=== RBP 帧链 ===")
    cur = rbp
    for d in range(32):
        pair = read(cur, 16)
        if pair is None or len(pair) < 16:
            print("  [%d] 读不到 %#x" % (d, cur))
            break
        nxt, ret = struct.unpack_from("<QQ", pair, 0)
        tag = ""
        if IMGBASE <= ret < IMGBASE + IMGSIZE:
            tag = "  RVA=%#x" % (ret - IMGBASE)
        elif IMGBASE - 0x20000 <= ret < IMGBASE:
            tag = "  ★CAVE (base%+#x)" % (ret - IMGBASE)
        print("  [%2d] rbp=%#x  ret=%#018x%s" % (d, cur, ret, tag))
        if nxt <= cur or nxt - cur > 0x200000:
            break
        cur = nxt


if __name__ == "__main__":
    main(sys.argv[1])
