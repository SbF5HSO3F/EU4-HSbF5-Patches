# -*- coding: utf-8 -*-
"""检查 minidump 里是否包含崩溃线程的栈内存，并列出所有线程的栈范围。"""
import struct
import sys


def main(path):
    data = open(path, "rb").read()
    sig, ver, nstreams, dirrva = struct.unpack_from("<4sIII", data, 0)
    streams = []
    for i in range(nstreams):
        t, sz, rva = struct.unpack_from("<III", data, dirrva + i * 12)
        streams.append((t, sz, rva))

    # --- 异常线程 ---
    exc_tid = None
    rsp = None
    for t, sz, rva in streams:
        if t == 6:
            (exc_tid,) = struct.unpack_from("<I", data, rva)
            csz, crva = struct.unpack_from("<II", data, rva + 8 + 152)
            ctx = data[crva:crva + csz]
            (rsp,) = struct.unpack_from("<Q", ctx, 0x98)
    print("崩溃线程 ThreadId = %#x   RSP = %#x" % (exc_tid, rsp))

    # --- 内存范围 ---
    ranges = []
    for t, sz, s_rva in streams:
        if t == 5:
            (n,) = struct.unpack_from("<I", data, s_rva)
            for i in range(n):
                st, msz, mrva = struct.unpack_from("<QII", data, s_rva + 4 + i * 16)
                ranges.append((st, st + msz))
        elif t == 9:
            n, base = struct.unpack_from("<QQ", data, s_rva)
            cur = s_rva + 16
            for i in range(n):
                st, msz = struct.unpack_from("<QQ", data, cur)
                cur += 16
                ranges.append((st, st + msz))
                base += msz
    ranges.sort()
    print("内存范围共 %d 段" % len(ranges))

    hit = [r for r in ranges if r[0] <= rsp < r[1]]
    print("RSP 是否落在某段内存里: %s" % (("是 -> %#x..%#x" % hit[0]) if hit else "否"))

    # --- 线程栈描述符 ---
    print("\n=== ThreadListStream：各线程的 Stack 范围 ===")
    for t, sz, rva in streams:
        if t == 3:
            (n,) = struct.unpack_from("<I", data, rva)
            cur = rva + 4
            for i in range(n):
                tid, susp, prio0, prio, teb, stk_start, stk_sz, stk_rva = \
                    struct.unpack_from("<IIIIQQII", data, cur)
                cur += 48
                mark = ""
                if tid == exc_tid:
                    mark = "   <<< 崩溃线程"
                in_dump = any(r[0] <= stk_start and stk_start + stk_sz <= r[1] for r in ranges)
                if tid == exc_tid or stk_sz > 0x10000:
                    print("  tid=%#-6x stack=%#x..%#x size=%#x  dump内含=%s%s"
                          % (tid, stk_start, stk_start + stk_sz, stk_sz, in_dump, mark))

    print("\n=== 与崩溃线程栈重叠的内存段 ===")
    if hit:
        st, en = hit[0]
        print("  %#x..%#x  (%d 字节)" % (st, en, en - st))
        # 找它来自哪个流
        for t, sz, s_rva in streams:
            if t == 5:
                (n,) = struct.unpack_from("<I", data, s_rva)
                for i in range(n):
                    mst, msz, mrva = struct.unpack_from("<QII", data, s_rva + 4 + i * 16)
                    if mst <= rsp < mst + msz:
                        print("  来自 MemoryListStream，文件偏移 %#x" % mrva)
    else:
        print("  无 —— 该 dump 【不含崩溃线程的栈内存】，无法走栈")


if __name__ == "__main__":
    main(sys.argv[1])
