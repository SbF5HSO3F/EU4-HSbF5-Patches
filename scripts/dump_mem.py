# -*- coding: utf-8 -*-
"""从 minidump 里读任意虚拟地址的内存，并 dump 栈上的返回地址。

minidump 的 Memory64ListStream (type 9) / MemoryListStream (type 5) 提供了
崩溃时刻的内存快照。这里用它做到两件调试器才能做的事：

  1. 读出崩溃点的寄存器指向的内存（判断"垃圾值"到底是什么）；
  2. 扫栈上的返回地址，还原调用链 —— 崩溃点落在被上千处内联调用的通用函数里时，
     这是唯一能回答"谁调用的"的办法。

用法： python scripts/dump_mem.py <minidump> [--read ADDR[,ADDR...]] [--stack]
"""
import io
import struct
import sys

IMAGE_BASE = 0x140000000


class MiniDump:
    def __init__(self, path):
        self.d = io.open(path, "rb").read()
        n = struct.unpack_from("<I", self.d, 8)[0]
        diroff = struct.unpack_from("<I", self.d, 12)[0]
        self.streams = {}
        for i in range(n):
            t, sz, off = struct.unpack_from("<III", self.d, diroff + i * 12)
            self.streams[t] = (sz, off)
        self.ranges = []          # (start, size, file_off)
        self._parse_memory()

    def _parse_memory(self):
        d = self.d
        # Memory64ListStream = 9
        if 9 in self.streams:
            sz, off = self.streams[9]
            nrec = struct.unpack_from("<Q", d, off)[0]
            base_rva = struct.unpack_from("<Q", d, off + 8)[0]
            p = off + 16
            cur = base_rva
            for _ in range(nrec):
                start = struct.unpack_from("<Q", d, p)[0]
                size = struct.unpack_from("<Q", d, p + 8)[0]
                self.ranges.append((start, size, cur))
                cur += size
                p += 16
        # MemoryListStream = 5
        if 5 in self.streams:
            sz, off = self.streams[5]
            nrec = struct.unpack_from("<I", d, off)[0]
            p = off + 4
            for _ in range(nrec):
                start = struct.unpack_from("<Q", d, p)[0]
                dsz = struct.unpack_from("<I", d, p + 8)[0]
                rva = struct.unpack_from("<I", d, p + 12)[0]
                self.ranges.append((start, dsz, rva))
                p += 16
        self.ranges.sort()

    def read(self, addr, length):
        """跨 range 拼接读取；读不到的部分用 0xFF 填充并报告。"""
        out = bytearray()
        cur = addr
        remaining = length
        while remaining > 0:
            hit = None
            for start, size, foff in self.ranges:
                if start <= cur < start + size:
                    hit = (start, size, foff)
                    break
            if hit is None:
                out.extend(b"\xee" * remaining)   # 不可读标记
                break
            start, size, foff = hit
            avail = min(remaining, start + size - cur)
            out.extend(self.d[foff + (cur - start): foff + (cur - start) + avail])
            cur += avail
            remaining -= avail
        return bytes(out)

    def exceptions(self):
        sz, off = self.streams[6]
        er = off + 8
        code = struct.unpack_from("<I", self.d, er)[0]
        addr = struct.unpack_from("<Q", self.d, er + 16)[0]
        nparam = struct.unpack_from("<I", self.d, er + 24)[0]
        params = struct.unpack_from("<15Q", self.d, er + 32)
        return code, addr, list(params[:nparam])

    def registers(self):
        sz, off = self.streams[6]
        tc = off + 8 + 152
        csz, crva = struct.unpack_from("<II", self.d, tc)
        ctx = self.d[crva:crva + csz]
        names = {"Rax": 0x78, "Rcx": 0x80, "Rdx": 0x88, "Rbx": 0x90,
                 "Rsp": 0x98, "Rbp": 0xa0, "Rsi": 0xa8, "Rdi": 0xb0,
                 "R8": 0xb8, "R9": 0xc0, "R10": 0xc8, "R11": 0xd0,
                 "R12": 0xd8, "R13": 0xe0, "R14": 0xe8, "R15": 0xf0,
                 "Rip": 0xf8}
        return {k: struct.unpack_from("<Q", ctx, o)[0] for k, o in names.items()}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    md = MiniDump(sys.argv[1])
    code, addr, params = md.exceptions()
    regs = md.registers()

    print("ExceptionCode    = %#x" % code)
    print("ExceptionAddress = %#x   RVA = %#x" % (addr, addr - 0x7ff77f550000))
    print("ExceptionInfo    = %s" % [hex(x) for x in params])
    print()
    print("--- 寄存器 ---")
    base = 0x7ff77f550000
    for k, v in regs.items():
        extra = ""
        if base <= v < base + 0x25E0000:
            extra = "  RVA=%#x" % (v - base)
        elif v > 0x10000 and v < 0x7fffffffffff:
            extra = "  (heap?)"
        print("  %-4s = %#018x%s" % (k, v, extra))

    # 按参数读内存
    for a in sys.argv:
        if a.startswith("--read="):
            for s in a.split("=", 1)[1].split(","):
                t = int(s, 16)
                buf = md.read(t, 64)
                print()
                print("--- mem %#x ---" % t)
                for row in range(0, len(buf), 16):
                    hexs = " ".join("%02X" % b for b in buf[row:row + 16])
                    print("  %#018x  %s" % (t + row, hexs))

    if "--stack" in sys.argv:
        print()
        print("--- 栈上的返回地址（RVA in eu4.exe）---")
        sp = regs["Rsp"]
        buf = md.read(sp, 0x400)
        for off in range(0, len(buf) - 8, 8):
            v = struct.unpack_from("<Q", buf, off)[0]
            if base <= v < base + 0x25E0000:
                print("  [rsp+%#05x] = %#018x   RVA=%#x" % (off, v, v - base))
    return 0


if __name__ == "__main__":
    sys.exit(main())
