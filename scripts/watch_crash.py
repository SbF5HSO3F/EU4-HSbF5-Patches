# -*- coding: utf-8 -*-
"""崩溃监控：盯着 EU4 的 crashes 目录与 MonarchNameFix.log，一有新崩溃就产出定位报告。

用法：python watch_crash.py [--once]
产出：monitor\report_<时间戳>.txt（工作区内，沙箱可写）
只读游戏目录与崩溃目录，不写任何游戏文件。
"""
import os
import struct
import subprocess
import sys
import time
import datetime
import glob

CRASH_DIR = r"%EU4_USER_DIR%\crashes"
LOG_PATH = r"%EU4_GAME_DIR%\plugins\MonarchNameFix.log"
GAME_EXE = r"%EU4_GAME_DIR%\eu4.exe"
OUT_DIR = r"%REPO_ROOT%\monitor"
OBJDUMP = r"D:\x86_64-8.1.0-release-win32-seh-rt_v6-rev0\mingw64\bin\objdump.exe"

IMGBASE = 0x140000000
IMGSIZE = 0x025E0000

# 我们补丁的站点（RVA），用于判定"崩在不在我们的地盘"
PATCH_SITES = {
    0xDA989B: "P1 WeightedNameList_PickByRandomIndex 入口",
    0x280274: "P2 PickNameFromCultureLists 取模",
    0xDA9A82: "P3 WeightedNameList_GetByModIndex 取模",
    0x314349: "P4 BuildFullName_Impl 出口",
    0x861FC0: "P5 CLeader_SetName 入口",
    0x313F40: "P6 BuildFullName_Impl 入口",
    0x314228: "P7 BuildFullName_Impl 循环前置位",
    0x3142F2: "P10 BuildFullName_Impl 存姓长度",
    0x3142FC: "P11 BuildFullName_Impl 重排",
    0xA4B4A6: "P8 CMonarch_GetFullName 重排",
}
FUNC_HINTS = {
    "BuildFullName_Impl": (0x313F40, 0x31434F),
    "CMonarch_GetFullName": (0xA4B280, 0xA4B600),
    "CLeader_SetName": (0x861FC0, 0x8620B4),
    "Country_CreateNewMonarch": (0x31EAD0, 0x320B00),
    "GenerateMonarchName": (0x313D90, 0x313F40),
}


def read_all(path):
    with open(path, "rb") as f:
        return f.read()


def parse_dump(path):
    """返回 dict：异常信息 + 寄存器 + 栈上的模块内地址。"""
    data = read_all(path)
    sig, ver, nstreams, dirrva = struct.unpack_from("<4sIII", data, 0)
    streams = []
    for i in range(nstreams):
        t, sz, rva = struct.unpack_from("<III", data, dirrva + i * 12)
        streams.append((t, sz, rva))

    out = {"streams": len(streams)}

    # 内存段
    ranges = []
    for t, sz, sr in streams:
        if t == 5:
            (n,) = struct.unpack_from("<I", data, sr)
            for i in range(n):
                st, ms, mr = struct.unpack_from("<QII", data, sr + 4 + i * 16)
                ranges.append((st, st + ms, mr))
        elif t == 9:
            n, base = struct.unpack_from("<QQ", data, sr)
            cur = sr + 16
            for i in range(n):
                st, ms = struct.unpack_from("<QQ", data, cur)
                cur += 16
                ranges.append((st, st + ms, base))
                base += ms
    ranges.sort(key=lambda r: (r[0], r[1] - r[0]))
    out["ranges"] = len(ranges)

    def read(addr, n):
        best = None
        for st, en, fo in ranges:
            if st <= addr < en and (best is None or (en - st) < (best[1] - best[0])):
                best = (st, en, fo)
        if not best:
            return None
        st, en, fo = best
        return data[fo + (addr - st): fo + (addr - st) + min(n, en - addr)]

    for t, sz, rva in streams:
        if t == 6:
            (tid,) = struct.unpack_from("<I", data, rva)
            (code, flags, rec, addr, nparam, _u) = struct.unpack_from("<IIQQII", data, rva + 8)
            info = struct.unpack_from("<15Q", data, rva + 8 + 0x20)
            csz, crva = struct.unpack_from("<II", data, rva + 8 + 152)
            ctx = data[crva:crva + csz]
            out["tid"] = tid
            out["code"] = code
            out["exc_addr"] = addr
            out["exc_info"] = list(info[:nparam])
            names = ["Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
                     "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip"]
            regs = {}
            off = 0x78
            for nm in names:
                (regs[nm],) = struct.unpack_from("<Q", ctx, off)
                off += 8
            out["regs"] = regs

            rsp = regs["Rsp"]
            blob = read(rsp, 0x300)
            out["stack_ok"] = blob is not None
            rets = []
            if blob:
                for i in range(0, len(blob) - 8, 8):
                    (v,) = struct.unpack_from("<Q", blob, i)
                    if IMGBASE <= v < IMGBASE + IMGSIZE:
                        rets.append((i, v, v - IMGBASE))
            out["rets"] = rets
            break
    return out


def rva_desc(rva):
    """把 RVA 映射到我们已知的补丁站点/函数。"""
    hits = []
    for site, name in PATCH_SITES.items():
        if abs(rva - site) <= 0x40:
            hits.append("★ 距 %s (RVA %#x) 仅 %+d 字节" % (name, site, rva - site))
    for fname, (lo, hi) in FUNC_HINTS.items():
        if lo <= rva < hi:
            hits.append("在 %s 内 (+%#x)" % (fname, rva - lo))
    return hits


def disasm(addr, n=40):
    if not os.path.exists(OBJDUMP):
        return "(objdump 不可用)"
    try:
        p = subprocess.run(
            [OBJDUMP, "-d", "--start-address=%d" % (addr - 0x20),
             "--stop-address=%d" % (addr + n * 8), GAME_EXE],
            capture_output=True, text=True, timeout=120,
            creationflags=0x08000000)
        lines = [l for l in p.stdout.splitlines() if ":\t" in l]
        return "\n".join(lines[:n])
    except Exception as e:
        return "(反汇编失败: %s)" % e


def log_tail(n=50):
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return "(读日志失败: %s)" % e


def log_head():
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[:3])
    except Exception:
        return ""


def log_runtime_base():
    """从 MonarchNameFix.log 里取本次运行的模块基址（用于把崩溃地址换算成 RVA）。

    dump 里的地址是【运行时地址】（ASLR），不是 0x140000000。
    日志里有两处可推：
        [i] registry slot=0x...        → slot - 0x242B9F8
        [i] cave=0x... delta=-0x10000  → cave + 0x10000
    """
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except Exception:
        return None, None
    import re
    m = re.search(r"registry slot=(0x[0-9a-fA-F]+)", txt)
    if m:
        return int(m.group(1), 16) - 0x242B9F8, "registry slot"
    m = re.search(r"cave=(0x[0-9a-fA-F]+)\s+delta=(-?0x[0-9a-fA-F]+)", txt)
    if m:
        return int(m.group(1), 16) + 0x10000, "cave"
    return None, None


def build_report(crash_dir):
    L = []
    stamp = os.path.basename(crash_dir)
    L.append("=" * 78)
    L.append("崩溃报告  %s" % stamp)
    L.append("=" * 78)

    exc = os.path.join(crash_dir, "exception.txt")
    if os.path.exists(exc):
        L.append("\n--- exception.txt ---")
        L.append(open(exc, "r", encoding="utf-8", errors="replace").read().strip()[:600])

    dmp = os.path.join(crash_dir, "minidump.dmp")
    if os.path.exists(dmp):
        try:
            d = parse_dump(dmp)
            addr = d["exc_addr"]
            # ★ 崩溃地址是【运行时地址】，必须先拿本次运行的模块基址才能换算 RVA
            rtbase, how = log_runtime_base()
            if rtbase is None:
                L.append("\n[!] 无法从日志推得运行时基址，RVA 无法换算（按 0x140000000 试算）")
                rtbase = IMGBASE
                how = "假设镜像基址"
            rva = addr - rtbase
            L.append("\n--- 崩溃点 ---")
            L.append("模块基址(运行时) = %#x   [来源: %s]" % (rtbase, how))
            L.append("ExceptionAddress = %#x" % addr)
            L.append("RVA              = %#x" % rva)
            L.append("ThreadId         = %#x" % d["tid"])
            L.append("ExceptionCode    = %#x" % d["code"])
            L.append("ExceptionInfo    = %s" % [hex(x) for x in d["exc_info"]])
            L.append("内存段 %d / dump stream %d" % (d["ranges"], d["streams"]))

            L.append("\n--- 归属判定 ---")
            hits = rva_desc(rva)
            if hits:
                for h in hits:
                    L.append("  " + h)
            else:
                L.append("  不在任何已知补丁站点/挂钩函数附近")

            L.append("\n--- 寄存器 ---")
            for k in ["Rip", "Rsp", "Rbp", "Rax", "Rcx", "Rdx", "Rbx",
                      "Rsi", "Rdi", "R8", "R9", "R10", "R11",
                      "R12", "R13", "R14", "R15"]:
                v = d["regs"][k]
                extra = ""
                if rtbase <= v < rtbase + IMGSIZE:
                    extra = "   RVA=%#x" % (v - rtbase)
                    hh = rva_desc(v - rtbase)
                    if hh:
                        extra += "  <<< " + hh[0]
                L.append("  %-4s = %#018x%s" % (k, v, extra))

            L.append("\n--- 栈上的返回地址链（RVA，由内向外）---")
            if not d["stack_ok"]:
                L.append("  (该 dump 不含崩溃线程栈内存)")
            elif not d["rets"]:
                L.append("  (栈里没有落在模块内的返回地址)")
            else:
                for off, v, r in d["rets"][:20]:
                    hh = rva_desc(r)
                    L.append("  [rsp+%#05x] RVA=%#x%s" % (off, r, ("   " + "; ".join(hh)) if hh else ""))

            L.append("\n--- 崩溃点反汇编（RVA %#x ⇒ VA %#x）---" % (rva, IMGBASE + rva))
            L.append(disasm(IMGBASE + rva))
        except Exception as e:
            L.append("\n(minidump 解析失败: %r)" % e)

    L.append("\n--- 本次启动的 DLL 版本 ---")
    L.append(log_head().strip())

    L.append("\n--- 日志尾部（最后 50 行）---")
    L.append(log_tail(50))
    return "\n".join(L)


def main():
    once = "--once" in sys.argv
    os.makedirs(OUT_DIR, exist_ok=True)
    known = set()
    for d in glob.glob(os.path.join(CRASH_DIR, "eu4_*")):
        known.add(d)
    print("[watch] 已存在的崩溃目录 %d 个（跳过）" % len(known), flush=True)
    print("[watch] 日志: %s" % LOG_PATH, flush=True)
    print("[watch] 报告输出: %s" % OUT_DIR, flush=True)

    # ★ 日志监控：记录上次读到哪一行，新增行里挑关键信息打出来。
    #   用途：确认"是否真的跑到了名字生成"（有 culture HIT / P11 才算）。
    #   若日志头出现新的 build 时间戳，说明用户换了 DLL，也报出来。
    log_pos = 0
    last_build = None
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        log_pos = len(lines)
        for l in lines[:1]:
            last_build = l.strip()
        print("[watch] 当前日志已有 %d 行, 版本: %s" % (log_pos, last_build), flush=True)
    except Exception as e:
        print("[watch] 初次读日志失败: %r" % e, flush=True)

    KEY = ("culture HIT", "[d] P11 #", "[!]", "result:", "=== MonarchNameFix")
    while True:
        try:
            # ---- 日志增量 ----
            try:
                with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                if len(lines) < log_pos:
                    print("[watch] 日志被截断（游戏重启）", flush=True)
                    log_pos = 0
                if len(lines) > log_pos:
                    new = lines[log_pos:]
                    log_pos = len(lines)
                    if new and "=== MonarchNameFix" in new[0]:
                        last_build = new[0].strip()
                        print("[watch] ★ 新一轮启动, 版本: %s" % last_build, flush=True)
                    nkey = [l.rstrip() for l in new if any(k in l for k in KEY)]
                    if nkey:
                        print("[watch] 日志新增 %d 行, 关键 %d 条:" % (len(new), len(nkey)), flush=True)
                        for l in nkey[:12]:
                            print("   > " + l[:150], flush=True)
                        hits = sum(1 for l in new if "culture HIT" in l)
                        if hits:
                            print("[watch]   ⇒ 本次启动已处理 %d 次文化命中（说明确实跑到名字生成）" % hits, flush=True)
            except FileNotFoundError:
                pass

            # ---- 崩溃目录 ----
            cur = set(glob.glob(os.path.join(CRASH_DIR, "eu4_*")))
            new_crash = sorted(cur - known)
            for d in new_crash:
                time.sleep(15)
                dmp = os.path.join(d, "minidump.dmp")
                for _ in range(20):
                    if os.path.exists(dmp) and os.path.getsize(dmp) > 1000000:
                        break
                    time.sleep(5)
                rep = build_report(d)
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                rp = os.path.join(OUT_DIR, "report_%s.txt" % ts)
                with open(rp, "w", encoding="utf-8") as f:
                    f.write(rep)
                known.add(d)
                print("[watch] ★★★ 新崩溃 %s ⇒ 报告 %s" % (os.path.basename(d), rp), flush=True)
                for line in rep.splitlines():
                    if line.startswith(("ExceptionAddress", "RVA ", "  在", "  ★",
                                        "  Rip", "  Rsp", "  Rdi", "  R15",
                                        "  [rsp+", "=== MonarchNameFix")):
                        print("   | " + line, flush=True)
            if once and not new_crash:
                break
        except Exception as e:
            print("[watch] 轮询异常: %r" % e, flush=True)
        time.sleep(10)


if __name__ == "__main__":
    main()
