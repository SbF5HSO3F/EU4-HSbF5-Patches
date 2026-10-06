# -*- coding: utf-8 -*-
"""验证 install.cpp 里那 6 个站点的模式 + RVA 筛选能否唯一定位。

为什么需要它：
  新钩子层用"字节模式 + RVA 筛选"定位站点。模式写得不好（太短）就会命中
  成千上万次 —— 第一次实测时 6 个钩子只装上 1 个，名字全乱。
  这个脚本在【不启动游戏】的前提下复现 install.cpp 的定位算法，
  直接从源码里提取模式，保证与代码同源、不会各写一份而漂移。

用法：python scripts\\verify_newhook.py
"""
import io
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_CPP = os.path.join(ROOT, "src", "monarchnamefix", "install.cpp")
EXE = r"%EU4_GAME_DIR%\eu4.exe"


def load_sections(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    sectab = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    secs = []
    for i in range(nsec):
        off = sectab + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, raw = struct.unpack_from("<IIII", data, off + 8)
        secs.append((name, va, vsz, raw))
    return data, secs


def parse_pattern(pat):
    """与 bytepattern.hpp 的 parse_pattern 同语义。"""
    vals, masks = [], []
    for tok in pat.split():
        if tok == "?":
            vals.append(0x00); masks.append(0x00)
        elif len(tok) == 2 and tok[0] == "?":
            vals.append(int(tok[1], 16)); masks.append(0x0F)
        elif len(tok) == 2 and tok[1] == "?":
            vals.append(int(tok[0], 16) << 4); masks.append(0xF0)
        elif len(tok) == 2:
            vals.append(int(tok, 16)); masks.append(0xFF)
        else:
            raise ValueError("非法 token: %r" % tok)
    return vals, masks


def find_all(data, secs, vals, masks):
    out = []
    L = len(vals)
    for name, va, vsz, raw in secs:
        if name not in (".text", ".rdata"):
            continue
        blob = data[raw:raw + vsz]
        for i in range(len(blob) - L + 1):
            ok = True
            for k in range(L):
                if (vals[k] & masks[k]) != (blob[i + k] & masks[k]):
                    ok = False
                    break
            if ok:
                out.append(va + i)
    return out


def extract_sites(src):
    """从 install.cpp 的 kSites[] 初始值里抠出 (name, site_rva, pattern_to_site, pattern)。

    依赖当前写法：每个条目是一段花括号内的初始值，含
        "名字",
        0xXXXXu, ... , 0xXXXXu,
        "字节 模式" ["续行"],
        0xNN, &mnp_ret_xx
    为了稳健，这里用"字符串字面量 + 十六进制"的出现顺序来切分，而不是硬套行号。
    """
    m = re.search(r"kSites\[\]\s*=\s*\{(.*?)\n\};", src, re.S)
    if not m:
        raise SystemExit("找不到 kSites[] 初始化块")
    body = m.group(1)

    # 去掉注释
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)

    # 条目：以 "{ " 开头到 "}," 结束
    entries = re.findall(r"\{(.*?)\}", body, re.S)
    sites = []
    for e in entries:
        # 名字 = 第一个字符串
        nm = re.search(r'"([^"]+)"', e)
        if not nm:
            continue
        name = nm.group(1)
        # 模式 = 最后一个字符串（可能由多段相邻字面量拼成）
        lits = re.findall(r'"([^"]*)"', e)
        if len(lits) < 2:
            continue
        pattern = " ".join(lits[1:]).strip()
        if not re.match(r"^[0-9A-Fa-f? ]+$", pattern):
            continue
        # 所有 0xNNNu 字面量，按出现顺序
        hexes = re.findall(r"0x([0-9A-Fa-f]+)u", e)
        if len(hexes) < 2:
            continue
        site_rva = int(hexes[0], 16)
        # pattern_to_site 是最后一个十六进制（非 u 后缀的裸 0xNN）
        offs = re.findall(r",\s*(0x[0-9A-Fa-f]+)\s*,", e)
        p2s = 0
        for o in offs:
            v = int(o, 16)
            if v < 0x1000:      # 偏移量都很小；RVA 都 >= 0x30000
                p2s = v
        sites.append((name, site_rva, p2s, pattern))
    return sites


def main():
    if not os.path.exists(EXE):
        print("[x] 找不到 eu4.exe: %s" % EXE)
        return 1
    src = io.open(INSTALL_CPP, encoding="utf-8").read()
    sites = extract_sites(src)
    print("从 install.cpp 提取到 %d 个站点\n" % len(sites))

    data, secs = load_sections(EXE)
    all_ok = True
    for name, want, p2s, pat in sites:
        vals, masks = parse_pattern(pat)
        hits = find_all(data, secs, vals, masks)
        matched = [h for h in hits if h + p2s == want]
        ok = (len(matched) == 1)
        all_ok = all_ok and ok
        print("%-58s len=%-3d hits=%-6d rva_match=%d  %s" %
              (name, len(vals), len(hits), len(matched), "OK" if ok else "FAIL"))
        if not ok:
            for h in hits[:5]:
                print("        hit %#x (site would be %#x, want %#x)" % (h, h + p2s, want))
    print()
    print("ALL OK" if all_ok else "SOME FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
