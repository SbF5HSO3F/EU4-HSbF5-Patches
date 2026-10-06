# -*- coding: utf-8 -*-
"""核对 CMonarch 的 name / dynasty 两个字段在存档里的位置。

背景：`CMonarch_Construct`（0x140A48CB0）的反编译给出：
    +0x28 名字 CString（data +0x28 / size +0x38 / cap +0x40）
    +0x58 ← params+56
    +0x60 ← params+64
本脚本把存档里某个角色块的实际结构解出来，看 name / dynasty 各落在哪。
只读。
"""
import io
import re
import struct
import sys

SAVE = (sys.argv[1] if len(sys.argv) > 1 else
        r"%EU4_USER_DIR%"
        r"\save games\autosave.eu4")


def utf16z(d, pos, limit=120):
    b = bytearray()
    j = pos
    while j + 1 < len(d) and len(b) < limit * 2:
        if d[j] == 0x22 and d[j + 1] == 0x00:
            break
        b += bytes((d[j], d[j + 1]))
        j += 2
    return b.decode("utf-16-le", errors="replace")


def main():
    out = io.open(sys.stdout.fileno(), "w", encoding="utf-8", errors="replace",
                   closefd=False)
    d = io.open(SAVE, "rb").read()
    out.write("save %s (%d bytes)\n\n" % (SAVE, len(d)))

    # 只取“开局存档”里前若干个 monarch 块，看它们的字段顺序
    n = 0
    for m in re.finditer(rb'monarch\s*=\s*\{', d):
        seg = d[m.start():m.start() + 700]
        nm = re.search(rb'\bname="', seg)
        dm = re.search(rb'\bdynasty="', seg)
        cm = re.search(rb'culture=([a-z_0-9]+)', seg)
        ctm = re.search(rb'country="([A-Z0-9]{3})"', seg)
        if not nm:
            continue
        name = utf16z(d, m.start() + nm.end())
        dyn = utf16z(d, m.start() + dm.end()) if dm else None
        out.write("[%d] country=%s culture=%s\n" % (
            n, ctm.group(1).decode() if ctm else "?",
            cm.group(1).decode() if cm else "?"))
        out.write("     name    = %r  (u16 chars=%d, bytes=%d)\n"
                  % (name, len(name), len(name) * 2))
        if dyn is not None:
            out.write("     dynasty = %r  (u16 chars=%d, bytes=%d)\n"
                      % (dyn, len(dyn), len(dyn) * 2))
        else:
            out.write("     dynasty = (无该字段)\n")
        n += 1
        if n >= 10:
            break
    out.write("\n共 %d 个块\n" % n)
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
