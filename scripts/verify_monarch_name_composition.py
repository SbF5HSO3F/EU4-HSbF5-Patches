# -*- coding: utf-8 -*-
"""逐字节确认 CMonarch 里存的是【name + dynasty 两个字段】还是【拼好的全名】。

判据（reversed/cmonarch_get_full_name.cpp）：
    CMonarch_GetFullName:  out = name;  out += " ";  out += dynasty->name;
    ⇒ 显示 = name + " " + dynasty
    ⇒ 若 name 里已经含了姓，显示时会重复出现姓

存档里角色块的形态（实测）：
    monarch={ id={...} name="<UTF-16LE>" country="QIC" DIP=5 ADM=4 MIL=5
              culture=shandong_culture religion=... dynasty="<UTF-16LE>" birth_date=... }
本脚本只读。
"""
import io
import re
import sys

SAVE = (sys.argv[1] if len(sys.argv) > 1 else
        r"%EU4_USER_DIR%"
        r"\save games\autosave.eu4")


def utf16z(d, pos, limit=120):
    """pos 起按 UTF-16LE 读到 ASCII 引号 (22 00)。"""
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

    shown = 0
    for m in re.finditer(rb'monarch\s*=\s*\{', d):
        seg_start = m.start()
        seg = d[seg_start:seg_start + 700]
        # 只要中国文化的
        cm = re.search(rb'culture=([a-z_0-9]+)', seg)
        if not cm or cm.group(1) not in (b"shandong_culture", b"chihan", b"wu"):
            continue
        nm = re.search(rb'\bname="', seg)
        if not nm:
            continue
        dmm = re.search(rb'\bdynasty="', seg)
        ctm = re.search(rb'country="([A-Z]{3})"', seg)

        name_pos = seg_start + nm.end()
        name = utf16z(d, name_pos)
        dyn = utf16z(d, seg_start + dmm.end()) if dmm else None

        out.write("=" * 72 + "\n")
        out.write("country=%s culture=%s\n"
                  % (ctm.group(1).decode() if ctm else "?", cm.group(1).decode()))
        out.write("  name  @+%d = %r\n" % (nm.end(), name))
        out.write("  name  raw = %s\n" % d[name_pos:name_pos + 20].hex(" "))
        if dyn is not None:
            out.write("  dynas @+%d = %r\n" % (dmm.end(), dyn))
            out.write("  dynas raw = %s\n" % d[seg_start + dmm.end():seg_start + dmm.end() + 20].hex(" "))
            d0 = dyn[0] if dyn else ""
            dup = bool(d0) and (d0 in name)
            out.write("  → name 是否已含 dynasty 首字 %r : %s\n"
                      % (d0, "是 ⇒ name 已拼好（显示会重复姓）" if dup
                         else "否 ⇒ name 只是名，dynasty 是姓"))
            out.write("  → GetFullName 显示 = %r\n" % (name + " " + dyn))
        else:
            out.write("  dynasty: 该块无 dynasty 字段\n")
        shown += 1
        if shown >= 10:
            break

    out.write("\n共 %d 个块\n" % shown)
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
