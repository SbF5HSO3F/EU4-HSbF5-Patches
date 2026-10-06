# -*- coding: utf-8 -*-
"""把 P8 的 form2 从"一律原样返回"改回真正的重排（一次性，2026-10-05）。

背景：我先前把 form2 临时改成"遇到 0xBF 形态就原样返回"，那是在 `nbf0`
      按"任意 0xBF"计数的前提下做的 —— 那个前提下 LJA（`12 BF 75` = 线）
      会被误判成"有标记"，导致 sur_len 少 1、丢字乱码。

现在 `nbf0` 已改为**只数独立标记**（按 escape 字节 10/11/12/13 步进），
两种布局可以正确区分：
    LJA  `12 BF 75`      ⇒ nbf0=0 ⇒ form1 命中，sur_len=dlen=3 ✓
    L141 `BF 10 1D 60`   ⇒ nbf0=1 ⇒ form2 命中，sur_len=dlen-nbf0=3 ✓
所以 form2 应当恢复。

本脚本按行号替换（先备份原文件）。
"""
import io
import os
import shutil
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src", "monarchnamefix", "monarchnamefix.cpp")

# 要被替换掉的那一段（以首行/末行的特征串定位，避免整段抄写出错）
HEAD = "        } else if (nbf0 > 0) {"
TAIL = "            return;\n        } else {\n"

NEW = '''        } else if (nbf0 > 0 && olen == nlen + (dlen - nbf0) && dlen > nbf0) {
            /* 形态 2：姓字段以【独立标记】0xBF 开头，游戏在拼 `" " + BF + 姓` 时
             *   把那个空格折叠掉了 ⇒ out = 名(nlen) + BF + 姓(dlen-nbf0)。
             *
             * 实测（L141，hex 已核）：姓字段 = `BF 10 1D 60`（标记 + 思 U+601D）
             *     nlen=6 dlen=4 nbf0=1 olen=9 ⇒ 9 == 6 + (4-1) ✓
             *     ssur = odata + nlen = odata+6，取 sur_len=3 字节 = `10 1D 60`
             *     ⇒ 姓阶段的"按字符步进"循环跳过整个字符、不删任何字节 = 思 ✓
             *
             * ★ 2026-10-05 历史（务必保留这段教训）：
             *   本分支曾被我临时改成"遇到 0xBF 形态一律原样返回"。原因：
             *   当时 `nbf0` 按**任意 0xBF** 计数，把 LJA 那种"字符内 0xBF"
             *   （`12 BF 75` = 线，U+7EBF，其 low 字节就是 0xBF）也算成标记
             *   ⇒ `sur_len = dlen - nbf0` 少 1 ⇒ 切分点左移、丢一个字节
             *   ⇒ 屏幕上乱码方块、size 少 1（实测 7 → 5）。
             *
             *   现在 `nbf0` 只数**独立标记**（按 escape 字节 10/11/12/13 步进，
             *   字符体内的 0xBF 不计），两种布局能正确区分，故恢复本分支。
             *
             * ★ 两种 0xBF 含义的判据（这是全部混乱的根源）：
             *     `BF 10 1D 60` —— 0xBF 后面跟 escape ⇒ 0xBF 是**独立标记**
             *     `12 BF 75`    —— 0xBF 前面是 escape ⇒ 0xBF 是**字符的 low 字节**
             */
            ssur = odata + nlen;   form = 2;   sur_len = dlen - nbf0;
        } else {
'''


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(SRC, encoding="utf-8").read()
    i = s.index(HEAD)
    j = s.index(TAIL, i) + len(TAIL)
    old = s[i:j]
    print("将替换 %d 字节：" % len(old))
    print("  首行: %s" % old.split("\n")[0])
    print("  末行: %s" % old.rstrip().split("\n")[-1])
    shutil.copyfile(SRC, SRC + ".bak2")
    s = s[:i] + NEW + s[j:]
    io.open(SRC, "w", encoding="utf-8", newline="").write(s)
    print("  已替换（原文件备份为 monarchnamefix.cpp.bak2）")


if __name__ == "__main__":
    main()
