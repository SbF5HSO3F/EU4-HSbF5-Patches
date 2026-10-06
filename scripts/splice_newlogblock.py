# -*- coding: utf-8 -*-
"""把新的日志基础设施整块换进 monarchnamefix.cpp（一次性，2026-10-05）。

替换范围：从 `static WCHAR  g_dir[MAX_PATH];` 到 `static void log_wide(const WCHAR *s)`
之前 —— 这一段包含旧的 log_str / 新加的（位置不对的）设施 / LOGS 宏等，
整体用 scripts/_newlogblock.txt 里的版本取代，理顺所有声明的先后顺序。

先备份原文件为 monarchnamefix.cpp.bak3。
"""
import io
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "monarchnamefix", "monarchnamefix.cpp")
NEW = os.path.join(ROOT, "scripts", "_newlogblock.txt")

START = "static WCHAR  g_dir[MAX_PATH];"
END   = "static void log_wide(const WCHAR *s)"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    s = io.open(SRC, encoding="utf-8").read()
    i = s.find(START)
    j = s.find(END)
    if i < 0 or j < 0 or j <= i:
        print("[x] 定位失败: i=%d j=%d" % (i, j))
        return 1
    old = s[i:j]
    new = io.open(NEW, encoding="utf-8").read()
    shutil.copyfile(SRC, SRC + ".bak3")
    s = s[:i] + new + "\n" + s[j:]
    io.open(SRC, "w", encoding="utf-8", newline="").write(s)
    print("  替换 %d 字节 -> %d 字节（原文件备份为 monarchnamefix.cpp.bak3）"
          % (len(old), len(new)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
