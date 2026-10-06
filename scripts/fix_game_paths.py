# -*- coding: utf-8 -*-
"""把 notes 里指向"还原函数目录"的路径从 game/ 改到 reversed/。

背景：还原成果原先放在 src\\monarchnamefix\\game\\，用户要求它独立，
      已 git mv 到仓库根的 reversed\\。

★ 必须区分两种 "game"：
    · 路径     src\\monarchnamefix\\game\\ 、game/build_full_name.cpp   → 要改
    · 命名空间 mnp::game::bfn 、mnp::game::monarch                     → 【不能改】
  所以先把命名空间替换成占位符，改完再还原。

用法： python scripts\\fix_game_paths.py [--apply]
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = [
    os.path.join(ROOT, "notes", "还原函数-交接文档.md"),
    os.path.join(ROOT, "notes", "当前架构与站点清单.md"),
    os.path.join(ROOT, "reversed", "README.md"),
]

NS = "@@MNP_GAME_NS@@"


def convert(s):
    # ① 保护命名空间
    s = s.replace("mnp::game::", NS)

    # ② src\monarchnamefix\game\  /  src/monarchnamefix/game/
    s = s.replace("src\\monarchnamefix\\game\\", "reversed\\")
    s = s.replace("src/monarchnamefix/game/", "reversed/")
    s = s.replace("src\\monarchnamefix\\game", "reversed")
    s = s.replace("src/monarchnamefix/game", "reversed")

    # ③ #include "game/xxx" → #include "xxx"（同目录）
    s = s.replace('#include "game/', '#include "')

    # ④ 反引号或空格开头的纯路径
    s = s.replace("`game/", "`reversed/")
    s = s.replace("`game\\", "`reversed\\")
    s = re.sub(r"(?<![\w:])game/", lambda m: "reversed/", s)
    s = re.sub(r"(?<![\w:])game\\(?=[A-Za-z_])", lambda m: "reversed" + "\\", s)

    # ⑤ 还原命名空间
    s = s.replace(NS, "mnp::game::")
    return s


def main():
    apply = "--apply" in sys.argv
    for p in TARGETS:
        if not os.path.exists(p):
            print("[skip] %s 不存在" % p)
            continue
        s = io.open(p, encoding="utf-8", newline="").read()
        new = convert(s)
        n = sum(1 for a, b in zip(s.split("\n"), new.split("\n")) if a != b)
        print("%-44s %d 行变化" % (os.path.basename(p), n))
        if apply and new != s:
            io.open(p, "w", encoding="utf-8", newline="").write(new)
    if not apply:
        print("\n(dry-run；加 --apply 才写回)")
        # 打印预览
        p = TARGETS[0]
        s = io.open(p, encoding="utf-8", newline="").read()
        new = convert(s)
        print("\n--- 预览：还原函数-交接文档.md 的变化行 ---")
        for a, b in zip(s.split("\n"), new.split("\n")):
            if a != b:
                print("  - %s" % a.strip()[:90])
                print("  + %s" % b.strip()[:90])
    return 0


if __name__ == "__main__":
    sys.exit(main())
