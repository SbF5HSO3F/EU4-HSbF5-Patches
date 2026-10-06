# -*- coding: utf-8 -*-
"""校验五个文件里的站点排列顺序是否一致。

为什么要它：
  站点信息分散在五处 —— install.cpp 的 kSites[]、stubs.asm 的 trampoline、
  monarchnamefix.cpp 的 handler、hookvars.cpp 的变量、stubs.hpp 的声明。
  任一处顺序不同步，读代码时就会"对不上号"。

★ 2026-10-05 站点改名：从"按添加时间编号（P1..P11）"改成【功能组 + 阶段】。
  旧编号只记录发现顺序、不含语义，且与表内顺序完全不对应
  （旧表内顺序是 P1 P2 P3 P6 P7 P10 P11 P4 P8）。新命名让"名字自己说明它在
  哪一步做什么"，并让同属一件事的站点靠前缀自然聚在一起。

  组      含义                                    站点
  ──────  ──────────────────────────────────────  ────────────────────────────
  modfix  取模缺陷修复（同一个 bug 的三处）        modfix_pick_idx / _pick_cult / _pick_modidx
  gen     生成期姓前名后（一条流水线，五站点）      gen_entry_culture / loop_decide / surn_len
                                                  / reorder / exit_fallback
  disp    显示期统治者姓名                          disp_ruler_name

  ★ gen 五个站点在 BuildFullName_Impl 内的执行顺序 =
       entry_culture → loop_decide → surn_len → reorder → exit_fallback
    与它们在 kSites[] 里的排列一致（本脚本校验的就是这个）。

用法： python scripts\\verify_site_order.py
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "monarchnamefix")

EXPECT = [
    "modfix_pick_idx",
    "modfix_pick_cult",
    "modfix_pick_modidx",
    "gen_entry_culture",
    "gen_loop_decide",
    "gen_surn_len",
    "gen_reorder",
    "gen_exit_fallback",
    "disp_ruler_name",
]


def read(name):
    return io.open(os.path.join(SRC, name), encoding="utf-8", errors="replace").read()


def order_from(text, pattern, group=1, transform=None):
    out = []
    for m in re.finditer(pattern, text, re.M):
        v = m.group(group)
        if transform:
            v = transform(v)
        if v not in out:
            out.append(v)
    return out


def main():
    checks = []

    # install.cpp：kSites[] 里每条的 "<组>  <动作>  说明…"，取行首那个标识符。
    #   显示名形如 "gen     reorder        BuildFullName_Impl (…)"
    #   ⇒ 抓 "组 + 动作"，中间的空格数不固定，用 \s+ 吃掉，再拼成下划线形式。
    s = read("install.cpp")
    m = re.search(r"kSites\[\]\s*=\s*\{(.*?)\n\};", s, re.S)
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S) if m else ""
    body = re.sub(r"//[^\n]*", "", body)
    seq = ["%s_%s" % (g, a) for g, a in
           re.findall(r'"\s*(modfix|gen|disp)\s+(\w+)', body)]
    checks.append(("install.cpp  kSites[]", seq))

    # stubs.asm：mnp_hook_<组>_<动作> PROC
    checks.append(("stubs.asm    trampoline",
                   order_from(read("stubs.asm"),
                              r"^mnp_hook_((?:modfix|gen|disp)_\w+)\s+PROC", 1)))

    # monarchnamefix.cpp：static void mnp_h_<组>_<动作>(
    checks.append(("main.cpp     handler",
                   order_from(read("monarchnamefix.cpp"),
                              r"^static void mnp_h_((?:modfix|gen|disp)_\w+)\(", 1)))

    # hookvars.cpp：mnpfn_<组>_<动作>_<后缀> = 0;
    checks.append(("hookvars.cpp 变量",
                   order_from(read("hookvars.cpp"),
                              r"^std::uintptr_t mnpfn_((?:modfix|gen|disp)_\w+?)\s*=", 1)))

    # stubs.hpp：void mnp_hook_<组>_<动作>(void);
    checks.append(("stubs.hpp    声明",
                   order_from(read("stubs.hpp"),
                              r"^void mnp_hook_((?:modfix|gen|disp)_\w+)\(void\);", 1)))

    # ★ 追加：四处的站点标识必须一致，否则同一个站点在不同文件里叫法不同，
    #   读代码的人还是对不上号（这正是本次改名的目的）。
    actions = {}
    for label, text, pat in (
        ("stubs.asm",    read("stubs.asm"),
         r"^mnp_hook_((?:modfix|gen|disp)_\w+)\s+PROC"),
        ("stubs.hpp",    read("stubs.hpp"),
         r"^void mnp_hook_((?:modfix|gen|disp)_\w+)\(void\);"),
        ("hookvars.cpp", read("hookvars.cpp"),
         r"^std::uintptr_t mnpfn_((?:modfix|gen|disp)_\w+?)\s*="),
        ("main.cpp",     read("monarchnamefix.cpp"),
         r"^static void mnp_h_((?:modfix|gen|disp)_\w+)\("),
    ):
        for mm in re.finditer(pat, text, re.M):
            actions.setdefault(mm.group(1), set()).add(label)

    print("期望顺序: %s\n" % " ".join(EXPECT))
    ok = True
    for name, seq in checks:
        good = (seq == EXPECT)
        ok = ok and good
        print("  %-26s %s   %s" % (name, " ".join(seq) if seq else "(空)",
                                   "OK" if good else "[x] 不一致"))

    print("\n各站点被四个文件覆盖的情况：")
    for p in EXPECT:
        seen = actions.get(p, set())
        full = len(seen) == 4
        ok = ok and full
        print("  %-22s %-34s %s" % (p, ",".join(sorted(seen)) or "(缺失)",
                                    "OK" if full else "[x] 并非四处齐全"))

    print()
    print("ALL OK" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
