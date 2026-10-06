# -*- coding: utf-8 -*-
"""站点按【功能】重命名（一次性脚本，2026-10-05）。

背景：旧编号 P1..P11 是【按添加时间】编的，不含语义 ——
      表内顺序是 P1 P2 P3 P6 P7 P10 P11 P4 P8，序号与位置完全不对应。
      用户要求改成"功能组 + 阶段"命名。

两组信息都保留：
  · 组前缀（modfix / gen / disp）表达"这是哪一件事"
  · 动作名（entry / decide / len / reorder / fallback）表达流水线阶段，
    且五个 gen 站点按字典序恰好等于执行顺序

映射：
  旧 P1  → modfix_pick_idx       旧 P6  → gen_entry_culture
  旧 P2  → modfix_pick_cult      旧 P7  → gen_loop_decide
  旧 P3  → modfix_pick_modidx    旧 P10 → gen_surn_len
  旧 P4  → gen_exit_fallback     旧 P11 → gen_reorder
  旧 P8  → disp_ruler_name

方法：两阶段替换（旧 → 占位符 → 新），避免"新名里含有旧名"造成的级联改写。
      用精确字符串替换，不用正则 —— P10/P11 是两位数字，正则的 \\b 边界
      在 `mnp_hook_p10_` 这种上下文里不可靠。
"""
import io
import os
import sys

# (旧标识, 新标识, 旧显示名token, 新显示名token, 显示名对齐后的完整前缀)
SITES = [
    # 组 1：取模缺陷修复（三个站点 = 同一个 bug 的三处）
    ("p1",  "modfix_pick_idx",    "P1",  "modfix", "modfix  pick_idx"),
    ("p2",  "modfix_pick_cult",   "P2",  "modfix", "modfix  pick_cult"),
    ("p3",  "modfix_pick_modidx", "P3",  "modfix", "modfix  pick_modidx"),
    # 组 2：生成期姓前名后（五个站点 = 一条流水线）
    ("p6",  "gen_entry_culture",  "P6",  "gen",    "gen     entry_culture"),
    ("p7",  "gen_loop_decide",    "P7",  "gen",    "gen     loop_decide"),
    ("p10", "gen_surn_len",       "P10", "gen",    "gen     surn_len"),
    ("p11", "gen_reorder",        "P11", "gen",    "gen     reorder"),
    ("p4",  "gen_exit_fallback",  "P4",  "gen",    "gen     exit_fallback"),
    # 组 3：显示期统治者姓名（一个站点）
    ("p8",  "disp_ruler_name",    "P8",  "disp",   "disp    ruler_name"),
]

FILES = [
    "src/monarchnamefix/install.cpp",
    "src/monarchnamefix/stubs.asm",
    "src/monarchnamefix/stubs.hpp",
    "src/monarchnamefix/hookvars.cpp",
    "src/monarchnamefix/monarchnamefix.cpp",
    "scripts/verify_site_order.py",
    "scripts/verify_newhook.py",
    "scripts/verify_patch_targets.py",
]


def build_pairs():
    """生成 (旧, 新) 替换对。长的先做，避免 p1 命中 p10 的前缀。"""
    pairs = []
    for old, new, _, _, _ in SITES:
        O, N = old.upper(), new
        # ---- 汇编 / C++ 符号 ----
        for tpl_old, tpl_new in [
            ("mnp_hook_%s_" % old,   "mnp_hook_%s_" % new),
            ("mnp_h_%s_" % old,      "mnp_h_%s_" % new),
            ("mnpfn_%s_" % old,      "mnpfn_%s_" % new),
            ("mnp_ret_%s" % old,     "mnp_ret_%s" % new),
            ("mnp_%s_skip" % old,    "mnp_%s_skip" % new),
        ]:
            # 只对"确实存在的前缀"生成；后缀部分靠逐符号精确替换（见下）
            pairs.append((tpl_old, tpl_new))
    return pairs


# 逐符号精确表（由扫描得出，避免猜后缀）
SYMBOLS = [
    # ---- P1 ----
    ("mnp_hook_p1_runmask",        "mnp_hook_modfix_pick_idx"),
    ("mnp_h_p1_mask_random",       "mnp_h_modfix_pick_idx"),
    ("mnpfn_p1_mask_random",       "mnpfn_modfix_pick_idx"),
    ("mnp_ret_p1",                 "mnp_ret_modfix_pick_idx"),
    # ---- P2 ----
    ("mnp_hook_p2_modulo",         "mnp_hook_modfix_pick_cult"),
    ("mnp_h_p2_modulo_unsigned",   "mnp_h_modfix_pick_cult"),
    ("mnpfn_p2_modulo_unsigned",   "mnpfn_modfix_pick_cult"),
    ("mnp_ret_p2",                 "mnp_ret_modfix_pick_cult"),
    # ---- P3 ----
    ("mnp_hook_p3_modulo",         "mnp_hook_modfix_pick_modidx"),
    ("mnp_h_p3_modulo_unsigned",   "mnp_h_modfix_pick_modidx"),
    ("mnpfn_p3_modulo_unsigned",   "mnpfn_modfix_pick_modidx"),
    ("mnp_ret_p3",                 "mnp_ret_modfix_pick_modidx"),
    # ---- P6 ----
    ("mnp_hook_p6_culture",        "mnp_hook_gen_entry_culture"),
    ("mnp_h_p6_capture_culture",   "mnp_h_gen_entry_culture"),
    ("mnpfn_p6_capture_culture",   "mnpfn_gen_entry_culture"),
    ("mnp_ret_p6",                 "mnp_ret_gen_entry_culture"),
    # ---- P7 ----
    ("mnp_hook_p7_decide",         "mnp_hook_gen_loop_decide"),
    ("mnp_h_p7_decide_sf",         "mnp_h_gen_loop_decide"),
    ("mnpfn_p7_decide_sf",         "mnpfn_gen_loop_decide"),
    ("mnp_ret_p7_skip",            "mnp_ret_gen_loop_decide_skip"),
    ("mnp_ret_p7",                 "mnp_ret_gen_loop_decide"),
    # ---- P10 ----
    ("mnp_hook_p10_surnlen",       "mnp_hook_gen_surn_len"),
    ("mnp_h_p10_record_surn_len",  "mnp_h_gen_surn_len"),
    ("mnpfn_p10_record_surn_len",  "mnpfn_gen_surn_len"),
    ("mnp_ret_p10",                "mnp_ret_gen_surn_len"),
    # ---- P11 ----
    ("mnp_hook_p11_reorder",       "mnp_hook_gen_reorder"),
    ("mnp_h_p11_reorder_sf",       "mnp_h_gen_reorder"),
    ("mnpfn_p11_reorder_sf",       "mnpfn_gen_reorder"),
    ("mnp_ret_p11",                "mnp_ret_gen_reorder"),
    # ---- P4 ----
    ("mnp_hook_p4_fallback",       "mnp_hook_gen_exit_fallback"),
    ("mnp_h_p4_fallback_reorder",  "mnp_h_gen_exit_fallback"),
    ("mnpfn_p4_fallback_reorder",  "mnpfn_gen_exit_fallback"),
    ("mnp_ret_p4",                 "mnp_ret_gen_exit_fallback"),
    # ---- P8 ----
    ("mnp_hook_p8_display",        "mnp_hook_disp_ruler_name"),
    ("mnp_h_p8_display_reorder",   "mnp_h_disp_ruler_name"),
    ("mnpfn_p8_display_reorder",   "mnpfn_disp_ruler_name"),
    ("mnp_ret_p8",                 "mnp_ret_disp_ruler_name"),
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report = []

    # 两阶段：先全部换成不可能冲突的占位符，再换成新名
    staging = []
    for i, (old, new) in enumerate(SYMBOLS):
        staging.append(("@@SYM%03d@@" % i, old, new))

    for rel in FILES:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            report.append("  [skip] %s 不存在" % rel)
            continue
        s = io.open(p, encoding="utf-8", errors="surrogateescape").read()
        orig = s
        n_hit = 0
        # 阶段 1
        for ph, old, new in staging:
            c = s.count(old)
            if c:
                s = s.replace(old, ph)
                n_hit += c
        # 阶段 2
        for ph, old, new in staging:
            s = s.replace(ph, new)
        if s != orig:
            io.open(p, "w", encoding="utf-8", errors="surrogateescape",
                    newline="").write(s)
        report.append("  %-46s %d 处" % (rel, n_hit))

    sys.stdout.reconfigure(encoding="utf-8")
    print("符号重命名完成：")
    print("\n".join(report))


if __name__ == "__main__":
    main()
