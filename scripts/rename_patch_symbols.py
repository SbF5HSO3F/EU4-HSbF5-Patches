# -*- coding: utf-8 -*-
"""把补丁站点的符号名从 `p1/p2/...` 改成带动作名的形式（一次性维护脚本）。

背景：P1..P11 是【按添加时间】编号的，光看 `mnp_h_p10` 完全不知道它在干什么。
但编号本身不能改 —— notes\\ 里有 500+ 处引用，且 `verify_site_order.py`
用 `_pN_` 这个片段校验五处文件的顺序。所以采用「保留编号 + 补动作名」。新名字里
仍然含 `pN`，既满足 verify_site_order.py 的抽取，也让旧笔记里的 "P1" 依旧能搜到。

    mnp_hook_p1   -> mnp_hook_p1_runmask      （stubs.asm 的 PROC / kSites[] 的取址）
    mnp_h_p1      -> mnp_h_p1_mask_random     （monarchnamefix.cpp 的处理器）
    mnpfn_p1_modfix -> mnpfn_p1_runmask       （桩要调的函数指针变量）
    mnp_ret_p1    -> mnp_ret_p1               （不变：回跳点槽，名字已够清楚）

只替换【标识符】，动作名里也不再重复 "modfix" 这种含糊词。
"""
import io
import os
import re
import sys

SRC = r"%REPO_ROOT%\src\monarchnamefix"

# 每个站点：(桩名后缀, 处理器名后缀, 指针变量后缀, 说明)
SITES = {
    "1":  ("runmask",  "mask_random",     "runmask",
           "随机值掩成 21 位非负（WeightedNameList_PickByRandomIndex 序言）"),
    "2":  ("modulo",   "modulo_unsigned", "modulo",
           "有符号取模改无符号（PickNameFromCultureLists）"),
    "3":  ("modulo",   "modulo_unsigned", "modulo",
           "有符号取模改无符号（WeightedNameList_GetByModIndex）"),
    "6":  ("culture",  "capture_culture", "culture",
           "函数入口捕获本次调用的文化名"),
    "7":  ("decide",   "decide_sf",       "decide",
           "循环前判定该文化是否姓前名后（只置标志，不碰缓冲）"),
    "10": ("surnlen",  "record_surn_len", "surnlen",
           "追加姓之前记下姓的字节数"),
    "11": ("reorder",  "reorder_sf",      "reorder",
           "追加姓之后就地重排成「姓 + sep + 名」"),
    "4":  ("fallback", "fallback_reorder","fallback",
           "函数出口兜底重排（P11 没做成时）"),
    "8":  ("display",  "display_reorder", "display",
           "显示期 CMonarch_GetFullName 重排"),
}

# 处理器名要能自解释，所以单独给一张表（不机械拼后缀）
HANDLER = {
    "1":  "mnp_h_p1_mask_random",
    "2":  "mnp_h_p2_modulo_unsigned",
    "3":  "mnp_h_p3_modulo_unsigned",
    "6":  "mnp_h_p6_capture_culture",
    "7":  "mnp_h_p7_decide_sf",
    "10": "mnp_h_p10_record_surn_len",
    "11": "mnp_h_p11_reorder_sf",
    "4":  "mnp_h_p4_fallback_reorder",
    "8":  "mnp_h_p8_display_reorder",
}

MAP = {}
for p, (stub, var, _v, _d) in SITES.items():
    MAP["mnp_hook_p" + p] = "mnp_hook_p" + p + "_" + stub
    MAP["mnp_h_p" + p] = HANDLER[p]
    # 桩调用的函数指针变量（旧名有 modfix/capture/notify/save/reorder/transform 六种后缀）
    for old_suffix in ("modfix", "capture", "notify", "save", "reorder",
                       "transform"):
        MAP["mnpfn_p" + p + "_" + old_suffix] = "mnpfn_p" + p + "_" + var

# 业务实现函数（不再是"prepend"了，必须改名，否则读代码会被名字骗）
EXTRA = {
    "p10_save_surlen":   "p10_record_surname_len",
    "p11_reorder":       "p11_reorder_surname_first",
    "p4_transform":      "p4_fallback_reorder",
    "p7_prepend_if_sf":  "p7_decide_surname_first",
    "cult_name_capture": "culture_capture_from_ctx",
}

# 全局标志：让名字自己说明含义
FLAGS = {
    "g_sf_active": "g_sf_want",       # 本次调用所属文化【要求】姓前名后
    "g_sf_done":   "g_sf_reordered",  # 生成期已重排完成（P4 据此不要再动）
}


def apply_map(text):
    allmap = {}
    allmap.update(MAP)
    allmap.update(EXTRA)
    allmap.update(FLAGS)
    # 先长后短，避免长名被短名规则截断
    for old in sorted(allmap, key=len, reverse=True):
        text = re.sub(r"\b" + re.escape(old) + r"\b", allmap[old], text)
    return text


def main():
    targets = ["stubs.hpp", "stubs.asm", "hookvars.cpp", "install.cpp",
               "monarchnamefix.cpp", "nameorder.h"]
    total = 0
    for name in targets:
        path = os.path.join(SRC, name)
        if not os.path.exists(path):
            print("  (skip) %s" % name)
            continue
        src = io.open(path, encoding="utf-8", errors="surrogateescape").read()
        out = apply_map(src)
        if out != src:
            io.open(path, "w", encoding="utf-8", errors="surrogateescape",
                    newline="").write(out)
            n = sum(1 for a, b in zip(src.split("\n"), out.split("\n")) if a != b)
            print("  %-22s %d 行改动" % (name, n))
            total += n
        else:
            print("  %-22s 无改动" % name)
    print("\n合计 %d 行" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
