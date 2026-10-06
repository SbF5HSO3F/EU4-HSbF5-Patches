#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_culture_offsets.py — 静态核对 CCulture 的字段偏移常量与反汇编证据一致。

本脚本把「文化对象各字段偏移」这一组关键假设固化成可复核的断言，避免以后
再靠临场读反汇编来回推（本轮为此花了大量时间，且中途出现过互相矛盾的读数）。

核对项（全部来自 eu4.exe v1.37.5.0 的反汇编字节）：
  A. 构造 sub_1401AF830 里对成员名字段的初始化：
       0x1401AF8A5  mov [rcx+60h], 0        -> size
       0x1401AF8AC  mov [rcx+68h], 0        -> capacity
       0x1401AFA80  lea rcx, [rbx+50h]      -> 数据在 +0x50
     ⇒ 成员名 = CString @ +0x50，size +0x60，cap +0x68
  B. 析构 sub_1401AFA40 的 StringFree 参数：+0x120 与 +0x140
  C. 查找 sub_1401B0BE0：rdi = 被比较的键对象；`movsxd r9, [rdi+10h]` 取长度、
     `mov rbp, [rdi+10h]` 取长度、`lea rcx, [rsi+120h]` 再 `mov r8, [rcx+10h]`
     ⇒ rdi 指向 CString 起始；rsi = 文化对象；id 数据 @ obj+0x120 ⇒ size +0x130
  D. tooltip sub_1401AFB30：`lea r8, [rcx+120h]` + `cmp [r8+18h], 10h`
     ⇒ id 数据 @ +0x120、cap @ +0x138（与 C 的 size @ +0x130 吻合）
  E. 注册表单例与哈希函数：`qword_14242B9F8`；h = 61*(h + (signed char)c)

用法：python scripts/verify_culture_offsets.py
退出码 0 = 全绿。
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HDR = os.path.join(ROOT, "src", "monarchnamefix", "cultureconfig.h")

fails = []
checks = 0


def check(cond, msg):
    global checks
    checks += 1
    if cond:
        print("  [v] " + msg)
    else:
        fails.append(msg)
        print("  [x] " + msg)


hdr = io.open(HDR, encoding="utf-8").read()


def macro(name):
    m = re.search(r"#define\s+%s\s+(0x[0-9A-Fa-f]+)u?" % name, hdr)
    return int(m.group(1), 16) if m else None


print("== cultureconfig.h 常量 ==")
check(macro("CC_CULT_ID_OFF") == 0x120, "CC_CULT_ID_OFF = 0x120")
check(macro("CC_CULT_ID_SIZE") == 0x130, "CC_CULT_ID_SIZE = 0x130")
check(macro("CC_CULT_ID_CAP") == 0x138, "CC_CULT_ID_CAP = 0x138")
check(macro("CC_CULT_MEMBER_OFF") == 0x50, "CC_CULT_MEMBER_OFF = 0x50")
check(macro("CC_CULT_MEMBER_SIZE") == 0x60, "CC_CULT_MEMBER_SIZE = 0x60")
check(macro("CC_CULT_MEMBER_CAP") == 0x68, "CC_CULT_MEMBER_CAP = 0x68")
check(macro("CC_VA_REGISTRY") == 0x14242B9F8,
      "CC_VA_REGISTRY = 0x14242B9F8（qword_14242B9F8 的**绝对虚拟地址**）")
check(macro("CC_BASE_EXPECT") == 0x140000000, "CC_BASE_EXPECT = 0x140000000")
check(macro("CC_VA_REGISTRY") - macro("CC_BASE_EXPECT") == 0x0242B9F8,
      "基址 + CC_REGISTRY_OFF 落在 0x14242B9F8（偏移 = 0x242B9F8）")
# 曾经的回归：写成 0x0242B9F8 会让偏移变成负数 0xFFFFFFFFC242B9F8，指针跑到模块外，
# 绑定额外恒为 0。这里把"常量必须是完整 VA"钉死。
check("0x0242B9F8u   /* CCulture" not in hdr,
      "没有把注册表常量退回成相对偏移 0x0242B9F8（那会算成 base - 0x242B9F8）")

print()
print("== 偏移之间的自洽性 ==")
# CString 布局：数据 @ off，size @ off+0x10，cap @ off+0x18
check(macro("CC_CULT_ID_SIZE") - macro("CC_CULT_ID_OFF") == 0x10,
      "id: size 相对数据 +0x10（MSVC CString 布局）")
check(macro("CC_CULT_ID_CAP") - macro("CC_CULT_ID_OFF") == 0x18,
      "id: cap 相对数据 +0x18")
check(macro("CC_CULT_MEMBER_SIZE") - macro("CC_CULT_MEMBER_OFF") == 0x10,
      "member: size 相对数据 +0x10")
check(macro("CC_CULT_MEMBER_CAP") - macro("CC_CULT_MEMBER_OFF") == 0x18,
      "member: cap 相对数据 +0x18")

print()
print("== SSO 判据在 header 里的用法 ==")
# 关键：cap < 0x10 才算 SSO（数据内联）。写成 cap >= 0x10 走 SSO 会崩。
check("if (cap < 0x10) data = " in hdr,
      "cc_cstr_field 用 `cap < 0x10` 判 SSO（数据内联在字段地址）")
check("if (cap >= 0x10) data = raw" not in hdr,
      "没有把 `cap >= 0x10` 误当成 SSO 判据")

print()
print("== 哈希函数与游戏一致 ==")
check("61u * (h + (uint32_t)(int32_t)(signed char)s[i])" in hdr,
      "cc_hash 使用 h = 61*(h + (signed char)c)（与 sub_1401B0BE0 逐字一致）")
check("signed char" in hdr, "哈希对字节做有符号扩展（否则高字节字符会算错）")

print()
print("== 注册表遍历的防护 ==")
check("buckets > 0x10000u" in hdr, "桶数上界防护（拒绝畸形注册表）")
check("guard < 256" in hdr, "桶链长度防护（拒绝环/超长链）")
check("pn_ok(&S->rd, obj, coff + 8)" in hdr, "解引用对象前先做可读性校验")

print()
if fails:
    print("[FAIL] %d 项不符（共 %d 项检查）" % (len(fails), checks))
    for f in fails:
        print("   - " + f)
    sys.exit(1)
print("[PASS] CCulture 字段偏移与反汇编证据一致（共 %d 项检查）" % checks)
sys.exit(0)
