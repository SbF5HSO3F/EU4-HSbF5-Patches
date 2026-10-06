/*
 * nameordertest.exe — 姓名顺序变换（PatchNameOrder）单元测试
 *
 * 验证核心变换：
 *   "<given> <space> 0xBF<surname>"  →  "<surname> <space> <given>"
 *   未含 " 0xBF" 的串必须【一字节都不改】。
 *
 * 覆盖 MSVC CString 的两种缓冲形态与 size 同步：
 *   - SSO：size <= 15，cap = 15，数据内联在对象起始处（16 字节）
 *   - 堆 ：size >= 16，cap >= 16，对象起始处是 char*
 * 说明：真实 MSVC 串【只有 size >= 16 才走堆】（SSO 装得下就不分配），
 *       所以 "cap < 16 的堆串" 是不存在的形态，测试不构造它。
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SSO_MAX 15

/* 变换逻辑统一来自 nameorder.h —— 与补丁 DLL 共用同一实现，避免分叉。
 * （此前这里有一份内联副本，曾导致分隔符改动只对 DLL 生效、测试仍测旧逻辑。） */
#include "nameorder.h"
typedef cstr_t CStr;          /* 本文件其余脚手架沿用 CStr 这个名字 */

/* ===================== 测试脚手架 ===================== */
static int fails = 0, total = 0;

static int  g_sf   = 1;                 /* surname_first */
static int  g_has_sep = 0;              /* 0 ⇒ 用全局缺省分隔符（空） */
static char g_sep[NAME_SEP_MAX];
static uint32_t g_seplen = 0;
static int  g_force = 0;                /* 1 ⇒ 测试 name_order_apply_cfg（配置命中路径） */
static int  g_sf_arg = 1;               /* 传给 _cfg 的 surname_first 实参 */
static int  g_replace = 0;              /* 1 ⇒ 测试 name_order_replace_sep（gen     loop_decide 启用后 gen     exit_fallback 的新职责） */

static void check(const char *title, const unsigned char *in, size_t in_len,
                  const unsigned char *want, size_t want_len)
{
    CStr *s;
    int heap = (in_len > SSO_MAX);
    unsigned char before[512];
    name_sep_t sep;

    if (in_len > sizeof(before)) { printf("[skip] %s (too long)\n", title); return; }
    s = (CStr *)malloc(sizeof(CStr));
    memset(s, 0, sizeof(CStr));
    if (heap) {
        s->u.ptr = (char *)malloc(in_len + 1);
        memcpy(s->u.ptr, in, in_len);
        s->u.ptr[in_len] = 0;
        s->cap = in_len;                 /* >= 16 */
    } else {
        memcpy(s->u.sso, in, in_len);
        s->u.sso[in_len] = 0;
        s->cap = SSO_MAX;                /* < 16 ⇒ SSO 分支 */
    }
    s->size = in_len;
    memcpy(before, heap ? (void *)s->u.ptr : (void *)s->u.sso, in_len);

    total++;
    if (g_replace) {
        if (g_has_sep) { pn_set_sep(&sep, g_sep, g_seplen); name_order_replace_sep(s, &sep); }
        else           { name_order_replace_sep(s, NULL); }
    } else if (g_force) {
        if (g_has_sep) { pn_set_sep(&sep, g_sep, g_seplen); name_order_apply_cfg(s, g_sf_arg, &sep, 1); }
        else           { name_order_apply_cfg(s, g_sf_arg, NULL, 1); }
    } else if (g_has_sep) { pn_set_sep(&sep, g_sep, g_seplen); name_order_apply(s, g_sf, &sep); }
    else                  { name_order_apply(s, g_sf, NULL); }
    {
        char *got = heap ? s->u.ptr : s->u.sso;
        if (s->size != want_len || memcmp(got, want, want_len) != 0) {
            printf("[FAIL] %-40s (%s) len %u -> %u\n", title, heap ? "heap" : "sso",
                   (unsigned)in_len, (unsigned)s->size);
            printf("        got  : "); { size_t i; for (i = 0; i < s->size; i++) printf("%02X ", (unsigned char)got[i]); }
            printf("\n        want : "); { size_t i; for (i = 0; i < want_len; i++) printf("%02X ", want[i]); }
            printf("\n");
            fails++;
        } else {
            const char *note = (want_len == in_len) ? "未改动 ✓" : "";
            printf("[ok]   %-40s (%s) len %u -> %u %s\n", title, heap ? "heap" : "sso",
                   (unsigned)in_len, (unsigned)s->size, note);
        }
    }
    if (heap) free(s->u.ptr);
    free(s);
}

/* 每次 check 前重置为默认判据（surname_first = 1，全局缺省分隔符 = 空串） */
static void reset_default(void) { g_sf = 1; g_has_sep = 0; g_seplen = 0; }


int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1) ASCII 重排（SSO：14 字节） */
    {
        const unsigned char in[]   = "Ferdinand \xBFZhu";
        const unsigned char want[] = "ZhuFerdinand";
        check("ASCII 重排（SSO）", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 2) ASCII 重排（堆：>= 16 字节） */
    {
        const unsigned char in[]   = "Ferdinand Alexander \xBFZhu";
        const unsigned char want[] = "ZhuFerdinand Alexander";
        check("ASCII 重排（堆）", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 3) 中文（UTF-8）重排（SSO） */
    {
        const unsigned char in[]   = "\xE5\xAD\x9F\xE5\xAD\x90 \xBF\xE6\x9C\xB1\xE5\x85\x83";
        const unsigned char want[] = "\xE6\x9C\xB1\xE5\x85\x83\xE5\xAD\x9F\xE5\xAD\x90";
        check("中文重排（SSO）", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 4) 中文（UTF-8）重排（堆） */
    {
        const unsigned char in[]   = "\xE7\x88\xB1\xE6\x96\xB0\xE8\xA7\x89\xE7\xBD\x97 \xBF\xE6\x9C\xB1\xE5\x85\x83\xE7\x92\x8B";
        const unsigned char want[] = "\xE6\x9C\xB1\xE5\x85\x83\xE7\x92\x8B\xE7\x88\xB1\xE6\x96\xB0\xE8\xA7\x89\xE7\xBD\x97";
        check("中文重排（堆）", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 5) 未含标记 ⇒ 逐字节不变（SSO：15 字节） */
    {
        const unsigned char in[] = "Ferdinand Habsb";
        check("无标记：零改动（SSO）", in, sizeof(in) - 1, in, sizeof(in) - 1);
    }
    /* 6) 未含标记 ⇒ 逐字节不变（堆：18 字节） */
    {
        const unsigned char in[] = "Ferdinand Habsburg";
        check("无标记：零改动（堆）", in, sizeof(in) - 1, in, sizeof(in) - 1);
    }
    /* 7) 标记在串首（"¿Zhu"）⇒ 无名，只剥标记并加分隔符 */
    {
        const unsigned char in[]   = "\xBFZhu";
        const unsigned char want[] = "Zhu";
        reset_default();
        check("标记在串首：剥标记", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 8) 标记后为空 ⇒ 不动 */
    {
        const unsigned char in[] = "Ferdinand \xBF";
        reset_default();
        check("标记后为空：不动", in, sizeof(in) - 1, in, sizeof(in) - 1);
    }
    /* 9) 长度不足 ⇒ 不动 */
    {
        const unsigned char in[] = "a\xBF";
        reset_default();
        check("长度不足：不动", in, sizeof(in) - 1, in, sizeof(in) - 1);
    }
    /* 10) 名里本来就有空格 ⇒ 取第一个标记 */
    {
        const unsigned char in[]   = "Jean Claude \xBFVan Damme";
        const unsigned char want[] = "Van DammeJean Claude";
        reset_default();
        check("多段名：取第一个标记", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 11) 空格+标记在中段（预期重排） */
    {
        const unsigned char in[]   = "Zhu \xBF" "Ferdinand";
        const unsigned char want[] = "FerdinandZhu";
        reset_default();
        check("标记在末段（预期重排）", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 12) 只有标记无空格分隔（两段之间不是空格）⇒ 不动 */
    {
        const unsigned char in[] = "Ferdinand\xBFZhu";
        reset_default();
        check("标记前非空格：不动", in, sizeof(in) - 1, in, sizeof(in) - 1);
    }

    /* ---------------- 分隔符与文化判据（本轮新增） ---------------- */
    /* 13) 分隔符 = 一个空格（西文习惯）⇒ "Zhu Ferdinand" */
    {
        const unsigned char in[]   = "Ferdinand \xBFZhu";
        const unsigned char want[] = "Zhu Ferdinand";
        g_sf = 1; g_has_sep = 1; g_sep[0] = ' '; g_seplen = 1;
        check("分隔符=\" \"：西文习惯", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 14) 分隔符 = 空串（中文习惯，默认）⇒ "ZhuFerdinand" */
    {
        const unsigned char in[]   = "Ferdinand \xBFZhu";
        const unsigned char want[] = "ZhuFerdinand";
        g_sf = 1; g_has_sep = 1; g_seplen = 0;
        check("分隔符=\"\"：中文习惯", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 15) surname_first = no ⇒ 不交换，只剥标记；得到「名+分隔符+姓」 */
    {
        const unsigned char in[]   = "Ferdinand \xBFZhu";
        const unsigned char want[] = "Ferdinand Zhu";
        g_sf = 0; g_has_sep = 1; g_sep[0] = ' '; g_seplen = 1;
        check("surname_first=no：不交换", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 16) surname_first = no + 空分隔符 ⇒ 粘在一起（用户显式选择） */
    {
        const unsigned char in[]   = "Ferdinand \xBFZhu";
        const unsigned char want[] = "FerdinandZhu";
        g_sf = 0; g_has_sep = 1; g_seplen = 0;
        check("surname_first=no + 空分隔符", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    /* 17) 分隔符 = 两个字节（多字节分隔符） */
    {
        const unsigned char in[]   = "Ferdinand \xBFZhu";
        const unsigned char want[] = "Zhu, Ferdinand";
        g_sf = 1; g_has_sep = 1; memcpy(g_sep, ", ", 2); g_seplen = 2;
        check("多字节分隔符 \", \"", in, sizeof(in) - 1, want, sizeof(want) - 1);
        printf("        （长度不变属正常：原串 \" ␠¿\" 共 2 字节，被 \", \" 2 字节替换）\n");
    }
    /* 18) 长分隔符需要扩容：堆串 cap 不足 ⇒ 放弃变换（保留原样的安全行为）
     * ★ 这里曾写 `memcpy(g_sep, "---------------", 15)` —— 而 NAME_SEP_MAX 只有 8，
     *   于是【越界写 7 字节】，把相邻的全局变量踩掉。以前被踩的变量没人用，
     *   所以一直没暴露；本轮新增 g_replace 后被踩成 0x2D2D2D（'---'），
     *   导致"无标记强制交换"整组测试失败。改用 NAME_SEP_MAX 字节，测试意图不变：
     *   need = 3(姓) + 20(名) + 8 = 31 > cap 24 ⇒ 仍然走"放弃、保留原样"分支。 */
    {
        const unsigned char in[] = "Ferdinand Alexander \xBFZhu";
        const unsigned char want[] = "Ferdinand Alexander \xBFZhu";   /* 未动 */
        g_sf = 1; g_has_sep = 1; memcpy(g_sep, "--------", NAME_SEP_MAX);
        g_seplen = NAME_SEP_MAX;
        check("半截名+超长分隔符（堆满⇒不动）", in, sizeof(in) - 1, want, sizeof(want) - 1);
    }
    reset_default();

    /* ================= 新增：无 0xBF 时的强制交换 =================
     * 数据来自实机日志（2026-10-03，明/江淮）：
     *   顾问、全部外交官/商人/传教士/殖民者、陆海军将领的名字
     *   形如「名 SP 姓」且【不含 0xBF】⇒ 旧逻辑在第 131 行就 return 了。
     * 这里沿用日志里的真实字节序列做回归。 */
    printf("\n== 无标记时按空格强制交换（配置命中路径）==\n");
    g_force = 1; g_has_sep = 1; g_seplen = 0; g_sf_arg = 1;

    /* 1) 日志原样：bytes(7) = 10 1b 69 20 10 8b 73（空格在 3） */
    {
        const unsigned char in[]   = { 0x10,0x1b,0x69,0x20,0x10,0x8b,0x73 };
        const unsigned char want[] = { 0x10,0x8b,0x73,0x10,0x1b,0x69 };   /* 姓+名，无分隔符 */
        check("无标记7B：姓+名（sep=\"\"）", in, sizeof(in), want, sizeof(want));
    }
    /* 2) 日志原样：bytes(13)，空格在 6（名 6B + 姓 5B） */
    {
        const unsigned char in[]   = { 0x10,0x31,0x75,0x10,0x21,0x6a,0x20,
                                       0x10,0xe4,0x4e,0x10,0xd0,0x72 };
        const unsigned char want[] = { 0x10,0xe4,0x4e,0x10,0xd0,0x72,
                                       0x10,0x31,0x75,0x10,0x21,0x6a };
        check("无标记13B：姓+名（sep=\"\"）", in, sizeof(in), want, sizeof(want));
    }
    /* 3) 同样输入，但配置给一个空格分隔符 */
    {
        const unsigned char in[]   = { 0x41,0x42,0x20,0x43,0x44 };
        const unsigned char want[] = { 0x43,0x44,0x20,0x41,0x42 };
        g_sep[0] = ' '; g_seplen = 1;
        check("无标记：姓 SP 名（sep=\" \"）", in, sizeof(in), want, sizeof(want));
        g_seplen = 0;
    }
    /* 4) surname_first = 0 ⇒ 名在前（分隔符仍按配置） */
    {
        const unsigned char in[]   = { 0x41,0x42,0x20,0x43,0x44 };
        const unsigned char want[] = { 0x41,0x42,0x43,0x44 };
        g_sf_arg = 0;
        check("无标记 sf=0：名+姓（sep=\"\"）", in, sizeof(in), want, sizeof(want));
        g_sf_arg = 1;
    }
    /* 5) 无空格 ⇒ 不猜边界，原样返回 */
    {
        const unsigned char in[]   = { 0x41,0x42,0x43,0x44,0x45 };
        check("无空格：原样不动", in, sizeof(in), in, sizeof(in));
    }
    /* 6) 两个空格 ⇒ 边界不唯一，原样返回 */
    {
        const unsigned char in[]   = { 0x41,0x20,0x42,0x20,0x43 };
        check("两个空格：原样不动", in, sizeof(in), in, sizeof(in));
    }
    /* 7) 空格在末尾 ⇒ 原样返回 */
    {
        const unsigned char in[]   = { 0x41,0x42,0x20 };
        check("空格在末尾：原样不动", in, sizeof(in), in, sizeof(in));
    }
    /* 8) 有 0xBF ⇒ 仍走原标记路径（语义不能被强制路径改变） */
    {
        const unsigned char in[]   = { 0x41,0x42,0x20,0xBF,0x43,0x44 };
        const unsigned char want[] = { 0x43,0x44,0x41,0x42 };
        check("有 0xBF：仍走标记路径", in, sizeof(in), want, sizeof(want));
    }
    /* 9) force=0 且无标记 ⇒ 原样不动（回退路径不受影响） */
    {
        const unsigned char in[]   = { 0x41,0x42,0x20,0x43,0x44 };
        g_force = 0;
        check("force=0 且无标记：原样不动", in, sizeof(in), in, sizeof(in));
        g_force = 1;
    }
    g_force = 0; g_sf_arg = 1;
    reset_default();

    /* ============ 新增：分隔符替换（gen     loop_decide 启用后 gen     exit_fallback 的新职责） ============
     * gen     loop_decide 已在生成阶段按文化反转「段」的顺序，所以出口拿到的字符串顺序已正确；
     * gen     exit_fallback 只剩一件事：把循环硬编码的空格替换成配置的 separator。
     * 这是**纯替换**，不需要识别边界 —— 因此彻底摆脱"恰好 1 个空格"的前提。 */
    printf("\n== 分隔符替换（gen/decide 后 gen/fallback 的新职责）==\n");
    g_replace = 1; g_has_sep = 1;

    /* 1) separator = "" ⇒ 删除空格（中文/日文/韩文场景） */
    {
        const unsigned char in[]   = { 0x41, 0x42, 0x20, 0x43, 0x44 };
        const unsigned char want[] = { 0x41, 0x42, 0x43, 0x44 };
        g_seplen = 0;
        check("sep=\"\"  ：删空格 A B → AB", in, sizeof(in), want, sizeof(want));
    }
    /* 2) separator = " " ⇒ 保持一个空格 */
    {
        const unsigned char in[]   = { 0x41, 0x42, 0x20, 0x43, 0x44 };
        const unsigned char want[] = { 0x41, 0x42, 0x20, 0x43, 0x44 };
        g_sep[0] = ' '; g_seplen = 1;
        check("sep=\" \"  ：等长替换（不变）", in, sizeof(in), want, sizeof(want));
    }
    /* 3) separator = "." ⇒ 单字节替换 */
    {
        const unsigned char in[]   = { 0x41, 0x42, 0x20, 0x43, 0x44 };
        const unsigned char want[] = { 0x41, 0x42, 0x2E, 0x43, 0x44 };
        g_sep[0] = '.'; g_seplen = 1;
        check("sep=\".\"  ：A B → A.B", in, sizeof(in), want, sizeof(want));
    }
    /* 4) separator = ", "（2 字节，需要扩容）—— 从右往左重写才不覆盖未读字节 */
    {
        const unsigned char in[]   = { 'X', 0x20, 'Y', 0x20, 'Z' };
        const unsigned char want[] = { 'X', ',', ' ', 'Y', ',', ' ', 'Z' };
        g_sep[0] = ','; g_sep[1] = ' '; g_seplen = 2;
        check("sep=\", \" ：X Y Z → X, Y, Z（扩容）", in, sizeof(in), want, sizeof(want));
    }
    /* 5) 多个空格、多段（这正是旧方案"恰好 1 个空格"做不到的） */
    {
        const unsigned char in[]   = { 'A', 0x20, 'B', 0x20, 'C', 0x20, 'D' };
        const unsigned char want[] = { 'A', 'B', 'C', 'D' };
        g_seplen = 0;
        check("sep=\"\"  ：四段 A B C D → ABCD", in, sizeof(in), want, sizeof(want));
    }
    /* 6) 没有空格 ⇒ 零影响 */
    {
        const unsigned char in[]   = { 'A', 'B', 'C', 'D' };
        g_seplen = 0;
        check("无空格：原样不动", in, sizeof(in), in, sizeof(in));
    }
    /* 7) 分隔符在两端：也应被替换（不做位置特判） */
    {
        const unsigned char in[]   = { 0x20, 'A', 0x20 };
        const unsigned char want[] = { 'A' };
        g_seplen = 0;
        check("首尾空格：→ A", in, sizeof(in), want, sizeof(want));
    }
    /* 8) 长串（堆路径）+ separator="" */
    {
        const unsigned char in[]   = { 'A','B','C','D','E','F','G','H', 0x20,
                                       'I','J','K','L','M','N','O','P' };
        const unsigned char want[] = { 'A','B','C','D','E','F','G','H',
                                       'I','J','K','L','M','N','O','P' };
        g_seplen = 0;
        check("堆路径（17B）+ sep=\"\"", in, sizeof(in), want, sizeof(want));
    }

    /* ============ ★★ 0xBF 标记必须被吃掉（实机两轮反复的根因） ============
     * 0xBF 是【双字节补丁】的反转词序触发标记（plugin.ini:
     * REVERSING_WORDS_BATTLE_OF_AREA=yes，见交接文档 §0-D）。
     * gen     loop_decide/disp    ruler_name 已经在数组层反转了段序；如果出口仍把 0xBF 留给渲染层，
     * 双字节补丁会【再反转一次】⇒ 顺序被抵消 ⇒ 表现为"补丁完全没生效"。
     * 所以 name_order_replace_sep 必须与 name_order_apply 行为对齐：吃掉标记。
     * 下面的字节取自实机真实数据：瞻基 = 10 BB 77 10 FA 57，朱 = BF 10 31 67。 */

    /* 9) gen     loop_decide 反转后的形态「¿朱 ␠ 瞻基」+ sep="" ⇒ 「朱瞻基」（标记删除） */
    {
        const unsigned char in[]   = { 0xBF, 0x10,0x31,0x67, 0x20,
                                       0x10,0xBB,0x77,0x10,0xFA,0x57 };
        const unsigned char want[] = { 0x10,0x31,0x67, 0x10,0xBB,0x77,0x10,0xFA,0x57 };
        g_seplen = 0;
        check("¿朱 SP 瞻基 + sep=\"\" ⇒ 朱瞻基（吃标记）", in, sizeof(in),
              want, sizeof(want));
    }
    /* 10) 原生形态「瞻基 ␠ ¿朱」+ sep="." ⇒ 「瞻基.朱」（标记删除） */
    {
        const unsigned char in[]   = { 0x10,0xBB,0x77,0x10,0xFA,0x57, 0x20,
                                       0xBF, 0x10,0x31,0x67 };
        const unsigned char want[] = { 0x10,0xBB,0x77,0x10,0xFA,0x57, 0x2E,
                                       0x10,0x31,0x67 };
        g_seplen = 1; g_sep[0] = '.';
        check("瞻基 SP ¿朱 + sep=\".\" ⇒ 瞻基.朱（吃标记）", in, sizeof(in),
              want, sizeof(want));
    }
    /* 11) 只有标记、没有空格 ⇒ 也要删除标记 */
    {
        const unsigned char in[]   = { 0xBF, 0x10,0x31,0x67 };
        const unsigned char want[] = { 0x10,0x31,0x67 };
        g_seplen = 0;
        check("仅 ¿朱 ⇒ 朱（无空格也吃标记）", in, sizeof(in), want, sizeof(want));
    }
    /* 11-b) ★★★ 回归用例（2026-10-05，来自实机 bug）：
     *   **0xBF 出现在 3 字节字符内部时必须保留** —— 它不是「¿」标记。
     *
     *   实测来源：LJA（shandong_culture）的姓字段 = `12 BF 75`，
     *   转码后是「线」(U+7EBF)：low=0xBF、high=0x7E 命中内部表 ⇒ escape=0x12。
     *   旧代码 `if (ch == 0xBF) continue;` 把它当标记删掉 ⇒ `12 75` 不成字
     *   ⇒ 屏幕上乱码方块，且串长少 1（实测 7 → 5）。
     *
     *   判据 = 「前一字节是不是 escape(0x10..0x13)」：
     *     前一个是 0x12 ⇒ 字符内部字节 ⇒ **保留**
     *     前一个是空格/串首 ⇒ 独立「¿」⇒ 删除
     *
     *   转码器验证：scripts/encode_eu4_special.py
     *     线 U+7EBF → [12 BF 75] ✓ 与日志一致；朱 U+6731 → [10 31 67]；军 U+519B → [10 9B 51] */
    {
        /* 【军 SP 线】= 10 9B 51 20 12 BF 75，sep="" ⇒ 期望 = 删空格、**保留**「线」的
         *   内部 0xBF ⇒ 10 9B 51 12 BF 75。
         *
         * ★ 本函数（name_order_replace_sep）是**纯空格替换**，不做段序交换 ——
         *   段序由 P7（buildP7_for）在拼接循环之前就反转好了。所以这里不能期望"线军"。
         * ★ 旧代码会把「线」的第 2 字节当标记删掉 ⇒ 得到 `10 9B 51 12 75`（少 1 字节、
         *   且「线」碎成乱码）。这正是 LJA 的实机 bug。 */
        const unsigned char in[]   = { 0x10,0x9B,0x51, 0x20, 0x12,0xBF,0x75 };
        const unsigned char want[] = { 0x10,0x9B,0x51, 0x12,0xBF,0x75 };
        g_replace = 1; g_seplen = 0;
        check("军SP线 + sep=\"\" ⇒ 军线（「线」的 0xBF 必须保留）",
              in, sizeof(in), want, sizeof(want));
        g_replace = 0;
    }
    /* 11-d) 同一条路径下，**真标记「¿」仍必须被删掉**（两条规则要能共存） */
    {
        /* 【¿朱】= BF 10 31 67 ⇒ 标记删除 ⇒ 10 31 67（朱） */
        const unsigned char in[]   = { 0xBF, 0x10,0x31,0x67 };
        const unsigned char want[] = { 0x10,0x31,0x67 };
        g_replace = 1; g_seplen = 0;
        check("仅 ¿朱 + sep=\"\" ⇒ 朱（独立 0xBF 仍被删）",
              in, sizeof(in), want, sizeof(want));
        g_replace = 0;
    }
    /* 11-e) ★★★ 回归用例（2026-10-05，实测 L7844）：
     *   **标记「¿」出现在"名的末尾"，而不是姓字段的第一个字节。**
     *
     *   实机现场（xibei 文化，游戏自动插入标记）：
     *       out    = 11 6A 67 | 10 0B 68 | BF | 20 | 49
     *       nlen=5（名的窗口 = 10 0B 68 BF 20 49）、dlen=4、olen=8
     *   ⇒ 判据必须**逐个位置**判断，不能假设标记只出现在字段开头。
     *     我曾在 nbf0 上加过 `p == 0` 的"收紧"，结果漏数这个 BF ⇒ nbf0=0
     *     ⇒ sur_len 多 1 ⇒ 姓多取一字节、名少一字节 ⇒ 屏幕名字错乱。
     *
     *   sep="" ⇒ 期望：删空格与那个独立 BF ⇒ 11 6A 67 10 0B 68 49 */
    {
        const unsigned char in[]   = { 0x11,0x6A,0x67, 0x10,0x0B,0x68, 0xBF, 0x20, 0x49 };
        const unsigned char want[] = { 0x11,0x6A,0x67, 0x10,0x0B,0x68, 0x49 };
        g_replace = 1; g_seplen = 0;
        check("标记在名末尾（非字段首字节）⇒ 仍须删除",
              in, sizeof(in), want, sizeof(want));
        g_replace = 0;
    }
    /* 12) 无标记无空格 ⇒ 保持零影响（不能误伤） */
    {
        const unsigned char in[]   = { 0x10,0x31,0x67 };
        const unsigned char want[] = { 0x10,0x31,0x67 };
        g_seplen = 0;
        check("无标记无空格：原样不动", in, sizeof(in), want, sizeof(want));
    }

    g_replace = 0; g_seplen = 0;
    reset_default();

    printf("\n%s (%d failures / %d cases)\n", fails == 0 ? "[PASS] name-order transform" : "[FAIL]",
           fails, total);
    return fails == 0 ? 0 : 1;
}
