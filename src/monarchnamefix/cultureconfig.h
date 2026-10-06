/*
 * cultureconfig.h - `common\cultures_name\*.txt` 的读取与「文化对象 -> 配置」解析
 *
 * 配置文件格式（用户撰写；`#` 起注释）：
 *
 *     # common\cultures_name\00_cultures_name.txt
 *     chinese_beijing  = { surname_first = yes  separator = ""  }
 *     korean           = { surname_first = yes }
 *     hungarian        = { surname_first = yes  separator = " " }
 *     # 也接受不带 = 或大括号的写法
 *     cantonese        = surname_first = yes
 *
 * 文化名 = `common\cultures\*.txt` 里的脚本名（即 `culture = <名>` 用的那个名字）。
 * 解析时先按【id 字符串】比对，不中再按【成员名】兜底。
 *
 * 读取范围（后读的覆盖先读的）：
 *     1) <游戏根>\common\cultures_name\*.txt
 *     2) 用户目录（<游戏根>\userdir.txt，空则 %USERPROFILE%\Documents\Paradox Interactive\
 *        Europa Universalis IV）下 dlc_load.json 里 enabled_mods 所列各 .mod 的 path= 目录
 *
 * 本文件只用标准 C + nameorder.h 的受保护读回调；文件系统访问与 SEH 都在
 * monarchnamefix.c（生产）或测试脚手架（单测）里。
 */
#ifndef CULTURECONFIG_H
#define CULTURECONFIG_H

#include <stdint.h>
#include <stddef.h>
#include "nameorder.h"

/* ---------------- 容量上限（静态分配，避免 CRT 堆） ---------------- */
#define CC_MAX_ENTRIES   512     /* 配置条目上限            */
#define CC_NAME_MAX       96     /* 文化名上限              */
#define CC_XREF_MAX      512     /* 「名字 -> 对象」解析缓存 */

/* ---------------- 游戏内固定地址（基址由调用方给） ---------------- */
/* 文化注册表单例指针槽 qword_14242B9F8 的【绝对虚拟地址】。
 * ⚠ 这里必须写完整 VA（0x14242B9F8），不能写"相对基址的 0x242B9F8"：
 *   下面 CC_REGISTRY_OFF 是【减去】镜像基址得出的，
 *   曾经把它写成 0x0242B9F8 导致实际算成 base − 0x242B9F8（0xFFFFFFFFC242B9F8），
 *   指针跑到模块外，绑定额外恒为 0（这正是"culture config: bound=0"的第二个根因）。 */
#define CC_VA_REGISTRY      0x14242B9F8u  /* = qword_14242B9F8（IDA 符号） */
#define CC_BASE_EXPECT      0x140000000ull

/* 指针槽相对镜像基址的偏移（base + 本值 = 指针槽地址）*/
#define CC_REGISTRY_OFF     ((uintptr_t)(CC_VA_REGISTRY) - (uintptr_t)CC_BASE_EXPECT)

/* id 字符串：CString 起始 +0x120（SSO 数据内联在 +0x120）=> size +0x130、cap +0x138。
 * 证据：构造 0x1401AF830 的 `mov rcx,[rdi+10h]` 取的是 size；
 *       查找 0x1401B0BE0 用 `[obj+120h]` 作数据、`[+130h]` 作长度；
 *       析构 0x1401AFA40 对 `a1+288`(=0x120) 调 StringFree。 */
#define CC_CULT_ID_OFF      0x120u
#define CC_CULT_ID_SIZE     0x130u
#define CC_CULT_ID_CAP      0x138u

/* 成员（member）名：CString 起始 +0x50（SSO 数据内联在 +0x50）=> size +0x60、cap +0x68。
 * 证据：构造 0x1401AF8A5/0x1401AF8AC 与析构 0x1401AFA80 的 `StringFree(a1+80)`。 */
#define CC_CULT_MEMBER_OFF  0x50u
#define CC_CULT_MEMBER_SIZE 0x60u
#define CC_CULT_MEMBER_CAP  0x68u

/* ==================================================================== */
/* ★★★ 文化【名字】字段（现行路径用这个）—— 2026-10-05 新增              */
/* ==================================================================== */
/* 所属对象：**文化对象**（`*(CMonarch+0x60)`，也等于 `BuildFullName_Impl`
 *          的第 3 参数 `a3`）。**不是**下面那个注册表节点。
 * 布局：CString 起始 +0x48（数据/SSO 联合）=> size +0x58、cap +0x60。
 *
 * ★ 为什么必须带 SSO 判据读它：
 *   短名（≤15 字符）时数据**内联在 +0x48**，直接 `(char*)(obj+0x48)` 就对；
 *   长名（≥16 字符，如 `shandong_culture`）时 +0x48 处是**堆指针**，
 *   裸读拿到的是指针字节（非 ASCII、随 ASLR 变）。
 *   这是"长名文化从未被识别"的根因，见 notes\诊断-长文化名SSO分界.md。
 *   读取请统一走 `monarchnamefix.cpp::culture_name_read(obj, CC_CULT_NAME_OFF, ...)`。
 *
 * ★ 文化 ID（int32）在 文化对象 +0x90 —— 与游戏 `HandleRulerCulture`
 *   (0x1406DF110) 的 `mov eax,[rbx+90h]` 逐字一致。 */
#define CC_CULT_NAME_OFF    0x48u
#define CC_CULT_NAME_SIZE   0x58u
#define CC_CULT_NAME_CAP    0x60u
#define CC_CULT_ID_INT      0x90u   /* 文化 ID：int32，非 CString */

/* ⚠️⚠️ 下面这两个偏移组（CC_CULT_ID_* / CC_CULT_MEMBER_*）属于**已废弃的对象绑定路**
 * （`cc_resolve` → `cc_registry_find` → `cc_chain_find` → `cc_cstr_field`），
 * 它们的读取对象是**注册表 qword_14242B9F8 的节点**，**不是文化对象**。
 *
 * 【实机结论，勿依赖】2026-10-05 复核：
 *   · 该注册表经项目实测是**通用字符串表**（键里含 `noAdvisorType`），不是文化表；
 *   · **`bound=0` 恒成立** —— 40/40 条配置一条都没绑上对象（见日志 CFGENTRY 行）；
 *   · 生产路径早已改用 `cc_lookup_name()`（按文化名字符串直接匹配配置），
 *     该函数只用不到对象，也不做任何哈希查找；
 *   · `cc_lookup()`（按对象指针）现在只剩 P4 回退路在用，而那条路实机从不执行
 *     （`P4 in/out` 恒为 0，因为 P6 快路径总是先命中并 goto out）。
 *
 * ⇒ 这两组常量**保留原样**（未删除，因为可能仍有归档价值），但**不要**
 *   把它们与 CC_CULT_NAME_* 混为一谈 —— 它们不是同一个对象的同一字段。
 *   之所以当年会认为"名字在 +0x120"，很可能就是因为裸读 +0x48 在长名下失败，
 *   于是被误判为"名字不在那里"。 */

/* ---------------- 配置存储 ---------------- */
typedef struct {
    int        used;
    int        surname_first;      /* 1 = 姓前名后 */
    name_sep_t sep;
    int        has_sep;            /* 0 = 用全局缺省分隔符 */
    uint8_t    name_len;
    char       name[CC_NAME_MAX];  /* 配置里写的文化名 */
} cc_entry_t;

typedef struct { void *obj; int idx; } cc_xref_t;

/* 绑定（文化名 → 对象）状态机。见 cc_lazy_bind 上方注释。 */
#define CC_BIND_IDLE   0        /* 还没试过（或注册表尚未创建，可再试） */
#define CC_BIND_DONE   1        /* 成功绑定，永久生效 */
#define CC_BIND_GIVEUP 2        /* 试满 CC_BIND_MAX_TRIES 次仍未果，放弃 */

typedef struct {
    cc_entry_t  entry[CC_MAX_ENTRIES];
    int         count;
    cc_xref_t   xref[CC_XREF_MAX];
    int         xref_n;
    int         resolved;
    int         bind_state;                     /* CC_BIND_* */
    int         bind_tries;                     /* 已尝试的解析次数 */
    uint8_t    *modbase;                        /* eu4.exe 基址 */
    pn_reader_t rd;                             /* 受保护读 */
} cc_state_t;

/* ---------------- 小工具 ---------------- */
static int cc_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static int cc_is_idchar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
}

static int cc_streq_n(const char *a, uint32_t alen, const char *b)
{
    uint32_t i;
    for (i = 0; i < alen; i++) if (!b[i] || a[i] != b[i]) return 0;
    return b[alen] == 0;
}

/* 比较定长字节（避免引入 <string.h>：本头文件被 DLL 与测试共用） */
static int cc_mem_eq_n(const char *a, const char *b, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

/* ---------------- 解析（只吃内存缓冲 => 可单测） ---------------- */
static void cc_add(cc_state_t *S, const char *name, uint32_t nlen, int surname_first,
                   const void *sep, uint32_t seplen, int has_sep)
{
    int idx = -1, i;
    uint32_t k;

    if (nlen == 0 || nlen >= CC_NAME_MAX) return;

    for (i = 0; i < S->count; i++)
        if (cc_streq_n(name, nlen, S->entry[i].name)) { idx = i; break; }

    if (idx < 0) {
        if (S->count >= CC_MAX_ENTRIES) return;
        idx = S->count++;
    }

    S->entry[idx].used          = 1;
    S->entry[idx].surname_first = surname_first;
    S->entry[idx].has_sep       = has_sep;
    pn_set_sep(&S->entry[idx].sep, has_sep ? sep : NULL, has_sep ? seplen : 0);
    S->entry[idx].name_len      = (uint8_t)nlen;
    for (k = 0; k < nlen; k++) S->entry[idx].name[k] = name[k];
    S->entry[idx].name[nlen] = 0;

    S->resolved = 0;      /* 条目变了 => 之前的对象解析作废 */
    S->xref_n   = 0;
}

/* 读一个「值」：带引号字符串，或裸 token。返回内容起点，*len 给长度。 */
static const char *cc_read_value(const char *p, const char *end,
                                 uint32_t *len, int *quoted)
{
    const char *q;
    *quoted = 0;
    while (p < end && cc_is_space(*p)) p++;
    if (p >= end) { *len = 0; return p; }

    if (*p == '"') {
        *quoted = 1;
        p++;
        q = p;
        while (p < end && *p != '"') p++;
        *len = (uint32_t)(p - q);
        if (p < end) p++;
        return q;
    }
    q = p;
    while (p < end && !cc_is_space(*p) && *p != '}' && *p != ',') p++;
    *len = (uint32_t)(p - q);
    return q;
}

static const char *cc_read_kv(const char *p, const char *end, int *surname_first,
                              int *has_sf, char *sepbuf, uint32_t *seplen, int *has_sep)
{
    const char *kstart, *v;
    uint32_t klen, vlen;
    int quoted, i;

    while (p < end && cc_is_space(*p)) p++;
    if (p >= end || *p == '}') return p;

    kstart = p;
    while (p < end && cc_is_idchar(*p)) p++;
    klen = (uint32_t)(p - kstart);
    if (klen == 0) return p + 1;                    /* 无法识别 => 前进 1 字节 */

    while (p < end && cc_is_space(*p)) p++;
    if (p < end && (*p == '=' || *p == ':')) p++;
    else return p;                                  /* 不是键值对 */

    v = cc_read_value(p, end, &vlen, &quoted);
    p = v + vlen;
    if (quoted && p < end && *p == '"') p++;

    if (cc_streq_n(kstart, klen, "surname_first")) {
        *has_sf = 1;
        *surname_first = (vlen >= 1 &&
                          (v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T' ||
                           v[0] == '1' || v[0] == 'o' || v[0] == 'O')) ? 1 : 0;
    } else if (cc_streq_n(kstart, klen, "separator")) {
        *has_sep = 1;
        *seplen = vlen > NAME_SEP_MAX ? NAME_SEP_MAX : vlen;
        for (i = 0; i < (int)*seplen; i++) sepbuf[i] = v[i];
    }
    return p;
}

/* 解析整个文件缓冲；返回处理过的条目数 */
static int cc_parse(cc_state_t *S, const char *buf, uint32_t size)
{
    const char *p = buf;
    const char *end = buf + size;
    int added = 0;

    while (p < end) {
        int surname_first = 1, has_sf = 0, has_sep = 0;
        uint32_t seplen = 0;
        char sepbuf[NAME_SEP_MAX];
        const char *nstart;
        uint32_t nlen;
        int guard = 0;

        while (p < end && cc_is_space(*p)) p++;
        if (p >= end) break;
        if (*p == '#') { while (p < end && *p != '\n') p++; continue; }
        if (*p == '}' || *p == ',') { p++; continue; }

        nstart = p;
        while (p < end && cc_is_idchar(*p)) p++;
        nlen = (uint32_t)(p - nstart);
        if (nlen == 0) { p++; continue; }

        while (p < end && cc_is_space(*p)) p++;
        if (p < end && (*p == '=' || *p == ':')) {
            p++;
            while (p < end && cc_is_space(*p)) p++;
        }

        if (p < end && *p != '{') {
            /* 无块语法：在本行内继续读 key = value（以换行结束） */
            while (p < end && *p != '\n') {
                const char *b = p;
                p = cc_read_kv(p, end, &surname_first, &has_sf, sepbuf, &seplen, &has_sep);
                if (p <= b) p = b + 1;
                if (++guard > 64) break;
            }
        } else {
            int depth = 1;
            p++;                                     /* 吃掉 '{' */
            while (p < end) {
                const char *b;
                if (*p == '\n' && depth <= 1) {
                    /* 换行时大括号已配平 => 把本行剩余部分读完即结束本块。
                     * 这样「作者漏写 '}'」最多影响它自己那一行，不会吞掉后面的文化。 */
                    const char *eol = p;
                    while (eol < end && *eol != '\n') eol++;
                    while (p < eol) {
                        const char *b2 = p;
                        while (p < eol && cc_is_space(*p)) p++;
                        if (p >= eol) break;
                        p = cc_read_kv(p, eol, &surname_first, &has_sf, sepbuf, &seplen, &has_sep);
                        if (p <= b2) p = b2 + 1;
                        if (++guard > 4096) break;
                    }
                    break;
                }
                while (p < end && cc_is_space(*p)) p++;
                if (p >= end) break;
                if (*p == '#') { while (p < end && *p != '\n') p++; continue; }
                if (*p == '{') { depth++; p++; continue; }
                if (*p == '}') {
                    depth--;
                    p++;
                    if (depth <= 0) break;
                    continue;
                }
                b = p;
                p = cc_read_kv(p, end, &surname_first, &has_sf, sepbuf, &seplen, &has_sep);
                if (p <= b) p = b + 1;
                if (++guard > 4096) break;
            }
        }
        cc_add(S, nstart, nlen, has_sf ? surname_first : 1,
               has_sep ? sepbuf : NULL, seplen, has_sep);
        added++;
    }
    return added;
}

/* ---------------- 「名字 -> 文化对象」 ---------------- */
/* 与游戏 `sub_1401B0BE0` 完全一致的哈希：h = 61 * (h + (signed char)c) */
static uint32_t cc_hash(const char *s, uint32_t len)
{
    uint32_t h = 0, i;
    for (i = 0; i < len; i++) h = 61u * (h + (uint32_t)(int32_t)(signed char)s[i]);
    return h;
}

/* 读文化对象里的一个 CString 字段；成功返回长度，失败返回 0。
 * 【关键】cap < 0x10 才是 SSO（数据内联在字段地址）；写成 cap >= 0x10 会走"堆"
 * 分支，把内联字符串字节当 char* 解引用。 */
static uint32_t cc_cstr_field(cc_state_t *S, void *obj, uint32_t off,
                              uint32_t soff, uint32_t coff, const char **out)
{
    uint64_t cap, sz, data;

    *out = NULL;
    if (!obj) return 0;
    if (!pn_ok(&S->rd, obj, coff + 8)) return 0;

    cap  = pn_rd(&S->rd, (const uint8_t *)obj + coff, 8);
    sz   = pn_rd(&S->rd, (const uint8_t *)obj + soff, 8);
    data = pn_rd(&S->rd, (const uint8_t *)obj + off,  8);

    if (cap < 0x10) data = (uint64_t)(uintptr_t)((const uint8_t *)obj + off);  /* SSO */
    if (!data || sz == 0 || sz > 128) return 0;
    if (!pn_ok(&S->rd, (const void *)(uintptr_t)data, (size_t)sz + 1)) return 0;

    *out = (const char *)(uintptr_t)data;
    return (uint32_t)sz;
}

/* 走一遍注册表的某个桶链。
 *   want_id = 1 时按 **id 字符串**（+0x120）比对；
 *   want_member = 1 时按 **成员名**（+0x50）比对。
 * 两者可以同时开：同一条链里先 id 后成员名，用于"配置写的是成员名"这种兜底。
 *
 * 【为什么成员名兜底必须留在 id 的桶里】游戏查找 sub_1401B0BE0 的哈希输入是
 * 传入键的内容，而比对的目标字段是 `obj+0x120`（id）。也就是说：**只有 id 才能
 * 决定桶号**。拿成员名去算桶号会落到另一个桶，永远找不到对象。 */
static void *cc_chain_find(cc_state_t *S, void *node, const char *name, uint32_t len,
                           int want_id, int want_member)
{
    int guard;
    for (guard = 0; node && guard < 256; guard++) {
        void *obj = (void *)(uintptr_t)pn_rd(&S->rd, node, 8);
        if (obj && want_id) {
            const char *s = NULL;
            uint32_t slen = cc_cstr_field(S, obj, CC_CULT_ID_OFF, CC_CULT_ID_SIZE,
                                          CC_CULT_ID_CAP, &s);
            if (slen == len && s && cc_mem_eq_n(s, name, len)) return obj;
        }
        if (obj && want_member) {
            const char *s = NULL;
            uint32_t slen = cc_cstr_field(S, obj, CC_CULT_MEMBER_OFF, CC_CULT_MEMBER_SIZE,
                                          CC_CULT_MEMBER_CAP, &s);
            if (slen == len && s && cc_mem_eq_n(s, name, len)) return obj;
        }
        node = (void *)(uintptr_t)pn_rd(&S->rd, (uint8_t *)node + 8, 8);
    }
    return NULL;
}

/* 桶号一律由 key 算（游戏用的是 `culture = <名>` 的值，也就是 id）；
 *   want_id     = 1 → 桶内按 id 字符串（+0x120）比对；
 *   want_member = 1 → 桶内再按成员名（+0x50）比对（配置写的是成员名时的兜底）。
 * ⚠ key 只能是 id：拿成员名当 key 会算到别的桶（见 cc_chain_find 注释）。 */
static void *cc_registry_find(cc_state_t *S, const char *key, uint32_t keylen,
                              const char *name, uint32_t len,
                              int want_id, int want_member)
{
    uint8_t *reg;
    uint32_t buckets, h;
    uint8_t **arr;
    void *node;

    if (!S->modbase) return NULL;
    reg = (uint8_t *)(uintptr_t)pn_rd(&S->rd, S->modbase + CC_REGISTRY_OFF, 8);
    if (!reg) return NULL;
    if (!pn_ok(&S->rd, reg, 16)) return NULL;

    buckets = (uint32_t)pn_rd(&S->rd, reg + 4, 4);
    if (buckets == 0 || buckets > 0x10000u) return NULL;
    arr = (uint8_t **)(uintptr_t)pn_rd(&S->rd, reg + 8, 8);
    if (!arr) return NULL;

    h = cc_hash(key, keylen) % buckets;
    if (!pn_ok(&S->rd, arr + h, 8)) return NULL;
    node = (void *)(uintptr_t)pn_rd(&S->rd, arr + h, 8);

    return cc_chain_find(S, node, name, len, want_id, want_member);
}

static void cc_resolve(cc_state_t *S)
{
    int i;
    if (!S->modbase) return;
    S->xref_n = 0;
    for (i = 0; i < S->count; i++) {
        void *obj;
        const char *n = S->entry[i].name;
        uint32_t nl = S->entry[i].name_len;
        /* 桶号用配置里写的名字算（用户写的是 common\cultures 的脚本名 = id）；
         * 桶内先按 id 比对，不中再按成员名兜底。 */
        obj = cc_registry_find(S, n, nl, n, nl, 1, 1);
        if (obj && S->xref_n < CC_XREF_MAX) {
            S->xref[S->xref_n].obj = obj;
            S->xref[S->xref_n].idx = i;
            S->xref_n++;
        }
    }
    S->resolved = 1;
}

/* ★ 按【文化名字符串】查配置条目下标；-1 = 未配置。
 *
 * 这是本补丁最终采用的查找方式。原因（实机确证，2026-10-03）：
 *   · 注册表 qword_14242B9F8 是通用字符串表（键里有 noAdvisorType），不是文化表；
 *   · `*(a3+0x88)` 那条"文化对象"路已在实机证伪（出口处 r14 被挪用）；
 *   · 而 `a3+0x48` 是干净的 C 字符串，实机读到 "swedish"（玩瑞典时）。
 * 所以直接拿名字匹配配置，不走任何对象/哈希。 */
static int cc_lookup_name(cc_state_t *S, const char *cultname)
{
    uint32_t n;
    int i;
    if (!S || !cultname || !cultname[0]) return -1;
    for (n = 0; cultname[n]; n++) ;
    for (i = 0; i < S->count; i++) {
        if (!S->entry[i].used) continue;
        if (S->entry[i].name_len != n) continue;
        {
            uint32_t k;
            int same = 1;
            for (k = 0; k < n; k++) {
                if (S->entry[i].name[k] != cultname[k]) { same = 0; break; }
            }
            if (same) return i;
        }
    }
    return -1;
}

/* 查文化对象对应的配置条目下标；-1 = 未配置 */
static int cc_lookup(cc_state_t *S, void *culture)
{
    int i;
    if (!culture) return -1;
    if (!S->resolved) cc_resolve(S);   /* 还没解析过（或条目后有变动）=> 先解析 */
    for (i = 0; i < S->xref_n; i++)
        if (S->xref[i].obj == culture) return S->xref[i].idx;
    return -1;
}

/* ------------------------------------------------------------------ */
/* 懒绑定：把配置里的文化名解析成 CCulture*                               */
/* ------------------------------------------------------------------ */
/* 【为什么必须懒】文化注册表单例 qword_14242B9F8 由游戏自己**惰性创建**
 * （sub_1401AFD00：`if (!qword_14242B9F8) { new ... }`），DllMain（安装期）
 * 它还是 0 ⇒ 那时 cc_resolve 必然一条都绑不上（bound=0），
 * 而且这份 0 结果会被 cc_lookup 当成"已解析、无命中"永久缓存。
 * 所以绑定推迟到**第一次真正要用配置的时候**（P4 变换入口），届时文化数据
 * 早已加载完毕。绑定成功即永久生效，之后不再重试（transform 是热路径）。
 *
 * 返回 1 = 已绑定成功（或本来就成功过）；0 = 现在还绑不上。 */
#define CC_BIND_MAX_TRIES 64        /* 绑定循环的尝试次数上限（每次 = 遍历全部条目） */

static int cc_lazy_bind(cc_state_t *S)
{
    if (!S) return 0;
    if (S->bind_state == CC_BIND_DONE)   return 1;
    if (S->bind_state == CC_BIND_GIVEUP) return 0;
    if (S->count <= 0 || !S->modbase) {          /* 没东西可绑 ⇒ 无需再试 */
        S->bind_state = CC_BIND_GIVEUP;
        return 0;
    }

    cc_resolve(S);                       /* cc_resolve 内部会先清 xref_n */
    S->bind_tries++;

    if (S->xref_n > 0) {                 /* 绑上至少一条 ⇒ 注册表已经在了 */
        S->bind_state = CC_BIND_DONE;
        return 1;
    }
    if (S->bind_tries >= CC_BIND_MAX_TRIES) {
        S->bind_state = CC_BIND_GIVEUP;  /* 一直绑不上：不再每次调用都找一遍 */
        return 0;
    }
    return 0;
}

#endif /* CULTURECONFIG_H */