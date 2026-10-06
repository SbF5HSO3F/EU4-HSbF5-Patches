/* cultureconfigtest.exe - `common\cultures_name\*.txt` 解析与「文化对象 → 配置」单测
 *
 * 覆盖：块/行内语法、注释与空白、separator ""/" "/多字节、surname_first yes/no、
 *       同名后写覆盖先写、畸形输入健壮性、以及用平坦内存伪造「注册表+文化对象」
 *       来验证哈希/桶链/id 匹配/成员名兜底/按对象查配置。
 *
 * 【本文件踩过的坑，留作警示】
 *   - cc_state_t 约 64KB，不能放栈上（会爆栈，表现为"静默退出"），必须 static。
 *   - 伪造 CCulture 时 cap 必须 < 0x10 才是 SSO；写成 0x1F 会让读取方走"堆"
 *     分支，把内联字符串字节当 char* 解引用 ⇒ 直接崩。
 *   - 注册表 count 必须显式清零再自增（用 |= 会得到垃圾值）。
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nameorder.h"
#include "cultureconfig.h"

static int fails = 0, total = 0;

/* 崩溃定位用：打印 RIP / 访问地址 */
static LONG WINAPI veh(EXCEPTION_POINTERS *ep)
{
    printf("\n[!] 异常 code=%08X RIP=%p 访问=%p\n",
           (unsigned)ep->ExceptionRecord->ExceptionCode,
           (void *)ep->ContextRecord->Rip,
           ep->ExceptionRecord->NumberParameters >= 2
               ? (void *)ep->ExceptionRecord->ExceptionInformation[1] : NULL);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void CHECK(int cond, const char *what)
{
    total++;
    if (cond) printf("[ok]   %s\n", what);
    else { printf("[FAIL] %s\n", what); fails++; }
}

/* 伪造模块基址必须让 `base + CC_VA_REGISTRY` 恰好落在竞技场里：
 * 那个 RVA 处是**指向注册表的指针槽**（qword_14242B9F8），不是注册表本体。
 * 竞技场共 64MB，够覆盖 0x242B9F8 这个偏移。
 * （曾把伪造基址写成 `reg - (CC_VA_REGISTRY - CC_BASE_EXPECT)` ⇒ 指针槽指向注册表
 *   对象本体，读出来的是 count/buckets 字节，cc_registry_find 永远返回 0。）
 * 指针槽偏移统一用 CC_REGISTRY_OFF（它内部按 uintptr_t 计算，不会把基址截断）。 */
#define ARENA (64u << 20)
static uint8_t *g_arena;
static size_t   g_arena_used;

static int flat_rd(void *ctx, const void *p, unsigned n, uint64_t *out)
{
    uintptr_t a = (uintptr_t)p;
    (void)ctx;
    *out = 0;
    if (a < (uintptr_t)g_arena || a + n > (uintptr_t)g_arena + ARENA) return 0;
    if (n == 1)      *out = *(const uint8_t *)p;
    else if (n == 2) *out = *(const uint16_t *)p;
    else if (n == 4) *out = *(const uint32_t *)p;
    else if (n == 8) *out = *(const uint64_t *)p;
    else return 0;
    return 1;
}

static int flat_ok(void *ctx, const void *p, size_t n)
{
    uintptr_t a = (uintptr_t)p;
    (void)ctx;
    return a >= (uintptr_t)g_arena && a + n <= (uintptr_t)g_arena + ARENA;
}

static void *arena_alloc(size_t n)
{
    void *p;
    n = (n + 15u) & ~(size_t)15u;
    if (g_arena_used + n > ARENA) return NULL;
    p = g_arena + g_arena_used;
    g_arena_used += n;
    memset(p, 0, n);
    return p;
}

static void *make_culture(const char *id, const char *member)
{
    uint8_t *o = (uint8_t *)arena_alloc(0x200);
    uint32_t idl = (uint32_t)strlen(id), ml = member ? (uint32_t)strlen(member) : 0;
    if (!o) return NULL;
    *(uint64_t *)(o + CC_CULT_ID_CAP) = 0x0F;
    *(uint64_t *)(o + CC_CULT_ID_SIZE) = idl;
    memcpy(o + CC_CULT_ID_OFF, id, idl + 1);
    if (member) {
        *(uint64_t *)(o + CC_CULT_MEMBER_CAP) = 0x0F;
        *(uint64_t *)(o + CC_CULT_MEMBER_SIZE) = ml;
        memcpy(o + CC_CULT_MEMBER_OFF, member, ml + 1);
    }
    return o;
}

/* 建一个伪造的「模块 + 注册表 + 桶链」。
 * 返回伪造模块基址；*reg_out（非空时）得到注册表本体地址。
 * 指针槽偏移一律用 CC_REGISTRY_OFF（内部按 uintptr_t 计算）。 */
static uint8_t *registry_build(void **objs, int n, uint8_t **reg_out)
{
    uint32_t buckets = 61;
    int i;
    void **arr = (void **)arena_alloc(sizeof(void *) * buckets);
    uint8_t *reg = (uint8_t *)arena_alloc(16);
    *(uint32_t *)(reg + 0) = 0;
    *(uint32_t *)(reg + 4) = buckets;
    *(uint64_t *)(reg + 8) = (uint64_t)(uintptr_t)arr;

    /* 指针槽（qword_14242B9F8）所在的地址上写上注册表本体地址 */
    *(uint64_t *)(g_arena + CC_REGISTRY_OFF) = (uint64_t)(uintptr_t)reg;
    if (reg_out) *reg_out = reg;

    for (i = 0; i < n; i++) {
        uint8_t *o = (uint8_t *)objs[i];
        uint64_t cap = 0, size = 0, data = 0;
        const uint8_t *id;
        uint32_t idl, h = 0, k;
        uint8_t *node;

        memcpy(&cap,  o + CC_CULT_ID_CAP,  8);
        memcpy(&size, o + CC_CULT_ID_SIZE, 8);
        memcpy(&data, o + CC_CULT_ID_OFF,  8);
        if (cap < 0x10) data = (uint64_t)(uintptr_t)(o + CC_CULT_ID_OFF);
        id = (const uint8_t *)(uintptr_t)data;
        idl = (uint32_t)size;

        for (k = 0; k < idl; k++) h = 61u * (h + (uint32_t)(int32_t)(signed char)id[k]);
        h %= buckets;
        node = (uint8_t *)arena_alloc(16);
        *(uint64_t *)node = (uint64_t)(uintptr_t)objs[i];
        *(uint64_t *)(node + 8) = (uint64_t)(uintptr_t)arr[h];
        arr[h] = node;
        (*(uint32_t *)reg)++;
    }
    /* 伪造的「模块基址」正好也等于竞技场起点 ⇒ base + CC_REGISTRY_OFF 命中指针槽 */
    return g_arena;
}

/* 把指针槽清 0 = 模拟"DllMain 安装期，游戏还没建注册表" */
static void registry_clear(void)
{
    *(uint64_t *)(g_arena + CC_REGISTRY_OFF) = 0;
}

static void cc_init_reader(cc_state_t *S)
{
    memset(S, 0, sizeof(*S));
    S->rd.rd = flat_rd;
    S->rd.ok = flat_ok;
}

static int entry_index(cc_state_t *S, const char *name)
{
    int i;
    for (i = 0; i < S->count; i++) if (!strcmp(S->entry[i].name, name)) return i;
    return -1;
}

int main(void)
{
    static cc_state_t st_main, st_second, R, RM;

    setvbuf(stdout, NULL, _IONBF, 0);
    AddVectoredExceptionHandler(1, veh);

    g_arena = (uint8_t *)VirtualAlloc(NULL, ARENA, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_arena) { printf("[x] arena alloc failed\n"); return 2; }

    printf("== 解析器 ==\n");
    {
        const char *txt =
            "# comment\r\n"
            "\r\n"
            "chinese_beijing = { surname_first = yes  separator = \"\" }\n"
            "korean          = { surname_first = yes }\n"
            "hungarian       = { surname_first = yes  separator = \" \" }\n"
            "cantonese       = surname_first = yes separator = \"\"\n"
            "  swedish = { surname_first = no separator = \" \" }\n"
            "broken  = { surname_first = yes\n"
            "ottoman = { }\n";
        int n, f;
        cc_init_reader(&st_main);
        n = cc_parse(&st_main, txt, (uint32_t)strlen(txt));
        CHECK(n == 7, "解析出 7 条");
        CHECK(st_main.count == 7, "条目数 = 7（含漏写 '}' 的那条，且未吞掉后面的）");

        f = entry_index(&st_main, "chinese_beijing");
        CHECK(f >= 0 && st_main.entry[f].surname_first == 1, "chinese_beijing: surname_first = yes");
        CHECK(f >= 0 && st_main.entry[f].has_sep == 1 && st_main.entry[f].sep.len == 0,
              "chinese_beijing: separator = \"\"");

        f = entry_index(&st_main, "korean");
        CHECK(f >= 0 && st_main.entry[f].surname_first == 1, "korean: surname_first = yes");
        CHECK(f >= 0 && st_main.entry[f].has_sep == 0, "korean: 未指定 separator 时用全局缺省");

        f = entry_index(&st_main, "hungarian");
        CHECK(f >= 0 && st_main.entry[f].has_sep == 1 && st_main.entry[f].sep.len == 1 &&
              st_main.entry[f].sep.b[0] == ' ', "hungarian: separator = \" \"");

        f = entry_index(&st_main, "cantonese");
        CHECK(f >= 0 && st_main.entry[f].surname_first == 1, "cantonese: 行内语法（无大括号）被识别");

        f = entry_index(&st_main, "swedish");
        CHECK(f >= 0 && st_main.entry[f].surname_first == 0, "swedish: surname_first = no（前导空白被忽略）");

        f = entry_index(&st_main, "ottoman");
        CHECK(f >= 0 && st_main.entry[f].surname_first == 1, "ottoman: 空块时缺省 surname_first = yes");
    }

    printf("\n== 覆盖语义（后写覆盖先写 = 模组覆盖基础游戏） ==\n");
    {
        const char *a = "hungarian = { surname_first = no  separator = \"\" }\n";
        const char *b = "hungarian = { surname_first = yes separator = \" \" }\n";
        cc_init_reader(&st_second);
        cc_parse(&st_second, a, (uint32_t)strlen(a));
        cc_parse(&st_second, b, (uint32_t)strlen(b));
        CHECK(st_second.count == 1, "同名文化只保留一条");
        CHECK(st_second.entry[0].surname_first == 1 && st_second.entry[0].sep.len == 1,
              "后写的配置生效（surname_first=yes, sep=space）");
    }

    printf("\n== 注册表查找（伪造 CCulture + hash 表） ==\n");
    {
        void *objs[3];
        uint8_t *base, *reg = NULL;
        uint32_t bi;
        const char *txt =
            "chinese_beijing = { surname_first = yes separator = \"\" }\n"
            "korean          = { surname_first = yes }\n"
            "hungarian       = { surname_first = yes separator = \" \" }\n";

        cc_init_reader(&R);
        objs[0] = make_culture("chinese_beijing", "Beijing Chinese");
        objs[1] = make_culture("korean", "Korean");
        objs[2] = make_culture("hungarian", "Hungarian");
        base = registry_build(objs, 3, &reg);
        R.modbase = base;

        cc_parse(&R, txt, (uint32_t)strlen(txt));
        CHECK(R.count == 3, "三条配置就绪");

        {
            const uint8_t *o = (const uint8_t *)objs[0];
            uint64_t cap = 0, size = 0;
            memcpy(&cap,  o + CC_CULT_ID_CAP,  8);
            memcpy(&size, o + CC_CULT_ID_SIZE, 8);
            CHECK(cap < 0x10, "伪造对象的 id 是 SSO 形态（cap < 0x10）");
            CHECK(size == 15 && !memcmp(o + CC_CULT_ID_OFF, "chinese_beijing", 15),
                  "伪造对象 id 内容 = chinese_beijing（长 15）");
            CHECK(!strcmp(R.entry[0].name, "chinese_beijing") && R.entry[0].name_len == 15,
                  "配置条目名 = chinese_beijing（长 15）");
        }

        {
            /* 指针槽（CC_REGISTRY_OFF 处）必须指向注册表本体 */
            uint64_t slot = *(uint64_t *)(base + CC_REGISTRY_OFF);
            void **arr;
            uint32_t buckets, h;
            void *node, *found = NULL;
            CHECK(slot != 0 && (uint8_t *)(uintptr_t)slot == reg,
                  "指针槽指向注册表本体（不是把注册表对象摆在指针槽里）");
            CHECK(*(uint32_t *)reg == 3, "注册表 count = 3");
            buckets = *(uint32_t *)(reg + 4);
            CHECK(buckets == 61, "注册表 buckets = 61");
            arr = (void **)*(uint64_t *)(reg + 8);
            h = cc_hash("chinese_beijing", 15) % buckets;
            node = arr[h];
            printf("        [info] hash=%u node=%p\n", h, node);
            if (node) {
                void *o = *(void **)node;
                uint64_t cap = 0;
                memcpy(&cap, (uint8_t *)o + CC_CULT_ID_CAP, 8);
                if (cap < 0x10) found = o;
                printf("        [info] node obj=%p cap=%llX str=%s\n", o,
                       (unsigned long long)cap, (const char *)((uint8_t *)o + CC_CULT_ID_OFF));
            }
            CHECK(found == objs[0], "桶链里找到的对象就是我们伪造的那个");
            for (bi = 0; bi < buckets; bi++)
                if (arr[bi]) printf("        [info] bucket %u -> %p\n", bi, arr[bi]);
        }

        /* 这一组走的是【生产路径】（cc_registry_find 经 pn_rd 读指针槽 → 桶链 → 对象字段）。
         * 早期版本的伪造基址写错了 RVA 语义，导致这里恒为 0、只能做信息输出；现已修正，
         * 于是可以真正断言。 */
        CHECK(cc_registry_find(&R, "chinese_beijing", 15, "chinese_beijing", 15, 1, 0) == objs[0],
              "cc_registry_find 经生产路径找到 chinese_beijing");
        CHECK(cc_registry_find(&R, "korean", 6, "korean", 6, 1, 0) == objs[1],
              "cc_registry_find 经生产路径找到 korean");
        CHECK(cc_registry_find(&R, "no_such_culture", 15, "no_such_culture", 15, 1, 1) == NULL,
              "不存在的文化名返回 NULL");
        /* 成员名兜底必须在**同一条 id 桶链**里做：游戏 sub_1401B0BE0 的桶号由
         * `culture = <名>`（即 id）算出，拿成员名算桶号会落到另一个桶。 */
        CHECK(cc_registry_find(&R, "chinese_beijing", 15, "Beijing Chinese", 15, 0, 1) == objs[0],
              "成员名兜底在 id 桶内命中（key 仍是 id）");
        CHECK(cc_registry_find(&R, "Beijing Chinese", 15, "Beijing Chinese", 15, 0, 1) == NULL,
              "拿成员名当 key 算桶号找不到（证明兜底不能脱离 id 桶）");

        cc_resolve(&R);
        CHECK(R.xref_n == 3, "cc_resolve 绑定全部 3 条");
        CHECK(cc_lookup(&R, objs[2]) == 2, "cc_lookup 按对象指针取到 hungarian 的下标");
        CHECK(cc_lookup(&R, (void *)0x1234) == -1, "未知对象返回 -1（未配置）");
        CHECK(cc_lookup(&R, NULL) == -1, "空指针返回 -1");
    }

    printf("\n== 懒绑定（本轮修复的核心） ==\n");
    {
        /* 场景 = 真实故障：DllMain 安装期注册表还不存在 ⇒ 必须推迟绑定，
         * 且这份"空结果"不能被永久缓存。 */
        static cc_state_t L, L2, L3;
        const char *txt =
            "chinese_beijing = { surname_first = yes separator = \"\" }\n"
            "korean          = { surname_first = yes }\n"
            "hungarian       = { surname_first = yes separator = \" \" }\n";
        void *objs[3];
        uint8_t *shadow, *realreg = NULL;
        int i;

        cc_init_reader(&L);
        objs[0] = make_culture("chinese_beijing", NULL);
        objs[1] = make_culture("korean", NULL);
        objs[2] = make_culture("hungarian", NULL);
        shadow = registry_build(objs, 3, &realreg);
        L.modbase = shadow;

        cc_parse(&L, txt, (uint32_t)strlen(txt));
        CHECK(L.count == 3, "懒绑定用例：三条配置就绪");

        /* ① 安装期：把指针槽清 0（模拟 DllMain 时注册表尚未创建） */
        registry_clear();
        CHECK(cc_lazy_bind(&L) == 0, "安装期（注册表不存在）：绑定返回 0");
        CHECK(L.bind_state == CC_BIND_IDLE, "安装期：状态仍是 IDLE ⇒ 以后还会再试");
        CHECK(L.xref_n == 0, "安装期：一条都没绑上");
        CHECK(cc_lookup(&L, objs[0]) == -1, "安装期：查配置返回 -1（未命中）");

        /* ② 注册表建好之后：第一次变换调用时再绑，必须绑上 */
        *(uint64_t *)(shadow + CC_REGISTRY_OFF) = (uint64_t)(uintptr_t)realreg;
        CHECK(cc_lazy_bind(&L) == 1, "注册表就绪后：绑定成功");
        CHECK(L.bind_state == CC_BIND_DONE, "绑定成功后状态 = DONE（热路径不再重试）");
        CHECK(L.xref_n == 3, "三条全部绑上 ⇒ bound == entries");
        CHECK(cc_lookup(&L, objs[1]) == 1, "绑定后 cc_lookup(korean) 命中");
        {
            int t = L.bind_tries;
            CHECK(cc_lazy_bind(&L) == 1 && L.bind_tries == t,
                  "已绑定后再调用：直接返回且不再遍历（tries 不增长）");
        }

        /* ③ 一直绑不上：试满上限后放弃，不无限重试 */
        cc_init_reader(&L2);
        cc_parse(&L2, txt, (uint32_t)strlen(txt));
        L2.modbase = shadow;
        registry_clear();
        for (i = 0; i < CC_BIND_MAX_TRIES; i++) (void)cc_lazy_bind(&L2);
        CHECK(L2.bind_state == CC_BIND_GIVEUP, "试满上限后状态 = GIVEUP");
        CHECK(cc_lazy_bind(&L2) == 0 && L2.bind_tries == CC_BIND_MAX_TRIES,
              "放弃之后不再尝试（tries 定格在上限）");

        /* ④ 本来就没有配置条目：直接放弃，不做无谓遍历 */
        cc_init_reader(&L3);
        L3.modbase = shadow;
        CHECK(cc_lazy_bind(&L3) == 0 && L3.bind_state == CC_BIND_GIVEUP,
              "没有配置条目时立即 GIVEUP（不浪费热路径）");
    }

    printf("\n== 健壮性 ==\n");
    {
        static cc_state_t S;
        cc_init_reader(&S);
        CHECK(cc_parse(&S, "", 0) == 0, "空文件：0 条");
        CHECK(cc_parse(&S, "   \n\t\n", 6) == 0, "只有空白：0 条");
        CHECK(cc_parse(&S, "{{{{{{{{", 8) >= 0, "全是 { ：不死循环");
        CHECK(cc_parse(&S, "a = { x = ", 9) >= 0, "截断的键值：不死循环");
        CHECK(cc_parse(&S, "\"quoted\" = { surname_first = yes }", 35) >= 0, "带引号的键：不崩");
        CHECK(cc_parse(&S, "a = { surname_first = maybe }", 29) >= 0, "非 yes/no 布尔值：不崩");
    }

    printf("\n== 按文化名查找 cc_lookup_name（★ 本补丁最终采用的匹配方式）==\n");
    {
        static cc_state_t S;
        const char *cfg =
            "swedish    = { surname_first = yes separator = \" \" }\n"
            "chihan     = { surname_first = yes separator = \"\" }\n"
            "hungarian  = { surname_first = yes separator = \" \" }\n";
        int n = cc_parse(&S, cfg, (uint32_t)strlen(cfg));
        CHECK(n == 3, "解析出 3 条");
        CHECK(cc_lookup_name(&S, "swedish") >= 0, "命中 swedish");
        CHECK(cc_lookup_name(&S, "chihan") >= 0, "命中 chihan");
        CHECK(cc_lookup_name(&S, "hungarian") >= 0, "命中 hungarian");
        CHECK(cc_lookup_name(&S, "korean") == -1, "未配置的 korean → -1");
        CHECK(cc_lookup_name(&S, "swedis") == -1, "前缀不足以命中（长度必须相等）");
        CHECK(cc_lookup_name(&S, "swedishx") == -1, "多一个字符不命中");
        CHECK(cc_lookup_name(&S, "") == -1, "空串 → -1");
        CHECK(cc_lookup_name(&S, NULL) == -1, "NULL → -1");
        CHECK(cc_lookup_name(NULL, "swedish") == -1, "状态为 NULL → -1");
        if (cc_lookup_name(&S, "swedish") >= 0) {
            int i = cc_lookup_name(&S, "swedish");
            CHECK(S.entry[i].surname_first == 1, "swedish 的 surname_first=1");
            CHECK(S.entry[i].has_sep == 1 && S.entry[i].sep.len == 1,
                  "swedish 的分隔符长度=1（空格）");
        }
        if (cc_lookup_name(&S, "chihan") >= 0) {
            int i = cc_lookup_name(&S, "chihan");
            CHECK(S.entry[i].has_sep == 1 && S.entry[i].sep.len == 0,
                  "chihan 的分隔符长度=0（无空格）");
        }
    }

    printf("\n%s (%d failures / %d checks)\n",
           fails == 0 ? "[PASS] culture config parser" : "[FAIL]", fails, total);
    return fails == 0 ? 0 : 1;
}