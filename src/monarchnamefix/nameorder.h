/*
 * nameorder.h — 姓名顺序变换与 P4/P5 动态桩构造器（单一事实来源）
 *
 * 被以下各处共用：
 *   - src\monarchnamefix\monarchnamefix.c  （实际补丁 DLL）
 *   - src\monarchnamefix\p4stubtest.c      （P4 桩的端到端执行测试）
 *   - src\monarchnamefix\p5stubtest.c      （P5 桩的端到端执行测试）
 *   - src\monarchnamefix\nameordertest.c   （变换逻辑单测）
 *
 * 两条判据【并存】：
 *   ① 配置命中（按文化）：该文化一律「姓前名后」，分隔符由该文化指定；
 *   ② 未命中：仍按 `0xBF` 标记决定（标记即"姓氏在后"，剥掉标记）。
 * 无论走哪条，标记都会被【消耗】—— 所以 P4/P5 两处并存不会二次反转。
 */
#ifndef NAMEORDER_H
#define NAMEORDER_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* 分隔符                                                                */
/* ------------------------------------------------------------------ */
/* 全局缺省分隔符：文化【未配置 separator】时用它。
 *   ""  → 中文习惯（朱翊钧）——当前默认
 *   " " → 西文习惯（Zhu Ferdinand）
 * 名字内部原有的空格不受影响（例如 "Jean Claude" 仍带空格）。 */
#define NAME_ORDER_SEP      ""
#define NAME_ORDER_SEP_LEN  (sizeof(NAME_ORDER_SEP) - 1)

/* 每个文化自己的分隔符设置（最长 NAME_SEP_MAX 字节） */
#define NAME_SEP_MAX 8

typedef struct {
    uint8_t len;
    uint8_t b[NAME_SEP_MAX];
} name_sep_t;

static void pn_set_sep(name_sep_t *s, const void *bytes, uint32_t len)
{
    uint32_t i;
    if (!s) return;
    if (len > NAME_SEP_MAX) len = NAME_SEP_MAX;
    s->len = (uint8_t)len;
    for (i = 0; i < len; i++) s->b[i] = ((const uint8_t *)bytes)[i];
}

static int pn_is_sep(const name_sep_t *s, const void *bytes, uint32_t len)
{
    uint32_t i;
    if (!s || s->len != len) return 0;
    for (i = 0; i < len; i++) if (s->b[i] != ((const uint8_t *)bytes)[i]) return 0;
    return 1;
}

/* 默认分隔符（把宏字符串转成 name_sep_t 用的静态初始化值） */
static const name_sep_t g_pn_default_sep = { (uint8_t)NAME_ORDER_SEP_LEN, { NAME_ORDER_SEP } };

/* 与 MSVC std::string 同布局：+0 联合(16B SSO / char*)、+16 size、+24 cap */
typedef struct {
    union { char sso[16]; char *ptr; } u;
    size_t size;
    size_t cap;
} cstr_t;

/* ------------------------------------------------------------------ */
/* 受保护读（由平台层实现；单测里用平坦缓冲的桩实现）                      */
/* ------------------------------------------------------------------ */
/* 变换本身只碰 CString，不需要这个；但「按文化查配置」要读游戏对象，
 * 因此把读操作抽象成两个回调，便于：
 *   ① 在生产 DLL 里加「模块范围校验 + SEH」双重防护；
 *   ② 在单测里用一块平坦内存直接实现，无需 Windows 头。 */
typedef struct {
    /* 读 1/4/8 字节；成功返回 1，越界/不可读返回 0 */
    int (*rd)(void *ctx, const void *p, unsigned n, uint64_t *out);
    /* p[0..n) 是否可读 */
    int (*ok)(void *ctx, const void *p, size_t n);
    void *ctx;
} pn_reader_t;

static uint64_t pn_rd(const pn_reader_t *r, const void *p, unsigned n)
{
    uint64_t v = 0;
    if (r && r->rd && r->rd(r->ctx, p, n, &v)) return v;
    return 0;
}
static int pn_ok(const pn_reader_t *r, const void *p, size_t n)
{
    if (!r || !r->ok) return 0;
    return r->ok(r->ctx, p, n);
}

/* ------------------------------------------------------------------ */
/* 变换                                                                  */
/* ------------------------------------------------------------------ */
/* 就地把 CString 的姓名分成「名 / 姓」两段，然后按参数重排。
 *
 *   姓的判定：字符串里存在 `0xBF` 标记，且它位于 **串首** 或 **紧跟一个空格** 之后。
 *             （`leader_names` 里的裸词是 `"¿Zhu"`，游戏拼名时补上空格 ⇒ 通常形如 `"名 ␠¿姓"`；
 *               也可能直接以标记开头，两种都处理。）
 *
 *   surname_first == 0  → 不作交换，得到「名+sep+姓」
 *   surname_first != 0  → 交换，       得到「姓+sep+名」
 *
 * sep == NULL 时用全局缺省 NAME_ORDER_SEP。
 *
 * 未命中标记 ⇒ **一个字节都不改**（对标记机制之外的数据零影响）。
 * 新长度可能比原串短（标记 1 字节）或长（分隔符比 1 个空格长）：
 *   - 变短：就地前移，无需分配；
 *   - 变长：仅当堆缓冲还有余量（cap 够）时才就地扩展，否则**放弃本次变换**
 *           （宁可保留标记，也不去调用游戏的内存分配器）。
 * 纯内存操作，不调用任何游戏函数。 */
static void name_order_apply(cstr_t *s, int surname_first, const name_sep_t *sep)
{
    char *buf;
    size_t size, i, give_start, give_len, sur_start, sur_len, need, k;
    const uint8_t *sp;
    uint32_t seplen;

    if (!s) return;
    if (!sep) sep = &g_pn_default_sep;
    seplen = sep->len;

    size = s->size;
    buf  = (s->cap >= 0x10) ? s->u.ptr : s->u.sso;   /* SSO 判据：cap >= 16 才走堆 */
    if (!buf || size == 0) return;

    /* ---- 找标记：仅接受 position 0 或 "空格之后" 的 0xBF ---- */
    i = 0;
    for (;;) {
        if (i >= size) return;                        /* 没有标记 ⇒ 零影响 */
        if ((unsigned char)buf[i] == 0xBF) break;
        i++;
    }
    if (i != 0 && (unsigned char)buf[i - 1] != 0x20) return;

    /* ---- 切出三段 ---- */
    if (i > 0) {
        /* "名 ␠ ¿ 姓"：名 = [0, i-1)，跳过标记前的空格 */
        if (i < 2) return;
        give_start = 0;
        give_len   = i - 1;
        sur_start  = i + 1;
    } else {
        /* "¿ 姓"：没有名 */
        give_start = 0;
        give_len   = 0;
        sur_start  = 1;
        if (size < 2) return;
    }
    sur_len = size - sur_start;
    if (sur_len == 0) return;                        /* 标记后为空 ⇒ 不动 */

    need = sur_len + give_len + (give_len ? seplen : 0);

    /* ---- 就地写出（重叠安全：先搬不重叠的部分再搬可能前移的部分） ---- */
    if (need > size) {
        if (s->cap < need + 1) return;               /* 堆余量不足 ⇒ 放弃，保留原样 */
        if (s->cap < 0x10) return;                   /* SSO 无法扩容 */
    }

    /* 两段在源缓冲里重叠（交换方向下必然互相覆盖），故先把「姓」和「名」各取一份副本，
     * 再写回原缓冲。 */
    sp = (const uint8_t *)buf + sur_start;
    {
        unsigned char ts[512], tg[512];
        if (sur_len >= sizeof(ts) || give_len >= sizeof(tg)) return;   /* 超长名：放弃，保留原样 */
        for (k = 0; k < sur_len; k++) ts[k] = sp[k];
        for (k = 0; k < give_len; k++) tg[k] = (unsigned char)buf[give_start + k];

        if (surname_first) {
            for (k = 0; k < sur_len; k++) buf[k] = (char)ts[k];
            for (k = 0; k < seplen; k++) buf[sur_len + k] = (char)sep->b[k];
            for (k = 0; k < give_len; k++) buf[sur_len + seplen + k] = (char)tg[k];
        } else {
            for (k = 0; k < seplen; k++) buf[give_len + k] = (char)sep->b[k];
            for (k = 0; k < give_len; k++) buf[k] = (char)tg[k];
            for (k = 0; k < sur_len; k++) buf[give_len + (give_len ? seplen : 0) + k] = (char)ts[k];
        }
    }

    buf[need] = 0;
    s->size  = need;
}

/* ------------------------------------------------------------------ */
/* ★ 分隔符替换（P7 启用后，P4 的职责缩减为这一件事）                      */
/* ------------------------------------------------------------------ */
/* 为什么 P4 不再需要"交换"：
 *   P7 已在 BuildFullName_Impl 的拼接循环【之前】按文化反转了「段」的顺序
 *   （见 buildP7_for），所以出口拿到的字符串已经是正确顺序。
 *   而循环里那条 StringAppend(" ") 的分隔符是硬编码常量，P4 只需把它
 *   替换成配置的 separator —— 这是**纯替换**，不需要识别"哪一段是姓"，
 *   因此彻底摆脱了"名字里恰好 1 个空格"这个前提。
 *
 * 规则：把所有 0x20 替换成 sep（sep 为空则等效于删除空格）。
 * 从右往左就地重写，保证 sep.len > 1 时不会覆盖尚未读取的字节。 */
static void name_order_replace_sep(cstr_t *s, const name_sep_t *sep)
{
    unsigned char *buf;
    size_t size, i, j, nsp = 0, nbf = 0, need, seplen, k;

    if (!s) return;
    if (!sep) sep = &g_pn_default_sep;
    seplen = sep->len;

    size = s->size;
    buf  = (s->cap >= 0x10) ? (unsigned char *)s->u.ptr : (unsigned char *)s->u.sso;
    if (!buf || size == 0) return;

    /* ★★ 必须同时处理 0xBF 标记（这是实机两次反复的根源）：
     *   0xBF 是【双字节补丁】的"反转词序"触发标记（plugin.ini 的
     *   REVERSING_WORDS_BATTLE_OF_AREA=yes，见 §0-D）。
     *   本函数早先只替换空格、把 0xBF 留在串里 ⇒ 双字节补丁看到标记后
     *   **又反转一次** ⇒ 与 P7 的数组反转互相抵消 ⇒ 顾问/将领/外交官退回"名在前"。
     *   而 name_order_apply（标记路径）的输出本来就不含 0xBF，所以两者行为必须对齐：
     *   **本函数同样吃掉标记**。 */
    /* ★★★ 2026-10-05 定案：0xBF 有**两种**身份，判据 = 「前一字节是不是 escape」。
     *
     * 转码器实测（`scripts/encode_eu4_special.py`，方案见 bruceCzK 的 gist）：
     *     ¿  U+00BF → **<256，直接返回原字符** ⇒ 编码 = `[BF]`（**1 字节**）
     *     线 U+7EBF → low=BF high=7E（high 命中内部表）⇒ escape=0x12 ⇒ `[12 BF 75]`
     *     朱 U+6731 → `[10 31 67]`      军 U+519B → `[10 9B 51]`
     *   ⇒ **「¿」的编码就是裸 0xBF**，它是合法的 1 字节字符（双字节补丁拿它当
     *     "反转词序"的触发标记，见 plugin.ini 的 REVERSING_WORDS_BATTLE_OF_AREA）。
     *   ⇒ 而「线」的第 2 字节**也是 0xBF**，但它是 3 字节字符的内部字节。
     *
     * 判据（唯一能同时满足单元测试与实机日志的规则）：
     *     · 前一个字节是 escape(0x10..0x13) ⇒ **字符内部字节，必须保留**（线）
     *     · 否则                              ⇒ **独立字符「¿」，删除**
     *
     * 实机对照：LJA 的姓字段 `12 BF 75` ⇒ 前一个是 0x12 ⇒ 保留 ⇒ 显示「线」✓ */
    for (i = 0; i < size; i++) {
        if (buf[i] == 0x20) nsp++;
        else if (buf[i] == 0xBF
                 && !(i > 0 && buf[i - 1] >= 0x10 && buf[i - 1] <= 0x13)) nbf++;
    }
    if (nsp == 0 && nbf == 0) return;           /* 既无空格也无标记 ⇒ 零影响 */

    need = size - nsp + nsp * seplen - nbf;     /* 空格→sep，标记删除 */
    /* 容量判据【只有一条】：need 是否超过当前 cap。
     *   · SSO 的 cap = 15（可存 15 字符 + NUL）⇒ need <= 15 时无需扩容，照常处理；
     *     曾错误地写成"cap < 0x10 就放弃"，于是 sep=", " 这种 need=7 的小串也被跳过
     *     （实测 got 仍是原串，测试抓住）。
     *   · need > cap 时本函数【不做扩容】（那要动游戏自己的堆分配器），
     *     一律放弃、保留原样 —— 这是有意的安全行为。 */
    if (need > (size_t)s->cap) return;

    /* ★ 方向必须按 need 与 size 的关系分两种，否则会自我覆盖：
     *   · need <= size（收缩/等长）⇒ 写指针 j 恒 <= 读指针 i，【左→右】安全；
     *     反例（本轮踩到）：size=5、sep="" 时 need=4，若从右往左，
     *     第一次就把 buf[3] 写成 buf[4] 的值，而下一轮恰好要读 buf[3]
     *     ⇒ 整串退化成末字节的重复（实测 got = 44 44 44 44）。
     *   · need > size（扩张）⇒ 写指针恒 >= 读指针，【右→左】安全
     *     （左→右会覆盖尚未读取的字节）。 */
    if (need <= size) {
        size_t j2 = 0;
        for (i = 0; i < size; i++) {
            if (buf[i] == 0x20) {
                for (k = 0; k < seplen; k++) buf[j2++] = (unsigned char)sep->b[k];
            } else if (buf[i] == 0xBF
                       && !(i > 0 && buf[i - 1] >= 0x10 && buf[i - 1] <= 0x13)) {
                /* ★ 只吃独立字符「¿」；前一个是 escape 的 0xBF 是字符内部字节（如 线），保留 */
            } else {
                buf[j2++] = buf[i];
            }
        }
    } else {
        j = need;                               /* 写指针从新末尾开始（右→左） */
        for (i = size; i > 0; i--) {
            if (buf[i - 1] == 0x20) {
                for (k = seplen; k > 0; k--) buf[--j] = (unsigned char)sep->b[k - 1];
            } else if (buf[i - 1] == 0xBF
                       && !(i >= 2 && buf[i - 2] >= 0x10 && buf[i - 2] <= 0x13)) {
                /* ★ 只吃独立「¿」（右→左：看 i-2 是不是 escape） */
            } else {
                buf[--j] = buf[i - 1];
            }
        }
    }
    buf[need] = 0;
    s->size  = need;
}

/* ------------------------------------------------------------------ */
/* ★★ 按【结构给出的姓长度】重排（2026-10-04 新增，取代"猜空格/找 0xBF"）   */
/* ------------------------------------------------------------------ */
/* 为什么能这么做：
 *   顾问 / 外交官 / 将领 / 商人 / 传教士 / 殖民者 的名字都由
 *   `GenerateMonarchName` → **`BuildFullName_Impl`** 生成，而该函数的形态是
 *       loop { append 段; append " " }      → 累积缓冲 Src = "名0 名1 … "
 *       取王朝名（arg_48 = [rbp+0x78]，一个 std::string*）
 *       append 王朝名（无分隔符）            → Src = "名0 名1 … 姓"
 *   ⇒ **「姓」就是末尾 arg_48.size 字节，「名」是前面的部分（末位是那个空格）**。
 *   所以在 P4 的站点（函数尾部、`pop rbp` 之前）把 `[rbp+0x78]` 取出来传给 C 函数，
 *   边界就由**数据结构**唯一确定 —— 不必猜"唯一的空格"，也不必依赖 0xBF 标记。
 *
 * 参数 sur_len = 姓的**有效长度**（已扣除 0xBF —— 游戏在拼 " " + 0xBF + 姓 时
 *   会把「空格 + 0xBF」一起折叠掉，所以实际占位是 size − 0xBF个数）。
 *
 * ★★ 两种形态都要认（2026-10-04 实机日志换来的教训）：
 *   游戏有时会把「空格 + 0xBF」一起折叠掉，于是同一个文化的名字会以两种样子出现：
 *     形态 A（未折叠）："名… SP 姓（含 0xBF）"   ⇒ 名长 = size − dsize − 1，且 buf[名长] == SP
 *     形态 B（已折叠）："名… 姓（0xBF 已剥）"   ⇒ 名长 = size − deff      （不减 1，也没有 SP）
 *   先前只认形态 A ⇒ 对 bai/miao/yi/wu/sichuanese 这些带 0xBF 的文化**每次都放弃**，
 *   表现为"这些文化的名字顺序完全没变"。现在两个候选都试，命中哪个用哪个。
 *
 * 参数：
 *   sur_len = 姓在串里【未折叠】时占的字节数（= 王朝名 size，含 0xBF）
 *   sur_eff = 姓【剔除 0xBF 后】的有效字节数（= 折叠形态下姓占的字节数）
 *
 * 前提都不满足时**原样返回**，零影响。 */
static int name_order_apply_struct(cstr_t *s, size_t sur_len, size_t sur_eff,
                                   const name_sep_t *sep)
{
    unsigned char *buf;
    size_t size, nlen, k, need, seplen, take;
    int folded;

    if (!s || sur_len == 0) return 0;
    if (!sep) sep = &g_pn_default_sep;
    seplen = sep->len;

    size = s->size;
    buf  = (unsigned char *)(s->cap >= 0x10 ? (void *)s->u.ptr : (void *)s->u.sso);
    if (!buf) return 0;

    /* ★★★ 前置完整性自检（2026-10-05）：接手前先看这个对象像不像完好的 CString。
     *   起因是一次实机崩溃 —— C0000005 @ RVA 0x94F4A（CString 移动赋值读源），
     *   异常记录里源指针竟然是 0x13（一个整数），属于"结构体字段错位"。
     *   崩溃点在被数千处内联调用的通用函数里，回溯不到调用方；
     *   我们能做的就是把住入口：对象可疑就**绝不写它**，宁可这个文化顺序不变。 */
    if (s->size > s->cap)   return 0;              /* size 超过容量 ⇒ 已坏 */
    if (s->cap > 0x10000)   return 0;              /* 容量离谱     ⇒ 已坏 */
    if (s->cap >= 0x10) {                          /* 堆串：校验 data 指针 */
        uintptr_t dp = (uintptr_t)buf;
        if (dp < 0x10000 || dp > 0x00007FFFFFFFFFFFull) return 0;
    }
    if (size <= 1) return 0;

    /* ---- 形态 A：名 + SP + 姓(含 0xBF) ---- */
    if (size > sur_len && buf[size - sur_len - 1] == 0x20) {
        nlen   = size - sur_len - 1;
        take   = sur_len;
        folded = 0;
    }
    /* ---- 形态 B：名 + 姓(已剥 0xBF，无 SP) ---- */
    else if (sur_eff > 0 && size > sur_eff && buf[size - sur_eff - 1] != 0x20) {
        nlen   = size - sur_eff;
        take   = sur_eff;
        folded = 1;
    } else {
        return 0;                                   /* 都不像 ⇒ 不动 */
    }
    if (nlen == 0) return 0;                        /* 没有名 ⇒ 不动 */

    need = sur_eff + seplen + nlen;
    if (need > s->cap) return 0;                    /* 堆余量不足 ⇒ 放弃（绝不调分配器） */

    {
        unsigned char ts[512], tg[512];
        size_t sw = 0;
        if (take >= sizeof(ts) || nlen >= sizeof(tg)) return 0;
        for (k = 0; k < nlen; k++)    tg[k] = buf[k];
        /* ★★★ 2026-10-05 修复：与双字节补丁同判据 —— **只在「空格紧跟 0xBF」**
         *   (`0x20 0xBF`) 时删那个 0xBF，其余 0xBF 一律当**字符编码字节**保留。
         *
         *   为什么：EU4 双字节编码里 `线`(U+7EBF) 的编码就是 `12 BF 75`，
         *   0xBF 是它的 low 字节；用户已确认 `dynasty_names` 里「线」是纯字符、
         *   不带任何 `¿` 标记。原代码 `if (ch == 0xBF) continue;` 会把「线」删碎
         *   ⇒ 乱码方块，且 `sw != sur_eff` 自检失败 ⇒ 功能静默失效。
         *
         *   补丁判据出处：EU4dll `Plugin64__localization_asm.asm`
         *       cmp byte ptr [rax+1], 0BFh   ; [0]は0x20(white space) */
        {
            size_t q = 0;
            while (q < take) {
                unsigned char c0 = buf[nlen + (folded ? 0 : 1) + q];
                if (c0 == 0x20 && (q + 1) < take
                    && buf[nlen + (folded ? 0 : 1) + q + 1] == 0xBF) {
                    ts[sw++] = c0;                  /* 空格保留 */
                    q += 2;                         /* 跳过被标记的 0xBF */
                    continue;
                }
                ts[sw++] = c0;                      /* 其余原样（含字符内的 0xBF） */
                q++;
            }
        }
        if (sw != sur_eff) return 0;                /* 自检失败 ⇒ 不动 */

        for (k = 0; k < sur_eff; k++) buf[k] = ts[k];
        for (k = 0; k < seplen; k++)  buf[sur_eff + k] = (unsigned char)sep->b[k];
        for (k = 0; k < nlen; k++)    buf[sur_eff + seplen + k] = tg[k];
        buf[need] = 0;
        s->size  = need;
    }
    return 1;
}

/* 兼容入口：无文化信息时按标记判据（surname_first = 1，全局分隔符）。 */
static void patch_name_order(cstr_t *s, void *ctx)
{
    (void)ctx;
    name_order_apply(s, 1, &g_pn_default_sep);
}

/* ------------------------------------------------------------------ */
/* ★ 无标记时的强制交换（本轮新增）                                       */
/* ------------------------------------------------------------------ */
/* 为什么需要它：实机日志（2026-10-03，玩明/江淮）证明——
 *   顾问、全部外交官/商人/传教士/殖民者、陆海军将领的名字形如
 *       `名 + 0x20(空格) + 姓`，且【不含 0xBF 标记】。
 *   实例：bytes(7)  = 10 1b 69 | 20 | 10 8b 73      spaces@3  marks@(空)
 *         bytes(13) = 10 31 75 10 21 6a | 20 | 10 e4 4e 10 d0 72   spaces@6  marks@(空)
 *   而 name_order_apply 只在找到 0xBF 时才动手 ⇒ 这批名字永远不被处理。
 *
 * 本函数补上另一半：**配置命中的文化，即使没有 0xBF，也按空格强制交换**。
 *   规则：取【唯一的空格】作边界（日志实测恰为 1 个）；
 *         surname_first → "名 SP 姓" 变 "姓 + sep + 名"；
 *         否则          → "名 + sep + 名"…即保持名在前（sep 仍按配置插入）。
 *   若空格数 != 1（含 0 或多于 1），一律【原样返回】——不猜、不切，宁可不动。
 */
static void name_order_apply_forced(cstr_t *s, int surname_first, const name_sep_t *sep)
{
    unsigned char *buf;
    size_t size, i, nsp = 0, sp_at = 0, give_len, sur_len, need, k;
    uint32_t seplen;
    unsigned char tg[512], ts[512];

    if (!s) return;
    if (!sep) sep = &g_pn_default_sep;
    seplen = sep->len;

    size = s->size;
    buf  = (s->cap >= 0x10) ? (unsigned char *)s->u.ptr : (unsigned char *)s->u.sso;
    if (!buf || size < 3) return;                  /* 太短，不可能有"名 SP 姓" */

    /* 找空格：必须是【唯一】一个，否则不猜边界 */
    for (i = 0; i < size; i++) {
        if (buf[i] == 0x20) { nsp++; sp_at = i; }
    }
    if (nsp != 1) return;                          /* 0 个或多个 ⇒ 原样返回 */
    if (sp_at == 0 || sp_at + 1 >= size) return;   /* 空格在首/尾 ⇒ 不处理 */

    give_len = sp_at;                              /* 名 = [0, sp_at) */
    sur_len  = size - sp_at - 1;                   /* 姓 = [sp_at+1, size) */

    need = give_len + sur_len + (give_len ? seplen : 0);
    if (need > size) {
        if (s->cap < need + 1) return;             /* 堆余量不足 ⇒ 放弃，保留原样 */
        if (s->cap < 0x10) return;                 /* SSO 无法扩容 */
    }
    if (sur_len >= sizeof(ts) || give_len >= sizeof(tg)) return;

    for (k = 0; k < sur_len; k++)  ts[k] = buf[sp_at + 1 + k];
    for (k = 0; k < give_len; k++) tg[k] = buf[k];

    if (surname_first) {
        /* 姓 + sep + 名 */
        for (k = 0; k < sur_len; k++) buf[k] = ts[k];
        for (k = 0; k < seplen; k++) buf[sur_len + k] = (unsigned char)sep->b[k];
        for (k = 0; k < give_len; k++) buf[sur_len + seplen + k] = tg[k];
    } else {
        /* 名 + sep + 姓（即"名在前"，分隔符仍按配置） */
        for (k = 0; k < seplen; k++) buf[give_len + k] = (unsigned char)sep->b[k];
        for (k = 0; k < give_len; k++) buf[k] = tg[k];
        for (k = 0; k < sur_len; k++) buf[give_len + seplen + k] = ts[k];
    }

    buf[need] = 0;
    s->size  = need;
}

/* 统一入口：先试标记判据；若名字里没有标记，而调用方【明确知道该文化要姓前名后】，
 * 则用强制交换补上。has_culture_cfg 表示"配置命中且给出了 surname_first"。 */
static void name_order_apply_cfg(cstr_t *s, int surname_first, const name_sep_t *sep,
                                 int force_when_unmarked)
{
    const unsigned char *b;
    size_t i, size;
    int has_mark = 0;

    if (!s) return;
    size = s->size;
    b = (const unsigned char *)(s->cap >= 0x10 ? (const void *)s->u.ptr : (const void *)s->u.sso);
    if (b) {
        for (i = 0; i < size; i++) {
            if (b[i] == 0xBF) { has_mark = 1; break; }
        }
    }
    if (has_mark) {
        name_order_apply(s, surname_first, sep);   /* 有标记 ⇒ 走原有那条（已验证正常） */
    } else if (force_when_unmarked) {
        name_order_apply_forced(s, surname_first, sep);  /* 无标记 ⇒ 强制按空格交换 */
    }
}

/* 我们的变换函数真实类型（桩里用非标准寄存器传参，故此处只作地址取值用） */
typedef void (*pn_apply_fn)(cstr_t *, int, const name_sep_t *);


/* ============================================================================
 * ⚠ 以下 P7 / P8旧 / P9 / P10 的桩构造器与说明**全部是已废弃方案的遗迹**：
 *   它们对应的补丁（P7、P9、P10）早已从补丁表移除 —— 原因见
 *   notes/交接-按文化决定姓名顺序.md §0-F / §0-H（连续四次实机崩溃 + 前提不成立）。
 *   保留实现只作教训参考，用 #if 0 排除编译。
 *   **正在使用的是下面的 buildP8_for（CMonarch_GetFullName）。**
 * ============================================================================ */

/* ============================================================================
 * ⚠ P9 / P10 桩构造器同样是废弃遗迹（对应补丁从未启用或已移除）⇒ #if 0 排除编译。
 * ============================================================================ */

#endif /* NAMEORDER_H */
