/*
 * install.cpp - 钩子安装层（C++）
 *
 * 职责：
 *   ① 用 BytePattern 在各站点定位（而不是硬编码 RVA 一把梭）；
 *   ② 分配 cave、为每个站点建"站点 → cave → 桩"的跳板；
 *   ③ 把回跳点写进 stubs.asm 的 EXTERN 变量。
 *
 * 与 EU4dll 的分工一致：
 *   C/C++ 侧："找地址、算偏移、安装"；
 *   .asm 侧："复刻被覆盖的指令 + 业务逻辑 + 回跳"。
 *
 * ★ 为什么还需要 cave（本机实测得出）：
 *   从 eu4.exe 里的站点跳到【我们 DLL 里】的桩，距离超过 ±2GB，
 *   hookmem::make_jmp 必须写 14 字节；而站点 cover 只有 5~8 字节。
 *   所以先 5 字节 E9 跳到贴近 eu4.exe 的 cave，再由 cave 写 14 字节绝对跳转。
 */
#include "hooks.hpp"
#include "stubs.hpp"

#include <cstdio>
#include <string>

/* ==================================================================== */
/* 站点表                                                                */
/* ==================================================================== */
/* 每一行都对应"人工反汇编确认过的一条完整指令边界"。
 * site_bytes 在安装前会逐字节比对 —— 对不上就【拒绝安装】，
 * 而不是像早期那样"取签名第一个命中"（got=0x1c605d want=0x3142f2 的教训）。 */

namespace {

struct SiteDecl
{
    const char      *name;
    std::uintptr_t   site_rva;        /* 站点 RVA（权威值：命中多个时用它筛） */
    void            *stub;
    std::size_t      cover;           /* 必须正好覆盖整数条指令 */
    std::uintptr_t   resume_rva;      /* 回跳点 */
    const char      *site_bytes;      /* 站点附近的字节模式（可含 ? 通配） */
    std::ptrdiff_t   pattern_to_site; /* 站点 = 模式命中点 + 这个偏移 */
    std::uintptr_t  *resume_var;
};

/* ★★ 模式为什么要"长"：
 *   第一版只用了 5~8 字节，结果 `48 89 5C 24 08` 在 .text 里命中 15437 次，
 *   6 个钩子只装上了 1 个（gen     loop_decide），于是"姓被追加了却没人重排" —— 名字全乱。
 *   现在的模式都在 19~37 字节，并且：
 *     - 命中恰好 1 次 ⇒ 直接采用；
 *     - 命中多次（gen     entry_culture 的序言在编译器眼里是通用模板，有 4 个函数一样）
 *       ⇒ 在命中集合里挑 RVA 等于 site_rva 的那个（这是权威判据）；
 *     - 一次都没命中 ⇒ 报错，不猜。
 *   这正是旧 prepare_one 的做法 —— 模式用于跨版本，RVA 用于精确定位。 */
/* ==================================================================== */
/* 站点表 —— 按【逻辑执行顺序】排列，分三组                              */
/* ==================================================================== */
/* ★★★ 站点命名表（2026-10-05 定稿）：一个站点在四处文件里用同一个名字。     */
/*                                                                        */
/*   命名格式： `<组>_<动作名>`（符号）/ `<组>  <动作名>`（显示名，日志里用）*/
/*     组   = 这件事属于哪一类（modfix / gen / disp）                        */
/*     动作 = 它在这一类里的哪一步                                          */
/*                                                                        */
/*   组      含义                                   站点（按 kSites 顺序）   */
/*   ──────  ─────────────────────────────────────  ──────────────────────  */
/*   modfix  取模缺陷修复（三个站点 = 同一个 bug）    pick_idx / pick_cult / pick_modidx */
/*   gen     生成期姓前名后（五站点 = 一条流水线）     entry_culture → loop_decide      */
/*                                                   → surn_len → reorder             */
/*                                                   → exit_fallback                  */
/*   disp    显示期统治者/继承人/配偶姓名             ruler_name                       */
/*                                                                        */
/*   站点（显示名）              插在哪里                        做什么          */
/*   ──────────────────────────  ────────────────────────────  ────────────────  */
/*   modfix  pick_idx            WeightedNameList_PickBy… 序言   随机值掩成 21 位非负 */
/*   modfix  pick_cult           PickNameFromCultureLists 取模   有符号 → 无符号    */
/*   modfix  pick_modidx         WeightedNameList_GetBy… 取模    有符号 → 无符号    */
/*   gen     entry_culture       BuildFullName_Impl 入口         捕获本次调用的文化名 */
/*   gen     loop_decide         拼接循环之前                    判定该文化是否姓前名后 */
/*   gen     surn_len            追加「姓」那次 call 之前         记下姓的字节数     */
/*   gen     reorder             追加「姓」那次 call 之后         就地重排「姓 sep 名」 */
/*   gen     exit_fallback       函数出口                        兜底重排（reorder 未成时） */
/*   disp    ruler_name          CMonarch_GetFullName            显示期重排        */
/*                                                                        */
/*   ★ gen 五个站点在 BuildFullName_Impl 内的执行顺序，就是上表的排列顺序。  */
/*                                                                        */
/* ────────────────────────────────────────────────────────────────────── */
/* ★★★ 旧编号对照表（**给旧笔记用**，2026-10-05 由"功能命名"取代编号）      */
/* ────────────────────────────────────────────────────────────────────── */
/* 为什么改：旧编号 P1..P11 是【按添加时间】编的，不含任何语义，而且与表内   */
/*   顺序完全不对应（旧表内顺序是 P1 P2 P3 P6 P7 P10 P11 P4 P8）。读代码时   */
/*   光看编号不知道它在哪一步做什么。现在改成"功能组 + 动作"，名字自己说明   */
/*   问题。                                                                 */
/*                                                                        */
/* ⚠️⚠️ **旧笔记里的 "Pn" 指的是下表左列，不是右列的同名项** ——             */
/*   因为新编号已经废弃，右列不再有 Pn 这个名字；搜 notes\ 时请按左列理解。  */
/*   特别注意旧 P4 / P6 / P7 / P8 的**含义曾被交换过**，不要按序号猜：       */
/*                                                                        */
/*   旧编号  新站点名                旧笔记里的 "Pn" 指的是什么              */
/*   ──────  ──────────────────────  ─────────────────────────────────────  */
/*   P1      modfix_pick_idx         PickByRandomIndex 序言掩随机值          */
/*   P2      modfix_pick_cult        PickNameFromCultureLists 取模改无符号   */
/*   P3      modfix_pick_modidx      WeightedNameList_GetByModIndex 取模     */
/*   P6      gen_entry_culture       BuildFullName_Impl 入口捕获文化名       */
/*   P7      gen_loop_decide         拼接循环前判定"是否姓前名后"            */
/*   P10     gen_surn_len            记下姓的字节数（call StringAppend 前）   */
/*   P11     gen_reorder             就地重排「姓 + sep + 名」（call 之后）   */
/*   P4      gen_exit_fallback       函数出口兜底重排                        */
/*   P8      disp_ruler_name         CMonarch_GetFullName 显示期重排         */
/*                                                                        */
/*   ⇒ 例：旧笔记写 "P4 兜底"、"P8 显示" —— 分别对应 gen_exit_fallback 与   */
/*     disp_ruler_name。而新名 gen_reorder 的前身是旧 P11（不是 P7）。       */
/*                                                                        */
/*   ★ `notes\` 里 500+ 处旧编号**未改动**（改动面太大、易引入新错误），      */
/*     靠本表对照即可。history: git log -S "P11" -- src/monarchnamefix/      */
/*                                                                        */
/*   ★ 顺序一致性与四处齐全性有机器校验：                                    */
/*     `python scripts\verify_site_order.py`                                */
/*     （校验 install.cpp / stubs.asm / stubs.hpp / hookvars.cpp /          */
/*       monarchnamefix.cpp 五处，并检查每个站点在四处文件里都存在）          */

const SiteDecl kSites[] = {
    /* ================= 组 1：名字选取阶段（取模修复） ================= */
    /* 三处共同病根：随机值/索引高位为 1 时，有符号除法产生负余数
     * ⇒ 取样全回落到第 0 号位 = "取第一号位的概率被放大"。 */

    /* modfix  pick_idx runmask：WeightedNameList_PickByRandomIndex 序言。覆盖 5 字节
     *     （`mov rdi,r8` + `mov esi,edx`），回跳 0xDA98A0（mov rcx,r10）。
     *     ★ 这是【继承人取名实际走的那条路径】：随机源是 Random_GetGlobalMT()
     *       的完整 32 位，而 0xDA98C3 直接拿它做 `cdq; idiv ecx`（有符号）
     *       ⇒ 负值产生负余数。
     *     掩码放在两条重放之前，`esi` 由 `mov esi,edx` 自然取到非负值，
     *     两条路径（mode 0/2 用 esi、mode 1 用 edx）一起被覆盖。
     *     模式取站点后 12 字节，避开只有 5 字节时可能的多处命中。 */
    { "modfix  pick_idx       PickByRandomIndex prologue (mask 21 bits)",
      0x00DA989Bu, reinterpret_cast<void *>(&mnp_hook_modfix_pick_idx),  5u, 0x00DA98A0u,
      "49 8B F8 8B F2 4C 8B D1 83 F8 01 75 72 83 79 30 00",
      0, &mnp_ret_modfix_pick_idx },

    /* modfix  pick_cult modulo：PickNameFromCultureLists。6 字节，回跳 0x28027A（cmp ecx,edx）。
     *     原指令 `mov eax,edi / cdq / idiv r8d` ⇒ 负余数被调用方按"越界"处理。 */
    { "modfix  pick_cult      PickNameFromCultureLists (unsigned fix)",
      0x00280274u, reinterpret_cast<void *>(&mnp_hook_modfix_pick_cult),  6u, 0x0028027Au,
      "8B C7 99 41 F7 F8 3B D1 7D 0B 8B C2 48 C1 E0 05",
      0, &mnp_ret_modfix_pick_cult },

    /* modfix  pick_modidx modulo：WeightedNameList_GetByModIndex。6 字节，回跳 0xDA9A88（lea (rdx,rdx,4),rax）。
     *     该函数元素 40 字节：(end-begin)/8/5 ⇒ /40，再 begin + (i%n)*40。
     *     负余数会直接算出野地址（潜伏型 OOB）。 */
    { "modfix  pick_modidx    WeightedNameList_GetByModIndex (unsigned fix)",
      0x00DA9A82u, reinterpret_cast<void *>(&mnp_hook_modfix_pick_modidx),  6u, 0x00DA9A88u,
      "8B C2 99 41 F7 F8 48 8D 04 92 49 8D 04 C1 C3 33 C0 C3",
      0, &mnp_ret_modfix_pick_modidx },

    /* ================= 组 2：生成期姓名顺序 ================= */
    /* 都在 BuildFullName_Impl（0x313F40..0x31434E）内部，按执行时机排列。 */

    /* gen     entry_culture culture：函数入口。37 字节模式 —— 该序言在 .text 里出现 4 次
     *     （编译器标准模板），所以靠 site_rva 筛选。 */
    { "gen     entry_culture  BuildFullName_Impl entry (capture culture name)",
      0x00313F40u, reinterpret_cast<void *>(&mnp_hook_gen_entry_culture),  5u, 0x00313F45u,
      "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 89 64 24 20 "
      "55 41 56 41 57 48 8D 6C 24 F0 48 81 EC 10 01 00 00",
      0, &mnp_ret_gen_entry_culture },

    /* gen     loop_decide decide：拼接循环之前。19 字节，唯一命中（含 `jle` 的 rel8 0x59，是这段的特征）。
     *     ★ 只置标志，绝不碰 Src —— 此时 Src 还是空 SSO 串（cap=15），
     *       中文姓名按 3 字节/字编码，写进去会被容量卡死。
     *     （历史名 `p7_prepend_if_sf` 来自它早期真的往缓冲里预写"姓"的版本，
     *       那个做法已废弃，现名 `p7_decide_surname_first` 才是它实际做的事。） */
    { "gen     loop_decide    BuildFullName_Impl loop prelude (surname-first?)",
      0x00314228u, reinterpret_cast<void *>(&mnp_hook_gen_loop_decide),  8u, 0x00314230u,
      "85 C0 7E 59 49 8B DF 90 49 8D 14 18 48 8B C2 48 8B 4A 18",
      0, &mnp_ret_gen_loop_decide },

    /* gen     surn_len surnlen：`call StringAppend` 之前，记下姓的字节数。
     *      模式跨过那次 call 的 rel32（用 ? 通配），直到下一条 movups。
     *      此刻 r8 = 姓的字节数（姓的两个来源已在此汇合）。 */
    { "gen     surn_len       BuildFullName_Impl (record surname length)",
      0x003142F2u, reinterpret_cast<void *>(&mnp_hook_gen_surn_len), 5u, 0x003142F7u,
      "48 8D 4C 24 30 E8 ? ? ? ? 0F 10 44 24 30 0F 11 07 0F 10 4C 24 40",
      0, &mnp_ret_modfix_pick_idx0 },

    /* gen     reorder reorder：`call StringAppend` 之后，就地重排。21 字节，唯一命中。 */
    { "gen     reorder        BuildFullName_Impl (surname + sep + given)",
      0x003142FCu, reinterpret_cast<void *>(&mnp_hook_gen_reorder), 5u, 0x00314301u,
      "0F 10 44 24 30 0F 11 07 0F 10 4C 24 40 0F 11 4F 10 48 8D 4D F0",
      0, &mnp_ret_modfix_pick_idx1 },

    /* gen     exit_fallback fallback：函数出口（唯一出口）。从 `mov rax,rdi`(0x31432B) 起 36 字节，
     *     站点 0x314349 相对命中点 +0x1E。
     *     ★ 紧邻站点之前的 0x31432B 就是返回值 `rax` —— 曾经因为旧桩用
     *       C 函数的返回值覆盖它，导致三次 C0000005 @ 0x94F4A。
     *       新架构下 rax 由寄存器包原样保存/恢复，该类问题不复存在。 */
    { "gen     exit_fallback  BuildFullName_Impl exit (last-resort reorder)",
      0x00314349u, reinterpret_cast<void *>(&mnp_hook_gen_exit_fallback),  5u, 0x0031434Eu,
      "48 8B C7 4C 8D 9C 24 10 01 00 00 49 8B 5B 20 49 8B 73 28 "
      "49 8B 7B 30 4D 8B 63 38 49 8B E3 41 5F 41 5E 5D C3",
      0x1E, &mnp_ret_gen_exit_fallback },

    /* ================= 组 3：统治者 / 继承人 / 配偶（显示期） ================= */

    /* disp    ruler_name display：CMonarch_GetFullName（0xA4B2C0）里那次
     *     `out += " " + 王朝名` 刚做完处（0xA4B4A6）。20 字节，唯一命中。
     *     ★ 这里是**唯一**把 name 与 dynasty 两个字段拼起来的地方：
     *       本补丁在此按该角色文化的配置把「名 + 姓」改成「姓 + separator + 名」，
     *       两个字段本身一个字节都不动。 */
    { "disp    ruler_name     CMonarch_GetFullName (ruler/heir/consort)",
      0x00A4B4A6u, reinterpret_cast<void *>(&mnp_hook_disp_ruler_name),  7u, 0x00A4B4ADu,
      "C7 45 B0 01 00 00 00 48 8B 55 D0 48 83 FA 10 72 31 48 FF C2",
      0, &mnp_ret_disp_ruler_name },
};

constexpr std::size_t kSiteCount = sizeof(kSites) / sizeof(kSites[0]);

/* 日志回调：由 C 侧注入，这样 C++ 层不必知道日志怎么开 */
void (*g_log_str)(const char *) = nullptr;

/* ==================================================================== */
/* 诊断开关：跳过取模修复（modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx）                                    */
/* ==================================================================== */
/* 用途：把"6 站点（只做姓名顺序）"与"9 站点（含取模修复）"分开测。
 *
 * 为什么需要它 —— 2026-10-05 10:04 那次崩溃：
 *   崩溃在 sub_14028AB40（country.cpp 月度更新里的一个遍历），
 *   被遍历的对象 +0x18 处有 1681 个 72 字节元素，每个元素的 [+0] 都回指 owner；
 *   而第 1306 个元素的 [+0] 变成了 owner<<24（垃圾）。
 *   我在补丁里所有写内存的路径都逐行验过边界（gen     reorder 有 need>cap / need>size
 *   双重守卫且可证 need<=size；gen     exit_fallback 的结构路径有 1..255 门槛，实机 202 次样本里
 *   从未落在该区间 ⇒ 一次都没执行过；modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx 只改寄存器、完全不写内存）。
 *   但"我验过"不等于"与补丁无关" —— modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx 会改变名字选取结果，
 *   可能只是让一个既有的状态不一致暴露出来。
 *   ⇒ 给一个能一键回到 6 站点的开关，让实机 A/B 来回答，而不是靠推理。
 *
 * 用法：在 plugins\ 下建空文件 MonarchNameFix.nomod */
extern "C" int mnp_skip_modfix = 0;

/* ==================================================================== */
/* 诊断开关：按站点跳过（二分定位）                                      */
/* ==================================================================== */
/* 为什么还要这一组 —— .nomod 的实机结果推翻了原先的假设：
 *   两次崩溃【都】发生，而且日志【都】停在最后一条 `[d] gen     reorder`：
 *       · 9 站点（含 modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx） → 留下 minidump（可捕获的 AV）
 *       · 6 站点（.nomod）      → 静默消失，连 crashes 目录都没有
 *   ⇒ 问题在姓名顺序链路，不在取模修复。
 *   ⇒ 而 6 站点那种"连 dump 都没有"的形态，很像 STATUS_STACK_OVERFLOW ——
 *     栈溢出时 SEH handler 自己都跑不起来，所以 p11_reorder_surname_first 的 __try 接不住，
 *     游戏也写不出崩溃报告。这一条后面要重点验。
 *
 * 用法（plugins\ 下建空文件，可任意组合）：
 *     MonarchNameFix.noP6 / noP7 / noP10 / noP11 / noP4 / noP8
 *   （noP1/noP2/noP3 等价于 .nomod，也一并支持）*/
extern "C" unsigned mnp_skip_mask = 0;   /* bit i ⇒ 跳过 kSites[i] */

/* 站点 RVA → 位号，按 kSites[] 的顺序：modfix  pick_idx modfix  pick_cult modfix  pick_modidx gen     entry_culture gen     loop_decide gen     surn_len gen     reorder gen     exit_fallback disp    ruler_name */
static int site_bit(std::uintptr_t rva)
{
    switch (rva) {
    case 0x00DA989Bu: return 0;   /* modfix  pick_idx  runmask  */
    case 0x00280274u: return 1;   /* modfix  pick_cult  modulo   */
    case 0x00DA9A82u: return 2;   /* modfix  pick_modidx  modulo   */
    case 0x00313F40u: return 3;   /* gen     entry_culture  culture  */
    case 0x00314228u: return 4;   /* gen     loop_decide  decide   */
    case 0x003142F2u: return 5;   /* gen     surn_len surnlen  */
    case 0x003142FCu: return 6;   /* gen     reorder reorder  */
    case 0x00314349u: return 7;   /* gen     exit_fallback  fallback */
    case 0x00A4B4A6u: return 8;   /* disp    ruler_name  display  */
    default:          return -1;
    }
}

/* 取模修复的三个站点 RVA（.nomod 一并跳过它们） */
static bool is_modfix_site(std::uintptr_t rva)
{
    return rva == 0x00DA989Bu     /* modfix  pick_idx runmask  PickByRandomIndex 序言       */
        || rva == 0x00280274u     /* modfix  pick_cult modulo   PickNameFromCultureLists     */
        || rva == 0x00DA9A82u;    /* modfix  pick_modidx modulo   WeightedNameList_GetByModIndex */
}

void log(const std::string &s)
{
    if (g_log_str) g_log_str(s.c_str());
}

std::string hexstr(std::uintptr_t v)
{
    char b[32];
    std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(v));
    return std::string(b);
}

std::string decstr(std::size_t v)
{
    char b[32];
    std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
    return std::string(b);
}

/* 把 cave 里的前 N 字节打成十六进制，用于确认跳转真的写对了。
 * 实机调试时"装上了"和"跳转是对的"是两件事 —— 必须能看到字节。 */
std::string hexdump(const unsigned char *p, std::size_t n)
{
    static const char *d = "0123456789ABCDEF";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        if (i) s += ' ';
        s += d[p[i] >> 4];
        s += d[p[i] & 0xF];
    }
    return s;
}

} /* namespace */

/* ==================================================================== */
/* 对外入口（C 链接）                                                    */
/* ==================================================================== */

extern "C" void mnp_install_set_logger(void (*fn)(const char *))
{
    g_log_str = fn;
}

/*
 * 安装全部新钩子。
 *   module      eu4.exe 基址
 *   cave        cave 起始；传 nullptr 表示"由本函数自己分配"
 *   cave_size   cave 字节数；cave 为 nullptr 时忽略
 * 返回已安装的钩子数（0 表示一个都没装上）。
 *
 * ★ 本机实测：DLL 与 eu4.exe 相距约 26GB（delta=0x6C3E50000），
 *   所以每个"站点 → 桩"都必须写 14 字节；而站点 cover 只有 5~8 字节。
 *   cave 必须贴近 eu4.exe，否则连"站点 → cave"的 5 字节 E9 都算不出来。
 */
extern "C" int mnp_install_new_hooks(void *module, unsigned char *cave, unsigned long cave_size)
{
    if (!module) return 0;

    const std::size_t need = kSiteCount * mnp::kSlotSize;

    /* ---- cave：没有就自己分配 ---- */
    unsigned char *slots = cave;
    if (!slots) {
        slots = static_cast<unsigned char *>(mnp::alloc_near_module(module, need));
        if (!slots) {
            log("[!] newhook: cave alloc failed (need " + decstr(need) + ")\r\n");
            return 0;
        }
        log("[i] newhook: cave=" + hexstr(reinterpret_cast<std::uintptr_t>(slots)) +
            " (self-allocated)\r\n");
    } else if (cave_size < need) {
        log("[!] newhook: cave too small (need " + decstr(need) + ")\r\n");
        return 0;
    }

    int installed = 0;

    for (std::size_t i = 0; i < kSiteCount; ++i) {
        const SiteDecl &s = kSites[i];

        /* ---- ⓪ 诊断：按开关跳过站点 ----
         *   .nomod           ⇒ 跳过取模修复的三个（回到 6 站点）
         *   .noP6/.noP7/...  ⇒ 单独跳过某一个（二分定位） */
        {
            const int bit = site_bit(s.site_rva);
            const char *why = nullptr;

            if (mnp_skip_modfix && is_modfix_site(s.site_rva)) {
                why = ".nomod";
            } else if (bit >= 0 && (mnp_skip_mask & (1u << bit)) != 0u) {
                why = "skip";
            }
            if (why) {
                log(std::string("[i] newhook: (") + why + ") 跳过 " + s.name + "\r\n");
                continue;
            }
        }

        /* ---- ① 用模式定位 ---- */
        const mnp::SearchResult sr = mnp::search(s.site_bytes, module);

        if (!sr.parsed) {
            log(std::string("[!] newhook: pattern parse failed: ") + s.site_bytes + "\r\n");
            continue;
        }
        if (sr.empty()) {
            log(std::string("[!] newhook: pattern hits=0 : ") + s.site_bytes + "\r\n");
            continue;
        }

        /* ---- ② 在命中集合里挑 RVA 匹配的那个（权威判据）----
         * 模式负责"跨版本仍然找得到"，RVA 负责"多个候选中确定是哪一个"。
         * 例如 gen     entry_culture 的序言在 .text 里有 4 份完全相同的拷贝。 */
        std::uint8_t *hit = nullptr;
        for (std::uint8_t *p : sr.hits) {
            const std::uintptr_t rva =
                reinterpret_cast<std::uintptr_t>(p) - reinterpret_cast<std::uintptr_t>(module);
            const std::uintptr_t site_rva =
                rva + static_cast<std::uintptr_t>(s.pattern_to_site);
            if (site_rva == s.site_rva) { hit = p; break; }
        }
        if (!hit) {
            log(std::string("[!] newhook: hits=") + decstr(sr.count()) +
                " but none maps to RVA " + hexstr(s.site_rva) + " : " + s.name + "\r\n");
            continue;
        }

        const std::uintptr_t found_rva = s.site_rva;   /* 已由上面的比对确认 */

        /* ---- ③ 建跳板并安装 ---- */
        mnp::HookSpec spec;
        spec.name       = s.name;
        spec.site_rva   = found_rva;              /* ★ 以实测为准 */
        spec.stub       = s.stub;
        spec.cover      = s.cover;
        spec.resume_rva = s.resume_rva;
        spec.site_bytes = std::string_view{};     /* 已在上面校验过 */
        spec.resume_var = s.resume_var;

        unsigned char *slot = slots + i * mnp::kSlotSize;
        const mnp::HookResult r = mnp::install_hook(spec, module, slot);

        if (r.installed) {
            ++installed;
            log(std::string("[+] newhook: ") + s.name + " site=" + hexstr(r.site) +
                " cave=" + hexstr(r.cave) + " resume=" + hexstr(r.resume) +
                " sitejmp=" + decstr(r.site_jmp) + "\r\n");
            /* 把"装上了"和"写的字节是对的"分开验证：
             * cave 里应当是一条 5 或 14 字节的跳转；站点处应当是 E9 rel32。
             * 曾经因为只看"installed"而漏掉真正的问题。 */
            log("     site bytes: " +
                hexdump(reinterpret_cast<const unsigned char *>(r.site), 5) + "\r\n");
            log("     cave bytes: " +
                hexdump(reinterpret_cast<const unsigned char *>(r.cave),
                        mnp::kTrampolineSize) + "\r\n");
            log("     stub bytes: " +
                hexdump(reinterpret_cast<const unsigned char *>(s.stub), 8) + "\r\n");
        } else {
            log(std::string("[!] newhook FAIL: ") + s.name +
                " reason=" + std::string(r.reason) + "\r\n");
        }
    }

    /* ---- ④ gen     loop_decide 的"跳过循环"分支：原 jle 的目标 0x314285 ---- */
    {
        const std::uintptr_t skip = reinterpret_cast<std::uintptr_t>(module) + 0x00314285u;
        const mnp::addr var{reinterpret_cast<std::uintptr_t>(&mnp_ret_gen_loop_decide_skip)};
        if (mnp::write<std::uintptr_t>(var, skip)) {
            log("[i] newhook: gen/decide skip target = " + hexstr(skip) + "\r\n");
        } else {
            log("[!] newhook: cannot set gen/decide skip target\r\n");
        }
    }

    log("[i] newhook: installed " + decstr(static_cast<std::size_t>(installed)) +
        " / " + decstr(kSiteCount) + "\r\n");
    return installed;
}
