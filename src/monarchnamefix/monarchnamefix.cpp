/*
 * MonarchNameFix.dll  —  Europa Universalis IV 1.37.5
 * 统治者 / 继承人随机姓名分布修复
 *
 * 缺陷：加权表选取器用【有符号取模】(cdq; idiv) 处理带符号位的 32 位随机值，
 *       余数为负时线性权重扫描第一步即 break，恒返回该组第一个条目
 *       ⇒ 名字库第一号位被严重放大。
 *
 * 修法：把进入取模的随机值掩为非负且足够窄（21 位），使
 *       ① 余数必为正；② mode2 的 1000*rnd 不再 32 位溢出。
 *       余数仍均匀（偏差 < 权重和 / 2^21）。
 *
 * 本文件自包含：PE 解析、签名扫描、cave 分配、字节改写、护栏全部自己实现，
 * 不依赖 injector.hpp / byte_pattern 等任何第三方代码。
 *
 * 载入方式：放入 <游戏目录>\plugins\ ，由 EU4DLL 的 version.dll 自动 LoadLibraryW。
 * 关闭方式：在同目录放一个名为 MonarchNameFix.off 的文件。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 目标构建指纹（不符则不改写任何字节）                                  */
/* ------------------------------------------------------------------ */
#define IMG_BASE_EXPECT   0x140000000ull       /* ImageBase     */
#define IMG_SIZE_EXPECT   0x025E0000u          /* SizeOfImage   */
#define IMG_TS_EXPECT     1727949497u          /* TimeDateStamp */
#define MASK_BITS         21u
#define MASK_VALUE        0x001FFFFFu          /* 2^21-1 */

#define OFF_FILE_NAME     L"MonarchNameFix.off"
#define NOCONF_FILE_NAME  L"MonarchNameFix.noconf"
#define NOXFORM_FILE_NAME L"MonarchNameFix.noxform"
#define NOHOOK_FILE_NAME  L"MonarchNameFix.nohook"
#define NOMOD_FILE_NAME   L"MonarchNameFix.nomod"
#define LOGVERBOSE_FILE_NAME L"MonarchNameFix.logverbose"
#define LOG_FILE_NAME     L"MonarchNameFix.log"

/* ★ 诊断开关（靠 plugins\ 下的空文件触发，放全局避免热路径反复查文件）：
 *   .off     → 连日志都不开，完全不碰游戏（已在实机确认不崩）；
 *   .nohook  → 做完初始化就收工，不安装任何钩子。
 *             用途：把"我们的 DLL 在场并做了初始化"与"我们改了游戏的代码"分开。
 *   .noconf  → 不做"按文化取配置"那一步（只用 0xBF 标记判据）；
 *   .noxform → 连变换都不做，只记日志（钩子仍挂载、仍调用我们的函数）。
 * 排查完删掉开关文件即可，不用改代码。
 *
 * ★ 已随旧补丁表一并删除的开关（它们只对 prepare_one/hook_one 那条路径有意义）：
 *   .nop1/.nop2/.nop3/.nop4/.noorder/.nop7/.nop10/.only1/.farcave/.oldhook
 *   新钩子层是"要么全挂、要么不挂"，逐条开关已无对应物。 */
static int g_no_conf = 0;
static int g_no_xform = 0;
static int g_no_hook = 0;
/* ★ 分别跳过「生成阶段反转」的两半（.nop7 / .nop10），用于一轮定位崩溃元凶 */
/* ★ disp    ruler_name 诊断输出次数上限。
 *   2026-10-04：功能确认无误（form=2 分支已实机验证："姓名"连写形态被正确改成
 *   「姓 + 配置分隔符 + 名」，0xBF 同时被消除），**故默认关闭（0）**。
 *   日后要再查，把它改成 24 之类的正值即可重新打开。
 *
 * ★★★ 2026-10-05 重新打开（0 -> 2000）。
 *   起因：用户报告 SDA 的 shandong_culture 没有姓前名后，而实机日志证明
 *   BuildFullName_Impl（gen     exit_fallback/gen     loop_decide）**从来没有收到过 shandong_culture**：
 *   这个文化在存档里有 80 个已存在的君主/继承人，而**载入存档不会重新生成
 *   他们的姓名** —— 这类角色只经过显示期路径 CMonarch_GetFullName（= disp    ruler_name）。
 *   disp    ruler_name 的 dump 当时是关的 ⇒ 日志里连一行 `[d] disp    ruler_name` 都没有，无从判断它是
 *   没被调用、还是读了文化后放手了。配额给到 2000：够覆盖启动阶段所有统治者，
 *   每个文化都能留痕；量仍然有限（只在 disp    ruler_name 被调用时才写）。 */
static int g_disp_dump_left = 2000;

/* ★ 文化对象探针额度（2026-10-05 新增）。
 *   目的：确认 `CMonarch+0x60` 通过 culture_obj_ok 校验的那些对象里，
 *   "文化 ID" 到底在 `+0x90`（游戏 HandleRulerCulture 的读法）还是别的偏移，
 *   以及 `+0x130` 那个候选串是什么。
 *   只在诊断额度内打印，且只在**已通过校验**的对象上打印 ⇒ 输出量很小。 */
static int g_disp_cultprobe_left = 64;

/* ★ "无姓可排"的独立留痕额度（2026-10-05 新增）。
 *   用途：这条分支**不受 g_disp_dump_left 配额保护**，必须在配额耗尽后
 *   仍然能被看见 —— 否则"判定退化"这件事在日志里没有任何痕迹。
 *   （另一条同类的 `g_disp_form2_seen_left` 已随 form2 的移除而删除：
 *     0xBF 形态现在一律原样返回，不再有"折叠"分支可记。） */
static int g_disp_nosur_seen_left  = 32;

/* ★ 2026-10-06：「王朝对象可疑」的留痕额度（"垃圾字节"防线）。
 *   正常情况应为 0 —— 一旦出现，说明读到了不属于该字段的字节。
 *   （原先这里还有 `g_disp_regent_seen_left`，随"摄政期不重排"那两道守卫
 *     一起撤除了：用户实测确认摄政期间姓名本来就正常显示。） */
static int g_disp_baddyn_seen_left = 32;

/* ==================================================================== */
/* 运行时日志详略：默认「发布模式」——只留启动/安装/错误/心跳/崩溃回捞    */
/* ==================================================================== */
/* 2026-10-06 新增（用户计划发布更新）。
 *
 * 为什么需要它：调试期的"每种文化 / 每个 tag / 每次新增"留痕在实际游玩时
 *   会写出几万行（实测 AHR 一个 tag 就 796 行），既拖慢日志、也让真正要看
 *   的启动与错误信息被淹掉。
 *
 * 约定（与已有的 .noconf / .noxform / .nomod 同一套机制）：
 *   · 默认           = 发布模式  ⇒ 内测留痕**全部不打**
 *   · 放一个空文件    plugins\MonarchNameFix.logverbose  ⇒ 恢复内测留痕
 *
 * ★ 哪些**永远**照打（不受此开关影响）：
 *     启动/安装横幅（[start]、安装结果、文化配置扫描结果）
 *     错误与异常（[!]、[!!!]、站点异常、王朝对象可疑、带「¿」跳过、摄政/空位跳过）
 *     心跳（[hb]）与崩溃回捞、站点计数
 *   —— 这些是"出问题时要看的东西"，一个都不能省。 */
static int g_log_verbose = 0;        /* 1 = 内测留痕开启（.logverbose 存在） */

/* ★ 2026-10-05 用户决定：**名字里带「¿」标记的统治者一律不碰**（保守降级）。
 *   这两条守卫必须**无条件留痕**（不受 g_disp_dump_left 配额保护）：
 *   否则"补丁没介入"与"补丁介入但改坏了"在日志里长得一样，
 *   而这两种情况的排查方向完全相反。
 *   g_mark_skip_left 只限制"详细行"的条数，计数本身不封顶。 */
static long long g_mark_skip_n   = 0;     /* 累计跳过的次数（不封顶） */
static int       g_mark_skip_left = 64;   /* 前 64 次打详细行（含字节位置） */

/* ★ 2026-10-05 删除 `g_disp_probe` 与 `g_no_surn_len`（用户批准：A2+C 一起做）。
 *   `g_disp_probe` 是"把 disp    ruler_name 结果强行写成 @ZZZ@"的**杀伤性探针**，
 *   2026-10-04 已由实机完成使命（国家选取界面出现 @ZZZ@ ⇒ 确证 CMonarch_GetFullName
 *   是统治者名字的显示路径之一），此后一直恒为 0 却仍留在生产路径上
 *   （一次 `if` 判断 + 一段永不执行的死代码）。
 *   `g_no_surn_len` 更早已无任何使用，且与前者挤在同一行声明。
 *   ⇒ 两者一并移除；disp    ruler_name 里对应的 `if (g_disp_probe) {...}` 块也已删除。
 *   说明：disp    ruler_name 与显示路径的关系此后由 `[i] disp    ruler_name TAG`（每国一条）与
 *   `disp    ruler_name done` 计数持续记录，不再需要杀伤性探针。 */

/* ★ disp    ruler_name 诊断用：上一个被打过 TAG 行的国家 tag（同一 tag 只打一条，避免刷屏）。
 *   用途见 p8_monarch_reorder 里的 "disp    ruler_name TAG" 注释：回答
 *   "某个国家的统治者到底有没有被这个显示路径处理过"。 */
static char g_disp_last_tag[4] = { 0, 0, 0, 0 };

/* ------------------------------------------------------------------ */
/* 极小日志（只用 kernel32，避免 loader lock 下加载新库）                */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* 极小日志（只用 kernel32，避免 loader lock 下加载新库）                */
/* ------------------------------------------------------------------ */
/* ★★★ 2026-10-05 为「长时间运行稳定性测试」改造。四个目标：
 *
 *  ① **逐行原子写入** —— 旧实现每个片段一次 WriteFile（一行要写十几次），
 *     崩溃时必然留下半行，多线程还会交错。现在攒进线程局部缓冲，
 *     遇到 '\n' 才**一次 WriteFile 写完整行** ⇒ 文件里只有完整行。
 *
 *  ② **内存环形缓冲（回捞区）** —— 最后 MNP_RING_LINES 行同时留在内存。
 *     进程"突然消失"（游戏自身 AV / 被强杀）时来不及再写文件，
 *     但退出路径（log_ring_dump）或下次启动还能把它捞出来。
 *
 *  ③ **行号 + 时间戳** —— 每行前缀 `#序号 t=毫秒`。
 *     序号连续 ⇒ 日志没丢行；跳变 ⇒ 有行没写下去（或被别的线程抢了槽位）。
 *     时间戳是 GetTickCount()（进程启动以来毫秒），可算两次事件的间隔。
 *
 *  ④ **心跳** —— 每 MNP_HEARTBEAT_LINES 行插一条（见 log_heartbeat），
 *     含存活时长、已写行数、线程 ID 与 9 个站点的累计调用次数。
 *     长时间跑时，看日志尾部就知道"最近还在跑什么"。
 *
 * ★ 不引入 CRT：本 DLL 在 loader lock 期间运行，加载新库有死锁风险。
 *   全程只用 kernel32；CreateThread 也走 GetProcAddress 动态取（见 log_start_thread）。
 */
#define MNP_LINE_MAX        2048u   /* 单行上限（超长截断并标记） */
#define MNP_RING_LINES      256u    /* 内存里保留的最近行数（回捞用） */
#define MNP_HEARTBEAT_LINES 500u    /* 每多少行插一条心跳 */
#define MNP_TSLOTS          16      /* 线程局部行缓冲槽位数 */

static WCHAR  g_dir[MAX_PATH];       /* 本 DLL 所在目录 */
static HANDLE g_log = INVALID_HANDLE_VALUE;
static int    g_log_ready = 0;       /* 日志系统初始化完成（之后才走逐行缓冲） */
static uint64_t g_line_no = 0;       /* 累计落盘行数（= 每行的 #序号） */
static uint32_t g_beat_left = MNP_HEARTBEAT_LINES;
static uint32_t g_start_ms = 0;      /* 启动时刻（GetTickCount），心跳里算存活时长 */

/* 线程局部行缓冲：动态加载的 DLL 里 __declspec(thread) 不可靠，
 * 所以用固定槽位数组按线程 ID 取模分配。槽位冲突时**抢占**（被抢者下次重新申请），
 * 最坏情况是丢几行，但绝不会写坏数据 —— 有意的取舍：日志绝不能拖垮游戏。 */
struct mnp_line_buf {
    char  b[MNP_LINE_MAX];
    DWORD n;                     /* 已攒字节数 */
    DWORD tid;                   /* 占用者；0 = 空闲 */
};

static mnp_line_buf g_lb[MNP_TSLOTS];

/* 内存环形缓冲（最后 N 行），供崩溃回捞 */
static char    *g_ring       = NULL;
static uint32_t g_ring_seg   = 0;    /* 每行槽位大小 */
static uint32_t g_ring_next  = 0;
static uint32_t g_ring_count = 0;

/* ---- 站点调用计数（心跳与退出时打印，答"崩之前最后在跑什么"）---- */
#define MNP_NSTAT 14

static const char *const g_stat_name[MNP_NSTAT] = {
    "modfix/pick_idx", "modfix/pick_cult", "modfix/pick_modidx",
    "gen/entry",       "gen/decide",       "gen/surn_len",
    "gen/reorder",     "gen/exit",         "disp/ruler",
    "hook/exception",                      /* ★ 被 SEH 接住的异常（关键指标，应为 0） */
    "lazy/bind",       "cult/miss",        "mark/skip",  "misc/other"
};

static volatile LONG64 g_stat[MNP_NSTAT];

enum {
    ST_MODFIX_IDX = 0, ST_MODFIX_CULT, ST_MODFIX_MODIDX,
    ST_GEN_ENTRY, ST_GEN_DECIDE, ST_GEN_SURNLEN, ST_GEN_REORDER, ST_GEN_EXIT,
    ST_DISP, ST_EXCEPTION, ST_LAZYBIND, ST_CULTMISS, ST_MARKSKIP, ST_OTHER
};

static void stat_bump(int i)
{
    if (i >= 0 && i < MNP_NSTAT) InterlockedIncrement64(&g_stat[i]);
}

static HANDLE g_log_thread = NULL;
static volatile LONG g_log_stop = 0;

static void log_flush_line(mnp_line_buf *lb);   /* 前置声明 */
static void log_str(const char *s);             /* 前置声明 */
static void log_heartbeat(void);                /* 前置声明 */

static void log_open(void)
{
    WCHAR path[MAX_PATH];
    lstrcpynW(path, g_dir, MAX_PATH);
    lstrcatW(path, LOG_FILE_NAME);

    /* ★ 每次启动【清空】旧日志（用户要求，2026-10-04）：
     *   先前是纯追加，日志会一轮轮累积，看"这一次"发生了什么很费劲。
     *   做法：先用 CREATE_ALWAYS 截断一次并立刻关闭，再按原来的 APPEND 模式
     *   长期持有句柄 —— 这样既有"每启动一次一个干净文件"，又保留了
     *   "安装之后（第一次变换、懒绑定、崩溃前）仍能写进去"的能力。
     *   （若改成全程 CREATE_ALWAYS 持有句柄，就退回到当初那个"崩溃前一个字都没有"的坑。） */
    {
        HANDLE htrunc = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (htrunc != INVALID_HANDLE_VALUE) CloseHandle(htrunc);
    }

    g_log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    /* ★ 内存环形缓冲（崩溃回捞用）。分配失败不影响功能（g_ring 为 NULL 时整体跳过）。 */
    if (!g_ring) {
        g_ring_seg = MNP_LINE_MAX;
        g_ring = (char *)VirtualAlloc(NULL,
                                      (SIZE_T)MNP_RING_LINES * g_ring_seg,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_ring_next = 0;
        g_ring_count = 0;
    }
    g_start_ms  = GetTickCount();
    g_line_no   = 0;
    g_beat_left = MNP_HEARTBEAT_LINES;
    g_log_ready = 1;                    /* 之后 log_str 才走逐行缓冲 */
}

/* ★★★ 2026-10-06 修复「多线程日志互相踩」。
 *
 * 病象（实机日志抓到的）：
 *     "  .>..KN.vf[t=4610] [d] gen/fallback in  ... s=\"\""   ← 行首混入乱码
 *     "piedmontese[i] CULTRAW disp: n=104 ... \"\""            ← 前半截是别的行
 *   即两条行的片段被拼到了一起。
 *
 * 根因：槽位用 `tid % MNP_TSLOTS`（16 个）挑，而游戏线程远多于 16 个。
 *   **两个线程映射到同一槽位时**，后到的会把先到者**攒了一半的缓冲**抢走
 *   （原来 `if (lb->tid != tid) { lb->tid = tid; lb->n = 0; }` 直接抢占），
 *   于是先到者剩下的片段被追加到后到者的行尾 —— 两条行混在一起。
 *   更糟的是抢占发生在**行中间**，所以连"哪些字节属于哪一行"都无法还原。
 *
 * 修法（两条，缺一不可）：
 *   ① **槽位只在"行首"才允许抢占**：若该槽位攒着半个未落盘的行（`n > 0`），
 *      就往后找一个空闲或同样处于行首的槽位；全都被占则退化到槽位 0
 *      （宁可截断，绝不再拼接）。
 *   ② 抢占/占用都用 `InterlockedCompareExchange` 做**原子**领取，
 *      避免两个线程同时判空、同时写入同一个槽。
 *
 * ★ 注意：这里只保证"不把两条行混在一起"。真正落盘的仍是**每行一次 WriteFile**。 */
static mnp_line_buf *log_buf(void)
{
    DWORD tid = (DWORD)GetCurrentThreadId();
    int i;

    /* 先找自己的槽位（已占用且是本人） */
    for (i = 0; i < MNP_TSLOTS; i++) {
        if (g_lb[i].tid == tid) return &g_lb[i];
    }
    /* 再找空闲槽（tid==0）或"处于行首"的槽（n==0，可以安全接管） */
    for (i = 0; i < MNP_TSLOTS; i++) {
        LONG prev = InterlockedCompareExchange((volatile LONG *)&g_lb[i].tid,
                                               0, 0);          /* 只读一下 */
        if (prev == 0 || g_lb[i].n == 0) {
            /* 原子领取：只有把它从原状态换成 tid 的那个线程才真正拥有它 */
            if (InterlockedCompareExchange((volatile LONG *)&g_lb[i].tid,
                                           (LONG)tid, prev) == prev) {
                g_lb[i].n = 0;                                  /* ★ 领取后清零，绝不拼接 */
                return &g_lb[i];
            }
        }
    }
    /* 全部被占且都在行中间 ⇒ 退化到槽位 0（只影响这一行，不会污染别人的行） */
    return &g_lb[0];
}

/* 把一行（以 '\n' 结尾）原子写出，并放进环形缓冲 */
static void log_flush_line(mnp_line_buf *lb)
{
    DWORD w = 0;
    if (lb->n == 0) return;

    if (g_log != INVALID_HANDLE_VALUE) {
        WriteFile(g_log, lb->b, lb->n, &w, NULL);   /* ★ 一次写完整行 */
    }
    if (g_ring) {
        char *dst = g_ring + (size_t)g_ring_next * g_ring_seg;
        uint32_t k, m = lb->n;
        if (m > g_ring_seg - 1) m = g_ring_seg - 1;
        for (k = 0; k < m; k++) dst[k] = lb->b[k];
        dst[m] = 0;
        g_ring_next = (g_ring_next + 1u) % MNP_RING_LINES;
        if (g_ring_count < MNP_RING_LINES) g_ring_count++;
    }
    g_line_no++;
    lb->n = 0;

    if (g_beat_left > 0 && --g_beat_left == 0) {
        g_beat_left = MNP_HEARTBEAT_LINES;
        log_heartbeat();
    }
}

static void log_str(const char *s)
{
    mnp_line_buf *lb;
    if (g_log == INVALID_HANDLE_VALUE) return;
    if (!g_log_ready) {                 /* 日志系统尚未初始化 ⇒ 退回直写 */
        DWORD n = 0;
        while (s[n]) n++;
        WriteFile(g_log, s, n, &n, NULL);
        return;
    }
    lb = log_buf();
    while (*s) {
        if (lb->n >= MNP_LINE_MAX - 2) {          /* 超长 ⇒ 截断标记后强制落盘 */
            lb->b[lb->n++] = '~';
            lb->b[lb->n++] = '\n';
            log_flush_line(lb);
            continue;
        }
        lb->b[lb->n++] = *s;
        if (*s == '\n') log_flush_line(lb);
        s++;
    }
}

/* ---- 行前缀：`#序号 t=毫秒 ` ----
 *   #序号  = 落盘行计数（连续 ⇒ 没丢行；跳变 ⇒ 有行没写下去，值得追）
 *   t=毫秒 = GetTickCount()，进程启动以来的毫秒数（算事件间隔用） */
static void log_stamp(void)
{
    char b[48];
    char *p = b;
    uint64_t v = g_line_no + 1;        /* 本行将要占用的序号（flush 时才++） */
    uint32_t ms = GetTickCount();

    *p++ = '#';
    {   char tmp[24]; int j = 0;
        if (v == 0) tmp[j++] = '0';
        while (v) { tmp[j++] = (char)('0' + (v % 10)); v /= 10; }
        while (j > 0) *p++ = tmp[--j];
    }
    *p++ = ' '; *p++ = 't'; *p++ = '=';
    {   char tmp[16]; int j = 0;
        if (ms == 0) tmp[j++] = '0';
        while (ms) { tmp[j++] = (char)('0' + (ms % 10)); ms /= 10; }
        while (j > 0) *p++ = tmp[--j];
    }
    *p++ = ' '; *p = 0;
    log_str(b);
}

static void log_hex(uint64_t v)
{
    char buf[19];
    char *p = buf + 18;
    *p = 0;
    if (v == 0) { *--p = '0'; }
    while (v) {
        unsigned d = (unsigned)(v & 0xF);
        *--p = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    log_str(p);
}

static void log_dec(uint32_t v)
{
    char buf[12];
    char *p = buf + 11;
    *p = 0;
    if (v == 0) *--p = '0';
    while (v) { *--p = (char)('0' + (v % 10)); v /= 10; }
    log_str(p);
}

#define LOGS(s)   log_str(s)
#define LOGH(v)   log_str("0x"); log_hex((uint64_t)(v))
#define LOGD(v)   log_dec((uint32_t)(v))
#define LOGNL()   log_str("\r\n")

/* ------------------------------------------------------------------ */
/* 心跳：每 MNP_HEARTBEAT_LINES 行插一条，答"还活着吗 / 在跑什么"        */
/* ------------------------------------------------------------------ */
static void log_heartbeat(void)
{
    uint32_t up = GetTickCount() - g_start_ms;
    int i;

    log_stamp();
    LOGS("[hb] alive up=");  LOGD(up / 1000u); LOGS("."); LOGD((up % 1000u) / 100u);
    LOGS("s lines=");        LOGD((uint32_t)g_line_no);
    LOGS(" tid=");           LOGD(GetCurrentThreadId());
    LOGS("\r\n");

    log_stamp();
    LOGS("[hb] 站点计数:");
    for (i = 0; i < MNP_NSTAT; i++) {
        if (g_stat[i] == 0) continue;
        LOGS(" "); LOGS(g_stat_name[i]); LOGS("="); LOGD((uint32_t)g_stat[i]);
    }
    LOGS("\r\n");
}

/* ------------------------------------------------------------------ */
/* 退出/异常前的回捞：把内存环形缓冲的最后若干行写回文件                 */
/* ------------------------------------------------------------------ */
static void log_ring_dump(const char *why)
{
    uint32_t i, start;
    DWORD w = 0;

    if (!g_ring || g_ring_count == 0 || g_log == INVALID_HANDLE_VALUE) return;

    {   char hdr[96]; DWORD k = 0;
        hdr[k++] = '\n'; hdr[k++] = '=';
        while (*why && k < sizeof(hdr) - 6) hdr[k++] = *why++;
        hdr[k++] = '='; hdr[k++] = '\n';
        WriteFile(g_log, hdr, k, &w, NULL);
    }
    start = (g_ring_count < MNP_RING_LINES) ? 0u : g_ring_next;
    for (i = 0; i < g_ring_count; i++) {
        const char *s = g_ring + (size_t)((start + i) % MNP_RING_LINES) * g_ring_seg;
        DWORD n = 0, got = 0;
        while (s[n]) n++;
        if (n) WriteFile(g_log, s, n, &got, NULL);   /* 环形里已是完整行 */
    }
    {   const char *end = "=== 回捞结束 ===\n"; DWORD n = 0;
        while (end[n]) n++;
        WriteFile(g_log, end, n, &w, NULL);
    }
}

/* 把各线程攒着没落盘的部分补完（保证文件里只有完整行） */
static void log_flush_all(void)
{
    int i;
    for (i = 0; i < MNP_TSLOTS; i++) {
        if (g_lb[i].tid != 0 && g_lb[i].n > 0) {
            if (g_lb[i].n < MNP_LINE_MAX - 1) g_lb[i].b[g_lb[i].n++] = '\n';
            log_flush_line(&g_lb[i]);
        }
    }
    if (g_log != INVALID_HANDLE_VALUE) FlushFileBuffers(g_log);
}

/* ==================================================================== */
/* 心跳后台线程 —— 长时间稳定性测试的"黑匣子"                            */
/* ==================================================================== */
/* 为什么必须有它：长时间跑的时候，崩溃/卡死的时刻往往**没有日志产生**
 *   （比如游戏主循环死锁、或崩在一个从不打日志的地方）。
 *   有了它，日志尾部会持续出现 `[hb]`，于是：
 *     · 最后一条 [hb] 的时间 ≈ 还活着的最后时刻 ⇒ 能框定崩溃区间；
 *     · `lines=` 长时间不变 ⇒ **卡死**（而不是崩溃）；
 *     · `tid=` 会显示是哪个线程在跑心跳。
 *
 * 退出/异常时由 log_crash_tail() 把环形缓冲回捞出来。
 */
#define MNP_HB_INTERVAL_MS 30000u   /* 30 秒一条心跳 */

/* 心跳行的小工具（刻意不用 CRT 的 sprintf：loader lock 下不碰 CRT） */
static void put(char *b, char **pp, const char *s, size_t cap)
{
    while (*s && (size_t)(*pp - b) < cap - 2) *(*pp)++ = *s++;
}

static void putd(char *b, char **pp, uint64_t v, size_t cap)
{
    char t[24];
    int j = 0;
    if (v == 0) t[j++] = '0';
    while (v) { t[j++] = (char)('0' + (v % 10)); v /= 10; }
    while (j > 0 && (size_t)(*pp - b) < cap - 2) *(*pp)++ = t[--j];
}

typedef void (WINAPI *pfn_Sleep_t)(DWORD);
static pfn_Sleep_t g_pfn_sleep = NULL;      /* 动态取的 Sleep（见 log_start_hb_thread） */

static DWORD WINAPI log_hb_thread(LPVOID param)
{
    uint64_t last_lines = 0;
    int      stall_n    = 0;
    (void)param;

    for (;;) {
        DWORD w = 0;
        if (InterlockedCompareExchange(&g_log_stop, 0, 0) != 0) break;

        /* ★ 心跳用**直写**（绕过逐行缓冲）：本线程独立于游戏线程，
         *   直写能保证"即使游戏线程卡在某个锁上，心跳照样落盘"。 */
        if (g_log != INVALID_HANDLE_VALUE) {
            char b[320];
            char *p = b;
            uint32_t up = GetTickCount() - g_start_ms;

            put(b, &p, "[hb] alive up=", sizeof(b));
            putd(b, &p, up / 1000u, sizeof(b));
            put(b, &p, "s lines=", sizeof(b));
            putd(b, &p, g_line_no, sizeof(b));
            if (g_line_no == last_lines) {
                stall_n++;
                put(b, &p, " STALL=", sizeof(b));
                putd(b, &p, (uint64_t)stall_n, sizeof(b));
                put(b, &p, " x30s(无新日志=疑似卡死)", sizeof(b));
            } else {
                stall_n = 0;
            }
            last_lines = g_line_no;
            put(b, &p, " tid=", sizeof(b));
            putd(b, &p, GetCurrentThreadId(), sizeof(b));
            put(b, &p, "\n", sizeof(b));
            WriteFile(g_log, b, (DWORD)(p - b), &w, NULL);
            FlushFileBuffers(g_log);
        }
        if (g_pfn_sleep) g_pfn_sleep(MNP_HB_INTERVAL_MS);
        else break;                          /* 拿不到 Sleep ⇒ 不空转烧 CPU */
    }
    return 0;
}

/* 用 GetProcAddress 动态取 CreateThread/Sleep —— 不新增导入依赖
 * （本 DLL 在 loader lock 期间运行，能少一个导入就少一分风险）。 */
static void log_start_hb_thread(void)
{
    typedef HANDLE (WINAPI *pfn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                              LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    pfn_CreateThread fn;
    DWORD tid = 0;

    if (!k32 || g_log == INVALID_HANDLE_VALUE) return;
    g_pfn_sleep = (pfn_Sleep_t)(void *)GetProcAddress(k32, "Sleep");
    fn = (pfn_CreateThread)(void *)GetProcAddress(k32, "CreateThread");
    if (!fn) { LOGS("[!] 心跳线程未启动（拿不到 CreateThread）\r\n"); return; }
    g_log_thread = fn(NULL, 0, log_hb_thread, NULL, 0, &tid);
    if (g_log_thread) {
        LOGS("[i] 心跳线程已启动 tid="); LOGD(tid);
        LOGS(" 间隔="); LOGD(MNP_HB_INTERVAL_MS / 1000u); LOGS("s\r\n");
    } else {
        LOGS("[!] 心跳线程创建失败\r\n");
    }
}

/* ==================================================================== */
/* 站点异常守卫（2026-10-05，为长时间稳定性测试新增）                    */
/* ==================================================================== */
/* 作用：每个 handler 的业务调用都包在 SEH 里。一旦站点内部抛异常：
 *   · 立刻写一条 `[!!!] 站点异常` 行，含**站点名 + 异常码 + 异常地址**；
 *   · 统计累加（心跳与退出时会看到 hook/exception 计数 ≠ 0）。
 *
 * 为什么有效：崩溃现场最难的是"知道崩在哪个站点"。以前只能靠日志最后一行猜；
 *   现在异常一发生就打点，即使随后进程仍被游戏自己终结，日志里也留下了确切位置。
 *
 * ★ 为什么守卫放在 handler **里面**而不是外面：
 *   handler 的入参 `r` 是栈上的 reg_pack，`__try` 在同一个函数里能正常访问它；
 *   放到 trampoline（汇编）里就要另写一套栈回溯，风险更大。
 * ★ 不吞异常：`__except` 里记完日志后 `return`，让 handler 安全退出，
 *   外层游戏代码继续跑 —— 对"顺序没改"这种降级是可接受的，
 *   比整个进程崩掉好，而且日志会明确记下发生过。 */

/* ★ 用法（每个业务调用外面包一层）：
 *
 *     MNP_SITE_GUARD_BEGIN
 *         ...业务代码...
 *     MNP_SITE_GUARD_END("gen/reorder")
 *
 * ★ MSVC 限制：`__except(...)` 的括号**只能是常量表达式**，不能调函数
 *   （所以不能写 `__except (mnp_site_except(...))`）。
 *   做法：`__except` 里只写 EXCEPTION_EXECUTE_HANDLER，
 *   真正的记录放在 `__except` 之后 —— 用一个 volatile 标志区分
 *   "正常走完" 与 "异常跳过来的"，两种路径都会经过同一处记录代码。 */
static volatile LONG g_site_fault = 0;     /* 本次调用是否发生了异常 */
static unsigned long  g_site_fault_code = 0;
static uint64_t       g_site_fault_addr = 0;

#define MNP_SITE_GUARD_BEGIN                     \
    g_site_fault = 0;                            \
    __try {

/* site 必须是字符串字面量 */
#define MNP_SITE_GUARD_END(site)                                              \
    } __except (g_site_fault_code = GetExceptionCode(),                       \
                g_site_fault_addr = (uint64_t)(uintptr_t)                     \
                    (GetExceptionInformation()                                \
                        ? GetExceptionInformation()->ExceptionRecord          \
                              ->ExceptionAddress : 0),                        \
                g_site_fault = 1,                                             \
                EXCEPTION_EXECUTE_HANDLER) {                                  \
    }                                                                         \
    if (g_site_fault) {                                                       \
        stat_bump(ST_EXCEPTION);                                              \
        log_stamp();                                                          \
        LOGS("[!!!] 站点异常 site="); LOGS(site);                             \
        LOGS(" code=0x"); log_hex((uint64_t)g_site_fault_code);               \
        LOGS(" addr=0x"); log_hex(g_site_fault_addr);                         \
        LOGS("（已接住，本站点本次放弃）\r\n");                                \
    }

/* 崩溃/退出收尾：停机 + 冲刷 + 回捞最后若干行。
 * 由 log_crash_filter（未处理异常）或 DllMain(DETACH) 调用。 */
static void log_crash_tail(const char *why)
{
    InterlockedExchange(&g_log_stop, 1);
    log_flush_all();
    log_ring_dump(why);
    if (g_log != INVALID_HANDLE_VALUE) FlushFileBuffers(g_log);
}

/* 未处理异常过滤器：写标记 + 回捞（不做 minidump —— 那要 dbghelp，风险更大）。 */
static LONG WINAPI log_crash_filter(EXCEPTION_POINTERS *ep)
{
    DWORD code = 0;
    uint64_t addr = 0;
    if (ep && ep->ExceptionRecord) {
        code = ep->ExceptionRecord->ExceptionCode;
        addr = (uint64_t)(uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    }
    if (g_log != INVALID_HANDLE_VALUE) {
        char b[160];
        char *p = b;
        const char *s = "\n[!!!] 未处理异常 code=";
        while (*s) *p++ = *s++;
        {   /* code 十六进制 */
            char t[16]; int j = 0;
            uint32_t v = code;
            if (v == 0) t[j++] = '0';
            while (v) { unsigned d = v & 0xF; t[j++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v >>= 4; }
            while (j > 0) *p++ = t[--j];
        }
        s = " addr=0x";
        while (*s) *p++ = *s++;
        {   char t[24]; int j = 0;
            uint64_t v = addr;
            if (v == 0) t[j++] = '0';
            while (v) { unsigned d = (unsigned)(v & 0xF); t[j++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v >>= 4; }
            while (j > 0) *p++ = t[--j];
        }
        s = " (崩溃，回捞最后日志)\n";
        while (*s) *p++ = *s++;
        {   DWORD w = 0;
            WriteFile(g_log, b, (DWORD)(p - b), &w, NULL);
        }
    }
    log_crash_tail("崩溃前最后若干行");
    return EXCEPTION_EXECUTE_HANDLER;   /* 让进程按原样死掉，不吞异常 */
}


static void log_wide(const WCHAR *s)
{
    char buf[2];
    DWORD n = 0;
    buf[1] = 0;
    if (g_log == INVALID_HANDLE_VALUE) return;
    for (; *s; s++) {
        WCHAR c = *s;
        buf[0] = (c >= 32 && c < 127) ? (char)c : '.';
        WriteFile(g_log, buf, 1, &n, NULL);
    }
}
#define LOGW(s)   log_wide(s)

static int memcmp_local(const char *a, const char *b, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) if ((unsigned char)a[i] != (unsigned char)b[i]) return 1;
    return 0;
}


/* ------------------------------------------------------------------ */
/* 签名（十六进制 + ?? 通配，空格分隔）                                  */
/* ------------------------------------------------------------------ */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}



/* gen     exit_fallback/P5 的姓名顺序变换与动态桩构造器：单一事实来源（DLL 与三个测试共用） */
#include "nameorder.h"
#include "cultureconfig.h"
/* 把已载入的配置整份列进日志（DLL 与离线核对工具共用同一份实现）。
 * ★ 放在这里而不是文化配置的加载段之后：cc_lazy_ready() 要用到它，
 *   而那个函数在文件前半段。 */
#include "cultureconfig_list.h"

/* ★★ 新钩子层（2026-10-05 改造，参照双字节补丁 EU4dll 的做法）
 *
 * 桩与变量的声明统一放在 stubs.hpp（带 extern "C" 保护）。
 * ★ 本文件已是 C++：若在此手写 `extern int mnp_install_new_hooks(...)`，
 *   MSVC 会按 C++ 规则修饰符号，而 install.cpp 导出的是 extern "C" 裸名，
 *   链接期必然 LNK2019。所以走头文件，不要手写。
 *
 *   站点 → 5 字节 E9 → cave（贴近 eu4.exe） → 14 字节 FF 25 → stubs.asm 里的桩
 *   桩末端 `push <retAddr>; ret` 回到站点之后。
 */
#include "stubs.hpp"
#include "reg_pack.hpp"

extern "C" {
int  mnp_install_new_hooks(void *module, unsigned char *cave, unsigned long cave_size);
void mnp_install_set_logger(void (*fn)(const char *));
/* install.cpp 定义；置 1 则跳过 modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx（.nomod 诊断开关） */
extern int mnp_skip_modfix;
/* install.cpp 定义；bit i ⇒ 跳过 kSites[i]（.noP1/.noP6/... 诊断开关） */
extern unsigned mnp_skip_mask;
}

/* 新钩子层的实测/安装入口（定义在本文件后面，靠近 do_fix） */
static void newhook_probe(uint8_t *mod);
static void newhook_probe_dll_base(HMODULE self);
static int  newhook_install(uint8_t *mod);

/* CAVE 跳板层的规划尺度：站点处最多写 5 字节 E9，绝对跳转最长 14 字节。
 * 声明与 C 侧必须一致（hooks.hpp 里也有同名常量）。 */
#define MNP_JMP_E9_LEN   5u
#define MNP_JMP_ABS_LEN  14u

/* 预判跳转会写几字节：与 hooks.hpp / hookmem.hpp 的判据逐字一致。
 * 这里用【有符号】比较 —— 原库 EU4dll 用无符号，导致"向后跳"一律被判成
 * 超范围、永远写 14 字节（我们在报告里记过这个 bug）。 */
static size_t mnp_jmp_len_for(uintptr_t site, uintptr_t dest)
{
    int64_t rel = (int64_t)(dest - (site + MNP_JMP_E9_LEN));
    return (rel >= (int64_t)INT32_MIN && rel <= (int64_t)INT32_MAX)
               ? MNP_JMP_E9_LEN
               : MNP_JMP_ABS_LEN;
}

/* ------------------------------------------------------------------ */
/* 模块内存区域：给文化对象指针做「明确边界 + SEH」双重校验，绝不野指针解引用 */
/* ------------------------------------------------------------------ */
static uint8_t *g_mod   = NULL;         /* eu4.exe 基址 */
static size_t   g_modsz = 0;            /* SizeOfImage  */
static cc_state_t g_cc;                 /* 文化配置状态 */

/* 配置加载的计数（定义在这里，因为懒绑定日志要用；加载逻辑在文件后半段） */
static uint32_t  g_cc_files = 0;          /* 读到的配置文件数 */
static uint32_t  g_cc_entries_n = 0;      /* 解析出的条目数 */
static uint32_t  g_cc_bound = 0;          /* 懒绑定成功后解析成对象指针的条目数 */

/* 可读性护栏。
 *
 * ★ 曾经这里把范围限死在 eu4.exe 镜像内（a<b 或 a-b>=SizeOfImage 一律拒绝）。
 *   那对"解引用游戏对象里的指针"是对的，但对**注册表**是致命的：
 *   文化注册表对象与它的节点都在**堆**上（0x18xxxxxxxx 一带），镜像之外，
 *   于是 cc_resolve 的每一次读取都被自己拒绝 ⇒ bound 恒为 0、
 *   64 次重试后 give up（实机日志："culture binding gave up after 64 tries"）。
 *
 *   现在只做最基本的合理性判断（非空、非内核空间、不溢出），
 *   真正的越界由调用处的 __try/__except（SEH）兜住 —— 这是只读操作，安全。 */
static int dll_region_ok(void *ctx, const void *p, size_t n)
{
    uintptr_t a = (uintptr_t)p;
    (void)ctx;
    if (!p || !n) return 0;
    if (a < 0x10000ull) return 0;                    /* 空页区，不可能有对象 */
    /* ★ 用户态上限是 0x00007FFFFFFFFFFF（47 位），不是 0x700000000000！
     *   写成后者会把**所有堆地址**都当成"内核空间"拒掉 —— 实测堆在
     *   0x1bb6b1f7d70，比 0x700000000000 大，于是文化注册表（在堆上）
     *   一个字节都读不到，bound 恒为 0。这正是 "culture binding gave up"
     *   的直接原因，而且它伪装成"护栏拒绝"（诊断里 dll_read 失败、
     *   绕过护栏直接读却成功、页属性是 MEM_COMMIT+PAGE_READWRITE）。 */
    if (a > 0x00007FFFFFFFFFFFull) return 0;         /* 用户态之上才是内核空间 */
    if (n > 0x1000000ull) return 0;                  /* 荒唐的长度 */
    return 1;
}

/* ★ 地址是否落在 eu4.exe 映像 [g_mod, g_mod + g_modsz) 内。
 *   与 dll_region_ok 的分工：dll_region_ok 是"能不能安全读"（对堆对象放行），
 *   本函数是"是不是游戏自己的代码/数据"（用于校验虚表与函数指针）。
 *   堆上的随机垃圾不可能落进映像范围，所以它正好用来识别
 *   "这个指针看起来像不像一个真正的 C++ 对象"。 */
static int mnp_image_addr_ok(const void *p)
{
    uintptr_t a = (uintptr_t)p;
    uintptr_t base;
    size_t    size;

    /* ★ 兜底：本补丁本来就绑定在固定 ImageBase 的 eu4.exe 上
     *   （IMG_BASE_EXPECT / IMG_SIZE_EXPECT，见文件开头的版本断言）。
     *   万一 g_mod/g_modsz 还没被填上，用编译期常量继续判 ——
     *   否则 disp    ruler_name 会因为"映像未知"而整体失效，那是最糟的失败方式（静默全灭）。 */
    if (g_mod && g_modsz) {
        base = (uintptr_t)g_mod;
        size = (size_t)g_modsz;
    } else {
        base = (uintptr_t)IMG_BASE_EXPECT;
        size = (size_t)IMG_SIZE_EXPECT;
    }
    if (a < base) return 0;
    if (a - base >= size) return 0;
    return 1;
}

/* 受保护读：先做模块范围校验，再包 SEH（双保险） */
static int dll_read(void *ctx, const void *p, unsigned n, uint64_t *out)
{
    uint64_t v = 0;
    (void)ctx;
    *out = 0;
    if (n != 1 && n != 2 && n != 4 && n != 8) return 0;
    if (!dll_region_ok(NULL, p, n)) return 0;
    __try {
        if (n == 1)      v = *(const volatile uint8_t *)p;
        else if (n == 2) v = *(const volatile uint16_t *)p;
        else if (n == 4) v = *(const volatile uint32_t *)p;
        else             v = *(const volatile uint64_t *)p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    *out = v;
    return 1;
}

/* ------------------------------------------------------------------ */
/* 懒绑定（第一次变换调用时）                                            */
/* ------------------------------------------------------------------ */
/* 安装期（DllMain）**文化数据还没加载**，此刻解析「文化名 → 对象」一条都绑不上；
 * 更糟的是这份空结果会被 cc_lookup 当成"已解析、无命中"**永久缓存**。
 * 所以绑定推迟到第一次真正要用配置的时候 —— gen     exit_fallback 变换入口（见 p4_fallback_reorder）。
 * 注册表单例本身就是游戏惰性创建的（sub_1401AFD00：`if (!qword_14242B9F8) new ...`），
 * 安装期它还是 0，这正是实机日志里 bound=0 的直接原因。
 * 详见 cultureconfig.h 的 cc_lazy_bind 注释。 */
static int g_cc_lazy_state = 0;      /* 0=未绑定 1=已绑定 -1=已放弃 */
static int g_cc_lazy_tries = 0;

/* ------------------------------------------------------------------ */
/* 热路径限量日志                                                        */
/* ------------------------------------------------------------------ */
/* 用途：定位"实机崩溃发生在第几次变换 / 绑定到底成功没有"。
 * 为什么必须限量：变换是热路径，日志是每次 write 落盘；限量避免刷爆磁盘与拖慢游戏。
 * 排查已完成 ⇒ 默认 0（关闭）。要再排查时改成 300 等正数即可。 */
#define CCFG_TRACE_TIMES 0
static int g_trace_left = CCFG_TRACE_TIMES;
static int g_gen_exit_calls = 0;

/* ★ 2026-10-05 新增：把一段字节打成 **hex**（空格分隔）。
 *
 * 为什么必须要有它（血泪）：
 *   `log_bytes()` 把不可打印字节一律打成 `.` —— 而这个游戏的自定义双字节编码
 *   里 CJK 字符**全是不可打印**的，于是日志里 "名" 和 "姓" 长得一模一样（都是点），
 *   连"哪个字节是 0xBF"都只能靠 `~` 猜。
 *   排查"0xBF 形态下姓名乱码"时，没有真实字节就只能在长度上反复推演，
 *   而长度之间是**互相矛盾**的（olen 与实际写入字节数不一致）⇒ 推不出结论。
 *   ⇒ 直接把字节摆出来，一眼就能看出边界在哪。 */
static void log_hex(const unsigned char *p, uint32_t n)
{
    static const char H[] = "0123456789ABCDEF";
    char buf[3];
    uint32_t i;
    DWORD w = 0;
    if (g_log == INVALID_HANDLE_VALUE) return;
    buf[2] = 0;
    for (i = 0; i < n && i < 48; i++) {
        unsigned char c = p[i];
        buf[0] = H[c >> 4];
        buf[1] = H[c & 15];
        WriteFile(g_log, buf, 2, &w, NULL);
        WriteFile(g_log, " ", 1, &w, NULL);
    }
}

/* 把一段字节安全地写成可见文本（非可打印字节写 .），并显示 0xBF 标记 */
static void log_bytes(const unsigned char *p, uint32_t n)
{
    char buf[2];
    uint32_t i;
    DWORD w = 0;
    if (g_log == INVALID_HANDLE_VALUE) return;
    buf[1] = 0;
    for (i = 0; i < n && i < 96; i++) {
        unsigned char c = p[i];
        buf[0] = (c == 0xBF) ? '~' : ((c >= 32 && c < 127) ? (char)c : '.');
        WriteFile(g_log, buf, 1, &w, NULL);
    }
}

/* ★ 2026-10-05 删除 `safe_cstr()`（用户批准）。
 *   它原本是"只读一个疑似 C 字符串"的防崩诊断助手，最后一个调用点是
 *   `+0x130` 那条候选串诊断 —— 而那个偏移基于**已被推翻**的假设
 *   （文化名的真位置是 CC_CULT_NAME_OFF(0x48)，且必须带 SSO 判据读）。
 *   删除后无调用者，故整函数移除。
 *
 * ⚠️ 留下的教训：这个函数的读法本身就是 SSO 根因的**同族错误** ——
 *   把字段地址当裸 `char*` 读到 `\0`。今后任何"读文化名字段"的代码
 *   都必须走 `culture_name_read(obj, CC_CULT_NAME_OFF, ...)`，不要自创读法。 */

/* ==================================================================== */
/* ★★★ 文化对象校验（2026-10-05 新增，修 disp    ruler_name 的根因）                      */
/* ==================================================================== */
/* 为什么需要它：                                                        */
/*   游戏自己取"统治者文化"的写法是（HandleRulerCulture @0x1406DF110，   */
/*   逐条汇编核对过）：                                                  */
/*       rbx = *(country + 0x1280)        ; 统治者对象                   */
/*       call [rbx->vtbl + 0x58]          ; ① 对象有效性                 */
/*       rbx = *(rbx + 0x60)              ; ★ 文化对象                  */
/*       test rbx,rbx / jz                ; ② 非空                       */
/*       call [rbx->vtbl + 0x40]          ; ③ 文化对象有效性             */
/*       eax = *(int*)(rbx + 0x90)        ; ★ 文化 ID                  */
/*                                                                      */
/*   本补丁原先**只做了 ②**，拿 `*(CMonarch+0x60)` 就直接把 `cu+0x48`    */
/*   当文化名读。实机证据（QIC 那局日志）：disp    ruler_name 共 2000 次调用里           */
/*   1767 次在 `+0x48` 读到非 ASCII 垃圾、且 `+0x120` 回退全部读空 ⇒     */
/*   "这个对象根本不是文化对象"时我们无从察觉，于是：                   */
/*     · 大部分角色被静默放弃（包括 shandong_culture，四个探针全 0 次）  */
/*     · 偶尔内存里恰好是像文化名的串 ⇒ 误命中（233 次"成功"）          */
/*   也就是说 disp    ruler_name 的命中率是**随机的**，不是按文化区分的。                */
/*                                                                      */
/* 本函数做的是 ③ 的**静态等价检查**：不调用虚函数（避免副作用/崩溃）， */
/* 改为验证"虚表指针与目标函数指针都落在 eu4.exe 映像内"。            */
/*   文化对象的 C++ 虚表在 .rdata，必然落在映像里；随机垃圾不可能同时   */
/*   满足"虚表在映像内"和"槽 8 指向 .text"。                             */
/*                                                                      */
/* 返回 1 = 看起来是合法文化对象；0 = 不是（调用方必须放弃）。           */
static int culture_obj_ok(const void *cu, uint64_t *vtbl_out, uint64_t *slot8_out)
{
    uint64_t vtbl = 0, slot8 = 0, first_byte = 0;

    if (vtbl_out) *vtbl_out = 0;
    if (slot8_out) *slot8_out = 0;
    if (!cu) return 0;
    if (!dll_region_ok(NULL, cu, 8)) return 0;

    /* 虚表指针：必须在映像 [ImageBase, ImageBase + SizeOfImage) 内 */
    if (!dll_read(NULL, cu, 8, &vtbl)) return 0;
    if (vtbl_out) *vtbl_out = vtbl;
    if (!mnp_image_addr_ok((const void *)(uintptr_t)vtbl)) return 0;

    /* 槽 8 = 虚表 + 0x40：文化有效性判定函数，必须指向可执行代码 */
    if (!dll_read(NULL, (const void *)(uintptr_t)(vtbl + 0x40), 8, &slot8)) return 0;
    if (slot8_out) *slot8_out = slot8;
    if (!mnp_image_addr_ok((const void *)(uintptr_t)slot8)) return 0;

    /* 该函数首字节必须可读（真正会被执行的东西） */
    if (!dll_read(NULL, (const void *)(uintptr_t)slot8, 1, &first_byte)) return 0;
    return 1;
}

/* 逐字节读（dll_read 只认 1/2/4/8 字节）。用于读变长字符串。 */
static int dll_read_bytes(const void *p, void *out, unsigned n)
{
    unsigned i;
    if (!p || !out || n > 0x1000) return 0;
    for (i = 0; i < n; i++) {
        uint64_t v = 0;
        if (!dll_read(NULL, (const uint8_t *)p + i, 1, &v)) return 0;
        ((uint8_t *)out)[i] = (uint8_t)v;
    }
    return 1;
}

/* ==================================================================== */
/* ★★★ 文化名字符串读取（带 SSO 判据）—— 2026-10-05 根因修复              */
/* ==================================================================== */
/* 根因（见 notes\诊断-长文化名SSO分界.md）：
 *   文化对象上的名字是一个 MSVC `std::string`（布局见 nameorder.h 的 cstr_t：
 *     +0x00 联合：16 字节 SSO 缓冲 / char* 堆指针
 *     +0x10 size      +0x18 cap
 *   **cap < 0x10 ⇒ 数据内联在字段地址本身；cap >= 0x10 ⇒ 字段处是堆指针。**
 *
 *   而本补丁原先在**两处**把 `文化对象 + 0x48` 直接当 `char*` 读：
 *     · p8_resolve_culture（显示期）         · culture_capture_from_ctx（gen     entry_culture 生成期捕获）
 *   ⇒ **只对短名有效**。长名（≥16 字符）时读到的是**堆指针的 8 个字节**，
 *     非 ASCII 且随 ASLR 变 —— 这就是它"读到垃圾"的真正原因。
 *
 * 铁证：配置里 40 条文化，**`shandong_culture` 是唯一 ≥16 字符的**，
 *   也是**唯一一个在整份日志里从未出现**的（其余未出现的都是"这局没玩到"）。
 *   16 字符正好跨过 SSO 上限（15 内容 + 结尾 0）。
 *
 * ★ 注意偏移：本例的字段起始就是 `+0x48`（即该 std::string 的**数据/SSO 联合**），
 *   size 在 `+0x58`、cap 在 `+0x60`。不要照抄别的类的 `+0x120/+0x130/+0x138`
 *   那一组（那是注册表对象的 id 串）。调用方只需传"字段起始偏移"。
 *
 * 读法完全照抄 `cultureconfig.h::cc_cstr_field` 的字段次序，不自创：
 *   先 cap → 再 size → 最后数据字段；cap<0x10 ⇒ 数据 = 字段地址本身。
 *
 * 返回名字长度（0 = 放弃），并把名字拷进 out（始终 NUL 结尾）。 */
static uint32_t culture_name_read(const void *obj, uint32_t off,
                                  char *out, uint32_t cap_out, int dbg)
{
    uint64_t cap = 0, sz = 0, fld = 0;
    uintptr_t data;
    uint32_t i;

    if (out && cap_out) out[0] = 0;
    if (!obj || !out || cap_out < 2) return 0;

    if (!dll_read(NULL, (const uint8_t *)obj + off + 0x18, 8, &cap))  return 0;
    if (!dll_read(NULL, (const uint8_t *)obj + off + 0x10, 8, &sz))   return 0;
    if (!dll_read(NULL, (const uint8_t *)obj + off,        8, &fld))  return 0;

    /* ★★ SSO 判据：cap < 0x10 ⇒ 数据就在字段地址本身 */
    data = (cap < 0x10) ? (uintptr_t)((const uint8_t *)obj + off)
                        : (uintptr_t)fld;

    if (dbg) {
        LOGS("[d] 名字字段 +0x"); LOGH(off);
        LOGS(": cap="); LOGD((uint32_t)cap);
        LOGS(" size="); LOGD((uint32_t)sz);
        LOGS(" sso="); LOGD((uint32_t)(cap < 0x10 ? 1 : 0));
        LOGS(" data="); LOGH((uint64_t)data);
        LOGS("\r\n");
    }

    if (!data) return 0;
    if (sz == 0 || sz > 128) return 0;                  /* 荒唐长度 ⇒ 不是名字 */
    if (!dll_region_ok(NULL, (const void *)data, (size_t)sz + 1)) return 0;

    /* 结尾必须真的是 \0（长度是权威，但不接受伪串） */
    {
        unsigned char last = 1;
        if (!dll_read_bytes((const void *)(data + sz), &last, 1)) return 0;
        if (last != 0) return 0;
    }
    for (i = 0; i < sz && i < cap_out - 1; i++) {
        unsigned char c = 0;
        if (!dll_read_bytes((const void *)(data + i), &c, 1)) { out[i] = 0; return 0; }
        out[i] = (char)c;
    }
    out[i] = 0;
    return i;
}

/* ★★★ 保留的历史说明（2026-10-05）：这里曾经把【载入的配置】整份列出来，
 *   但那条分支在实机上永远不执行 —— p4_fallback_reorder 走的是"按文化名查配置"的
 *   快路径，命中后直接 goto out，只有 g_cult_name 尚未捕获时才落到本函数。
 *   所以 CFGENTRY 一条都没进过日志。列表逻辑现已移到 cultureconfig_list.h，
 *   由 cc_init() 在解析完成后【无条件】调用；本函数只负责记录绑定结果。 */
static void cc_lazy_ready(void)
{
    if (g_cc_lazy_state != 0) return;

    g_cc_lazy_tries++;
    if (cc_lazy_bind(&g_cc)) {
        g_cc_lazy_state = 1;
        g_cc_bound = (uint32_t)g_cc.xref_n;
        LOGS("[i] culture bound lazily: bound="); LOGD(g_cc_bound);
        LOGS("/"); LOGD(g_cc_entries_n);
        LOGS(" tries="); LOGD((uint32_t)g_cc_lazy_tries);
        LOGS(" (first transform call)\r\n");
    } else if (g_cc.bind_state == CC_BIND_GIVEUP) {
        g_cc_lazy_state = -1;
        LOGS("[!] culture binding gave up after "); LOGD((uint32_t)g_cc_lazy_tries);
        LOGS(" tries (entries="); LOGD(g_cc_entries_n);
        LOGS(") -> 全部条目按未配置处理\r\n");
    }
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* 按文化决定姓名顺序：把「文化对象」翻译成 (surname_first, 分隔符)        */
/* ------------------------------------------------------------------ */
/* ★ 文化名捕获缓冲区（定义在 p4_fallback_reorder 之前，因为出口侧要用它）。
 * 文化名在 `文化对象 + CC_CULT_NAME_OFF`(0x48)，但那是 **std::string 的数据/SSO 联合**：
 *   · 短名（≤15 字符）⇒ 字符内联在 +0x48，直接当 char* 读"看起来"就对；
 *   · 长名（≥16 字符）⇒ +0x48 是**堆指针**，裸读拿到指针字节（非 ASCII）。
 * ⇒ 必须走 `culture_name_read()`（带 SSO 判据）。**这是 2026-10-05 的根因修复**：
 *   此前裸读导致长名文化（如 `shandong_culture`，16 字符）从未被捕获，
 *   因而永远不进入取名函数。详见 notes\诊断-长文化名SSO分界.md。
 * 而 a3 只在函数【入口】的 r8 可靠 ⇒ gen     entry_culture（入口）捕获、gen     exit_fallback（出口）使用。 */
#define CULT_NAME_MAX 64
static char g_cult_name[CULT_NAME_MAX] = { 0 };
static int  g_cult_name_ok = 0;
static int  g_cult_name_len = 0;
static int  g_cult_logs_left = 12;   /* 旧：文化名切换时最多记录 12 次（已弃用，见下方去重日志） */
#define CULT_LOG_MAX 64              /* ★ 按文化名去重后最多列出这么多个不同文化 */
static char g_cult_seen[CULT_LOG_MAX + 1][CULT_NAME_MAX];
static int  g_cult_seen_n = 0;       /* 已列出的不同文化个数 */

/* ★★★ 生成侧"见过哪些文化"的完整清单（2026-10-05）。
 *
 * 用途：终结一个反复出现的争论 ——「某个文化的配置明明读到了，为什么日志里
 *       一条它的记录都没有？」
 * 只有两种可能：
 *   ① 游戏从来没为这个文化生成过姓名（那它就不会出现在本清单里）；
 *   ② 生成了、但文化名读错了（那它会以别的名字出现）。
 * 把**所有**见过的文化名去重列出来，一眼就能分清是①还是② ——
 * 这比继续猜偏移、猜数据可靠得多。
 *
 * 与 "culture HIT" 的区别：那个只记**命中配置**的文化（未配置的看不见，
 * 也就无法判断"到底有没有来过"）；本清单不过滤。 */
#define CULT_SEEN_MAX 512
static char g_cult_all[CULT_SEEN_MAX][CULT_NAME_MAX];
static int  g_cult_all_n = 0;

static void cult_seen_note(const char *name)
{
    int i, q;

    if (!name || !name[0]) return;
    for (i = 0; i < g_cult_all_n; i++) {
        q = 0;
        for (;;) {
            if (g_cult_all[i][q] != name[q]) break;
            if (!name[q]) return;                 /* 已记录过 */
            q++;
            if (q >= CULT_NAME_MAX) break;
        }
    }
    if (g_cult_all_n >= CULT_SEEN_MAX) return;

    for (q = 0; q < CULT_NAME_MAX - 1 && name[q]; q++)
        g_cult_all[g_cult_all_n][q] = name[q];
    g_cult_all[g_cult_all_n][q] = 0;

    {
        int ci = (g_cc.count > 0) ? cc_lookup_name(&g_cc, name) : -1;
        /* 发布模式：逐文化留痕不打。★ 上面的数组记录与下面的 `g_cult_all_n++`
         *   **照旧执行** —— 诊断关了不代表数据不收集。 */
        if (g_log_verbose) {
            LOGS("[i] CULTSEEN #"); LOGD((uint32_t)g_cult_all_n);
            LOGS(" \""); LOGS(name); LOGS("\" ci=");
            LOGD((uint32_t)(ci < 0 ? 0xFFFFFFFFu : (uint32_t)ci));
            if (ci >= 0) {
                LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
                LOGS(" sep_len="); LOGD((uint32_t)g_cc.entry[ci].sep.len);
            }
            LOGS("\r\n");
        }
        (void)ci;
    }
    g_cult_all_n++;
}

/* ★ gen     loop_decide（生成阶段按文化反转名字段顺序）是否已成功挂载。
 *   true  ⇒ gen     exit_fallback 只做【分隔符替换】（顺序已从源头修正）；
 *   false ⇒ gen     exit_fallback 退回旧职责【交换两段 + 分隔符】（gen     loop_decide 未挂载时的保底）。 */
/* ★ 「生成阶段反转」是否已完整生效 = gen     loop_decide（循环前写姓）与 gen     surn_len（循环后跳过追加）**双双**挂上。
 *   只有两个都在，输出才是「姓 空格 名…」；缺一个都不能让 gen     exit_fallback 放弃交换。 */

/* gen     exit_fallback 桩直接调用：rcx = 结果 CString*，rdx = BuildFullName_Impl 的第 3 参数
 * （其 +0x88 是文化对象），r8 = 桩预先取好的文化对象（同一来源，便于直接使用）。
 * ctx 指向被挂钩函数栈上的结构，一定可读；仍用 SEH 兜底。 */
/* ★★ 生成阶段反转：把「王朝名 + 空格」先写进累积输出缓冲
 * ------------------------------------------------------------------
 * 为什么必须这样做（用户的核心要求："gen     exit_fallback 按空格切割不够本质，回到生成阶段反转"）：
 *   BuildFullName_Impl 的真实流水线是
 *       PickNameFromCultureLists → 名字串
 *       sub_1417047C0(str,&arr,' ') → 段数组
 *       loop { append 段; append " " }        ← 只处理「名」
 *       append 王朝名                          ← ★「姓」是循环【之后】单独追加的
 *   ⇒ 所以"反转数组"永远动不了姓（这是我 gen     loop_decide 三轮失败的根因）。
 *
 *   本质的做法：**在循环之前就把「姓」写进累积缓冲**，让它在输出里天然排在最前，
 *   然后把循环产的「名」接在后面。这样顺序完全由数据结构决定，
 *   不需要在出口按空格/0xBF 去猜边界。
 *
 * 地址已由反汇编确认：
 *   累积缓冲 Src = [rbp-0xD0]（序言 lea rbp,[rsp-0x10]; sub rsp,0x110 ⇒ rsp=rbp-0x100，
 *                              而 `lea rcx,[rsp+0x30]`（0x1403142F2）⇒ Src=rsp+0x30=rbp-0xD0）
 *   王朝名     = [rbp+0x78]（`mov rdx,[rbp+0x78]` @0x140314285 = IDA 的 arg_48）
 *   两者都是 32 字节的 MSVC std::string（+0 data/SSO、+0x10 size、+0x18 cap）。
 *
 * 参数：
 *   out  = Src（累积缓冲）
 *   dyn  = 王朝名 std::string*
 *   ap   = StringAppend 的绝对地址（由桩构造器用 base 算好传进来 —— 因为
 *          cave 在安装期才知道模块基址，而 C 函数自己不知道）
 *   sepp = 分隔符数据（先用固定 1 字节空格，之后由 gen     exit_fallback 按文化替换）
 * 先追加「姓」，再追加一个空格（gen     exit_fallback 之后会把空格换成该文化配置的 separator）。 */
typedef void (*mnp_append_fn)(void *dst, const void *src, size_t n);


/* ★★★ disp    ruler_name（统治者/继承人/配偶）：在 CMonarch_GetFullName 的成果上按【统治者自己的文化】重排
 * ================================================================================================
 * 目标函数：`CMonarch_GetFullName`（RVA 0x140A4B2C0）—— **全游戏唯一把「名」和「姓」拼到一起的地方**。
 *   它做两件事：① StringAssign(out, CMonarch+0x28)      —— 名
 *                ② StringAppend(out, " " + *(CMonarch+0x68)+8) —— 姓（分隔符是硬编码的一个空格）
 *   ⇒ 输出恒为「名 + " " + 姓」（空位期/摄政分支另走 INTERREGNUM 等文本）。
 *
 * 站点：RVA **0x140A4B4A6**（上面那次 StringAppend 刚返回，结果已完整），
 *       覆盖 7 字节 `48 C7 45 B0 01 00 00 00`（`mov [rbp-var_50], 1`，一条完整指令），
 *       resume **0x140A4B4AD**，重放该指令后正常继续 —— **不改控制流**。
 *       站点处：`rbx` = out（输出 std::string*）、`rdi` = CMonarch*、rsp ≡ 0 (mod 16)。
 *
 * ★★ 「统治者自己的文化」怎么取（本节的核心，2026-10-04 查实）：
 *     铁证是脚本命令 `ruler_culture` 的实现 `HandleRulerCulture`（0x1406DF110）：
 *         v3 = *(country + 0x1280)          // 统治者对象
 *         v5 = v3[12]                       // ★ = *(CMonarch + 0x60) → 文化对象
 *         id = v5[36]                       //   = *(文化对象 + 0x90) → 文化 ID
 *     而文化名在 `文化对象 + CC_CULT_NAME_OFF`(0x48) —— 但那是 **std::string 的
 *     数据/SSO 联合**，**不是**裸 C 字符串：短名内联、长名是堆指针。
 *     必须用 `culture_name_read()` 读（2026-10-05 根因修复；早期"直接是 C 字符串"
 *     的说法只在短名成立，正是它导致了长名文化从未被识别）。
 *     ⇒ **不需要**「tag → 国家表 → 国家 → +0x1228」那条绕路，也不依赖"统治者文化=国家文化"的假设。
 *
 * ★ 边界判定用**两个字段的 size**（不是猜空格、不是找 0xBF）：
 *     nlen = *(CMonarch + 0x38)                    // 名字 std::string 的 size（data@+0x28）
 *     dlen = *(*(CMonarch + 0x68) + 0x18)          // 王朝名 std::string 的 size（data@+0x08）
 *     只有 out->size == nlen + 1 + dlen 时才动手 ⇒ 空位期/摄政等分支天然被跳过。
 *
 * ★★ 红线（前四次崩溃换来的）：
 *   ① 绝不碰 BuildFullName_Impl 的内部累积缓冲（那里是不变量，动它必崩）；
 *   ② 绝不调用会抛 C++ 异常的游戏函数（__try/__except 捕获不了 C++ 异常）——
 *      这里只做字段读写与字节搬移；
 *   ③ 本函数只负责业务逻辑。被我们覆盖掉的那条原指令
 *      （`mov dword ptr [rbp-50h], 1`）由 （私有还原笔记，未随本仓库发布） 还原，
 *      控制流与回跳由 stubs.asm 的 trampoline 负责 —— 本函数不再参与"补回原指令"。
 *      （旧实现要求"桩末尾必须是 90 90 90 E9 rel32"，因为 prepare_one 会无条件
 *        按最后 5 字节填 resume；那套机制已随旧补丁表一并删除。）
 */
/* ★ 注（2026-10-05）：这里曾经有个 `cc_name_looks_valid()`，用"是不是 ASCII
 *   小写标识符"来判断"读到的是不是文化名"。**它已被删除** ——
 *   那是用我自己假定的格式去否认真实数据，而这游戏的 mod 数据里文化名
 *   完全可以带非 ASCII。现在一律改用【配置表本身】当判据：
 *   能 `cc_lookup_name` 查到就是配置里的那条文化，查不到就跟本补丁无关。
 *   详见 p8_monarch_reorder 里"文化名解析"那段注释。 */

/* ★★★ 文化名"全量清单"（2026-10-05，用户要求）                          */
/* ==================================================================== */
/* 为什么必须做成【无条件、全量】：
 *
 *   之前的 `CULTSEEN` 挂在 `p4_transform` 里"按文化名查配置"那条**快路径命中之后**
 *   —— 于是它只在特定分支才说话。我拿它的沉默去推断"某文化走了另一条路"，
 *   这是错的推理：**探针不响不代表事件没发生，只代表事件没走到那个分支。**
 *   （同一个坑在 2026-10-03 也踩过一次：当时日志被配额截断，
 *     我却据此推断"统治者不经过 BuildFullName_Impl"，用户当场指出。）
 *
 * ★★ 2026-10-05 修订记录（两次都是用户指出来的）：
 *   ① v1 把 `CULTSEEN` 挂在"查配置命中之后"⇒ 探针不响被误读成"走了另一条路"。
 *   ② v2 给清单设了 512 条上限，还判"非 ASCII 就不算文化名"。
 *      —— 设上限本身就是错的：EU4 有几百种文化、上千个国家，
 *      **我没有任何依据假定"不同原始串"的总数是多少**。设了上限，
 *      被截掉的那条正好可能就是答案，而且截断是静默的、我连丢了都不知道。
 *      判 ASCII 更是用自己臆想的格式去否认真实数据。
 *   ⇒ v3（本版）：**动态扩容，不设任何上限**；一切原样记录，
 *      内容一律按字节摆出来。容量只受进程内存限制，且扩容失败会明确告警。
 *
 * 记录位置（两处，都在拿到原始字节之后、任何过滤之前）：
 *   · `culture_capture_from_ctx`（gen     entry_culture，每次 BuildFullName_Impl 调用都跑）
 *     ⇒ 看到"游戏传给生成函数的每一个文化"，与顺序/配置/形态全无关
 *   · `p8_monarch_reorder`（disp    ruler_name，每次取统治者全名都跑）
 *     ⇒ 看到"显示期每一次取全名时，该角色的文化"
 *
 * 每条只在**首次出现**时打一行（带两个挂点的累计计数），所以日志不会刷爆。 */

/* ---- 存储：分页 + 动态 commit，不设上限 ---- */
/* 用 VirtualAlloc 保留一段地址空间，按需 commit —— 不申请就只占地址、
 * 不占物理内存；真到了几万条也只是一次次 commit，不需要"上限"这种东西。
 * 每页 CRAW_PER_PAGE 条，条目固定 CRAW_LEN 字节。 */
#define CRAW_LEN        128                        /* 单个串最多存这么多字节 */
#define CRAW_PER_PAGE   (65536 / CRAW_LEN)         /* 每页 64 KB ⇒ 512 条 */
#define CRAW_MAX_PAGES  16384                      /* 纯地址空间上限（=32 MB），
                                                      不是"条数上限"；到不了，
                                                      且到了会明确告警 */

static char   **g_craw_page  = NULL;      /* 页表：每页 CRAW_PER_PAGE 条 */
static uint32_t *g_craw_ctx  = NULL;      /* 该条经 gen     entry_culture（生成期）见过几次 */
static uint32_t *g_craw_disp = NULL;      /* 该条经 disp    ruler_name（显示期）几次 */
static uint32_t  g_craw_cap  = 0;         /* 已 commit 的条数容量（会持续增长） */
static uint32_t  g_craw_n    = 0;         /* 已记录的不同串数 */
static int       g_craw_warned = 0;
/* ★ 调用计数（2026-10-05 加，用于定位"解析成功但没留痕"）：
 *   calls = 进入 cult_raw_note 的次数（按 src 分）
 *   hits  = 查重命中的次数（即"这个串以前见过"）
 *   adds  = 真正新增条目的次数
 *   三者对不上就说明计数逻辑本身有问题，而不是"没走到这里"。 */
static uint32_t  g_craw_calls[2] = { 0, 0 };
static uint32_t  g_craw_hits[2]  = { 0, 0 };
static uint32_t  g_craw_adds[2]  = { 0, 0 };

/* 确保 capacity >= need；失败返回 0（调用方降级为"只计数不记录"） */
static int craw_reserve(uint32_t need)
{
    uint32_t want;
    void *p;

    if (need <= g_craw_cap) return 1;

    /* 首次分配：页表 + 计数数组（计数数组按最大页数一次性 commit：
     * 16384 页 × 512 条 × 4 字节 × 2 = 64 MB 太多，所以计数数组也随页成长）*/
    if (!g_craw_page) {
        g_craw_page = (char **)VirtualAlloc(NULL,
                          (size_t)CRAW_MAX_PAGES * sizeof(char *),
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_craw_ctx  = (uint32_t *)VirtualAlloc(NULL,
                          (size_t)CRAW_MAX_PAGES * CRAW_PER_PAGE * sizeof(uint32_t),
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_craw_disp = (uint32_t *)VirtualAlloc(NULL,
                          (size_t)CRAW_MAX_PAGES * CRAW_PER_PAGE * sizeof(uint32_t),
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_craw_page || !g_craw_ctx || !g_craw_disp) {
            if (!g_craw_warned) {
                g_craw_warned = 1;
                LOGS("[!] CULTRAW 页表分配失败 -> 只能计数，无法记录内容\r\n");
            }
            return 0;
        }
    }

    want = ((need + CRAW_PER_PAGE - 1) / CRAW_PER_PAGE) * CRAW_PER_PAGE;
    if (want / CRAW_PER_PAGE > CRAW_MAX_PAGES) {
        if (!g_craw_warned) {
            g_craw_warned = 1;
            LOGS("[!] CULTRAW 地址空间保留上限(");
            LOGD((uint32_t)CRAW_MAX_PAGES * CRAW_PER_PAGE);
            LOGS(" 条)已到 -> 后续不再记录内容\r\n");
        }
        return 0;
    }

    /* 为"还没 commit 的页"逐页 commit（每页 64 KB） */
    {
        uint32_t have_pages = g_craw_cap / CRAW_PER_PAGE;
        uint32_t want_pages = want / CRAW_PER_PAGE;
        uint32_t i;
        for (i = have_pages; i < want_pages; i++) {
            p = VirtualAlloc(NULL, CRAW_PER_PAGE * CRAW_LEN,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!p) {
                if (!g_craw_warned) {
                    g_craw_warned = 1;
                    LOGS("[!] CULTRAW 分页 commit 失败 -> 停在 ");
                    LOGD(g_craw_cap);
                    LOGS(" 条\r\n");
                }
                return 0;
            }
            g_craw_page[i] = (char *)p;
        }
    }
    g_craw_cap = want;
    return 1;
}

/* 取第 i 条的名字指针 */
static char *craw_name(uint32_t i)
{
    return g_craw_page[i / CRAW_PER_PAGE] + (size_t)(i % CRAW_PER_PAGE) * CRAW_LEN;
}

/* 记录一个"原始文化名观测"。src: 0 = gen     entry_culture/生成期，1 = disp    ruler_name/显示期。
 * ★ 不做任何有效性判断、不设任何条数上限：传进来什么就记什么。 */
static void cult_raw_note(const char *name, int len, int src)
{
    uint32_t i;
    int q, trunc = 0;

    if (!name) return;
    if (len < 0) len = 0;
    if (len > CRAW_LEN - 1) { len = CRAW_LEN - 1; trunc = 1; }

    g_craw_calls[src ? 1 : 0]++;

    if (!g_craw_page && !craw_reserve(CRAW_PER_PAGE)) {
        /* 连存储都没有：仍然计数，这样"来过多少次"不会丢 */
        return;
    }

    /* ★ 线性查重：与已记录的串比较。
     *   ★★ 2026-10-05 修复：原来用 `for(;;){ if(e[q]!=name[q])break;
     *      if(!name[q]){命中} q++; if(q>=CRAW_LEN)break; }` ——
     *      与**未初始化字节**比较、且越界判断在自增之后，逻辑上就会出现
     *      "本该命中却被当成新串 / 本该新串却提前 break"的错乱。
     *      实测症状：disp    ruler_name 侧解析成功 45 次，却只留下 1 条 CULTRAW 记录，
     *      而 gen     entry_culture 侧同名串的 `disp    ruler_name=` 计数一次都没涨（说明那次调用根本没走到
     *      计数分支）。现在改成"先比长度、再逐字节比"，不依赖终止符位置。 */
    for (i = 0; i < g_craw_n; i++) {
        const char *e = craw_name(i);
        int eq = 1;

        if (!e) continue;
        for (q = 0; q <= len; q++) {          /* 含结尾 '\0' 共 len+1 字节 */
            if ((unsigned char)e[q] != (unsigned char)name[q]) { eq = 0; break; }
        }
        if (eq) {                             /* 同一串：只涨计数 */
            g_craw_hits[src ? 1 : 0]++;
            if (src) g_craw_disp[i]++; else g_craw_ctx[i]++;
            return;
        }
    }

    /* 新串：按需扩容（没有条数上限） */
    if (!craw_reserve(g_craw_n + 1)) return;

    {
        char *dst = craw_name(g_craw_n);
        if (!dst) return;
        for (q = 0; q < CRAW_LEN; q++) dst[q] = 0;   /* ★ 清零，杜绝脏字节参与比较 */
        for (q = 0; q < len; q++) dst[q] = name[q];
        dst[len] = 0;
        if (src) g_craw_disp[g_craw_n] = 1; else g_craw_ctx[g_craw_n] = 1;
        i = g_craw_n;
        g_craw_n++;
        g_craw_adds[src ? 1 : 0]++;

        /* ★ 前 6 次 disp    ruler_name（src=1）新增条目时打一条带计数的行：
         *   把"调用/命中/新增"三个数并排打出来，一眼就能看出三者是否自洽。
         *   正常情况下 calls = hits + adds。若 disp    ruler_name 的 calls 涨了而 hits/adds
         *   都不涨，说明函数中途返回了。 */
        if (g_log_verbose && src && g_craw_adds[1] <= 6) {
            LOGS("[d] CRAWNEW disp adds="); LOGD(g_craw_adds[1]);
            LOGS(" calls="); LOGD(g_craw_calls[1]);
            LOGS(" hits="); LOGD(g_craw_hits[1]);
            LOGS(" n="); LOGD(i);
            LOGS(" \""); LOGS(craw_name(i)); LOGS("\"\r\n");
        }
    }

    {
        /* 用配置表本身当判据：命中就是配置里那条文化，没命中就是别的串。
         * 不再用"长得像不像"来猜。 */
        int ci = (g_cc.count > 0 && len > 0)
                     ? cc_lookup_name(&g_cc, craw_name(i)) : -1;

        if (!g_log_verbose) goto craw_done;   /* 发布模式：不打逐文化留痕 */
        LOGS("[i] CULTRAW ");
        LOGS(src ? "disp:" : "gen/entry:");
        LOGS(" n="); LOGD(i);                 /* 第几条不同串 */
        LOGS(" cb="); LOGD((uint32_t)len);
        if (trunc) LOGS("+");
        LOGS(" ci="); LOGD((uint32_t)(ci < 0 ? 0xFFFFFFFFu : (uint32_t)ci));
        if (ci >= 0 && ci < g_cc.count) {
            LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
            LOGS(" has_sep="); LOGD((uint32_t)g_cc.entry[ci].has_sep);
            LOGS(" sep_len="); LOGD((uint32_t)g_cc.entry[ci].sep.len);
        }
        /* ★ 一律按字节摆出来：可打印的照显，其余打点（0xBF 打成 ~）。
         *   非 ASCII 在这里会显示成点，所以同时给出 cb= 以便判断真实长度。 */
        LOGS(" \""); log_bytes((const unsigned char *)craw_name(i),
                               (uint32_t)len); LOGS("\"");
        LOGS("  [gen/entry="); LOGD(g_craw_ctx[i]);
        LOGS(" disp="); LOGD(g_craw_disp[i]);
        LOGS("]\r\n");
craw_done:                       /* ★ 上面 goto 的落点：发布模式下也必须走到末尾的
                                  *   `g_cult_all_n++`，否则 CULTSEEN 计数会停住。 */
        ;                        /* 空语句：避免"标签位于复合语句末尾"（C5299） */
    }
    g_cult_all_n++;              /* ★ 两种模式下都要执行（发布模式只是不打日志） */
}


static int p8_resolve_culture(const unsigned char *c, int dbg,
                              const char **cname_out, char *cn, uint32_t *cnl_out,
                              const void **cu_out, uint32_t *cid_out)
{
    const void *cu = NULL;
    uint64_t cu_vtbl = 0, cu_slot8 = 0;

    if (cu_out)   *cu_out = NULL;
    if (cid_out)  *cid_out = 0xFFFFFFFFu;
    if (cname_out) *cname_out = NULL;
    if (cn) { for (uint32_t z = 0; z < CULT_NAME_MAX + 8; z++) cn[z] = 0; }
    if (cnl_out) *cnl_out = 0;
    if (!c || !cname_out || !cn || !cnl_out) return -1;

    /* ---- ① 取文化指针 ---- */
    cu = *(const void *const *)(const void *)(c + 0x60);
    if (!cu) {
        if (dbg) { LOGS("[d] disp cult: cm+0x60 = NULL -> 放弃\r\n"); }
        return -1;
    }

    /* ---- ② 校验它到底是不是文化对象（游戏 HandleRulerCulture 的第 ③ 步） ---- */
    if (!culture_obj_ok(cu, &cu_vtbl, &cu_slot8)) {
        if (dbg) {
            LOGS("[d] disp 非文化对象: cu="); LOGH((uint64_t)(uintptr_t)cu);
            LOGS(" vtbl="); LOGH(cu_vtbl);
            LOGS(" slot8="); LOGH(cu_slot8);
            LOGS(" -> 放弃\r\n");
        }
        return -1;
    }
    if (cu_out) *cu_out = cu;

    /* ---- ③ 文化 ID（游戏读法：文化对象 +0x90，安全读，不裸解引用） ---- */
    if (cid_out) {
        uint64_t v90 = 0;
        if (dll_read(NULL, (const void *)((const char *)cu + 0x90), 4, &v90))
            *cid_out = (uint32_t)v90;
    }

    /* ---- ④ 文化名（**带 SSO 判据**，2026-10-05 根因修复） ----
     *   `cu + 0x48` 是 std::string 的数据/SSO 联合字段：
     *     cap < 0x10 ⇒ 名字字符**内联在 +0x48 本身**
     *     cap >= 0x10 ⇒ +0x48 处是**堆指针**
     *   原来把它无条件当 `char*` 读 ⇒ 长名（≥16 字符）读到指针字节。
     *   现在走 culture_name_read，并**把解析后的串拷进调用方缓冲**：
     *   `cname_out` 指向 `cn`（调用方自己的数组），不再是游戏内存地址 ——
     *   因为长名的字符根本不在 +0x48 那个地址上，沿用"游戏内地址"没有意义。 */
    {
        uint32_t l = culture_name_read(cu, CC_CULT_NAME_OFF, cn, CULT_NAME_MAX + 8,
                                       (dbg && g_disp_cultprobe_left > 0) ? 1 : 0);

        /* ★ 裸读一份用于并排对照（诊断文档 §4 判据 1）：
         *   短名 ⇒ 与 SSO 读一致；长名 ⇒ 看着像指针（非 ASCII）。
         *   这一份**故意保留裸读法**，它存在的唯一价值就是证明"裸读是错的"。
         *   ⚠️ 不要用它当实际名字来源 —— 实际名字一律取上面的 SSO 读结果。 */
        char bare[24];
        int bn = 0;
        for (bn = 0; bn < (int)sizeof(bare) - 1; bn++) {
            unsigned char c = 0;
            if (!dll_read_bytes((const uint8_t *)cu + CC_CULT_NAME_OFF + bn, &c, 1)) break;
            if (c == 0) break;
            bare[bn] = (char)c;
        }
        bare[bn] = 0;

        *cname_out = cn;
        *cnl_out = l;

        if (dbg && g_disp_cultprobe_left > 0) {
            g_disp_cultprobe_left--;
            LOGS("[d] disp 文化对象确认: cu="); LOGH((uint64_t)(uintptr_t)cu);
            LOGS(" vtbl="); LOGH(cu_vtbl);
            LOGS(" slot8="); LOGH(cu_slot8);
            LOGS(" id@+0x90="); LOGD(*cid_out);
            LOGS("\r\n      name(SSO读) len="); LOGD(l);
            LOGS(" \""); LOGS(cn); LOGS("\"\r\n      bare(+0x48) len=");
            LOGD((uint32_t)bn);
            LOGS(" \""); log_bytes((const unsigned char *)bare, (uint32_t)bn);
            LOGS("\"\r\n");
        }
        if (l == 0) return -1;      /* 读不出合法名字 ⇒ 放手 */
    }
    return 1;
}

static void p8_monarch_reorder(void *out, const void *cm)
{
    unsigned char *op = (unsigned char *)out;
    const unsigned char *c = (const unsigned char *)cm;
    unsigned char *odata;
    const char *cname;
    const void *dobj;
    const void *cu;
    size_t nlen, dlen, olen, ocap, k;
    int ci = -1;
    const name_sep_t *sep = NULL;
    unsigned char sepb[NAME_SEP_MAX];
    size_t seplen = 0;
    /* ★ 文化解析结果（p8_resolve_culture 的输出；此处声明以便在函数早段调用，
     *   因为形态检查/守卫都会 return，文化读取必须发生在它们之前）。 */
    const void *g_cu_r = NULL;
    const char *g_cname_r = NULL;
    char        g_cn_r[CULT_NAME_MAX + 8];
    uint32_t    g_cnl_r = 0;
    uint32_t    g_cid_r = 0xFFFFFFFFu;
    int         g_cult_ok = -1;

    if (!out || !cm) return;

    __try {
        size_t nbf0 = 0;                 /* 王朝名里 0xBF 的个数（★ 参与形态判定，不是纯诊断） */
        int dbg = 0;                     /* 本次是否输出诊断 */
        const unsigned char *dd0 = NULL; /* 王朝名数据指针（诊断与 nbf0 共用） */

        /* ---- 名/姓两个字段的长度（边界由结构给出） ---- */
        nlen = *(const size_t *)(const void *)(c + 0x38);
        dobj = *(const void *const *)(const void *)(c + 0x68);

        /* ★ 2026-10-06：此处原本有两道守卫（`cm+0x78` 摄政非空 / `cm+0x07` 空位期
         *   ⇒ 不重排），**已按用户实测结论撤除** ——
         *   用户确认：**摄政期间姓名本来就是正常显示的**，那两道守卫拦错了对象，
         *   只会把本来正确的显示改成"不动手"。
         *
         *   （撤除的是"是否该重排"的推测判据；同一批里的
         *     「王朝对象完整性校验」是"垃圾字节"防线，与此无关，予以保留。） */

        dlen = dobj ? *(const size_t *)(const void *)((const char *)dobj + 0x18) : 0;

        /* ★★★ 2026-10-06 新增：**王朝对象的完整性校验**（"垃圾字节"的防线）。
         *
         * 病象：用户报告某些统治者显示成「三个字为姓」。长度统计显示
         *   `olen == nlen + 1 + dlen` 在 2000 个样本里全部成立、`dlen` 也全是
         *   3 的倍数（本游戏 1 个汉字 = 3 字节）⇒ 长度本身自洽
         *   ⇒ **若真多出一个字，只能是"读到了不属于这个字段的字节"**，
         *     也就是 `dlen` / `data` 这一对与对象真实布局不符。
         *
         * 而本函数此前**完全信任** `*(dobj+0x18)` 当长度、`*(dobj+0x08)` 当数据
         *   —— 与 `cstr_t` 那边不同，这里**一个校验都没有**。
         *   这正是"垃圾字节"最容易进来的地方。
         *
         * ⇒ 补上与 `cstr_t` 同级的校验（都不通过就放手，绝不带着可疑长度去读内存）：
         *     ① size ≤ cap         （cap 在 +0x20，与 +0x18 同一套布局）
         *     ② cap 有上限         （离谱的容量 ⇒ 对象已坏）
         *     ③ 堆模式时 data 指针须落在用户地址区间
         *     ④ dlen 有上限        （姓名不可能这么长）
         */
        if (dobj) {
            size_t dcap  = 0;
            int    got_c = dll_read(NULL, (const void *)((const char *)dobj + 0x20),
                                    sizeof(size_t), (uint64_t *)&dcap);
            const unsigned char *dptr =
                (dcap >= 0x10) ? *(const unsigned char *const *)(const void *)
                                     ((const char *)dobj + 0x08)
                               : (const unsigned char *)dobj + 0x08;
            int bad = 0;

            if (!got_c)                                   bad = 1;   /* 读不到 cap */
            else if (dlen > dcap)                         bad = 2;   /* size > cap */
            else if (dcap > 0x10000)                      bad = 3;   /* 容量离谱 */
            else if (dlen > 0x1000)                       bad = 4;   /* 长度离谱 */
            else if (dcap >= 0x10) {                                  /* 堆串：验指针 */
                uintptr_t dp = (uintptr_t)dptr;
                if (dp < 0x10000 || dp > 0x00007FFFFFFFFFFFull) bad = 5;
            }

            if (bad) {
                stat_bump(ST_OTHER);
                if (g_disp_baddyn_seen_left > 0) {
                    g_disp_baddyn_seen_left--;
                    LOGS("[!] disp 王朝对象可疑(no="); LOGD((uint32_t)bad);
                    LOGS(") dobj=");  LOGH((uint64_t)(uintptr_t)dobj);
                    LOGS(" dlen=");   LOGD((uint32_t)dlen);
                    LOGS(" dcap=");   LOGD((uint32_t)dcap);
                    LOGS(" -> 原样保留(不用可疑长度读字节)\r\n");
                }
                return;
            }
        }

        /* ---- 输出串现状 ---- */
        olen = *(size_t *)(void *)(op + 0x10);
        ocap = *(size_t *)(void *)(op + 0x18);
        odata = (ocap >= 0x10) ? *(unsigned char **)out : op;

        /* ================================================================ */
        /* ★★★ 王朝名数据指针 + 0xBF 计数 —— **无条件计算**                  */
        /* ================================================================ */
        /* ★ 2026-10-05 修复：这两件事原先都写在下面的 `if (dbg)` 里，于是
         *   **诊断配额一耗尽（本局第 2000 次调用之后），`nbf0` 恒为 0**。
         *   而 `nbf0` 是 `form2`（「空格 + 0xBF 被折叠」那条形态）判定的
         *   必要输入 —— 它挂在诊断开关下面属于结构错误：
         *   配额用完后，带 0xBF 的文化（需开双字节补丁模组才会出现）
         *   **判定会静默退化**，且日志上完全看不出来（因为日志本身也没了）。
         *
         *   ⇒ nbf0 与 dd0 现在无条件算；只有"打印"仍受配额控制。 */
        if (dobj) {
            const size_t dcap0 = *(const size_t *)(const void *)((const char *)dobj + 0x20);
            dd0 = (dcap0 >= 0x10)
                ? *(const unsigned char *const *)(const void *)((const char *)dobj + 0x08)
                : (const unsigned char *)dobj + 0x08;

            /* ★★★ 2026-10-05 定案：0xBF 有**两种**身份，判据 = 「前一字节是不是 escape」。
             *
             * 转码器实测（`scripts/encode_eu4_special.py`）：
             *     ¿  U+00BF → **<256，转码器直接返回原字符** ⇒ 编码 = `[BF]`（**1 字节**）
             *     线 U+7EBF → high 命中内部表 ⇒ escape=0x12 ⇒ `[12 BF 75]`
             *   ⇒ **「¿」的编码就是裸 0xBF**（它是双字节补丁的"反转词序"触发标记），
             *     而「线」的第 2 字节**也是 0xBF**，属于 3 字节字符的内部。
             *
             * 判据（唯一同时满足单元测试与实机日志的规则）：
             *     · 前一个字节是 escape(0x10..0x13) ⇒ **字符内部字节，保留**（线）
             *     · 否则                              ⇒ **独立字符「¿」，删除**
             *
             * 实机对照：LJA 的姓字段 `12 BF 75` ⇒ 前一个是 0x12 ⇒ 保留 ⇒ 显示「线」✓
             * 单元测试：`BF 10 31 67`(¿朱) ⇒ 前一个是空格/串首 ⇒ 删除 ⇒ 显示「朱」✓ */
            if (dd0 && dlen && dll_region_ok(NULL, (void *)dd0, dlen)) {
                size_t p = 0;
                for (p = 0; p < dlen; p++) {
                    if (dd0[p] != 0xBF) continue;
                    /* ★ 唯一判据：前一个字节是 escape(0x10..0x13) ⇒ 3 字节字符的内部字节
                     *   （如「线」的 `12 BF 75`），保留；否则 ⇒ 独立字符「¿」，算标记。
                     *
                     * ★★ 不要加 `p == 0` 之类的"收紧"限制！
                     *   2026-10-05 踩过：实测（L7844）游戏会把「¿」插在**名的末尾**
                     *   （out = `11 6A 67 10 0B 68 [BF] 20 49`，nlen=5 的窗口里含那个 BF），
                     *   并不是总在姓字段的第一个字节。加了 `p == 0` 就会漏数它
                     *   ⇒ nbf0=0 ⇒ sur_len 多 1 ⇒ 姓多取一字节、名少一字节 ⇒ 名字错乱。 */
                    if (!(p > 0 && dd0[p - 1] >= 0x10 && dd0[p - 1] <= 0x13)) {
                        nbf0++;
                    }
                }
            }
        }

        /* ★★ 诊断（无条件先判定是否打印）：这一版必须看清"到底走到了哪一步"
         *   上一次把诊断放在形态检查之后，结果形态不符就静默 return ⇒ 一行日志都没有，
         *   反而掩盖了真相。现在无条件先打出来，再决定动不动手。
         *   （2026-10-04 功能确认后已由 g_disp_dump_left=0 关闭，代码保留备用。） */
        dbg = (g_disp_dump_left > 0);
        if (dbg) {
            g_disp_dump_left--;
            LOGS("[d] disp cm="); LOGH((uint64_t)(uintptr_t)cm);
            LOGS(" dobj="); LOGH((uint64_t)(uintptr_t)dobj);
            LOGS(" nlen="); LOGD((uint32_t)nlen);
            LOGS(" dlen="); LOGD((uint32_t)dlen);
            LOGS(" dbf="); LOGD((uint32_t)nbf0);
            LOGS(" olen="); LOGD((uint32_t)olen);
            LOGS(" ocap="); LOGD((uint32_t)ocap);
            LOGS(" expect="); LOGD((uint32_t)(nlen + 1 + dlen));
            if (dd0 && dlen && dll_region_ok(NULL, (void *)dd0, dlen)) {
                LOGS(" din=\""); log_bytes(dd0, dlen); LOGS("\"");
            }
            if (odata && olen && dll_region_ok(NULL, odata, olen)) {
                LOGS(" sout=\""); log_bytes(odata, olen); LOGS("\"");
            }
            LOGS("\r\n");
        }

        /* ================================================================ */
        /* ★★★ 文化解析（2026-10-05 第四版：先校验对象，再读名）            */
        /* ================================================================ */
        /* ★ 位置很关键：**必须在下面所有 return 之前**。
         *   之前把它放在形态检查之后，于是"形态不符 / 守卫不过"的角色
         *   连一行文化日志都不会留下 —— 而那正是 shandong_culture 消失的
         *   表象。现在它紧跟在无条件 dump 之后，覆盖面与 disp    ruler_name 调用一一对应。 */
        g_cult_ok = p8_resolve_culture(c, dbg, &g_cname_r, g_cn_r, &g_cnl_r,
                                       &g_cu_r, &g_cid_r);
        if (g_cult_ok < 0) {
            /* 文化对象不成立 ⇒ 不可能按文化排序，放手。
             * 不再猜别的偏移 —— 猜只会掩盖"对象不对"这个事实。 */
            return;
        }
        cu    = g_cu_r;
        cname = g_cname_r;

        /* ★★★ 无条件全量记录（用户要求，2026-10-05）：
         *   紧接在拿到文化名之后、**在任何按配置过滤之前**记一条。
         *   上一版的 CULTSEEN 只挂在"按文化名查配置命中之后"，于是它不响
         *   被我误读成"这个文化走了另一条路"—— 那是错的：
         *   探针不响只说明没走到那个分支，不说明事件没发生。 */
        {
            char raw[CRAW_LEN];
            int rn = 0;

            /* ★ 先整体清零：CULTRAW 与查重都按"到 \0 为止"读这个缓冲，
             *   若不清零，`raw[rn]=0` 之后的字节是栈上残留 ⇒ 查重会把
             *   两个不同的串误判成相同（实测：disp    ruler_name 解析成功 45 次只留下 1 条记录）。 */
            for (rn = 0; rn < CRAW_LEN; rn++) raw[rn] = 0;
            rn = 0;
            while (rn < CRAW_LEN - 1) {
                unsigned char ch = 0;
                if (!dll_read_bytes((const uint8_t *)cname + rn, &ch, 1)) break;
                if (ch == 0) break;
                raw[rn++] = (char)ch;   /* ★ 不判 ASCII，交给配置表判 */
            }
            raw[rn] = 0;
            cult_raw_note(raw, rn, 1);
        }

        /* ★ 守卫（诊断开着时每条都记一行，否则"为什么没动手"无从判断） */
        if (!dobj || nlen == 0 || dlen == 0 || !odata) {
            if (dbg) {
                LOGS("[d] disp 提前放手: dobj=");   LOGH((uint64_t)(uintptr_t)dobj);
                LOGS(" nlen="); LOGD((uint32_t)nlen);
                LOGS(" dlen="); LOGD((uint32_t)dlen);
                LOGS(" odata="); LOGH((uint64_t)(uintptr_t)odata);
                LOGS("\r\n");
            }
            return;
        }

        /* ★★★ 2026-10-05 用户决定：**名字带「¿」标记的统治者一律不碰**。
         *
         * ★★ 判据必须用 `nbf0 > 0`（王朝**字段**里有独立「¿」），
         *    **不能**去扫 `out` 里有没有 0xBF —— 实测两者不等价：
         *      · `dbf=1`（字段里有标记）实测 **774 次**
         *      · 而扫 `out` 的守卫命中 **0 次**
         *    ⇒ **游戏在拼 `out` 时已经把标记剥掉了**，`out` 里根本没有 0xBF。
         *      用扫 out 的判据 ⇒ 守卫永远空转 ⇒ 名字照样被改（就是本轮的 bug）。
         *
         * ★ 这也正是**两天前那个可用版本的实际行为**（从旧源码反查）：
         *     旧版 `nbf0` 在 `if (dbg)` 内计算，而 `dbg = (g_disp_dump_left > 0) = 0`
         *     ⇒ `nbf0 ≡ 0` ⇒ form2 判据 `dlen > nbf0` 恒真、`olen == nlen + dlen`
         *     ⇒ 带标记的名字**匹配不上 form1/form2** ⇒ 落到 `else { return; }`
         *     ⇒ **一个字节都不动** ⇒ 不乱码。
         *   也就是说：旧版"能用"的原因是**它对带标记的名字完全不介入**。
         *   现在用 `nbf0 > 0` 把这件事**显式表达**出来，不再依赖死代码。 */
        if (nbf0 > 0) {
            g_mark_skip_n++;
            if (dbg || g_mark_skip_left > 0) {
                g_mark_skip_left--;
                LOGS("[i] disp 带「¿」标记 -> 原样保留(不重排) #");
                LOGD((uint32_t)g_mark_skip_n);
                LOGS(" nlen="); LOGD((uint32_t)nlen);
                LOGS(" dlen="); LOGD((uint32_t)dlen);
                LOGS(" dbf="); LOGD((uint32_t)nbf0);
                LOGS(" olen="); LOGD((uint32_t)olen);
                LOGS(" cult=\""); LOGS(cname ? cname : "?"); LOGS("\"");
                LOGS(" 姓字段="); if (dd0 && dlen) log_hex(dd0, (uint32_t)dlen);
                LOGS(" out="); log_hex(odata, (uint32_t)((olen <= 24) ? olen : 24));
                LOGS("\r\n");
            }
            return;
        }

        /* ★★ 形态判定（实机日志确定，两种都合法）：
         *   ① 姓【不带】0xBF：out = 名(nlen) + ' ' + 姓(dlen)      ⇒ olen == nlen + 1 + dlen
         *   ② 姓【带】  0xBF：out = 名(nlen) + 姓(dlen - nbf)      ⇒ olen == nlen + (dlen - nbf)
         *      —— 游戏在拼 " " + 0xBF + 姓 时，会把「空格 + 0xBF」一起折叠掉，
         *         于是结果既没有空格、也没有 0xBF（这正是"0xBF 的姓仍然没有空格"的机制）。
         *   非这两种形态（空位期 INTERREGNUM / 摄政 REGENT_TITLE 等）⇒ 不动。
         *
         * ★ 姓直接取自 out 本身（两种形态下它都已经躺在 out 里），
         *   不再去 dobj 取 —— 少一次解引用，也天然带上游戏已做好的折叠结果。 */
        const unsigned char *ssur = NULL;
        size_t sur_len = 0;
        int form = 0;

        /* ================================================================ */
        /* ★★★ 形态判定之前的【真实字节】记录（2026-10-05，为 0xBF 乱码定案） */
        /* ================================================================ */
        /* 为什么必须打 hex：
         *   `log_bytes` 把不可打印字节打成 `.`，而本游戏的双字节编码里 CJK 全是
         *   不可打印 ⇒ 日志里"名"和"姓"长得一样，只能靠长度反复推演；而
         *   `olen`（size 字段）与"实际写入的字节数"在 0xBF 形态下**并不一致**，
         *   推演会自相矛盾。⇒ 直接把字节摆出来，边界一眼可见。
         *
         * 打三样（同一现场）：
         *   ① odata[0..min(olen+4,48)) —— 输出缓冲真实内容（**多打 4 字节**，
         *      用来判断 olen 之后是不是残留垃圾；这正是"乱码"的嫌疑来源）；
         *   ② 名/姓两个**字段**的字节（din / 王朝名）；
         *   ③ 判定结果（form / 名长 / 姓长 / 姓起点）。
         * 只在 nbf0>0（即 0xBF 形态）时打，避免刷屏 —— 这正是出问题的那条路。 */
        /* ★★ 2026-10-06 修正门控：**不能只限 0xBF 形态**。
         *   先前写成 `dbg && nbf0 > 0`，而用户报的"三个字为姓"（AHR / jianghuai）
         *   恰恰是 `dbf=0`（无标记）⇒ **hex dump 被自己的条件排除掉了**，
         *   日志里一行字节都没有，无法判定是"数据如此"还是"读到了垃圾"。
         *   ⇒ 改为只要 `dbg` 就打（`dbg` 本身已由 g_disp_dump_left 配额控制）。 */
        if (dbg) {
            const unsigned char *dd = NULL;
            if (dobj) {
                const size_t dcap = *(const size_t *)(const void *)((const char *)dobj + 0x20);
                dd = (dcap >= 0x10)
                    ? *(const unsigned char *const *)(const void *)((const char *)dobj + 0x08)
                    : (const unsigned char *)dobj + 0x08;
            }
            LOGS("[d] disp 字节 olen="); LOGD((uint32_t)olen);
            LOGS(" nlen="); LOGD((uint32_t)nlen);
            LOGS(" dlen="); LOGD((uint32_t)dlen);
            LOGS(" dbf="); LOGD((uint32_t)nbf0);
            LOGS(" ocap="); LOGD((uint32_t)ocap);
            if (odata && dll_region_ok(NULL, (void *)odata, olen + 4)) {
                LOGS("\r\n      out  = "); log_hex(odata, (uint32_t)(olen + 4));
            } else {
                LOGS("\r\n      out  = (odata 不可读)");
            }
            if (dll_region_ok(NULL, (void *)(c + 0x28), nlen)) {
                LOGS("\r\n      名字段 = "); log_hex((const unsigned char *)c + 0x28, (uint32_t)nlen);
            } else {
                LOGS("\r\n      名字段 = (不可读)");
            }
            if (dd && dlen && dll_region_ok(NULL, (void *)dd, dlen)) {
                LOGS("\r\n      姓字段 = "); log_hex(dd, (uint32_t)dlen);
            } else {
                LOGS("\r\n      姓字段 = (不可读)");
            }
            LOGS("\r\n");
        }

        if (olen == nlen + 1 + dlen) {
            /* 形态 1：无 0xBF。out = 名(nlen) + 1 字节分隔 + 姓(dlen)
             *   —— 对应 CMonarch_GetFullName 的「④ 拼王朝名」出口
             *   （汇编已核实：该出口无条件追加 Src = " " + 王朝名，Size=1）。 */
            ssur = odata + nlen + 1;   form = 1;   sur_len = dlen;
        } else if (nbf0 > 0 && olen == nlen + (dlen - nbf0) && dlen > nbf0) {
            /* 形态 2：姓字段以【独立标记】0xBF 开头，游戏在拼 `" " + BF + 姓` 时
             *   把那个空格折叠掉了 ⇒ out = 名(nlen) + BF + 姓(dlen-nbf0)。
             *
             * 实测（L141，hex 已核）：姓字段 = `BF 10 1D 60`（标记 + 思 U+601D）
             *     nlen=6 dlen=4 nbf0=1 olen=9 ⇒ 9 == 6 + (4-1) ✓
             *     ssur = odata + nlen = odata+6，取 sur_len=3 字节 = `10 1D 60`
             *     ⇒ 姓阶段的"按字符步进"循环跳过整个字符、不删任何字节 = 思 ✓
             *
             * ★ 2026-10-05 历史（务必保留这段教训）：
             *   本分支曾被我临时改成"遇到 0xBF 形态一律原样返回"。原因：
             *   当时 `nbf0` 按**任意 0xBF** 计数，把 LJA 那种"字符内 0xBF"
             *   （`12 BF 75` = 线，U+7EBF，其 low 字节就是 0xBF）也算成标记
             *   ⇒ `sur_len = dlen - nbf0` 少 1 ⇒ 切分点左移、丢一个字节
             *   ⇒ 屏幕上乱码方块、size 少 1（实测 7 → 5）。
             *
             *   现在 `nbf0` 只数**独立标记**（按 escape 字节 10/11/12/13 步进，
             *   字符体内的 0xBF 不计），两种布局能正确区分，故恢复本分支。
             *
             * ★ 两种 0xBF 含义的判据（这是全部混乱的根源）：
             *     `BF 10 1D 60` —— 0xBF 后面跟 escape ⇒ 0xBF 是**独立标记**
             *     `12 BF 75`    —— 0xBF 前面是 escape ⇒ 0xBF 是**字符的 low 字节**
             */
            ssur = odata + nlen;   form = 2;   sur_len = dlen - nbf0;
        } else {
            /* 其余形态 ⇒ out 里**没有姓**（空位期 INTERREGNUM / 摄政称号那几条出口），
             *   原样保留。必须单独记一行：
             *   否则"没有姓可排"与"文化没查到"在日志里是同一个样子（都只有前面那条
             *   无条件 dump），会把定位引向错误的方向。 */
            if (dbg) {
                LOGS("[d] disp 无姓可排(原样保留) olen="); LOGD((uint32_t)olen);
                LOGS(" nlen="); LOGD((uint32_t)nlen);
                LOGS(" dlen="); LOGD((uint32_t)dlen);
                LOGS(" dbf="); LOGD((uint32_t)nbf0);
                LOGS("  [形式不匹配 form1="); LOGD((uint32_t)(nlen + 1 + dlen));
                LOGS(" form2="); LOGD((uint32_t)(nlen + (dlen > nbf0 ? dlen - nbf0 : dlen)));
                LOGS("]\r\n");
            } else if (g_disp_nosur_seen_left > 0) {
                /* 配额外也要留一次痕：这条分支一旦开始高频出现，
                 *   说明形态判定在新的游戏/mods 组合下失效了。 */
                g_disp_nosur_seen_left--;
                LOGS("[i] disp 无姓可排(原样保留) olen="); LOGD((uint32_t)olen);
                LOGS(" nlen="); LOGD((uint32_t)nlen);
                LOGS(" dlen="); LOGD((uint32_t)dlen);
                LOGS(" dbf="); LOGD((uint32_t)nbf0);
                LOGS("\r\n");
            }
            return;
        }

        /* ★ 2026-10-05：`form == 2` 的"折叠"日志块已删除 —— form2 现在一律
         *   原样返回（见上方 0xBF 分支的说明），永远不会走到这里。 */
    
        /* ============================================================ */
        /* ★★★ 按配置决定「姓 / 名」的先后（2026-10-05 按用户规格重写）  */
        /* ============================================================ */
        /* 用户订下的规格（原话）：                                      */
        /*   「dynasty 和 name 字段不能动！我要依据配置文件：            */
        /*     mongol = { surname_first = yes  separator = " " }        */
        /*     那么 mongol 文化的角色就是姓前名后，中间分隔用 separator」*/
        /*                                                              */
        /* ⇒ 本函数**只做一件事**：把游戏已经拼好的「名 + 分隔 + 姓」    */
        /*   重排成「姓 + separator + 名」。两个字段一个字节都不碰      */
        /*   （不写 CMonarch+0x28，也不写 Dynasty+0x08）—— 只改写这次    */
        /*   调用的出参 out。存档、界面、任何别处读到的字段都保持原样。  */
        /*                                                              */
        /* 配置里的三条语义（全部按规格照做）：                          */
        /*   surname_first = no   ⇒ 完全不介入，保持游戏原样             */
        /*   separator = " "      ⇒ 姓与名之间一个空格（mongol 就是这种）*/
        /*   separator = ""       ⇒ 姓与名直接相连，中间不加任何字符     */
        /*   未写 separator       ⇒ 用全局缺省 g_pn_default_sep          */
    
        /* ---- ★ 统治者自己的文化：已在函数早段解析并校验（见 p8_resolve_culture）。
         *   这里不再重复读取 —— `cu` / `cname` / `g_cn_r` / `g_cnl_r` 沿用早段结果。
         *   下面只做「拿文化名去查配置」这一件事。 ---- */

        if (!cname) return;
    
        /* ★ 名字已由 p8_resolve_culture 内部的 culture_name_read（带 SSO 判据）
         *   读好并放进 g_cn_r；这里只把它搬到本地缓冲，长度取 g_cnl_r。
         *   长度为 0（空文化名 / 读取失败）⇒ 后面自然放弃。
         *   ⚠️ 不要再改用 safe_cstr 之类的"裸读 C 串"—— 那正是 SSO 根因的同族错误。 */
        {
            char cn[CULT_NAME_MAX + 8];
            uint32_t cnl = 0;
            for (k = 0; k <= g_cnl_r && k < sizeof(cn); k++) cn[k] = g_cn_r[k];
            cnl = g_cnl_r;

            /* ============================================================ */
            /* ★★★ 文化名解析：**判据是配置表本身，不是"长得像不像"**       */
            /* ============================================================ */
            /* 2026-10-05 第三版修订（用户指出上一个判据是我臆想的）：
             *
             * 上一版用 `cc_name_looks_valid`（要求 ASCII 小写标识符）来判
             * "+0x48 读到的到底是不是文化名"。那是**用我自己假定的格式去
             * 否认真实数据** —— 这游戏的 mod 数据里文化名完全可以带非 ASCII。
             *
             * 正确的判据是：**这个串能不能在配置表里查到**。
             *   · 配置表里有什么，只有配置文件说了算，与我的假设无关；
             *   · 我们最终要的就是"用它查配置"，所以直接拿查询结果当判据，
             *     既没有多余假设，也不会把合法的文化名误判掉。
             *
             * 于是逻辑变成：
             *   +0x48 查得到 ⇒ 就用它
             *   两处都查不到 ⇒ 这个角色不在配置覆盖范围内 ⇒ 放手（安全） */
            if (g_cc.count <= 0) {
                if (dbg) { LOGS("[d] disp cult: 配置条目为 0 -> 放弃\r\n"); }
                return;
            }

            ci = (cnl > 0) ? cc_lookup_name(&g_cc, cn) : -1;

            /* ★★ 第四版（2026-10-05）：删掉 +0x120 回退。
             *   那个偏移来自 `（私有还原笔记）` 里"文化对象 id 字符串"的旧记录，但实机
             *   证明它 1767 次**全部读到空串**（`+120 len=0`），从来没有救回一次。
             *   它的真正作用是**掩盖**"cu 根本不是文化对象"这个事实。
             *   现在 culture_obj_ok 已经在前面挡掉了非文化对象，这里不需要猜备胎。
             *
             * ★★ 第五版（2026-10-05）：连 `+0x130` 那条候选串诊断也一并删除。
             *   它是在"名字可能在 +0x120/+0x130"那个**已被推翻**的假设下加的；
             *   名字的真实位置已确证为 `CC_CULT_NAME_OFF`(0x48) 且必须带 SSO 判据。
             *   实机每次都打出固定的 `len=6 "\x7f\xff\xff\xff\xff\xff"` ——
             *   那只是那块内存的常量填充，从未提供过任何信息，反而会误导。
             *   （`safe_cstr()` 随之成为死代码，已一并删除。） */
            if (ci < 0 && dbg && g_disp_cultprobe_left > 0) {
                uint64_t id90 = 0;
                g_disp_cultprobe_left--;
                (void)dll_read(NULL, (const void *)((const char *)cu + CC_CULT_ID_INT), 4, &id90);
                LOGS("[d] disp 文化未命中: name(SSO读)=\"");
                LOGS(cn);
                LOGS("\" len="); LOGD(cnl);
                LOGS("  id@+0x90="); LOGD((uint32_t)id90);
                LOGS("  (注：未命中只表示配置里没有它，不是读取失败)\r\n");
            }

            /* 查不到 ⇒ 放手。注意这里**不是**"判定它无效"，
             * 而是"配置里没有它，本补丁对它无事可做"。 */
            if (ci < 0) return;
    
            /* ★★★ 关键诊断：把 disp    ruler_name 实际读到的文化名打出来。
             *   "某文化没做姓前名后"这件事只可能停在四个地方：
             *     ① 没走到这里（上面每条 return 都已单独记日志）；
             *     ② 读到的名字不是配置里那个（本行直接暴露）；
             *     ③ 读到了、但配置里没这条或 surname_first=0；
             *     ④ 读到了、配置也对，但分隔符/容量让写入放弃。
             *   同时打出 cu 与 cu+0x48，便于和 gen     exit_fallback 那条路径（a3+0x48）对照。 */
            if (dbg) {
                /* ★★★ 2026-10-05 新增：把**这个统治者属于哪个国家**打出来。
                 *
                 * 起因：disp    ruler_name 对 gan / mongol / sichuanese / zhongyuan 全部成功
                 * （日志里 `disp    ruler_name done ... sep_len=0` 有 318 条），
                 * 但 `shandong_culture` 一条都没有 —— 而它在存档里是
                 * **38 个国家的主流文化**（SDA 就是其中之一）。
                 * ⇒ 必须回答："SDA 的统治者到底有没有被 disp    ruler_name 处理过？"
                 *
                 * CMonarch+0x20 = owner_ref（8 字节 tag，+7 = 有效标志，见
                 * （私有还原笔记，未随本仓库发布） 的 CMonarch::owner_ref）。
                 * 带上这个 tag，就能把"某个国家"与"它是否走到这里"直接对上：
                 *   · 日志里出现 SDA 且有 disp    ruler_name done ⇒ 这条路通了，问题在别处；
                 *   · 日志里【从不出现】SDA          ⇒ 那个名字不经过
                 *     CMonarch_GetFullName，得顺着显示层再往上找。 */
                const unsigned char *ctag = (const unsigned char *)c + 0x20;
                char tg[5];
                tg[0] = (ctag[0] >= 32 && ctag[0] < 127) ? (char)ctag[0] : '.';
                tg[1] = (ctag[1] >= 32 && ctag[1] < 127) ? (char)ctag[1] : '.';
                tg[2] = (ctag[2] >= 32 && ctag[2] < 127) ? (char)ctag[2] : '.';
                tg[3] = (ctag[3] >= 32 && ctag[3] < 127) ? (char)ctag[3] : '.';
                tg[4] = 0;

                /* 同一个 tag 只打第一条（否则刷屏；disp    ruler_name 命中数已达 1750+） */
                if (g_log_verbose && ctag[7] != 0 && (g_disp_last_tag[0] != tg[0] || g_disp_last_tag[1] != tg[1] ||
                                     g_disp_last_tag[2] != tg[2] || g_disp_last_tag[3] != tg[3])) {
                    g_disp_last_tag[0] = tg[0]; g_disp_last_tag[1] = tg[1];
                    g_disp_last_tag[2] = tg[2]; g_disp_last_tag[3] = tg[3];
                    LOGS("[i] disp TAG "); LOGS(tg); LOGS(" cult=\""); LOGS(cn);
                    LOGS("\" ci="); LOGD((uint32_t)(ci < 0 ? 0xFFFFFFFFu : (uint32_t)ci));
                    LOGS("\r\n");
                }

                LOGS("[d] disp cult cu="); LOGH((uint64_t)(uintptr_t)cu);
                LOGS(" tag="); LOGS(tg);
                /* ★ 注意：`cname` 现在指向**调用方缓冲里的解析结果**（不是游戏内存地址）。
                 *   原因：长名（≥16 字符）的字符根本不在 `文化对象+0x48` 那个地址上
                 *   （那里是堆指针），沿用"游戏内地址"没有意义。
                 *   所以这里打 `name(resolved)`，不要打 `name@cu+0x48`。 */
                LOGS(" name(resolved)=\""); LOGS(cn);
                LOGS("\" len="); LOGD(cnl);
                LOGS(" ci="); LOGD((uint32_t)(ci < 0 ? 0xFFFFFFFFu : (uint32_t)ci));
                if (ci >= 0) {
                    LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
                    LOGS(" has_sep="); LOGD((uint32_t)g_cc.entry[ci].has_sep);
                    LOGS(" seplen="); LOGD((uint32_t)g_cc.entry[ci].sep.len);
                }
                LOGS("\r\n");
            }
    
            /* 未配置，或配置说 surname_first = no ⇒ 一律不介入 */
            if (ci < 0 || !g_cc.entry[ci].surname_first) return;
    
            /* ---- 分隔符 ---- */
            /* ★★★ 2026-10-05 统一：`has_sep == 0`（配置里没写 separator）
             *   一律用【项目全局缺省】`g_pn_default_sep`（由 nameorder.h 的
             *   `NAME_ORDER_SEP` 决定），**不再各写各的**。
             *
             *   这里曾经写死一个空格，而 gen     exit_fallback 那条路（sep=NULL 交给
             *   name_order_apply*）用的是全局缺省（空串）⇒
             *   **同一个文化走 disp    ruler_name 和走 gen     exit_fallback 会得到不同的分隔符**。
             *   现在两处都取 g_pn_default_sep，行为一致。 */
            if (g_cc.entry[ci].has_sep) {
                seplen = g_cc.entry[ci].sep.len;          /* "" ⇒ 0，就是不加分隔 */
                for (k = 0; k < seplen && k < NAME_SEP_MAX; k++)
                    sepb[k] = g_cc.entry[ci].sep.b[k];
            } else {
                seplen = g_pn_default_sep.len;            /* 未写 ⇒ 全局缺省 */
                for (k = 0; k < seplen && k < NAME_SEP_MAX; k++)
                    sepb[k] = g_pn_default_sep.b[k];
            }
        }
    
        /* ---- 重排：out 里已经是「名… [空格] 姓」，改成「姓 + sep + 名…」 ----
         * ★ 顺序来源是**结构**：名 = out 的前 nlen 字节，姓 = 后面的 sur_len 字节，
         *   两者都由 CMonarch 自己的 size 字段给出边界，不猜空格、不数标记。
         *
         * ★ need ≤ olen 恒成立（推导见下），所以**不需要扩容**，cap 天然够：
         *     形态 1：olen = nlen + 1 + dlen = nlen + 1 + sur_len
         *             need = sur_len + seplen + nlen ⇒ need = olen − 1 + seplen
         *     形态 2：olen = nlen + sur_len
         *             need = sur_len + seplen + nlen = olen + seplen
         *   ⇒ 只有「形态 2 且 seplen ≥ 1」才会加长，最长 olen + 8（分隔符上限 8）。
         *     配置里常见的是 ""(0) 与 " "(1)，即最多加 1 字节。
         *   ⇒ 仍然显式校验一次，宁可不改也不越界。 */
        {
            unsigned char tmp[512];
            unsigned char odata_save[512];
            size_t w = 0;
    
            /* ★ 2026-10-05：这些守卫全部补日志。
             *   静默 return 会让"界面没变化"与"文化没命中"在日志里长得一样，
             *   而两者的修法完全不同 —— 必须能区分。 */
            if (!dll_region_ok(NULL, (void *)ssur, sur_len)) {
                if (dbg) { LOGS("[d] disp 放弃(ssur 越界) sur_len="); LOGD((uint32_t)sur_len); LOGS("\r\n"); }
                return;
            }
            if (!dll_region_ok(NULL, (void *)odata, nlen + 1)) {
                if (dbg) { LOGS("[d] disp 放弃(odata/name 越界) nlen="); LOGD((uint32_t)nlen); LOGS("\r\n"); }
                return;
            }
            if (olen > sizeof(odata_save)) {
                if (dbg) { LOGS("[d] disp 放弃(olen 超缓冲) olen="); LOGD((uint32_t)olen); LOGS("\r\n"); }
                return;
            }
    
            for (k = 0; k < olen; k++) odata_save[k] = odata[k];   /* 改写前留档 */
    
            /* ① 姓（防御性再滤一遍 0xBF —— 双字节补丁的复用标记不参与显示） */
            /* ① 姓。
             * ★★★ 2026-10-05 关键修复：**不能无条件丢掉 0xBF**。
             *
             * 依据 EU4 的双字节编码方案（bruceCzK / matanki-saito 的 specialEscape）：
             *   每个 CJK 字符 = **3 字节** `[escape][low][high]`
             *     escape ∈ {0x10,0x11,0x12,0x13}（低两位分别表示 low/high 被转过）
             *     low,high = UTF-16 code point 的低/高字节
             *     若 low/high 命中"内部字符表"则 escape +1/+2，且 low += 15 / high += -9
             *
             * 实测（日志 LJA）：
             *     名字段 = 10 9B 51        → 军(U+519B)   escape=0x10
             *     姓字段 = 12 BF 75        → 线(U+7EBF)   escape=0x12, low=0xBF, high=0x75
             *   ⇒ **那个 0xBF 是「线」字的 low 字节，是字符本身的一部分**。
             *     原代码 `if (ssur[k] == 0xBF) continue;` 把它丢掉 ⇒ `12 75` 不成字
             *     ⇒ 屏幕上是乱码方块，且 size 少 1（实测 7 → 5）。这正是用户报的现象。
             *
             * ★★★ 用户已确认（2026-10-05）：`shandong_culture` 的 `dynasty_names` 里
             *   「线」是**纯字符、不带任何 `¿`(0xBF) 标记**。
             *   ⇒ **任何"删掉 0xBF"的行为都是错的** —— 那个字节是字符编码的一部分。
             *
             * ★ 那 0xBF 标记什么时候才真存在？
             *   查双字节补丁（EU4dll）源码 `Plugin64__localization_asm.asm`：
             *       ;逆疑問符(0xBF)が最初に来ていれば反転させる
             *       cmp  byte ptr [rax+1], 0BFh
             *       ; [0]は0x20(white space)
             *   ⇒ 补丁的判据是 **「`rax[0]` 是空格、`rax[1]` 是 0xBF」**，
             *     也就是 **`20 BF` 这个两字节组合**，而不是"任意 0xBF"。
             *   （且补丁**只消费、从不生成** 0xBF —— 它是 mod 数据的约定。）
             *
             * ⇒ 与补丁对齐：**只在「空格紧跟 0xBF」(0x20 0xBF) 时才认定是标记并删除**，
             *   其余位置的 0xBF 一律当字符字节保留。
             *   这样 LJA 的 `12 BF 75` 被完整搬运（线），而真正的 `20 BF` 标记仍会被清掉。 */
            {
                size_t p = 0;
                for (p = 0; p < sur_len; p++) {
                    unsigned char b = ssur[p];
                    /* ★ 判据：前一个是 escape(0x10..0x13) ⇒ 字符内部字节（如 线的 0xBF），保留；
                     *   否则 ⇒ 独立字符「¿」，删除。 */
                    if (b == 0xBF
                        && !(p > 0 && ssur[p - 1] >= 0x10 && ssur[p - 1] <= 0x13)) {
                        continue;               /* 独立「¿」⇒ 删 */
                    }
                    if (w >= sizeof(tmp)) {
                        if (dbg) { LOGS("[d] disp 放弃(tmp 溢出, 姓阶段)\r\n"); }
                        return;
                    }
                    tmp[w++] = b;
                }
            }
            if (w == 0) {                             /* 姓为空 ⇒ 放手 */
                if (dbg) { LOGS("[d] disp 放弃(姓为空)\r\n"); }
                return;
            }
    
            /* ② separator（"" ⇒ 一个字节都不加） */
            for (k = 0; k < seplen; k++) {
                if (w >= sizeof(tmp)) {
                    if (dbg) { LOGS("[d] disp 放弃(tmp 溢出, 分隔符阶段)\r\n"); }
                    return;
                }
                tmp[w++] = sepb[k];
            }
    
            /* ③ 名 */
            for (k = 0; k < nlen; k++) {
                if (w >= sizeof(tmp)) {
                    if (dbg) { LOGS("[d] disp 放弃(tmp 溢出, 名阶段) nlen="); LOGD((uint32_t)nlen); LOGS("\r\n"); }
                    return;
                }
                tmp[w++] = odata_save[k];
            }
    
            if (w == 0 || w + 1 > ocap) {
                /* 装不下 ⇒ 放手，绝不调分配器。
                 * ★ 2026-10-05：补日志 —— 这类静默 return 会让"界面没变化"
                 *   与"文化没命中"在日志里长得一样，无法区分。 */
                if (dbg) {
                    LOGS("[d] disp 放弃(容量不足) w="); LOGD((uint32_t)w);
                    LOGS(" ocap="); LOGD((uint32_t)ocap);
                    LOGS(" nlen="); LOGD((uint32_t)nlen);
                    LOGS(" sur_len="); LOGD((uint32_t)sur_len);
                    LOGS(" seplen="); LOGD((uint32_t)seplen);
                    LOGS("\r\n");
                }
                return;
            }
            if (!dll_region_ok(NULL, odata, w + 1)) {
                if (dbg) { LOGS("[d] disp 放弃(odata 越界)\r\n"); }
                return;
            }
    
            for (k = 0; k < w; k++) odata[k] = tmp[k];
            odata[w] = 0;
            *(size_t *)(void *)(op + 0x10) = w;
    
            if (dbg) {
                LOGS("[d] disp done form="); LOGD((uint32_t)form);
                LOGS(" size="); LOGD((uint32_t)w);
                LOGS(" sep_len="); LOGD((uint32_t)seplen);
                LOGS(" s=\""); log_bytes(odata, w); LOGS("\"");
                /* ★ 精确计数：输入串/输出串里到底还有几个 0xBF
                 *   （log_bytes 把不可打印字节都打成 '.'，肉眼分不出 0xBF，
                 *     所以必须单独数 —— 这是本轮定位的关键） */
                {
                    size_t sb = 0, ob = 0, nb = 0, z;
                    for (z = 0; z < olen; z++)
                        if (odata_save[z] == 0xBF) sb++;
                    for (z = 0; z < w; z++)
                        if (odata[z] == 0xBF) ob++;
                    for (z = 0; z < nlen && z < olen; z++)
                        if (odata_save[z] == 0xBF) nb++;
                    LOGS(" sin_bf="); LOGD((uint32_t)sb);
                    LOGS(" sout_bf="); LOGD((uint32_t)ob);
                    LOGS(" name_bf="); LOGD((uint32_t)nb);
                    LOGS(" name=\""); log_bytes(odata_save, nlen); LOGS("\"");
                }
                LOGS("\r\n");
            }
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
}

/* ★★★ 生成阶段实现「姓前名后」—— 用文化判定走两套逻辑（2026-10-04）
 * ================================================================================================
 * 思路（用户提出并确认）：**在 BuildFullName_Impl 里用 if 按文化分流**，而不是事后重排。
 *   · 姓前名后的文化 ⇒ 先把「姓 + sep」写进累积缓冲，再让循环 append 名；
 *     并在"追加王朝名"那一步让它【空转】。
 *   · 其它文化 ⇒ 完全走原逻辑（一个字节都不碰）。
 *
 * ★★ 与前四次崩溃方案（gen     loop_decide+gen     surn_len）的**本质区别：一条指令都不跳过**。
 *   旧方案跳过"取王朝名 + append + 挑名"整段，导致 rdx/r8 成垃圾、控件状态被破坏 ⇒ 崩。
 *   本方案两个站点都只是"重放原指令 + 跳回原处"，控制流与寄存器副作用完全不变：
 *     点 1（0x00314228，循环之前）：Src 刚被初始化为【空】(size=0, cap=15 SSO)
 *                                  按文化把「姓 + sep」写进去（只写 SSO，绝不扩容）
 *     点 2（0x003142F2，append 王朝名之前）：若点了点 1，就把 r8(size) 置 0
 *                                  于是那次 append 写 0 字节 = 空转
 *   标志 g_sf_want 由点 1 设置、点 2 读取。
 *
 * ★ 点 2 的位置很关键：`test r8,r8`（0x31428D）用的是【原始 size】⇒ 仍走"非空"正常分支；
 *   我们只在真正 call StringAppend 之前的 0x3142F2 处把 r8 清 0。
 *   （若在 test 之前清 0，会误入"从 names 数组挑一个"的分支。） */
static int g_sf_want = 0;          /* 点 1 设置：本次调用是否"姓前名后" */
/* ★ gen     reorder 成功重排后置 1；gen     exit_fallback（出口）据此跳过 —— 否则 g_sf_want 被 gen     reorder 清 0 后，
 *   gen     exit_fallback 会以为"没处理过"而再交换一次，把顺序又换回去。 */
static int g_sf_reordered = 0;

/* ★★★ 关键：StringAppend 那一刻「姓」的字节数（由 gen     surn_len 在 0x3142F2 存下、gen     reorder 在 0x3142FC 使用）。
 *
 * 为什么必须这样取（2026-10-04，用户点醒）：
 *   BuildFullName_Impl 里「姓」有【两个来源】，只有在这里才汇合：
 *     ① 0x314285  mov rdx,[rbp+arg_48]  → 王朝名字符串；size 非 0 就直接用它
 *     ② 0x314292  mov rax,[rbp+arg_20]  → 否则从【名字表】里挑一个元素当姓
 *   顾问 / 外交官 / 将领 走的正是 ②（Envoy_GenerateName 与 Leader_GenerateName 传进来的
 *   王朝名都是空 string）⇒ 盯着 arg_48([rbp+0x78]) 看永远是 size=0，
 *   这就是"冯 哈布斯堡 这类多词姓拿不到边界"的真正原因（我先前一直按统治者的
 *   「名字 + 王朝名」两字段模型去想，方向就错了）。
 *   而 0x3142F2 处 r8/size 已经把两种来源统一好了 ⇒ 只认它。 */
static size_t g_sur_len = 0;

/* ★ 定位用诊断（2026-10-04）：gen     surn_len 一直 GIVE_UP、gen     loop_decide 是否置位无从判断。
 *   ★★ 必须【只在配置命中时】打印 —— 未配置的文化（swedish/danish/norwegian…）
 *   量大得多，先前把 24 次配额全吃光了，真正关心的文化一条日志都没留下。
 *   ★★★ 2026-10-05 调整：配额从 24 放大到 4000。
 *   起因是一次"运行中崩溃"（C0000005 @ RVA 0x94F4A，CString 移动赋值读源越界）——
 *   崩溃点落在被数千处内联调用的通用函数里，回溯不到调用方，只能靠
 *   "崩溃前最后若干次姓名生成现场"来定位。配额太小会把关键现场冲掉。 */
/* ==================================================================== */
/* 日志策略（2026-10-05 重写）：两段式采样 + 线程标记                    */
/* ==================================================================== */
/* 老策略是"配额 N 条，用完永久静默"。它埋了一个严重的诊断陷阱：
 *
 *   配额是【按类型】分别计的，于是最先用完的类型从此消失，
 *   日志尾部只剩下配额还没用完的那一两种。
 *   看起来"最后一条总是 gen     reorder" —— 那不是因为崩溃在 gen     reorder，
 *   而是因为 gen     reorder 是唯一还亮着的那盏灯。
 *   （实际误导过一次定位：2026-10-05 那次，gen     loop_decide 配额 4000 早在 gen     reorder 首次出现
 *     之前就用满了，而 gen     reorder 只用了 7/4000。所谓"日志停在 gen     reorder"是必然的。）
 *
 * 新策略：
 *   ① 两段式采样 —— 前 WINDOW 次每次都记（留住启动/早期），
 *      之后每 STRIDE 次记一次。这样【全程都有覆盖】，
 *      崩溃前最多漏 STRIDE-1 次，而不是"从此再也看不见"。
 *   ② 状态变化无条件记 —— 文化切换、act 翻转这类稀疏事件信息量最大，
 *      不该被采样掉。
 *   ③ 每条带线程 ID —— 日志是逐片段 WriteFile 且无锁，
 *      多线程的片段会互相穿插；没有线程 ID 就无法还原"某个线程的最后动作"。
 */
#define MNP_LOG_WINDOW   2000u              /* 前这么多次每次都记 */
#define MNP_LOG_STRIDE   64u                /* 之后每这么多次记一次（必须是 2 的幂） */
#define MNP_LOG_STRIDE_M (MNP_LOG_STRIDE - 1u)

#define MNP_LOG_SHOULD(n) ((n) <= MNP_LOG_WINDOW || (((n) & MNP_LOG_STRIDE_M) == 0u))

/* 每条诊断行前面挂线程 ID，便于把交错的多线程日志分开 */
static void log_tid(void)
{
    char b[24];
    char *p = b;
    unsigned long tid = GetCurrentThreadId();
    unsigned i;
    *p++ = '['; *p++ = 't'; *p++ = '=';
    for (i = 0; i < 4; i++) {
        unsigned d = (unsigned)((tid >> ((3u - i) * 4u)) & 0xFu);
        *p++ = (char)(d < 10u ? '0' + d : 'a' + d - 10u);
    }
    *p++ = ']'; *p++ = ' '; *p = 0;
    log_str(b);
}

static uint32_t g_gen_loop_calls = 0;      /* gen     loop_decide 累计调用次数（采样用） */
static uint32_t g_gen_loop_logged = 0;     /* 实际记下的条数 */
static uint32_t g_gen_reorder_calls = 0;     /* gen     reorder 累计调用次数（采样用；也是"被调了多少次"的权威计数） */
static char     g_gen_loop_prev_cult[CULT_NAME_MAX] = { 0 };
static int      g_gen_loop_prev_act = -1;

/* gen     reorder 的 rsp 自检配额：前这么多次 gen     reorder 调用都打一行 rbp/rsp 关系（见 mnp_h_gen_reorder） */
static int      g_rsp_check_left = 64;

#define DBGP7(why) do {                                                        \
    g_gen_loop_calls++;                                                              \
    if (ci >= 0) {                                                             \
        const char *cc_ = (cult ? cult : "");                                  \
        int chg_ = (g_gen_loop_prev_act != (int)g_sf_want) ||                      \
                   (strcmp(g_gen_loop_prev_cult, cc_) != 0);                         \
        if (chg_ || MNP_LOG_SHOULD(g_gen_loop_calls)) {                              \
            int k_;                                                            \
            g_gen_loop_logged++;                                                     \
            log_tid();                                                         \
            LOGS("[d] gen/decide "); LOGS(why);                                        \
            LOGS(" #"); LOGD(g_gen_loop_calls);                                      \
            LOGS(" cult=\""); LOGS(cc_);                                       \
            LOGS("\" ci="); LOGD((uint32_t)ci);                                \
            LOGS(" act="); LOGD((uint32_t)g_sf_want);                        \
            if (chg_) LOGS(" <CHG>");                                          \
            LOGNL();                                                           \
            for (k_ = 0; k_ < CULT_NAME_MAX - 1 && cc_[k_]; k_++)              \
                g_gen_loop_prev_cult[k_] = cc_[k_];                                  \
            g_gen_loop_prev_cult[k_] = 0;                                            \
            g_gen_loop_prev_act = (int)g_sf_want;                                  \
        }                                                                      \
    } } while (0)

/* ★★ gen     surn_len（RVA 0x3142F2，call StringAppend 之前）：把「姓」的字节数存下来。
 *   站点覆盖【5】字节：48 8D 4C 24 30   lea rcx, [rsp+30h]   （即 Src 的地址）
 *   此刻现场：rcx 即将指向 Src（已含"名…"），rdx = 姓数据指针，r8 = 姓字节数。
 *   我们只做"记下 r8"；被覆盖的 lea 由 （私有还原笔记，未随本仓库发布） 还原，
 *   回跳 0x3142F7 让 StringAppend 照常执行。
 *
 *   ★ 曾把覆盖长度误记为【4】字节 —— 那会让 gen     surn_len 的 E9 第 5 字节没被写入，
 *     实机崩在 RVA 0x3142F6（C000001D）。此处订正为 5。 */
static void p10_record_surname_len(void *src, size_t sur_len)
{
    (void)src;
    g_sur_len = 0;
    if (!g_sf_want) return;                       /* 该文化不姓前名后 ⇒ 什么都不用记 */
    if (sur_len > 0 && sur_len < 256) g_sur_len = sur_len;
}

/* ★★ gen     reorder（0x3142FC，StringAppend 刚返回）：此时 Src = "名… " + 姓。
 *   站点覆盖 5 字节：0F 10 44 24 30   movups xmm0, [rsp+Src]（它就是把它交给结果的那一步）。
 *   用 g_sur_len（姓字节数）作边界，把 Src 重排成「姓 + 配置分隔符 + 名」。
 *   这里只做字节搬移，不调用任何游戏函数。 */
static void p11_reorder_surname_first(void *src)
{
    unsigned char *sp = (unsigned char *)src;
    const char *cult;
    unsigned char *buf;
    unsigned char sepb[NAME_SEP_MAX];
    size_t size, cap, sur, nbf = 0, deff = 0, nlen = 0, seplen = 0, need, k, z, take = 0;
    int ci = -1, folded = 0;

    if (!g_sf_want || !src || g_sur_len == 0) { g_sf_want = 0; return; }

    __try {
        cult = g_cult_name_ok ? g_cult_name : NULL;
        if (!cult || !cult[0] || g_cc.count <= 0) { g_sf_want = 0; return; }
        ci = cc_lookup_name(&g_cc, cult);
        if (ci < 0 || !g_cc.entry[ci].surname_first) { g_sf_want = 0; return; }

        if (g_cc.entry[ci].has_sep) {
            seplen = g_cc.entry[ci].sep.len;
            for (k = 0; k < seplen && k < NAME_SEP_MAX; k++) sepb[k] = g_cc.entry[ci].sep.b[k];
        } else {
            /* 未写 ⇒ 全局缺省（与 disp    ruler_name / gen     exit_fallback 保持同一份定义，见 nameorder.h） */
            seplen = g_pn_default_sep.len;
            for (k = 0; k < seplen && k < NAME_SEP_MAX; k++) sepb[k] = g_pn_default_sep.b[k];
        }
        if (seplen > 1) { g_sf_want = 0; return; }   /* 需要扩容 ⇒ 交给 gen     exit_fallback 兜底 */

        size = *(size_t *)(void *)(sp + 0x10);
        cap  = *(size_t *)(void *)(sp + 0x18);
        buf  = (cap >= 0x10) ? *(unsigned char **)src : sp;

        /* ★★★ 前置完整性自检（2026-10-05，来自一次实机崩溃的教训）
         *   那次崩溃：C0000005 @ RVA 0x94F4A（CString 移动赋值 `movups (%rdi),%xmm0`），
         *   异常记录里 **Rdi = 0x13**、目标 Rcx 是合法地址 —— 即有人拿着"值等于 19 的
         *   假指针"当 CString* 用。这是典型的结构体字段错位。
         *   崩溃点在被数千处内联调用的通用函数里，回溯不到调用方；我们能做的是：
         *   **接手任何对象之前先验证它像不像一个完好的 CString**，不像就立刻放手。
         *   宁可这个文化的顺序不变，也绝不去踩一个已经可疑的对象、把破坏放大。
         *   合法条件：size ≤ cap、cap 有上限、堆模式下 data 指针须落在用户地址区间。 */
        if (!buf || size <= 1) { g_sf_want = 0; return; }
        if (size > cap)        { g_sf_want = 0; return; }   /* size 超过容量 ⇒ 对象已坏 */
        if (cap > 0x10000)     { g_sf_want = 0; return; }   /* 容量离谱 ⇒ 对象已坏 */

        /* ★★★ 2026-10-05 用户决定：**名字里带「¿」标记的一律不碰**。
         *
         * 背景：0xBF 有**两种**身份，且游戏插入标记的位置不固定（实测既出现在
         *   姓字段首字节 `BF 11 6A 67`，也出现在**名的末尾**
         *   `11 6A 67 10 0B 68 [BF] 20 49`）。两义性判不准就会改坏名字。
         *
         * ⇒ 用户拍板：**带标记的交给游戏自己处理，补丁完全不介入**。
         *   这是一个**保守降级** —— 判错的方向变成"少处理一个名字"，
         *   而不是"把名字改坏"。
         *
         * 判据：存在 0xBF 且其前一字节不是 escape(0x10..0x13) ⇒ 就是独立「¿」。
         *   （转码器实测：「¿」U+00BF < 256 ⇒ 编码就是裸 0xBF，
         *     见 scripts/encode_eu4_special.py） */
        {
            size_t q2;
            for (q2 = 0; q2 < size; q2++) {
                if (buf[q2] != 0xBF) continue;
                if (q2 > 0 && buf[q2 - 1] >= 0x10 && buf[q2 - 1] <= 0x13) continue;
                g_sf_want = 0;                    /* 带「¿」⇒ 放手，不改 */
                g_mark_skip_n++;
                if (g_mark_skip_left > 0) {
                    g_mark_skip_left--;
                    LOGS("[i] gen 带「¿」标记 -> 不重排 #");
                    LOGD((uint32_t)g_mark_skip_n);
                    LOGS(" at="); LOGD((uint32_t)q2);
                    LOGS(" size="); LOGD((uint32_t)size);
                    LOGS(" hex="); log_hex(buf, (uint32_t)size);
                    LOGS("\r\n");
                }
                return;
            }
        }
        if (cap >= 0x10) {                                    /* 堆串：校验指针合理性 */
            uintptr_t dp = (uintptr_t)buf;
            if (dp < 0x10000 || dp > 0x00007FFFFFFFFFFFull) { g_sf_want = 0; return; }
        }

        sur = g_sur_len;                     /* 姓在 Src 末尾占的字节数 */
        if (sur == 0 || sur >= size) { g_sf_want = 0; return; }

        /* ★★★ 2026-10-05 与双字节补丁对齐的判据修复。
         *
         * 原实现把「姓里所有 0xBF」都当成标记：
         *     for (z = 0; z < sur; z++) if (buf[size-sur+z] == 0xBF) nbf++;
         *     deff = sur - nbf;                 ← 少算 1 字节
         * 但用户已确认 `dynasty_names` 里「线」是**纯字符、不带任何 `¿` 标记**，
         * 而 EU4 双字节编码里 `线`(U+7EBF) 的编码就是 `12 BF 75` —— **0xBF 是字符字节**。
         * ⇒ 按"任意 0xBF"计数会把姓的有效长度算少 1，切分点整体错位。
         *
         * 双字节补丁的真实判据（`Plugin64__localization_asm.asm`）：
         *     cmp byte ptr [rax+1], 0BFh    ; [0]は0x20(white space)
         * ⇒ **「空格紧跟 0xBF」(`0x20 0xBF`) 才是标记**，且补丁只消费、从不生成。
         *
         * ⇒ 改为只数 `0x20 0xBF` 组合，其余 0xBF 一律按字符字节保留：
         *     nbf  = 真标记个数
         *     deff = 姓的有效字节数 = sur − nbf */
        for (z = 0; z < sur; z++) {
            unsigned char b = buf[size - sur + z];
            /* ★ 判据（2026-10-05 定案）：前一个是 escape(0x10..0x13) ⇒ 字符内部字节，
             *   保留（如「线」的 `12 BF 75`）；否则 ⇒ 独立字符「¿」，算作标记删除。
             *   转码器实测：「¿」U+00BF < 256 ⇒ 直接返回原字符 ⇒ 编码就是裸 0xBF。 */
            if (b == 0xBF && !(z > 0 && buf[size - sur + z - 1] >= 0x10
                               && buf[size - sur + z - 1] <= 0x13)) {
                nbf++;
            }
        }
        deff = sur - nbf;
        if (deff == 0) { g_sf_want = 0; return; }

        /* 形态 A：名 + SP + 姓(含 0xBF) —— 串里还留着那个分隔空格 */
        if (buf[size - sur - 1] == 0x20) {
            nlen   = size - sur - 1;
            take   = sur;
            folded = 0;
        }
        /* 形态 B：名 + 姓(0xBF 已剥、也没有 SP) —— 上游折叠过 */
        else if (size > deff && buf[size - deff - 1] != 0x20) {
            nlen   = size - deff;
            take   = deff;
            folded = 1;
        } else {
            g_sf_want = 0; return;
        }
        if (nlen == 0) { g_sf_want = 0; return; }

        need = deff + seplen + nlen;
        if (need > cap) { g_sf_want = 0; return; }   /* 装不下 ⇒ 交给 gen     exit_fallback，绝不调分配器 */

        /* ★★ 硬守卫：本函数**只允许把串变短或保持不变**，绝不允许加长。
         *   推导：size = nlen + 1 + sur（形态 A）或 nlen + deff（形态 B），
         *         need = deff + seplen + nlen，且 seplen ∈ {0,1}（>1 已在上面放手）
         *         ⇒ need = size − (sur − deff) − (1 − seplen) ≤ size
         *   若这个不等式不成立，说明我对 Src 布局的假设出了问题。此时宁可放手、交给
         *   gen     exit_fallback 兜底，也不能去写坏游戏的对象 —— 这类写坏的典型表现就是"很久之后
         *   某个 CString 移动赋值读源越界"（2026-10-05 的 C0000005 @ RVA 0x94F4A），
         *   从崩溃点回溯不到我们，极难定位。 */
        if (need > size) { g_sf_want = 0; return; }

        /* 两段式采样，不再"用完永久静默"（详见文件上方日志策略说明）。
         * g_gen_reorder_calls 无论如何都累加 —— 它是"gen     reorder 到底被调了多少次"的权威计数，
         * 采样掉的只是日志行，不是计数。 */
        g_gen_reorder_calls++;
        if (ci >= 0 && MNP_LOG_SHOULD(g_gen_reorder_calls)) {
            log_tid();
            LOGS("[d] gen/reorder #"); LOGD(g_gen_reorder_calls);
            LOGS(" cult=\""); LOGS(cult ? cult : "?");
            LOGS("\" size="); LOGD((uint32_t)size);
            LOGS(" sur="); LOGD((uint32_t)sur);
            LOGS(" nbf="); LOGD((uint32_t)nbf);
            LOGS(" deff="); LOGD((uint32_t)deff);
            LOGS(" nlen="); LOGD((uint32_t)nlen);
            LOGS(" take="); LOGD((uint32_t)take);
            LOGS(" folded="); LOGD((uint32_t)folded);
            LOGS(" sep="); LOGD((uint32_t)seplen);
            LOGS(" sepb0="); LOGD((uint32_t)(seplen ? sepb[0] : 0xFFFFu));
            LOGS(" need="); LOGD((uint32_t)need);
            LOGS(" cap="); LOGD((uint32_t)cap);
            /* ★★★ 关键诊断（2026-10-05 12:47 崩溃后新增）：
             *   那次崩溃证明 gen     reorder 的 buf 落在了一个游戏对象内部
             *   （对象+4 处出现 "lf"... 与 gen     reorder 的 in= 前 13 字节逐字节吻合）。
             *   所以必须把【写入地址】打出来：
             *     sp  —— 站点处 rsp+0x30，即那个局部 CString 的地址
             *     buf —— 实际要写的缓冲区
             *   若 sp 不是栈地址（应落在 0x000000xx_xxxxxxxx 的线程栈区间），
             *   说明寄存器包里的 rsp 修正量错了（当前是 add [rsp+18h],70h）。 */
            LOGS(" sp="); LOGH((uint64_t)(uintptr_t)sp);
            LOGS(" buf="); LOGH((uint64_t)(uintptr_t)buf);
            LOGS(" in=\""); log_bytes(buf, (uint32_t)size); LOGS("\"");
            LOGNL();
        }

        {
            unsigned char ts[512], tg[512];
            size_t sw = 0;
            if (take >= sizeof(ts) || nlen >= sizeof(tg)) { g_sf_want = 0; return; }
            for (k = 0; k < nlen; k++) tg[k] = buf[k];
            /* ★★ 取姓的起点随形态而不同（上一轮重写时把这里写漏，导致"姓少 1 字节 + 开头多空格"）：
             *     形态 A（未折叠）：nlen 处正是"名与姓之间那个空格" ⇒ 姓从 nlen+1 开始
             *     形态 B（已折叠）：nlen 处已经是姓的首字节             ⇒ 姓从 nlen   开始
             *
             * ★★★ 2026-10-05 修复：原来在这里 `if (ch == 0xBF) continue;` 无条件丢掉
             *   所有 0xBF —— 那是把**字符编码字节**当标记删了。
             *   用户已确认 `dynasty_names` 里「线」是纯字符（编码 `12 BF 75`，0xBF 是其
             *   low 字节）⇒ 删掉它「线」就碎成 `12 75`，显示为乱码方块。
             *
             *   现在与双字节补丁同判据：**只在「空格紧跟 0xBF」(`0x20 0xBF`) 时删那个 0xBF**，
             *   其余 0xBF 一律当字符字节保留。这样 `deff`（前面已按同判据算好）与实际
             *   搬运字节数才能对上（否则 `sw != deff` 会直接放手，功能静默失效）。 */
            {
                size_t q = 0;
                while (q < take) {
                    size_t idx = nlen + (folded ? 0 : 1) + q;
                    unsigned char c0 = buf[idx];
                    /* ★ 判据：前一个是 escape(0x10..0x13) ⇒ 字符内部字节，保留；
                     *   否则 ⇒ 独立「¿」，删除。 */
                    if (c0 == 0xBF
                        && !(idx > 0 && buf[idx - 1] >= 0x10 && buf[idx - 1] <= 0x13)) {
                        q++;                    /* 独立「¿」⇒ 跳过（删） */
                        continue;
                    }
                    ts[sw++] = c0;              /* 其余原样（含字符内的 0xBF） */
                    q++;
                }
            }
            if (sw != deff) { g_sf_want = 0; return; }

            for (k = 0; k < deff; k++)   buf[k] = ts[k];
            for (k = 0; k < seplen; k++) buf[deff + k] = sepb[k];
            for (k = 0; k < nlen; k++)   buf[deff + seplen + k] = tg[k];
            buf[need] = 0;
            *(size_t *)(void *)(sp + 0x10) = need;
        }
        (void)folded;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_sf_want = 0;
        return;
    }
    g_sf_reordered   = 1;   /* ★ 已按文化重排完毕 */
    g_sf_want = 0;   /* 用过就清，避免影响后续调用 */
    g_sur_len   = 0;   /* 一并清掉，不给下一次调用留残值 */
}

/* ★★★ gen     loop_decide（0x00314228，循环之前）：只判断文化并置位，**绝不碰 Src**。
 *
 * ★★ 为什么这里不能写 Src（血泪）：Src 在循环之前还是【空 SSO 串】(cap=15 字节)。
 *   而中文姓名按 3 字节/字编码 —— 像「冯 哈布斯堡」这种多字姓轻松超过 15 字节，
 *   于是"提前写姓"这条路会被容量卡死（实测：该文化姓氏后名前，就是这么来的）。
 *   ⇒ 改为只记标志，真正重排交给 gen     surn_len/gen     reorder（那时 Src 已装下「名+空格+姓」，cap 必然够）。 */
static void p7_decide_surname_first(void *src, const void *dyn)
{
    const char *cult = NULL;
    int ci = -1;                     /* ★ 必须初始化：DBGP7("no-cult") 会在赋值前用到它 */

    (void)src;
    (void)dyn;

    /* ★★★ 每次 BuildFullName_Impl 调用开头，把本次调用的全部状态清干净。
     *
     * g_sur_len 必须在这里清 —— 这是实机日志暴露出来的一个真实 bug：
     *   反汇编里有两条路径【跳过 StringAppend】直接到 0x3142FC：
     *       0x1403142d5  jz short loc_1403142FC
     *       0x1403142de  jz short loc_1403142FC
     *   它们**不经过 gen     surn_len 的站点（0x3142F2）** ⇒ 那些调用里 g_sur_len 不会被更新，
     *   如果不清，gen     reorder 就会拿【上一次调用的姓长度】去切当前串 ⇒ 位置错位 + 乱码
     *   （实机现象：size=22 的串被切成 " 名 空格 姓"，多出前导空格）。
     *   ⇒ 清 0 之后，那两条路径下 gen     reorder 会因为 g_sur_len==0 而直接放手。 */
    g_sf_want = 0;
    g_sf_reordered   = 0;
    g_sur_len   = 0;

    __try {
        cult = g_cult_name_ok ? g_cult_name : NULL;
        if (!cult || !cult[0] || g_cc.count <= 0) { DBGP7("no-cult"); return; }
        ci = cc_lookup_name(&g_cc, cult);
        if (ci < 0 || !g_cc.entry[ci].surname_first) { DBGP7("no-cfg"); return; }
        g_sf_want = 1;                 /* ★ 仅置位：本次走"姓前名后"那套逻辑 */
        DBGP7("SET");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_sf_want = 0;
    }
}

/* ★★ 点 2（0x003142FC，Src 即将交给结果之前）：就地重排成「姓 + 配置分隔符 + 名」。
 *
 *   此刻 Src 的内容 = "名0 名1 … " + 姓（循环末尾那个空格就是分隔符，姓紧随其后）。
 *   ⇒ 姓 = 末尾 (dyn->size − 0xBF个数) 字节；名 = 前面的部分。
 *   ⇒ 边界**完全由结构给出**，不猜空格、不依赖 0xBF。
 *   ⇒ 长度变化仅 |sep| − 1 字节，而 Src 的 cap 已经装下过更长的原串，
 *     所以只要 |sep| ≤ 1（空分隔符或一个空格）就**无需扩容**；否则放弃、保持原样。
 *   ★ 本函数只做字节搬移，不调用任何游戏函数（__try/__except 挡不住 C++ 异常）。 */

/* ★ 命中配置时的串形态 dump（诊断用）
 * 为什么需要它（前几轮的根本教训）：我一直拿不到"那个名字串到底长什么样"，
 * 只能从反汇编推断格式 —— `#`（世代）、`0xBF`（双字节补丁标记）、空格数全都猜错过。
 * 这个 helper 直接把证据打出来：size / 空格数与位置 / 0xBF 个数 / 逐字节内容。
 *
 * ★★ 配额必须【按文化分别计数】（2026-10-03 深夜修正）：
 *   起初用的是一个全局计数器（40 次），结果实机日志里
 *   hungarian(7) + vietnamese(8) + japanese(12) + togoku(15) = 42 次
 *   **在到达中国文华之前就把配额耗尽了** ⇒ 关键的 jianghuai/wu/chihan
 *   一行 `[d] gen     exit_fallback` 都没打出来，我又差点据此得出"gen     exit_fallback 没被中国角色调用"的错误结论。
 *   ⇒ 改成每个文化各有一份配额（GEN_EXIT_DUMP_PER_CULT 次），互不挤占。
 *
 * ★★★ 2026-10-05 再改：把"配额用满即永久静默"改成【两段式采样】。
 *   实测这次日志里 33 个文化中有 32 个的 gen     exit_fallback 配额（6 次）早已用满，
 *   也就是说崩溃前的绝大部分 gen     exit_fallback 现场【根本没有记录】——
 *   而"配额满就静默"正是让我把"日志最后一条"误读成"最后发生的事"的元凶。
 *   新规则：前 GEN_EXIT_DUMP_PER_CULT 次全记，之后每 GEN_EXIT_DUMP_STRIDE 次记一次。
 *   这样每个文化的 gen     exit_fallback 在全过程都有覆盖，崩溃前最多漏 GEN_EXIT_DUMP_STRIDE-1 次。 */
#define GEN_EXIT_DUMP_PER_CULT   6                /* 前这么多次全记 */
#define GEN_EXIT_DUMP_STRIDE     32               /* 之后每这么多次记一次（2 的幂） */
#define GEN_EXIT_DUMP_CULT_MAX   64

static char g_gen_exit_dump_cult[GEN_EXIT_DUMP_CULT_MAX][CULT_NAME_MAX];
static int  g_gen_exit_dump_used[GEN_EXIT_DUMP_CULT_MAX];      /* 该文化的累计调用次数 */
static int  g_gen_exit_dump_n = 0;

/* 累计调用次数复用文件上方的 g_gen_exit_calls（line ~295 已定义，int 类型）；
 * 采样掉的只是日志行，不是计数。 */

static int p4_dump_allow(const char *cult)
{
    int i, q;

    if (!cult) return 0;
    g_gen_exit_calls++;

    /* ★ 诊断开关（2026-10-04 重新打开，用于确认 gen     surn_len 到底有没有生效）：
     *   看 [d] gen     exit_fallback in / out 两行就能判定 ——
     *     · in 已经是「姓在前」 ⇒ gen     surn_len（生成阶段）成功，gen     exit_fallback 什么都没做；
     *     · in 是「名在前」、out 才变「姓在前」 ⇒ gen     surn_len 放弃了，是 gen     exit_fallback 出口兜底的。
     *   要彻底关掉就改成 `if (1) return 0;`。 */
    if (0) { (void)i; (void)q; return 0; }
    for (i = 0; i < g_gen_exit_dump_n; i++) {
        q = 0;
        for (;;) {
            if (g_gen_exit_dump_cult[i][q] != cult[q]) break;
            if (!cult[q]) {                              /* 完全相同 */
                int n = ++g_gen_exit_dump_used[i];
                if (n <= GEN_EXIT_DUMP_PER_CULT) return 1;                  /* 前几次全记 */
                return ((n & (GEN_EXIT_DUMP_STRIDE - 1)) == 0) ? 1 : 0;     /* 之后按步长采样 */
            }
            q++;
            if (q >= CULT_NAME_MAX) break;
        }
    }
    if (g_gen_exit_dump_n >= GEN_EXIT_DUMP_CULT_MAX) {
        /* 文化数超上限：退化为全局采样，而不是直接静默 */
        return ((g_gen_exit_calls & (GEN_EXIT_DUMP_STRIDE - 1)) == 0) ? 1 : 0;
    }
    for (q = 0; q < CULT_NAME_MAX - 1 && cult[q]; q++)
        g_gen_exit_dump_cult[g_gen_exit_dump_n][q] = cult[q];
    g_gen_exit_dump_cult[g_gen_exit_dump_n][q] = 0;
    g_gen_exit_dump_used[g_gen_exit_dump_n] = 1;
    g_gen_exit_dump_n++;
    return 1;
}

static void p4_dump_one(cstr_t *s, const char *cult, int ci, const char *tag)
{
    const unsigned char *b;
    size_t q;
    int nsp = 0, nbf = 0, sp_at = -1;

    if (!s) return;
    b = (const unsigned char *)(s->cap >= 0x10 ? (const void *)s->u.ptr
                                               : (const void *)s->u.sso);
    if (!b) return;
    for (q = 0; q < s->size; q++) {
        if (b[q] == 0x20) { nsp++; sp_at = (int)q; }
        else if (b[q] == 0xBF) nbf++;
    }
    log_tid();
    LOGS("[d] gen/fallback "); LOGS(tag);
    LOGS(" s="); LOGH((uint64_t)(uintptr_t)s);      /* ★ CString 对象地址 */
    LOGS(" b="); LOGH((uint64_t)(uintptr_t)b);      /* ★ 实际缓冲区地址 */
    LOGS(" cult=\""); LOGS(cult);
    LOGS("\" #"); LOGD((uint32_t)ci);
    LOGS(" n="); LOGD(g_gen_exit_calls);            /* 全局累计调用次数（采样掉的只是日志行） */
    LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
    LOGS(" size="); LOGD((uint32_t)s->size);
    LOGS(" sp="); LOGD((uint32_t)nsp);
    LOGS("@"); LOGD((uint32_t)(sp_at < 0 ? 0xFFFFFFFFu : (uint32_t)sp_at));
    LOGS(" bf="); LOGD((uint32_t)nbf);
    LOGS(" s=\""); log_bytes(b, s->size); LOGS("\"\r\n");
}

static void p4_fallback_reorder(cstr_t *s, void *ctx, void *culture_in)
{
    void *culture = culture_in;
    int ci;
    int trace = (g_trace_left > 0);

    g_gen_exit_calls++;
    if (trace) {
        LOGS("[t] gen/fallback #"); LOGD((uint32_t)g_gen_exit_calls);
        LOGS(" s="); LOGH((uint64_t)(uintptr_t)s);
        LOGS(" ctx="); LOGH((uint64_t)(uintptr_t)ctx);
        LOGS(" cult="); LOGH((uint64_t)(uintptr_t)culture);
        LOGS(" size="); LOGD((uint32_t)(s ? s->size : 0));
        LOGS(" cap="); LOGD((uint32_t)(s ? s->cap : 0));
        LOGS(" in=\""); if (s) log_bytes((const unsigned char *)(s->cap >= 0x10 ? (const void *)s->u.ptr : (const void *)s->u.sso), s->size);
        LOGS("\"\r\n");
    }

    if (g_no_conf || g_no_xform) {   /* 诊断：不查文化配置（连绑定也不做） */
        if (trace) { LOGS("[t]   (诊断: 跳过文化配置)\r\n"); g_trace_left--; }
        if (!g_no_xform) name_order_apply(s, 1, NULL);
        return;
    }

    /* ★ 首选：用【入口捕获的文化名】直接匹配配置。
     * 该名字由 gen     entry_culture 用 `culture_name_read()`（**带 SSO 判据**）从
     * `文化对象 + CC_CULT_NAME_OFF`(0x48) 读出 —— 短名内联、长名堆指针都能正确处理。
     * 这条路径不依赖注册表、也不依赖被函数体挪用过的 r14 —— 是实机验证后
     * 唯一可靠的取文化方式。命中即用该文化的 surname_first / separator。 */
    if (g_cult_name_ok && g_cc.count > 0) {
        ci = cc_lookup_name(&g_cc, g_cult_name);
        cult_seen_note(g_cult_name);      /* ★ 去重记录：这个文化确实来生成过姓名 */
        if (trace) {
            LOGS("[t]   cult=\""); LOGS(g_cult_name);
            LOGS("\" ci="); LOGD((uint32_t)(ci < 0 ? 0xFFFFFFFFu : (uint32_t)ci));
            if (ci >= 0) {
                LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
                LOGS(" sep_len="); LOGD((uint32_t)g_cc.entry[ci].sep.len);
            }
            LOGS("\r\n");
        }
        if (ci >= 0) {
            const name_sep_t *sep = g_cc.entry[ci].has_sep ? &g_cc.entry[ci].sep : NULL;
            int dump = p4_dump_allow(g_cult_name);
            int done = 0;

            if (dump) {
                p4_dump_one(s, g_cult_name, ci, "in ");
            }

            /* ★★★ 若 gen     loop_decide/gen     surn_len/gen     reorder 已在【生成阶段】按文化拼好（gen     reorder 置 g_sf_reordered），
             *   串此时已是「姓 + sep + 名」，gen     exit_fallback 绝不能再动手 —— 否则会把顺序换回去。
             *   g_sf_reordered 覆盖"gen     reorder 已成功"；g_sf_want 覆盖"还轮到 gen     reorder 但尚未跑"。
             *   （gen     loop_decide 在每次 BuildFullName_Impl 开头会把 g_sf_reordered 清 0。） */
            if (g_sf_reordered || g_sf_want) {
                done = 1;
            }

            /* ★★★ 首选：**用结构给出的姓长度**重排（2026-10-04，本轮新增）。
             *   ctx 现在是 BuildFullName_Impl 的 arg_48 = [rbp+0x78]，
             *   即王朝名 std::string*（起点；size@+0x10、cap@+0x18、data@+0x00）。
             *   ⇒ 姓在结果串末尾占 (size − 0xBF个数) 字节 —— 边界由数据结构确定，
             *     既不猜"唯一的空格"，也不依赖 0xBF 标记。
             *   这条路对【多段名】同样正确（它从末尾数，不受前面空格数量影响）。 */
            if (ctx) {
                __try {
                    const unsigned char *d = (const unsigned char *)ctx;
                    size_t dsize = *(const size_t *)(const void *)(d + 0x10);
                    size_t dcap  = *(const size_t *)(const void *)(d + 0x18);
                    const unsigned char *ddata = (dcap >= 0x10)
                        ? *(const unsigned char *const *)d : d;
                    if (dump) {
                        LOGS("[d] gen/fallback struct dsize="); LOGD((uint32_t)dsize);
                        LOGS(" dcap="); LOGD((uint32_t)dcap);
                        LOGS(" slen="); LOGD((uint32_t)s->size);
                        LOGS(" scap="); LOGD((uint32_t)s->cap);
                        LOGS(" raw12=\""); log_bytes(d, 12); LOGS("\"");
                        LOGNL();
                    }
                    if (dsize > 0 && ddata && dsize < 256) {
                        size_t z, nbf = 0, deff;
                        /* ★★★ 2026-10-05 定案：0xBF 两种身份，判据 = 「前一字节是不是 escape」。
                         *   转码器实测：「¿」U+00BF < 256 ⇒ 编码就是裸 0xBF（独立字符，删）；
                         *             「线」U+7EBF ⇒ `12 BF 75`（第 2 字节是字符内部，留）。
                         *   见 scripts/encode_eu4_special.py。 */
                        for (z = 0; z < dsize; z++) {
                            unsigned char b = ddata[z];
                            if (b == 0xBF && !(z > 0 && ddata[z - 1] >= 0x10
                                               && ddata[z - 1] <= 0x13)) {
                                nbf++;
                            }
                        }
                        deff = dsize - nbf;
                        if (deff > 0) {
                            /* ★ 两种形态（未折叠 / 已折叠）都在函数内部试；
                             *   只有它真的改了串才置 done，否则留给下面的兜底。 */
                            if (name_order_apply_struct(s, dsize, deff, sep)) done = 1;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    done = 0;
                }
            }

            /* 兜底：拿不到姓（或形态不符）时，退回原来的判据路径 */
            if (!done) {
                name_order_apply_cfg(s, g_cc.entry[ci].surname_first, sep, 1);
            }

            if (dump) {
                p4_dump_one(s, g_cult_name, ci, "out");
            }
        } else {
            /* ★★ 未配置姓前名后的文化 —— **这正是 gen     exit_fallback 的职责**（用户明确定义）：
             *   处理双字节补丁遗留的 0xBF（它在姓名出口手动读该标记来调整顺序）。
             *   注意 0xBF 只是那个补丁作者额外做的功能，**不是 mod 数据的约定**。 */
            name_order_apply(s, 1, NULL);
        }
        goto out;
    }

    cc_lazy_ready();                 /* 回退：旧的对象绑定路径（注册表） */

    if (!culture && ctx) {
        __try {
            culture = *(void **)((uint8_t *)ctx + 0x88);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            culture = NULL;
        }
    }

    ci = (culture && g_cc.count > 0) ? cc_lookup(&g_cc, culture) : -1;

    if (trace) {
        LOGS("[t]   -> bound_state="); LOGD((uint32_t)g_cc_lazy_state);
        LOGS(" xref="); LOGD((uint32_t)g_cc.xref_n);
        LOGS(" ci="); LOGD((uint32_t)(ci < 0 ? 0xFFFFFFFFu : (uint32_t)ci));
        if (ci >= 0) {
            LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
            LOGS(" sep_len="); LOGD((uint32_t)g_cc.entry[ci].sep.len);
        }
        LOGS("\r\n");
        g_trace_left--;
    }

    if (ci >= 0) {
        const name_sep_t *sep = g_cc.entry[ci].has_sep ? &g_cc.entry[ci].sep : NULL;
        name_order_apply(s, g_cc.entry[ci].surname_first, sep);
    } else {
        name_order_apply(s, 1, NULL);            /* 未配置 ⇒ 沿用 0xBF 标记判据 */
    }

    if (trace) {
        LOGS("[t]   out size="); LOGD((uint32_t)(s ? s->size : 0));
        LOGS(" out=\""); if (s) log_bytes((const unsigned char *)(s->cap >= 0x10 ? (const void *)s->u.ptr : (const void *)s->u.sso), s->size);
        LOGS("\"\r\n");
    }
out:
    ;
}


/* ==================================================================== */

static void culture_capture_from_ctx(void *a3)
{
    char tmp[CULT_NAME_MAX];
    uint32_t sso_len;
    int n, k;

    if (!a3) return;

    /* ★★★ 读取：**带 SSO 判据**（2026-10-05 根因修复）。
     *   `a3 + CC_CULT_NAME_OFF` 是 std::string 的数据/SSO 联合字段 ——
     *   cap<0x10 时数据内联在此，cap>=0x10 时这里是堆指针。
     *   原来直接把 `+0x48` 当 `char*` 读 ⇒ 长名（≥16 字符，如 shandong_culture）
     *   永远读不出来，这正是"长名文化从未进入任何取名函数"的直接原因。 */
    sso_len = culture_name_read(a3, CC_CULT_NAME_OFF, tmp, CULT_NAME_MAX, 0);
    n = (int)sso_len;
    if (n <= 0) return;

    /* ★★★ 2026-10-05：**删掉原来的 ASCII 校验**（用户批准）。
     *
     * 原代码在这里逐字节要求 `0x20 <= c < 0x7F`，非 ASCII 一律 return。
     * 删掉的理由有两条：
     *   ① 判据不该由我定。用户此前已明确否掉过同类做法
     *      （`cc_name_looks_valid`："用我自己假定的格式去否认真实数据"）——
     *      中文/日文 mod 完全可以有非 ASCII 文化名，那样会被整条丢掉。
     *   ② 它与 disp    ruler_name 那条路**判据不一致**：disp    ruler_name 早就改成"配置表能不能查到"，
     *      这里却还在用格式假设。同一个名字两侧结论可能不同。
     *
     * 现在改成与 disp    ruler_name 一致：**查得到配置就用，查不到就放手**（见下方 cc_lookup_name）。
     * 安全性由 `culture_name_read` 保证 —— 它已经校验了
     *   "cap/size 合理" + "结尾确实是 \0" + "指针可读"，
     * 伪串即便长度合法也过不了配置表这一关，不会有副作用。 */
    if (n >= CULT_NAME_MAX - 1) return;

    if (g_cult_name_ok && g_cult_name_len == n && memcmp(g_cult_name, tmp, (size_t)n) == 0)
        return;                                  /* 与上次同文化 ⇒ 无需动作 */

    for (k = 0; k <= n; k++) g_cult_name[k] = tmp[k];
    g_cult_name_len = n;
    g_cult_name_ok = 1;

    /* ★ 日志策略（2026-10-03 深夜，按用户要求修正两次）：
     *   ① 早先是"文化切换时最多记 12 次"（g_cult_logs_left = 12）。那是个陷阱：
     *      我拿"日志里只看到欧洲文化"去推断"统治者不经过 BuildFullName_Impl"，
     *      而真相只是**日志被截断**。用户当场指出。
     *   ② 我随后改成"每个不同文化都记一次" —— 又被用户纠正：
     *      **游戏有几百个文化，绝大多数没有配置，列出来没有意义。**
     *      我们真正关心的只有一件事：**哪些文化命中了配置、会做姓前名后处理。**
     *   ⇒ 最终策略：**只记录【命中配置】的文化**（去重），并带上配置摘要
     *      （配置序号 / surname_first / 分隔符长度）。
     *      这既没有噪音，又能直接回答"某个角色生成名字时，到底命中了哪条配置"。 */
    if (g_cc.count > 0) {
        int ci = cc_lookup_name(&g_cc, g_cult_name);
        if (ci >= 0) {
            int seen = 0, m;
            for (m = 0; m < g_cult_seen_n; m++) {
                int q = 0, same = 1;
                while (q <= n) {
                    if (g_cult_seen[m][q] != tmp[q]) { same = 0; break; }
                    if (!tmp[q]) break;
                    q++;
                }
                if (same) { seen = 1; break; }
            }
            if (!seen && g_cult_seen_n < CULT_LOG_MAX) {
                for (k = 0; k <= n && k < CULT_NAME_MAX; k++)
                    g_cult_seen[g_cult_seen_n][k] = tmp[k];
                g_cult_seen[g_cult_seen_n][CULT_NAME_MAX - 1] = 0;
                g_cult_seen_n++;
                /* 发布模式：逐文化命中留痕不打（实测 AHR 一个 tag 就几百行）。 */
                if (g_log_verbose) {
                    LOGS("[i] culture HIT: \""); LOGS(g_cult_name);
                    LOGS("\" #"); LOGD((uint32_t)ci);
                    LOGS(" sf="); LOGD((uint32_t)g_cc.entry[ci].surname_first);
                    LOGS(" sep_len="); LOGD((uint32_t)(g_cc.entry[ci].has_sep
                                                       ? g_cc.entry[ci].sep.len : 0));
                    LOGNL();
                }
            }
        }
    }
}

/* gen     entry_culture 入口钩子：ctx = BuildFullName_Impl 的第 3 参数（= 入口处的 r8）。
 *
 * 职责（正式功能，不是诊断）：把【当前这次调用所属的文化名】从 ctx+0x48 捕获到
 * g_cult_name，供出口侧的 gen     exit_fallback 查配置使用。见 culture_capture_from_ctx 的注释。
 * 只读字符串、不解引用任何其它偏移 ⇒ 零崩溃风险。 */
static void p6_capture_culture(void *ctx)
{
    culture_capture_from_ctx(ctx);
}

/* gen     entry_culture：站点 = BuildFullName_Impl 入口 RVA 0x00313F40，
 * 覆盖 5 字节 48 89 5C 24 08 (mov [rsp+8], rbx)，回跳 0x00313F45。
 * 栈对齐：入口 rsp ≡ 8；sub rsp, 0x48（72 ≡ 8）⇒ call 前 rsp ≡ 0 ✓ */

/* ------------------------------------------------------------------ */
/* common\cultures_name\ 配置的加载（只用 kernel32，静态缓冲，不用 CRT 堆） */
/* ------------------------------------------------------------------ */
#define CC_DIRNAME        L"common\\cultures_name"
#define CC_READ_MAX       (1u << 20)      /* 单个配置文件读入上限 1 MiB */
#define CC_ROOT_MAX       1024
#define CC_MODPATH_MAX    1024
#define CC_MAX_MODFILES   256

static uint8_t  *g_cc_buf = NULL;         /* 读文件缓冲（VirtualAlloc） */

static uint32_t w_len(const WCHAR *s) { uint32_t n = 0; while (s[n]) n++; return n; }

static int w_join(WCHAR *buf, uint32_t cap, const WCHAR *a, const WCHAR *b)
{
    uint32_t n = w_len(a);
    uint32_t i;
    if (n + 1 >= cap) return 0;
    for (i = 0; a[i]; i++) buf[i] = a[i];
    for (i = 0; b[i]; i++) {
        if (n + i + 1 >= cap) return 0;
        buf[n + i] = b[i];
    }
    buf[n + i] = 0;
    return 1;
}

/* 指向 buf 内最后一个分隔符（用于截断文件名） */
static WCHAR *w_last_sep(WCHAR *buf)
{
    WCHAR *p = buf, *last = NULL;
    while (*p) { if (*p == L'\\' || *p == L'/') last = p; p++; }
    return last;
}

static int file_read_all(const WCHAR *path, uint8_t *dst, uint32_t cap, uint32_t *out_len)
{
    HANDLE h;
    DWORD got = 0;
    *out_len = 0;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(h, dst, cap - 1, &got, NULL)) { CloseHandle(h); return 0; }
    CloseHandle(h);
    dst[got] = 0;
    *out_len = got;
    return 1;
}

/* 解析一个配置文件（缓冲需含结尾 NUL） */
static void cc_handle_file(const WCHAR *path)
{
    uint32_t len = 0;
    if (!g_cc_buf) return;
    if (!file_read_all(path, g_cc_buf, CC_READ_MAX, &len)) {
        LOGS("[!] culture config unreadable: "); LOGW(path); LOGNL();
        return;
    }
    g_cc_files++;
    cc_parse(&g_cc, (const char *)g_cc_buf, len);
}

static void cc_scan_dir(const WCHAR *dir)
{
    WCHAR pat[CC_ROOT_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    if (!w_join(pat, CC_ROOT_MAX, dir, L"\\*")) return;
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        WCHAR full[CC_ROOT_MAX];
        uint32_t n;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        n = w_len(fd.cFileName);
        if (n < 4) continue;
        if (lstrcmpiW(fd.cFileName + n - 4, L".txt") != 0) continue;
        if (!w_join(full, CC_ROOT_MAX, dir, L"\\")) continue;
        if (!w_join(full, CC_ROOT_MAX, full, fd.cFileName)) continue;
        cc_handle_file(full);
    } while (g_cc_files < 256 && FindNextFileW(h, &fd));
    FindClose(h);
}

/* 打开 dlc_load.json，取出 enabled_mods 数组里的候选模组文件名片段。
 * 不实现完整 JSON 解析：只在数组范围内逐个取带引号的字符串。 */
static HANDLE dlc_load_open(const WCHAR *userdir, uint8_t **buf, uint32_t *len)
{
    WCHAR path[CC_ROOT_MAX];
    HANDLE h;
    DWORD got = 0;

    *buf = NULL; *len = 0;
    if (!w_join(path, CC_ROOT_MAX, userdir, L"\\dlc_load.json")) return INVALID_HANDLE_VALUE;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    if (!g_cc_buf) { CloseHandle(h); return INVALID_HANDLE_VALUE; }
    if (!ReadFile(h, g_cc_buf, CC_READ_MAX - 1, &got, NULL)) { CloseHandle(h); return INVALID_HANDLE_VALUE; }
    CloseHandle(h);
    g_cc_buf[got] = 0;
    *buf = g_cc_buf;
    *len = got;
    return (HANDLE)1;                       /* 仅作"成功"标志 */
}

/* 在 .mod 描述里找 path="..."；找到返回其内容（拷进 out） */
static int mod_read_path(const WCHAR *modpath, WCHAR *out, uint32_t outcap)
{
    WCHAR full[CC_MODPATH_MAX];
    static uint8_t tmp[65536];
    uint32_t len = 0;
    const char *p, *end;

    if (!w_join(full, CC_MODPATH_MAX, modpath, L"")) return 0;
    if (!file_read_all(full, tmp, sizeof(tmp), &len)) return 0;

    p = (const char *)tmp;
    end = p + len;
    while (p < end) {
        if ((p[0] == 'p' || p[0] == 'P') &&
            (p[1] == 'a' || p[1] == 'A') &&
            (p[2] == 't' || p[2] == 'T') &&
            (p[3] == 'h' || p[3] == 'H')) {
            const char *q = p + 4;
            while (q < end && (*q == ' ' || *q == '\t')) q++;
            if (q < end && *q == '=') {
                uint32_t n = 0;
                q++;
                while (q < end && (*q == ' ' || *q == '\t')) q++;
                if (q < end && *q == '"') {
                    q++;
                    while (q < end && *q != '"' && *q != '\r' && *q != '\n' && n + 1 < outcap)
                        out[n++] = (WCHAR)(unsigned char)*q++;
                } else {
                    while (q < end && *q != '\r' && *q != '\n' && n + 1 < outcap)
                        out[n++] = (WCHAR)(unsigned char)*q++;
                }
                while (n > 0 && (out[n - 1] == L' ' || out[n - 1] == L'\t')) n--;
                out[n] = 0;
                return n > 0;
            }
        }
        p++;
    }
    return 0;
}

/* 游戏根目录（= 本 DLL 所在 plugins\ 的上一级） */
static WCHAR g_game_root[CC_ROOT_MAX];
static WCHAR g_user_dir[CC_ROOT_MAX];

static void derive_game_root(HMODULE self)
{
    WCHAR buf[CC_ROOT_MAX];
    WCHAR *sep;
    GetModuleFileNameW(self, buf, CC_ROOT_MAX);
    sep = w_last_sep(buf);          /* 指向 '\\'（DLL 文件名之前） */
    if (sep) *sep = 0;              /* → "...\plugins" */
    sep = w_last_sep(buf);
    if (sep) *sep = 0;              /* → "...\<游戏根>" */
    lstrcpynW(g_game_root, buf, CC_ROOT_MAX);
}

static void derive_user_dir(void)
{
    WCHAR path[CC_ROOT_MAX];
    static uint8_t tmp[4096];
    uint32_t len = 0, i, n = 0;

    g_user_dir[0] = 0;
    if (w_join(path, CC_ROOT_MAX, g_game_root, L"\\userdir.txt") &&
        file_read_all(path, tmp, sizeof(tmp), &len) && len > 0) {
        const char *p = (const char *)tmp;
        /* 去掉 UTF-8 BOM */
        if (len >= 3 && (unsigned char)p[0] == 0xEF &&
            (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) { p += 3; len -= 3; }
        for (i = 0; i < len && n + 1 < CC_ROOT_MAX; i++) {
            if (p[i] == '\r' || p[i] == '\n') break;
            g_user_dir[n++] = (WCHAR)(unsigned char)p[i];
        }
        while (n > 0 && (g_user_dir[n - 1] == L' ' || g_user_dir[n - 1] == L'\t')) n--;
        g_user_dir[n] = 0;
    }
    if (g_user_dir[0]) {
        LOGS("[i] userdir.txt -> "); LOGW(g_user_dir); LOGNL();
        return;
    }
    {
        WCHAR up[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", up, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            WCHAR suffix[] = L"\\Documents\\Paradox Interactive\\Europa Universalis IV";
            if (w_join(g_user_dir, CC_ROOT_MAX, up, suffix))
                LOGS("[i] user dir (%%USERPROFILE%%) -> "); LOGW(g_user_dir); LOGNL();
        }
    }
}

/* 读用户目录下 dlc_load.json 的 enabled_mods → 各 .mod → path= → 扫该模组的配置 */
static void cc_scan_enabled_mods(void)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    WCHAR modfile[CC_MAX_MODFILES][CC_MODPATH_MAX];
    uint32_t nmods = 0, i, j;

    if (dlc_load_open(g_user_dir, &buf, &len) == INVALID_HANDLE_VALUE) {
        LOGS("[i] dlc_load.json not found -> only game dir scanned\r\n");
        return;
    }
    {
        const char *p = (const char *)buf;
        const char *end = p + len;
        const char *arr = NULL;
        int depth = 0;
        /* 找 "enabled_mods" 后的 '[' */
        while (p + 14 < end) {
            if (p[0] == '"' && !memcmp_local(p + 1, "enabled_mods", 12) && p[13] == '"') {
                const char *q = p + 14;
                while (q < end && *q != '[' && *q != '{' && *q != '\n' && *q != '}') q++;
                if (q < end && *q == '[') { arr = q + 1; }
                break;
            }
            p++;
        }
        if (arr) {
            p = arr;
            while (p < end && nmods < CC_MAX_MODFILES) {
                if (*p == ']') break;
                if (*p == '"') {
                    uint32_t n = 0;
                    p++;
                    while (p < end && *p != '"' && n + 1 < CC_MODPATH_MAX) {
                        modfile[nmods][n++] = (WCHAR)(unsigned char)*p++;
                    }
                    modfile[nmods][n] = 0;
                    if (n) nmods++;
                    if (p < end && *p == '"') p++;
                    continue;
                }
                p++;
            }
        }
        (void)depth;
    }

    LOGS("[i] enabled mods = "); LOGD(nmods); LOGNL();
    for (i = 0; i < nmods; i++) {
        WCHAR modpath[CC_MODPATH_MAX];
        WCHAR vpath[CC_MODPATH_MAX];
        WCHAR cdir[CC_ROOT_MAX];
        uint32_t n;

        if (modfile[i][0] == L'/' || (modfile[i][0] && modfile[i][1] == L':')) {
            lstrcpynW(modpath, modfile[i], CC_MODPATH_MAX);
        } else {
            if (!w_join(modpath, CC_MODPATH_MAX, g_user_dir, L"\\")) continue;
            if (!w_join(modpath, CC_MODPATH_MAX, modpath, modfile[i])) continue;
        }
        vpath[0] = 0;
        if (!mod_read_path(modpath, vpath, CC_MODPATH_MAX)) continue;
        vpath[CC_MODPATH_MAX - 1] = 0;

        n = w_len(vpath);
        while (n > 0 && (vpath[n - 1] == L'\\' || vpath[n - 1] == L'/')) vpath[--n] = 0;
        if (n == 0) continue;

        if (vpath[0] == L'/' || (n > 1 && vpath[1] == L':')) {
            lstrcpynW(cdir, vpath, CC_ROOT_MAX);
        } else {
            if (!w_join(cdir, CC_ROOT_MAX, g_user_dir, L"\\")) continue;
            if (!w_join(cdir, CC_ROOT_MAX, cdir, vpath)) continue;
        }
        if (GetFileAttributesW(cdir) == INVALID_FILE_ATTRIBUTES) {
            LOGS("[!] mod path missing: "); LOGW(cdir); LOGNL();
            continue;
        }
        if (!w_join(cdir, CC_ROOT_MAX, cdir, L"\\" CC_DIRNAME)) continue;
        LOGS("[i] mod cultures_name: "); LOGW(cdir); LOGNL();
        cc_scan_dir(cdir);
    }
    (void)j;
}

/* 入口：读全部配置并把文化名解析成对象指针 */
static void cc_init(HMODULE self)
{
    WCHAR dir[CC_ROOT_MAX];

    if (!g_mod) return;
    if (!g_cc_buf) {
        g_cc_buf = (uint8_t *)VirtualAlloc(NULL, CC_READ_MAX, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
        if (!g_cc_buf) { LOGS("[!] culture config buffer alloc failed\r\n"); return; }
    }
    memset(g_cc_buf, 0, 64);

    g_cc.modbase = g_mod;
    g_cc.rd.rd   = dll_read;
    g_cc.rd.ok   = dll_region_ok;
    g_cc.rd.ctx  = NULL;

    derive_game_root(self);
    derive_user_dir();

    if (w_join(dir, CC_ROOT_MAX, g_game_root, L"\\" CC_DIRNAME)) {
        LOGS("[i] game cultures_name: "); LOGW(dir); LOGNL();
        cc_scan_dir(dir);
    }
    if (g_user_dir[0]) cc_scan_enabled_mods();

    g_cc_entries_n = (uint32_t)g_cc.count;
    /* 【不要在这里 cc_resolve】安装期文化数据未加载、注册表单例还是 0，
     * 这里解析只会得到空结果并被永久缓存。绑定改到第一次变换调用时做：
     * 见 cc_lazy_ready() / p4_fallback_reorder()。 */

    /* ★★★ 把【载入的配置】整份列进日志（用户要求，2026-10-05）
     *
     * 起因：用户报告 SDA 的姓"亢"没能姓前名后，而 shandong_culture
     * 在配置里是写了的；日志里该文化的 gen     loop_decide/gen     reorder/gen     exit_fallback 计数却全为 0。
     * 两者矛盾 ⇒ 要么配置文件没被读到，要么解析时把这个条目丢了。
     *
     * ★ 必须在这里（解析刚结束、且与绑定成功与否无关）调用：
     *   上一轮把它放在 cc_lazy_ready() 的绑定成功分支里，而那条分支
     *   在实机上永远走不到（gen     exit_fallback 走"按文化名查配置"的快路径直接 goto out），
     *   结果整份清单一条都没进过日志。
     *   此时注册表还没建好 ⇒ 每条都会打 bound=0，这是预期行为。
     *
     * 这段日志直接回答"到底读到了哪些文化、顺序如何、分隔符是什么"：
     *   [i] CFGENTRY #<索引> "<文化名>" sf=<0/1> sep_len=<n> sep="<字节>" bound=<0/1>
     * 只要 shandong_culture 不在这份清单里，问题就在读取/解析侧；
     * 它在清单里、日志里却见不到它的 gen     loop_decide/gen     exit_fallback ⇒ 问题在"游戏有没有用这个名字
     * 生成姓名"，而不是我们的判断侧。 */
    cc_list_dump(&g_cc, log_str, g_cc_files);

    LOGS("[i] culture config: files="); LOGD(g_cc_files);
    LOGS(" entries="); LOGD(g_cc_entries_n);
    LOGS(" bound=0 (deferred: lazy bind at first transform)\r\n");
    LOGS("[i] registry slot="); LOGH((uint64_t)(uintptr_t)(g_mod + CC_REGISTRY_OFF));
    LOGS("\r\n");
}

/* --- modfix  pick_idx: WeightedNameList_PickByRandomIndex（RVA 0x140DA9880）入口 ---
 * 覆盖 0x140DA989B..9F（5 字节）: 49 8B F8 (mov rdi,r8) / 8B F2 (mov esi,edx)
 * 回跳 0x140DA98A0（原 `mov r10,rcx`），即站点后紧接着的一条指令。
 *
 * ★★ 为什么重写（2026-10-03 15:06 实机证据）：
 *   `.only1`（只挂 modfix  pick_idx、其余全不挂）仍然崩在 0x140DA99F2（`mov r11,[r10+18h]`，
 *   r10=a1 已是野指针）⇒ **modfix  pick_idx 单独就足以致命**。
 *
 *   旧实现是 `and edx, 001FFFFFh` —— 它有两个错：
 *     ① **改错了寄存器语义**。原指令在 0x140DA98C3 用 `mov eax, edx`（a2）作被除数、
 *        0x140DA98C9 `cdq` 再 `idiv ecx`；而 `edx` 里那份 a2 是给 mode1 分支单独用的
 *        （0x140DA989E `mov esi,edx`）。把 `edx` 掩码会连带改掉 mode1 的输入。
 *     ② **只掩输入、不管除数**：`idiv` 的除数（ecx/r15）为 0 或负数时照样出问题，
 *        而这正是我当初想修的。
 *
 *   新实现严格保持**有符号语义**（`cdq` + `idiv`，与原版逐条对应），只把
 *   "除数 <= 0" 这一种原始代码会死掉的情形，改走游戏自己的失败返回值（eax=0）。
 *   除数就是 r15，在站点处已是调用者的值（本函数序言只保存 r15、未改写）。 */




/* 从 PE 头取 SizeOfImage / TimeDateStamp / 机器类型；并给出 .text 范围 */
static int pe_info(uint8_t *base, uint32_t *size_out, uint32_t *ts_out,
                   uint8_t **text, size_t *text_len)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned i;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;

    *size_out = nt->OptionalHeader.SizeOfImage;
    *ts_out   = nt->FileHeader.TimeDateStamp;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *text = base + sec->VirtualAddress;
            *text_len = sec->Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}



/* ------------------------------------------------------------------ */
/* 新钩子层：安装（C++ 实现见 install.cpp）                              */
/* ------------------------------------------------------------------ */
/* C 侧只做两件事：
 *   ① 把桩要调用的 C 函数地址填进 hookvars.c 的全局（stubs.asm 的 EXTERN 变量）；
 *   ② 把日志函数交给 C++ 层（这样 C++ 不必知道日志怎么开）。
 * 其余（分配 cave、模式定位、建跳板）都由 install.cpp 负责。 */
/* ==================================================================== */
/* 新钩子层的 C++ 处理器（reg_pack 版）                                  */
/* ==================================================================== */
/* 通用 trampoline 已经把 16 个通用寄存器 + RFLAGS 打包成 mnp::reg_pack 传进来，
 * 这里只写业务逻辑；被覆盖的原指令由 stubs.asm 里那 1~3 行重放。
 * 本文件完全不碰汇编 —— 这正是照 EU4dll 的 MakeInline 思路改造的目的。
 *
 * ★★★ 站点命名约定（2026-10-05 统一）：完整对照表在 stubs.hpp 的文件头，
 *   格式为 `mnp_h_pN_<动作>`，与 stubs.asm 的 `mnp_hook_pN_<动作>`、
 *   hookvars.cpp 的 `mnpfn_pN_<动作>`、install.cpp 的 `"PN  <动作>"` 一一对应。
 *   速查：
 *     modfix  pick_idx  runmask   随机值掩成 21 位非负      gen     loop_decide  decide   判定该文化是否姓前名后
 *     modfix  pick_cult  modulo    有符号取模 → 无符号        gen     surn_len surnlen  记下姓的字节数
 *     modfix  pick_modidx  modulo    有符号取模 → 无符号        gen     reorder reorder  就地重排「姓 sep 名」
 *     gen     entry_culture  culture   捕获本次调用的文化名       gen     exit_fallback  fallback 出口兜底重排
 *                                              disp    ruler_name  display  显示期统治者重排
 *
 * ★ 排列顺序与 install.cpp 的 kSites[]、stubs.asm 的 trampoline 一致：
 *     组 1 名字选取（取模修复）  modfix  pick_idx / modfix  pick_cult / modfix  pick_modidx
 *     组 2 生成期姓名顺序        gen     entry_culture / gen     loop_decide / gen     surn_len / gen     reorder / gen     exit_fallback
 *     组 3 统治者显示链          disp    ruler_name
 *
 * ★ 编号 modfix  pick_idx..gen     reorder 是【按添加时间】编的，不是执行顺序（gen     exit_fallback 是出口却编号在前，
 *   modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx 反而是最后补的）。编号保留不动 —— 它在 notes 的多份历史文档里
 *   被引用过，重编号会让旧笔记全部失准。顺序靠分组与注释表达。
 *
 * 参数取值依据（站点处 x64 Windows ABI）：
 *   modfix  pick_idx  rdx = 随机值（Random_GetGlobalMT 的完整 32 位）
 *   modfix  pick_cult  rdi = 被除数源（第 1 参数），r8d = 除数
 *   modfix  pick_modidx  rdx = 被除数源（第 2 参数），r8d = 除数
 *   gen     entry_culture  第 3 参数 r8 = 文化对象
 *   gen     loop_decide  Src = [rbp-0D0h]，王朝名 = [rbp+78h]
 *   gen     surn_len r8 = 姓的字节数，Src = [rsp+30h]
 *   gen     reorder Src = [rsp+30h]
 *   gen     exit_fallback  rax = 输出对象（就是本函数的返回值）、[rbp+78h] = 姓、[r14+88h] = 文化名
 *   disp    ruler_name  rbx = out、rdi = CMonarch*
 */

/* ==================================================================== */
/* 组 1：取模修复（modfix  pick_idx / modfix  pick_cult / modfix  pick_modidx）                                       */
/* ==================================================================== */
/* 三处共同病根：随机值/索引的高位为 1 时，【有符号】除法产生负余数。
 * 调用方拿到负余数后会把它当"越界"或直接算成负偏移，
 * 于是大量取样回落到第 0 号位 —— 即"取第一号位的概率被放大"。
 *
 * ★ 分工原则（modfix  pick_idx 与 modfix  pick_cult/modfix  pick_modidx 不同）：
 *   · 纯数据操作（掩码、清零）→ 放在 handler 里改 reg_pack；
 *   · 除法指令本身            → 留在桩里执行。
 *   因为 `div` 的溢出行为（商放不下 32 位时抛 #DE）必须与硬件一致，
 *   用 C++ 的 `/` 表达不了。 */

/* ---- modfix  pick_idx runmask：WeightedNameList_PickByRandomIndex 序言（RVA 0xDA989B）----
 * ★★★ 这是【继承人取名实际走的那条路径】，也是"取第一号位概率被放大"的主因。
 *
 * 站点覆盖两条普通 mov（`mov rdi,r8` / `mov esi,edx`）。原实现在后面直接做：
 *     0x140DA98C3  mov  eax, edx           ; ★ 直接拿 edx 当被除数
 *     0x140DA98C9  cdq
 *     0x140DA98CA  idiv ecx                ; ★ 有符号除法
 * 而 edx 的来源是 `Random_GetGlobalMT()` 的【完整 32 位】—— 可以为负。
 *
 * 调用链（见 notes\继承人姓名子系统-调用链与未决事项.md §2）：
 *     Country_CreateHeir_Impl
 *       └─ GenerateMonarchNameAlt
 *            └─ WeightedNameList_PickByRandomIndex(mode = 性别 byte)
 *                 mode == 1 ⇒ 0x140DA98CA
 * 该文档明确写着："modfix  pick_idx 精确命中继承人取名实际走的 mode 1 路径"。
 *
 * ★ 为什么只需掩 edx、不必单独掩 esi：
 *   `esi` 是 mode 0/2 使用的副本，而取它的那条指令
 *       mov esi, edx
 *   正是本站点覆盖的第 2 条、由桩在【掩码之后】重放
 *   ⇒ esi 自然拿到同一个非负值，两条路径一起被覆盖。
 *
 * ★ 本站点整段都是数据操作，桩里没有除法指令，所以掩码放在这里，
 *   桩只负责重放那两条 mov。 */
static void mnp_h_modfix_pick_idx(mnp::reg_pack &r)
{
    stat_bump(ST_MODFIX_IDX);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    r.rdx.i = static_cast<std::uint64_t>(
                  static_cast<std::uint32_t>(r.rdx.i) & 0x001FFFFFu);
    MNP_SITE_GUARD_END("modfix/pick_idx")
}

/* ---- modfix  pick_cult modulo：PickNameFromCultureLists 取模（RVA 0x280274）----
 * 原指令： 8B C7   mov  eax, edi
 *          99      cdq                  ← 有符号扩展
 *          41 F7 F8 idiv r8d             ← 有符号除法
 * 调用方紧接着 `cmp ecx,edx / jge 0x280289` —— 负余数被当成"越界"。
 * 修法：掩掉高位 + 清 edx（无符号除法的高 32 位），除法由桩里的 `div r8d` 完成。 */
static void mnp_h_modfix_pick_cult(mnp::reg_pack &r)
{
    stat_bump(ST_MODFIX_CULT);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    r.rax.i = static_cast<std::uint64_t>(
                  static_cast<std::uint32_t>(r.rdi.i) & 0x001FFFFFu);
    r.rdx.i = 0;
    MNP_SITE_GUARD_END("modfix/pick_cult")
}

/* ---- modfix  pick_modidx modulo：WeightedNameList_GetByModIndex 取模（RVA 0xDA9A82）----
 * 同一个错误，源操作数是 edx（第 2 参数）。
 * 该函数元素 40 字节：(end-begin)/8/5 ⇒ /40，返回 begin + (index%count)*40；
 * 负余数会直接算出野地址（潜伏型 OOB，见 notes 同一文档 §2）。 */
static void mnp_h_modfix_pick_modidx(mnp::reg_pack &r)
{
    stat_bump(ST_MODFIX_MODIDX);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    r.rax.i = static_cast<std::uint64_t>(
                  static_cast<std::uint32_t>(r.rdx.i) & 0x001FFFFFu);
    r.rdx.i = 0;
    MNP_SITE_GUARD_END("modfix/pick_modidx")
}



/* ==================================================================== */
/* 组 2：生成期姓名顺序（gen entry_culture / loop_decide / surn_len /    */
/*                       reorder / exit_fallback）                       */
/* ==================================================================== */
/* 全部在 BuildFullName_Impl（0x313F40..0x31434E）内部，按执行时机排列。 */

/* ---- gen     entry_culture culture：函数入口（RVA 0x313F40）----
 * 第 3 参数 r8 = 文化对象，文化名在 a3+0x48。
 * 必须【每次调用都刷新】—— 只捕获一次会让"逐文化细分"退化成单文化。 */
static void mnp_h_gen_entry_culture(mnp::reg_pack &r)
{
    stat_bump(ST_GEN_ENTRY);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    p6_capture_culture((void *)(uintptr_t)r.r8.i);
    MNP_SITE_GUARD_END("gen/entry_culture")
}

/* ---- gen     loop_decide decide：拼接循环之前（RVA 0x314228）----
 * Src = [rbp-0D0h]，王朝名 = [rbp+78h]。
 * ★ 只判断文化、只置标志，绝不碰 Src —— 此时 Src 还是空 SSO 串（cap=15），
 *   而中文姓名按 3 字节/字编码，写进去会被容量卡死（曾实测复现）。 */
static void mnp_h_gen_loop_decide(mnp::reg_pack &r)
{
    stat_bump(ST_GEN_DECIDE);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    p7_decide_surname_first((void *)(uintptr_t)(r.rbp.i - 0x0D0u),
                     (const void *)(uintptr_t)(r.rbp.i + 0x078u));
    MNP_SITE_GUARD_END("gen/loop_decide")
}

/* ---- gen     surn_len surnlen：`call StringAppend` 之前（RVA 0x3142F2）----
 * r8 = 姓的字节数。此时"姓"的两个来源（王朝名 / 名字表）已经汇合。 */
static void mnp_h_gen_surn_len(mnp::reg_pack &r)
{
    stat_bump(ST_GEN_SURNLEN);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    p10_record_surname_len((void *)(uintptr_t)(r.rsp.i + 0x30u), (size_t)r.r8.i);
    MNP_SITE_GUARD_END("gen/surn_len")
}

/* ---- gen     reorder reorder：`call StringAppend` 之后（RVA 0x3142FC）----
 * 此时 Src = "名… SP 姓"，用 g_sur_len 作边界就地重排成「姓 sep 名」。
 * Src 此刻已装下过更长的原串，cap 必然够。 */
static void mnp_h_gen_reorder(mnp::reg_pack &r)
{
    stat_bump(ST_GEN_REORDER);   /* 站点计数：心跳/退出时打印 */
    /* ★★ 注意：本函数内部**已经有一个 `__try`**（rsp 自检探针，见下），
     *   MSVC 不允许 `__try` 直接嵌套（C2713）⇒ 守卫只包住最后那次真正的
     *   重排调用（`p11_reorder_surname_first`），那才是会写内存、可能出错的一步。
     *   自检那段本来就用 `__except (EXCEPTION_EXECUTE_HANDLER)` 自己护住了。 */
    /* ★★★ rsp 自检（2026-10-05 13:01 崩溃后新增）
     *
     * 崩溃事实：ntdll!RtlFreeHeap 内部崩掉，而崩溃时 Rdi 恰好等于
     * gen     reorder 记录的 buf（0x22bc239c5b0）—— 即 gen     reorder 写的那块内存随后被堆使用，
     * 说明它已经不属于那个 CString。所以第一件要排除的就是"sp 取错了"。
     *
     * 由序言可推导出恒等式：
     *     push rbp/r14/r15   ⇒ rsp -= 0x18
     *     lea  rbp,[rsp-0x10]⇒ rbp = rsp - 0x10
     *     sub  rsp,0x110     ⇒ rsp = rbp - 0x100
     *   ⇒ rbp - rsp 必须恒为 0x100
     *   ⇒ sp = rsp + 0x30 = rbp - 0xD0 = &Src（正是 gen     loop_decide 注释里的 [rbp-0D0h]）
     *
     * 若 rbp-rsp != 0x100，则寄存器包里的 rsp 修正量在本次路径上不成立
     * （trampoline 目前写的是 `add qword ptr [rsp+18h], 70h`），
     * 那么 sp 指向的根本不是 Src，后面全错。 */
    if (g_rsp_check_left > 0) {
        g_rsp_check_left--;
        log_tid();
        LOGS("[d] gen/reorderCHK rsp="); LOGH((uint64_t)r.rsp.i);
        LOGS(" rbp="); LOGH((uint64_t)r.rbp.i);
        LOGS(" rbp-rsp="); LOGH((uint64_t)(r.rbp.i - r.rsp.i));
        LOGS(" (expect 0x100)");
        LOGS(" sp=rsp+30="); LOGH((uint64_t)(r.rsp.i + 0x30u));
        LOGS(" rbp-D0="); LOGH((uint64_t)(r.rbp.i - 0xD0u));
        LOGS(" src@[rbp-D0]=");
        {
            /* 只读，且包在 __try 里：即便 sp 错了也只是放弃这行日志 */
            unsigned long long v = 0;
            __try {
                v = *(unsigned long long *)(uintptr_t)(r.rbp.i - 0xD0u);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                v = 0xDEADBEEFDEADBEEFuLL;
            }
            LOGH((uint64_t)v);
        }
        LOGNL();
    }

    MNP_SITE_GUARD_BEGIN
    p11_reorder_surname_first((void *)(uintptr_t)(r.rsp.i + 0x30u));
    MNP_SITE_GUARD_END("gen/reorder")
}

/* ---- gen     exit_fallback fallback：函数出口（RVA 0x314349）----
 * 兜底：若 gen     reorder 没做成，用 rax(out) + [r14+88h](文化名) + [rbp+78h](姓) 再试一次。
 * ★ 紧邻站点之前的 0x31432B `mov rax,rdi` 就是本函数的返回值 ——
 *   旧实现曾用它去调 C 函数、被返回值覆盖，导致三次 C0000005 @ 0x94F4A。
 *   新架构下 rax 由寄存器包原样保存/恢复，该类问题不复存在。 */
static void mnp_h_gen_exit_fallback(mnp::reg_pack &r)
{
    stat_bump(ST_GEN_EXIT);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    p4_fallback_reorder((cstr_t *)(uintptr_t)r.rax.i,               /* s = 返回值         */
                 (void *)(uintptr_t)(r.rbp.i + 0x078u),      /* dyn = 王朝名       */
                 (void *)(uintptr_t)(r.r14.i + 0x088u));     /* culture = 文化名   */
    MNP_SITE_GUARD_END("gen/exit_fallback")
}

/* ==================================================================== */
/* 组 3：统治者 / 继承人 / 配偶（disp    ruler_name）                                    */
/* ==================================================================== */

/* ---- disp    ruler_name display：CMonarch_GetFullName 重排（RVA 0xA4B4A6）----
 * rbx = out（此时已是「名 SP 姓」）、rdi = CMonarch*。
 * 边界用两个字段的 size 判定（不猜空格、不找 0xBF）：
 *     nlen = *(CMonarch+0x38)；dlen = *(*(CMonarch+0x68)+0x18)
 * 只有 out->size == nlen + 1 + dlen 时才动手 ⇒ 空位期/摄政等分支天然跳过。
 * 统治者自己的文化：*(CMonarch+0x60) → 文化对象；文化名在【文化对象+0x48】。 */
static void mnp_h_disp_ruler_name(mnp::reg_pack &r)
{
    stat_bump(ST_DISP);   /* 站点计数：心跳/退出时打印 */
    MNP_SITE_GUARD_BEGIN
    p8_monarch_reorder((void *)(uintptr_t)r.rbx.i,
                       (const void *)(uintptr_t)r.rdi.i);
    MNP_SITE_GUARD_END("disp/ruler_name")
}

static void newhook_set_handlers(void)
{
    /* 桩只负责"打包寄存器 → 调这里 → 弹回"，所以签名统一是 void(reg_pack&)。
     * 各处理器内部再按站点语义取参数、调用既有实现（业务逻辑没变）。
     * 顺序与 kSites[] / stubs.asm / stubs.hpp / hookvars.cpp 一致。 */

    /* 组 1：取模修复 */
    mnpfn_modfix_pick_idx    = (uintptr_t)&mnp_h_modfix_pick_idx;
    mnpfn_modfix_pick_cult    = (uintptr_t)&mnp_h_modfix_pick_cult;
    mnpfn_modfix_pick_modidx    = (uintptr_t)&mnp_h_modfix_pick_modidx;

    /* 组 2：生成期姓名顺序（按 BuildFullName_Impl 内执行时机） */
    mnpfn_gen_entry_culture   = (uintptr_t)&mnp_h_gen_entry_culture;
    mnpfn_gen_loop_decide    = (uintptr_t)&mnp_h_gen_loop_decide;
    mnpfn_gen_surn_len     = (uintptr_t)&mnp_h_gen_surn_len;
    mnpfn_gen_reorder  = (uintptr_t)&mnp_h_gen_reorder;
    mnpfn_gen_exit_fallback = (uintptr_t)&mnp_h_gen_exit_fallback;

    /* 组 3：统治者 / 继承人 / 配偶 */
    mnpfn_disp_ruler_name   = (uintptr_t)&mnp_h_disp_ruler_name;
}

static int newhook_install(uint8_t *mod)
{
    int n;

    newhook_set_handlers();
    mnp_install_set_logger(log_str);

    /* cave 由 C++ 层自己分配（它会贴近 eu4.exe，保证"站点 → cave"的 rel32 算得出来） */
    n = mnp_install_new_hooks(mod, NULL, 0);

    LOGS("[i] newhook: install returned "); LOGD((uint32_t)n); LOGNL();
    return n;
}

/* ------------------------------------------------------------------ */
/* 新钩子层：实测跳转长度（只测量不写字节，用于诊断）                     */
/* ------------------------------------------------------------------ */
/* 确认 make_jmp 在本进程里会写 5 字节（E9 rel32）还是 14 字节（FF 25）。
 * 桩在我们自己的 DLL 里，而 eu4.exe 是主模块，两者距离可能超 2GB ——
 * 这正是必须加 cave 跳板层的原因。 */
static void newhook_probe(uint8_t *mod)
{
    static const struct {
        const char *name;
        uintptr_t   rva;
        const void *stub;
        size_t      cover;
    } t[] = {
        { "gen     entry_culture",  0x313F40u, (const void *)&mnp_hook_gen_entry_culture,  5u },
        { "gen     loop_decide",  0x314228u, (const void *)&mnp_hook_gen_loop_decide,  8u },
        { "gen     surn_len", 0x3142F2u, (const void *)&mnp_hook_gen_surn_len, 5u },
        { "gen     reorder", 0x3142FCu, (const void *)&mnp_hook_gen_reorder, 5u },
        { "gen     exit_fallback",  0x314349u, (const void *)&mnp_hook_gen_exit_fallback,  5u },
        { "disp    ruler_name",  0xA4B4A6u, (const void *)&mnp_hook_disp_ruler_name,  7u },
    };
    unsigned i;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        uintptr_t site = (uintptr_t)mod + t[i].rva;
        uintptr_t stub = (uintptr_t)t[i].stub;
        size_t    need = mnp_jmp_len_for(site, stub);
        int64_t   dist = (int64_t)(stub - site);

        LOGS("[i] PROBE "); LOGS(t[i].name);
        LOGS(" dist=");   LOGH((uint64_t)dist);
        LOGS(" jmp_len="); LOGD((uint32_t)need);
        LOGS(" cover=");  LOGD((uint32_t)t[i].cover);
        LOGS(need <= t[i].cover ? "  [fits direct]" : "  [needs cave]");
        LOGNL();
    }
}

static void newhook_probe_dll_base(HMODULE self)
{
    uintptr_t dll = (uintptr_t)self;
    uintptr_t exe = (uintptr_t)GetModuleHandleW(NULL);
    int64_t   d   = (int64_t)(dll - exe);

    LOGS("[i] PROBE dll="); LOGH(dll);
    LOGS(" exe="); LOGH(exe);
    LOGS(" delta="); LOGH((uint64_t)d);
    LOGS((d > 0x7FFFFFFFll || d < -0x80000000ll) ? "  (>2GB)" : "  (within 2GB)");
    LOGNL();
}

static void do_fix(HMODULE self)
{
    uint8_t  *mod;
    uint8_t  *text = NULL;
    size_t    text_len = 0;
    uint32_t  size = 0, ts = 0;
    WCHAR     offpath[MAX_PATH];
    WCHAR     exename[MAX_PATH];
    WCHAR    *p;

    /* 自身目录 */
    GetModuleFileNameW(self, g_dir, MAX_PATH);
    p = g_dir;
    while (*p) p++;
    while (p > g_dir && p[-1] != L'\\' && p[-1] != L'/') p--;
    *p = 0;                 /* 保留 [p] 处的分隔符，使 g_dir 以 '\\' 结尾 */
    if (p > g_dir && p[1] != 0) p[1] = 0;   /* 截断文件名，留下末尾分隔符 */

    /* 关闭开关 */
    lstrcpynW(offpath, g_dir, MAX_PATH);
    lstrcatW(offpath, OFF_FILE_NAME);
    if (GetFileAttributesW(offpath) != INVALID_FILE_ATTRIBUTES) return;

    log_open();
    LOGS("=== MonarchNameFix (build " __DATE__ " " __TIME__ ") ===\r\n");

    /* ★★ 稳定性测试用启动横幅：把"这一次运行"的环境全部记下来。
     *   长时间跑出问题时，第一步就是确认"当时是哪个版本、什么配置、跑在哪个进程里"。
     *   带 #序号 与 t=毫秒（由 log_stamp 提供），便于与后续事件对齐时间。 */
    log_stamp();
    LOGS("[start] pid=");   LOGD(GetCurrentProcessId());
    LOGS(" tid=");          LOGD(GetCurrentThreadId());
    LOGS(" tick0=");        LOGD(GetTickCount());
    LOGS(" line_max=");     LOGD(MNP_LINE_MAX);
    LOGS(" ring_lines=");   LOGD(MNP_RING_LINES);
    LOGS(" hb_sec=");       LOGD(MNP_HB_INTERVAL_MS / 1000u);
    LOGS("\r\n");
    log_stamp();
    LOGS("[start] 逐行原子写 + 内存环形回捞已启用（崩溃时回捞最后 ");
    LOGD(MNP_RING_LINES);
    LOGS(" 行）\r\n");

    /* 诊断开关：plugins\ 下的空文件 */
    {
        WCHAR ncp[MAX_PATH];
        lstrcpynW(ncp, g_dir, MAX_PATH);
        lstrcatW(ncp, NOCONF_FILE_NAME);
        g_no_conf = (GetFileAttributesW(ncp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
        if (g_no_conf) LOGS("[i] .noconf 存在 -> gen/fallback 不查文化配置（诊断模式）\r\n");

        lstrcpynW(ncp, g_dir, MAX_PATH);
        lstrcatW(ncp, NOXFORM_FILE_NAME);
        g_no_xform = (GetFileAttributesW(ncp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
        if (g_no_xform) LOGS("[i] .noxform 存在 -> 不做任何姓名变换（诊断模式）\r\n");

        /* ★ .nomod：跳过取模修复（modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx），回到"6 站点、只做姓名顺序"。
         *   变量定义在 install.cpp，用 extern "C" 声明以避开名称修饰。 */
        lstrcpynW(ncp, g_dir, MAX_PATH);
        lstrcatW(ncp, NOMOD_FILE_NAME);
        mnp_skip_modfix = (GetFileAttributesW(ncp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
        if (mnp_skip_modfix) LOGS("[i] .nomod 存在 -> 跳过 modfix/idx/modfix/cult/modfix/modidx（不做取模修复，诊断模式）\r\n");

        /* ★★ 单站点开关（二分定位）：MonarchNameFix.noP1 … noP8
         *   为什么需要它 —— .nomod 的实机结果推翻了原先的假设：
         *   两次崩溃【都】发生、日志【都】停在最后一条 `[d] gen     reorder`，
         *   区别只是 9 站点留下 minidump、6 站点静默消失。
         *   ⇒ 问题在姓名顺序链路，光靠 .nomod 这一刀切不够，
         *     得能逐个关掉、二分到具体某一个站点。
         *   位号按 kSites[] 顺序：modfix  pick_idx=0 modfix  pick_cult=1 modfix  pick_modidx=2 gen     entry_culture=3 gen     loop_decide=4 gen     surn_len=5 gen     reorder=6 gen     exit_fallback=7 disp    ruler_name=8 */
        {
            static const WCHAR *const kNoNames[9] = {
                L"MonarchNameFix.noP1",  L"MonarchNameFix.noP2",  L"MonarchNameFix.noP3",
                L"MonarchNameFix.noP6",  L"MonarchNameFix.noP7",  L"MonarchNameFix.noP10",
                L"MonarchNameFix.noP11", L"MonarchNameFix.noP4",  L"MonarchNameFix.noP8"
            };
            static const char *const kNoTags[9] = {
                "modfix  pick_idx", "modfix  pick_cult", "modfix  pick_modidx", "gen     entry_culture", "gen     loop_decide", "gen     surn_len", "gen     reorder", "gen     exit_fallback", "disp    ruler_name"
            };
            int b;
            mnp_skip_mask = 0;
            for (b = 0; b < 9; b++) {
                lstrcpynW(ncp, g_dir, MAX_PATH);
                lstrcatW(ncp, kNoNames[b]);
                if (GetFileAttributesW(ncp) != INVALID_FILE_ATTRIBUTES) {
                    mnp_skip_mask |= (1u << b);
                    LOGS("[i] .no"); LOGS(kNoTags[b]); LOGS(" 存在 -> 跳过");
                    LOGS(kNoTags[b]); LOGS("\r\n");
                }
            }
            if (mnp_skip_mask) LOGS("[i] 单站点诊断模式已启用\r\n");
        }






        /* ★ .logverbose：恢复内测期的逐文化 / 逐 tag 留痕（默认关闭 = 发布模式）。
         *   需要"每种文化到底怎么解析的""每个 tag 用了哪个文化"时放这个文件。 */
        lstrcpynW(ncp, g_dir, MAX_PATH);
        lstrcatW(ncp, LOGVERBOSE_FILE_NAME);
        g_log_verbose = (GetFileAttributesW(ncp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
        if (g_log_verbose) LOGS("[i] .logverbose 存在 -> 恢复内测留痕（逐文化/逐 tag）\r\n");

        lstrcpynW(ncp, g_dir, MAX_PATH);
        lstrcatW(ncp, NOHOOK_FILE_NAME);
        g_no_hook = (GetFileAttributesW(ncp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
        if (g_no_hook) LOGS("[i] .nohook 存在 -> 只做初始化，不安装任何补丁\r\n");
    }

    /* 目标进程必须是 eu4.exe */
    GetModuleFileNameW(NULL, exename, MAX_PATH);
    p = exename;
    {
        WCHAR *last = exename;
        while (*p) { if (*p == L'\\' || *p == L'/') last = p + 1; p++; }
        if (lstrcmpiW(last, L"eu4.exe") != 0) {
            LOGS("[!] host is not eu4.exe, skip\r\n");
            return;
        }
    }

    mod = (uint8_t *)GetModuleHandleW(NULL);
    if (!mod) { LOGS("[!] GetModuleHandle failed\r\n"); return; }

    if (!pe_info(mod, &size, &ts, &text, &text_len)) {
        LOGS("[!] PE parse failed\r\n"); return;
    }
    LOGS("[i] image size="); LOGH(size);
    LOGS(" timestamp="); LOGD(ts); LOGNL();

    if (size != IMG_SIZE_EXPECT || ts != IMG_TS_EXPECT) {
        LOGS("[!] build fingerprint mismatch -> no patch applied\r\n");
        return;
    }
    LOGS("[i] fingerprint ok\r\n");

    /* 文化对象指针必须落在本模块镜像内 —— 先把范围记下来，供后面所有解引用校验 */
    g_mod   = mod;
    g_modsz = size;

    /* ---- 读 common\cultures_name\ 配置并解析成文化对象指针 ---- */
    cc_init(self);

    /* ★ .nohook：初始化做完就收工 —— 不分配 cave、不写桩、不打任何补丁。
     * 用途：把"我们的 DLL 在场并做了初始化"与"我们改了游戏的代码"分开。
     * 实机已确认 `.off`（完全不碰游戏）不崩；若 `.nohook` 也不崩，则元凶在
     * 安装期改代码；若 `.nohook` 仍崩，则元凶在初始化副作用（文件 I/O / 扫描 /
     * 全局对象构造 / 日志句柄），与补丁无关。 */
    if (g_no_hook) { LOGS("[i] .nohook 存在 -> 初始化后直接退出，不安装任何补丁\r\n"); return; }

    /* ★ 新钩子层（参照 EU4dll 改造）：先诊断，再安装。
     *
     * 旧的 g_patches[] 补丁表 / prepare_one / hook_one / alloc_near 已经
     * 随"机械拼字节 + 机械重放"的时代一并删除 —— 那些代码正是三次崩溃的源头：
     *   · 桩是 C 里的 uint8_t 数组，末尾必须凑出 `90 90 90 E9 rel32`；
     *   · 每个桩手工 push/pop 寄存器，还要手工保存 rax；
     *   · 站点定位用自制的签名扫描，命中多处时取第一个。
     * 现在：
     *   · 站点定位   -> hooks.hpp + bytepattern.hpp（模式 + RVA 双判据，必须唯一）
     *   · 跳转与保护 -> hooks.hpp（分层跳转 + RAII 页保护 + 指令缓存刷新）
     *   · 桩          -> stubs.asm 的通用 trampoline（寄存器打包全部自动化）
     *   · 业务逻辑    -> 本文件的 mnp_h_p* 处理器（纯 C++） */
    newhook_probe_dll_base(self);
    newhook_probe(mod);

    LOGS("[i] === 安装钩子（.asm trampoline + cave 跳板 + C++ handler）===\r\n");
    {
        int n = newhook_install(mod);
        LOGS("[i] result: "); LOGD((uint32_t)n); LOGS(" hooks installed\r\n");
    }

    /* ★ 安装完成后才启动心跳线程与异常过滤器：
     *   · 心跳线程要等 g_log 就绪；
     *   · 异常过滤器放在安装之后 —— 安装期的异常由游戏自己的机制处理，
     *     我们只在"补丁已生效"这段时间里负责收尾，避免掩盖安装期问题。 */
    log_start_hb_thread();
    SetUnhandledExceptionFilter(log_crash_filter);
    log_stamp();
    LOGS("[start] 异常过滤器已安装（崩溃时会回捞最后日志）\r\n");
}

BOOL WINAPI DllMain(HMODULE self, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(self);
        do_fix(self);
        /* 注意：这里【不再】CloseHandle(g_log) —— 安装之后还要靠它记录
         * 第一次变换 / 懒绑定 / 崩溃前的动作。进程退出时由系统回收句柄。 */
    } else if (reason == DLL_PROCESS_DETACH) {
        /* ★ 稳定性测试：正常退出时也做一次收尾 —— 打印最终站点计数 + 回捞最后若干行。
         *   这样"跑完一局正常退出"与"半路消失"在日志末尾就能区分开：
         *     · 有 [exit] 行 ⇒ 正常退出（进程按 DETACH 走完）
         *     · 只有 [hb] 或什么都没有 ⇒ 非正常结束，去看 [!!!] 或最后一条 [hb] 的时间 */
        if (g_log_ready) {
            int i;
            InterlockedExchange(&g_log_stop, 1);
            log_stamp();
            LOGS("[exit] 进程正常退出，最终站点计数:\r\n");
            for (i = 0; i < MNP_NSTAT; i++) {
                if (g_stat[i] == 0) continue;
                log_stamp();
                LOGS("[exit]   "); LOGS(g_stat_name[i]);
                LOGS(" = "); LOGD((uint32_t)g_stat[i]); LOGS("\r\n");
            }
            log_stamp();
            LOGS("[exit] 共落盘 "); LOGD((uint32_t)g_line_no); LOGS(" 行\r\n");
            log_crash_tail("正常退出前最后若干行");
        }
    }
    return TRUE;
}
