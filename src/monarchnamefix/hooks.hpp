/*
 * hooks.hpp - 钩子注册表 + cave 跳板（C++）
 *
 * ============================ 为什么需要 cave 跳板 ======================
 *
 * 本机实测（test-compile 里量过）：从 eu4.exe 里的站点跳到【我们 DLL 里】的桩，
 * 距离超过 ±2GB ⇒ hookmem::make_jmp 必须写 14 字节的 `FF 25 + 绝对目标`。
 * 而我们的站点 cover 只有 5~8 字节（站点都取在"最后一条边界整齐的指令"上），
 * 14 > cover ⇒ 直接写就会把后面的指令切坏。
 *
 * 所以补一层：
 *
 *     eu4.exe 站点   E9 rel32 → cave        5 字节   （cover 不变，仍是 5~8）
 *     cave（近距）   FF 25 + 绝对目标 → 桩  14 字节  （cave 内不受距离限制）
 *     DLL 里的 .asm 桩                      ——       （可读、可 diff）
 *     桩末端         push <retAddr>; ret    ——       （回跳，不受 5 字节限制）
 *
 * cave 由 alloc_near_module() 在 eu4.exe 附近分配（同一 2GB 窗口内），
 * 这样"站点 → cave"那 5 字节 E9 一定算得出来。
 *
 * ============================ 相对旧实现 ==============================
 *
 * 旧实现（monarchnamefix.c 的 prepare_one/hook_one）：
 *   - 桩是 C 里的 uint8_t 数组，用 memcpy 拼字节；
 *   - 桩末尾【必须】是 `90 90 90 E9 rel32`（prepare_one 无条件按最后 5 字节填 resume）；
 *   - 因此桩的形态被这个约定绑死，可读性差、改一处要看十处。
 *
 * 新实现：
 *   - 桩是 stubs.asm 里的具名过程，由 ml64 汇编；
 *   - 桩用 `push <retAddr>; ret` 回跳，回跳点由 C++ 侧算好写进 EXTERN 变量；
 *   - 每个钩子的覆盖长度、回跳点、预期原字节，都在一张表里声明。
 */
#ifndef MNP_HOOKS_HPP
#define MNP_HOOKS_HPP

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <vector>

#include "hookmem.hpp"
#include "bytepattern.hpp"

namespace mnp {

/* -------------------------------------------------------------------- */
/* cave 跳板的固定布局                                                   */
/* -------------------------------------------------------------------- */
/* cave 槽里只有一条 14 字节的绝对跳转；32 字节对齐留余量，便于将来扩展。 */
constexpr std::size_t kTrampolineSize = 14;
constexpr std::size_t kSlotSize       = 32;

/* -------------------------------------------------------------------- */
/* 一个钩子的声明                                                        */
/* -------------------------------------------------------------------- */
struct HookSpec
{
    std::string_view name;         /* 日志用，如 "gen     entry_culture BuildFullName_Impl entry" */
    std::uintptr_t   site_rva;     /* 站点 RVA */
    void            *stub;         /* .asm 桩的地址 */
    std::size_t      cover;        /* 被覆盖的原字节数（必须正好覆盖整数条指令） */
    std::uintptr_t   resume_rva;   /* 回跳点 RVA */
    std::string_view site_bytes;   /* 站点原字节（形如 "48 89 5C 24 08"），空则跳过校验 */
    std::uintptr_t  *resume_var;   /* 把回跳点写进这个 EXTERN 变量（可为 nullptr） */
};

/* 安装结果 */
struct HookResult
{
    bool            installed = false;
    bool            verified  = false;   /* site_bytes 校验是否通过 */
    std::size_t     site_jmp  = 0;       /* 站点处实际写的字节数（应为 5） */
    std::uintptr_t  site      = 0;
    std::uintptr_t  cave      = 0;
    std::uintptr_t  resume    = 0;
    std::string_view reason;             /* 失败原因 */
};

/* -------------------------------------------------------------------- */
/* 在模块附近分配可执行内存（cave）                                      */
/* -------------------------------------------------------------------- */
/* 优先贴近 module（让"站点 → cave"的 rel32 一定算得出来）；失败则退到
 * 模块基址下方 0x10000 处（EU4 实测可用，见旧实现的 alloc_near 注释）。 */
inline void *alloc_near_module(void *module, std::size_t size)
{
    auto *base = static_cast<std::uint8_t *>(module ? module : GetModuleHandleA(nullptr));
    if (!base || size == 0) return nullptr;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::uintptr_t granularity = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;

    const std::uintptr_t want = reinterpret_cast<std::uintptr_t>(base);

    /* 从模块基址附近的地址起，向两侧找一块空闲的 MEM_FREE 区域。
     * 用 VirtualQuery 步进扫描；找到就 VirtualAlloc(MEM_RESERVE|MEM_COMMIT)。 */
    for (int dir = 0; dir < 2; ++dir) {
        const long long lo = -0x4000000LL;   /* -64MB */
        const long long hi =  0x4000000LL;   /* +64MB */
        for (long long off = 0; off < hi; off += static_cast<long long>(granularity)) {
            for (int sign = 0; sign < 2; ++sign) {
                const long long d = (sign == 0) ? off : -off;
                if (d < lo || d > hi) continue;

                const std::uintptr_t probe = want + static_cast<std::uintptr_t>(d);
                if (probe < granularity) continue;

                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(reinterpret_cast<void *>(probe), &mbi, sizeof(mbi)) == 0) continue;
                if (mbi.State != MEM_FREE) continue;
                if (mbi.RegionSize < size) continue;

                void *p = VirtualAlloc(reinterpret_cast<void *>(probe), size,
                                       MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) return p;
            }
        }
        (void)dir;
    }
    return nullptr;
}

/* -------------------------------------------------------------------- */
/* 安装一个钩子                                                          */
/* -------------------------------------------------------------------- */
/* 步骤：
 *   1. 校验站点原字节（若提供了 site_bytes）
 *   2. 站点 → cave 的 rel32 必须放得下（5 字节）
 *   3. 把回跳点写进 EXTERN 变量（必须在改站点之前，桩随时可能被调用）
 *   4. 站点写 E9 → cave
 *   5. cave 写 FF 25 + 绝对目标 → 桩
 * 任何一步失败都返回未安装（并且不留下半成品：校验都在写之前完成）。 */
inline HookResult install_hook(const HookSpec &spec, void *module,
                               std::uint8_t *cave_slot)
{
    HookResult r;

    auto *base = static_cast<std::uint8_t *>(module ? module : GetModuleHandleA(nullptr));
    if (!base) { r.reason = "no module"; return r; }

    const std::uintptr_t site_v = reinterpret_cast<std::uintptr_t>(base) + spec.site_rva;
    const std::uintptr_t cave_v = reinterpret_cast<std::uintptr_t>(cave_slot);
    r.site = site_v;
    r.cave = cave_v;
    r.resume = reinterpret_cast<std::uintptr_t>(base) + spec.resume_rva;

    if (!spec.stub) { r.reason = "no stub"; return r; }
    if (spec.cover == 0) { r.reason = "cover=0"; return r; }

    /* 1. 校验站点原字节 */
    if (!spec.site_bytes.empty()) {
        const Pattern pat = parse_pattern(spec.site_bytes);
        if (!pat.ok) { r.reason = "bad site_bytes literal"; return r; }
        if (pat.size() > spec.cover) { r.reason = "site_bytes longer than cover"; return r; }
        if (!pat.matches(reinterpret_cast<const std::uint8_t *>(site_v))) {
            r.reason = "site bytes mismatch";
            return r;
        }
        r.verified = true;
    } else {
        r.verified = true;   /* 没给就视为通过 */
    }

    /* 2. 站点 → cave 必须是 5 字节 rel32 */
    if (jmp_len_for(addr{site_v}, addr{cave_v}) != 5) {
        r.reason = "site->cave exceeds rel32";
        return r;
    }
    /* 3. cave → 桩可以是 14 字节绝对跳转 */
    if (jmp_len_for(addr{cave_v}, addr{spec.stub}) > kTrampolineSize) {
        r.reason = "cave trampoline too small";
        return r;
    }

    /* 4. 先把回跳点写进 EXTERN 变量 */
    if (spec.resume_var) {
        if (!write<std::uintptr_t>(addr{spec.resume_var}, r.resume)) {
            r.reason = "cannot write resume var";
            return r;
        }
    }

    /* 5. 站点写 E9 → cave */
    r.site_jmp = make_jmp(addr{site_v}, addr{cave_v});
    if (r.site_jmp != 5) { r.reason = "site jmp write failed"; return r; }

    /* 6. cave 写绝对跳转 → 桩 */
    if (make_jmp(addr{cave_v}, addr{spec.stub}) == 0) {
        r.reason = "cave jmp write failed";
        return r;
    }

    r.installed = true;
    return r;
}

} /* namespace mnp */

#endif /* MNP_HOOKS_HPP */
