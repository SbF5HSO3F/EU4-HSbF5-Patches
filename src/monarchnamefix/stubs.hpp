/*
 * stubs.hpp - 汇编桩的接口声明
 *
 * 桩本体在 stubs.asm，由 build.bat 用 ml64 汇编后与 C++ 一起链接。
 *
 * ★ 关键的"变量语义"提醒（EU4dll 的 font_asm.asm 里也专门写过）：
 *   stubs.asm 里是 `EXTERN mnpfn_modfix_pick_idx : QWORD` —— 那是【变量】不是函数。
 *   汇编里 `mov rax, mnpfn_modfix_pick_idx` 取到的是【变量的地址】，
 *   必须再 `mov rax, qword ptr [rax]` 才拿到值。
 *   所以这里声明的必须是【函数地址的值】与【回跳点的值】。
 *
 * ====================================================================
 * ★★★ 站点命名约定（2026-10-05 统一）
 * ====================================================================
 * 一个补丁站点在五处文件里出现，必须用**同一个名字**，格式固定：
 *
 *      mnp_hook_pN_<动作>    —— stubs.asm 的 PROC 本体（桩）
 *      mnp_h_pN_<动作>       —— monarchnamefix.cpp 的处理器（业务逻辑）
 *      mnpfn_pN_<动作>       —— 桩要调用的函数指针变量（hookvars.cpp 定义）
 *      mnp_ret_pN            —— 回跳点槽（名字已够清楚，不带动作名）
 *      "PN  <动作>  …"        —— install.cpp 的 kSites[] 显示名（进日志）
 *
 *   站点  动作      插在哪里                      做什么
 *   ────  ────────  ────────────────────────────  ─────────────────────────
 *   modfix  pick_idx    runmask   WeightedNameList_PickBy… 序言  随机值掩成 21 位非负
 *   modfix  pick_cult    modulo    PickNameFromCultureLists 取模  有符号 → 无符号
 *   modfix  pick_modidx    modulo    WeightedNameList_GetBy… 取模   有符号 → 无符号
 *   gen     entry_culture    culture   BuildFullName_Impl 入口        捕获本次调用的文化名
 *   gen     loop_decide    decide    拼接循环之前                   判定该文化是否姓前名后
 *   gen     surn_len   surnlen   追加「姓」那次 call 之前        记下姓的字节数
 *   gen     reorder   reorder   追加「姓」那次 call 之后        就地重排「姓 sep 名」
 *   gen     exit_fallback    fallback  函数出口                        兜底重排（gen     reorder 未成时）
 *   disp    ruler_name    display   CMonarch_GetFullName           显示期统治者/继承人重排
 *
 * ★ 为什么编号留着不改：modfix  pick_idx..gen     reorder 是【按添加时间】编的，不是执行顺序
 *   （gen     exit_fallback 是出口却编号在 gen     entry_culture 之前，modfix  pick_idx/modfix  pick_cult/modfix  pick_modidx 反而是最后补的）。这些编号在
 *   notes\ 的多份历史文档里有 500+ 处引用，重编号会让旧笔记全部失准。
 *   所以只把【动作名】补进符号，编号原样保留 —— 新名字里仍含 `pN`，
 *   旧笔记里搜 "modfix  pick_idx" 依旧命中。
 *
 * ★ 顺序与齐全性有机器校验：
 *     python scripts\verify_site_order.py
 *   （它同时校验五处的编号顺序，以及每个站点是否五处齐全。）
 *
 * 排列顺序与 install.cpp 的 kSites[]、stubs.asm 的 trampoline 完全一致：
 *     组 1 名字选取（取模修复）  modfix  pick_idx / modfix  pick_cult / modfix  pick_modidx
 *     组 2 生成期姓名顺序        gen     entry_culture / gen     loop_decide / gen     surn_len / gen     reorder / gen     exit_fallback
 *     组 3 统治者显示链          disp    ruler_name
 */
#ifndef MNP_STUBS_HPP
#define MNP_STUBS_HPP

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- 桩本体（stubs.asm 里的 PROC） ---------------- */
/* ===== 组 1：名字选取（取模修复） ===== */
void mnp_hook_modfix_pick_idx(void);      /* 0x00DA989B  掩随机值 21 位（继承人走的路径） */
void mnp_hook_modfix_pick_cult(void);       /* 0x00280274  有符号取模 → 无符号              */
void mnp_hook_modfix_pick_modidx(void);       /* 0x00DA9A82  有符号取模 → 无符号              */

/* ===== 组 2：生成期姓名顺序（BuildFullName_Impl 内部，按执行时机）===== */
void mnp_hook_gen_entry_culture(void);      /* 0x00313F40  入口：捕获文化名                 */
void mnp_hook_gen_loop_decide(void);       /* 0x00314228  循环前：该文化是否姓前名后？     */
void mnp_hook_gen_surn_len(void);     /* 0x003142F2  追加姓之前：记下姓的字节数       */
void mnp_hook_gen_reorder(void);     /* 0x003142FC  追加姓之后：就地重排             */
void mnp_hook_gen_exit_fallback(void);     /* 0x00314349  出口：兜底                       */

/* ===== 组 3：统治者 / 继承人 / 配偶（显示期）===== */
void mnp_hook_disp_ruler_name(void);      /* 0x00A4B4A6  CMonarch_GetFullName 重排        */

/* ---------------- 桩要调用的处理器地址（均为 void(reg_pack&)）---------------- */
/* ===== 组 1 ===== */
extern uintptr_t mnpfn_modfix_pick_idx;
extern uintptr_t mnpfn_modfix_pick_cult;
extern uintptr_t mnpfn_modfix_pick_modidx;

/* ===== 组 2 ===== */
extern uintptr_t mnpfn_gen_entry_culture;
extern uintptr_t mnpfn_gen_loop_decide;
extern uintptr_t mnpfn_gen_surn_len;
extern uintptr_t mnpfn_gen_reorder;
extern uintptr_t mnpfn_gen_exit_fallback;

/* ===== 组 3 ===== */
extern uintptr_t mnpfn_disp_ruler_name;

/* ---------------- 各桩的回跳点（由安装代码算好写进） ---------------- */
/* ===== 组 1 ===== */
extern uintptr_t mnp_ret_modfix_pick_idx;
extern uintptr_t mnp_ret_modfix_pick_cult;
extern uintptr_t mnp_ret_modfix_pick_modidx;

/* ===== 组 2 ===== */
extern uintptr_t mnp_ret_gen_entry_culture;
extern uintptr_t mnp_ret_gen_loop_decide;
extern uintptr_t mnp_ret_gen_loop_decide_skip;   /* gen     loop_decide 的"跳过拼接循环"分支（0x314285） */
extern uintptr_t mnp_ret_modfix_pick_idx0;
extern uintptr_t mnp_ret_modfix_pick_idx1;
extern uintptr_t mnp_ret_gen_exit_fallback;

/* ===== 组 3 ===== */
extern uintptr_t mnp_ret_disp_ruler_name;

#ifdef __cplusplus
}
#endif

#endif /* MNP_STUBS_HPP */
