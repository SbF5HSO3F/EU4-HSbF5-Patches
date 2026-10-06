/*
 * hookvars.cpp - 汇编桩（stubs.asm）所需的外部变量定义
 *
 * stubs.asm 里写的是 `EXTERN mnpfn_modfix_pick_idx : QWORD` 之类，
 * 那是【变量】不是函数：汇编里 `mov rax, mnpfn_modfix_pick_idx` 取到的是变量地址，
 * 必须再 `mov rax, qword ptr [rax]` 才拿到值。
 * 所以这里放的是【函数地址的值】与【回跳点的值】。
 *
 * ★★ 必须包在 extern "C" 里：本文件是 C++，若不加，MSVC 会把符号名修饰成
 *    ?mnp_ret_modfix_pick_idx@@3_KA 之类，而 stubs.asm 引用的是裸名，
 *    链接期就会报 LNK2001 无法解析的外部符号。
 *
 * 排列顺序与 install.cpp 的 kSites[]、stubs.asm 的 trampoline 完全一致：
 *     组 1 取模修复        modfix  pick_idx / modfix  pick_cult / modfix  pick_modidx
 *     组 2 生成期姓名顺序  gen     entry_culture / gen     loop_decide / gen     surn_len / gen     reorder / gen     exit_fallback
 *     组 3 统治者链        disp    ruler_name
 */
#include <cstdint>

extern "C" {

/* ================= 组 1：取模修复 ================= */
std::uintptr_t mnpfn_modfix_pick_idx    = 0;   /* void (*)(reg_pack&)  掩随机值 21 位     */
std::uintptr_t mnpfn_modfix_pick_cult    = 0;   /* void (*)(reg_pack&)  有符号 → 无符号    */
std::uintptr_t mnpfn_modfix_pick_modidx    = 0;   /* void (*)(reg_pack&)  有符号 → 无符号    */

/* ================= 组 2：生成期姓名顺序 ================= */
std::uintptr_t mnpfn_gen_entry_culture   = 0;   /* void (*)(reg_pack&)  捕获文化名         */
std::uintptr_t mnpfn_gen_loop_decide    = 0;   /* void (*)(reg_pack&)  判断是否姓前       */
std::uintptr_t mnpfn_gen_surn_len     = 0;   /* void (*)(reg_pack&)  记姓的字节数       */
std::uintptr_t mnpfn_gen_reorder  = 0;   /* void (*)(reg_pack&)  就地重排           */
std::uintptr_t mnpfn_gen_exit_fallback = 0;   /* void (*)(reg_pack&)  出口兜底           */

/* ================= 组 3：统治者 / 继承人 / 配偶 ================= */
std::uintptr_t mnpfn_disp_ruler_name   = 0;   /* void (*)(reg_pack&)  重排               */

/* ================= 回跳点（安装时由 install.cpp 填入）================= */
std::uintptr_t mnp_ret_modfix_pick_idx      = 0;
std::uintptr_t mnp_ret_modfix_pick_cult      = 0;
std::uintptr_t mnp_ret_modfix_pick_modidx      = 0;

std::uintptr_t mnp_ret_gen_entry_culture      = 0;
std::uintptr_t mnp_ret_gen_loop_decide      = 0;
std::uintptr_t mnp_ret_gen_loop_decide_skip = 0;      /* gen     loop_decide 的"跳过拼接循环"分支：0x314285 */
std::uintptr_t mnp_ret_modfix_pick_idx0     = 0;
std::uintptr_t mnp_ret_modfix_pick_idx1     = 0;
std::uintptr_t mnp_ret_gen_exit_fallback      = 0;

std::uintptr_t mnp_ret_disp_ruler_name      = 0;

} /* extern "C" */
