/*
 * reg_pack.hpp - 寄存器包（照 EU4dll 的 Injectors/assembly.hpp 设计）
 *
 * 出处：matanki-saito/EU4dll Plugin64/assembly.hpp（Copyright (C) 2012-2014
 * LINK/2012，zlib 风格许可）。已验证其 git blob SHA1 = 4e48bd58caf223b43ba5e61662cc52ba5de9f82d。
 *
 * 目的：让钩子的业务逻辑可以完全用 C++ 写 ——
 *   汇编侧只负责"把 16 个通用寄存器 + RFLAGS 按固定顺序压栈，把栈指针作为
 *   reg_pack* 传进来，回调结束后再原样弹回去"；一切判断与变换都在 C++ 里。
 *
 * ★★ 字段顺序是硬约定，不要改：
 *   "The first field is the last to be pushed and first to be poped"
 *   即 reg_pack 的内存布局与 trampoline 里的 push 顺序互为镜像。
 *   trampoline 的压栈顺序（从先到后）：
 *       pushfq
 *       push r15, r14, r13, r12, r11, r10, r9, r8
 *       push rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi
 *   于是栈上从低地址到高地址（= 结构体从前往后）依次是：
 *       rdi rsi rbp rsp rbx rdx rcx rax r8..r15  flags
 *
 * ★ 与 EU4dll 的差异（务必知道）：
 *   它没有 rip 字段，所以"被覆盖的指令"无法自动重放，必须由各钩子自己在
 *   trampoline 尾部那段手写汇编里重放。我们沿用同样的约定，但把那段重放
 *   压缩成 MASM 宏的一个参数 —— 业务逻辑一行汇编都不写，只有 1~3 条
 *   "把原指令的语义表达出来"的指令留在桩里（例如 `mov [rsp+8], rbx`）。
 */
#ifndef MNP_REG_PACK_HPP
#define MNP_REG_PACK_HPP

#include <cstdint>
#include <cstddef>

namespace mnp {

union general_register
{
    std::uint64_t i;
    void         *p;

    template <class T>
    operator T *() const { return static_cast<T *>(p); }
};

struct flags_register
{
    std::uint64_t raw;

    bool carry_flag()     const { return (raw >> 0)  & 1; }
    bool parity_flag()    const { return (raw >> 2)  & 1; }
    bool adjust_flag()    const { return (raw >> 4)  & 1; }
    bool zero_flag()      const { return (raw >> 6)  & 1; }
    bool sign_flag()      const { return (raw >> 7)  & 1; }
    bool direction_flag() const { return (raw >> 10) & 1; }
    bool overflow_flag()  const { return (raw >> 11) & 1; }
};

/* 16 个通用寄存器 + RFLAGS。
 *
 * ★ 顺序与 trampoline 的 push 序列严格对应，改一处必须同时改另一处。 */
struct reg_pack
{
    union
    {
        general_register arr[16];
        struct
        {
            general_register
                rdi, rsi, rbp, rsp, rbx, rdx, rcx, rax,
                r8, r9, r10, r11, r12, r13, r14, r15;
        };
    };
    flags_register ef;          /* pushfq 压入的 RFLAGS */
};

static_assert(sizeof(general_register) == 8, "general_register 必须是 8 字节");
static_assert(sizeof(flags_register) == 8, "flags_register 必须是 8 字节");
static_assert(sizeof(reg_pack) == 136, "reg_pack 必须是 16*8 + 8 = 136 字节");
static_assert(offsetof(reg_pack, ef) == 128, "ef 必须紧跟在 16 个寄存器之后");
static_assert(offsetof(reg_pack, rax) == 56, "rax 必须落在第 8 个槽（索引 7）");

/* 便捷访问：按名字取第 n 个参数（x64 Windows ABI 的前 4 个整型参数）
 *   arg1 = rcx, arg2 = rdx, arg3 = r8, arg4 = r9 */
inline std::uint64_t arg1(const reg_pack &r) { return r.rcx.i; }
inline std::uint64_t arg2(const reg_pack &r) { return r.rdx.i; }
inline std::uint64_t arg3(const reg_pack &r) { return r.r8.i;  }
inline std::uint64_t arg4(const reg_pack &r) { return r.r9.i;  }

/* 读写调用者栈上的内存（重放 `mov [rsp+N], reg` 这类指令时用）。
 * ★ 注意 r.rsp 是"进入 trampoline 时"的 rsp，不是当前 rsp。 */
inline std::uint64_t *stack_slot(reg_pack &r, std::ptrdiff_t off)
{
    return reinterpret_cast<std::uint64_t *>(r.rsp.i + static_cast<std::uint64_t>(off));
}

} /* namespace mnp */

#endif /* MNP_REG_PACK_HPP */
