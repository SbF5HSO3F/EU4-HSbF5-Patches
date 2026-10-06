/*
 * hookmem.hpp - 内存改写层（C++）
 *
 * 参照双字节补丁（EU4dll, matanki-saito/EU4dll）的 Plugin64/injector.hpp。
 *
 * 为什么改成 C++：EU4 本身是 C++ 写的，本项目后续要持续加修复与功能，
 * 用 C++ 才能用上 RAII / 类型安全 / 更强的表达能力。核心的字节操作与
 * 汇编桩本身与语言无关，这里的迁移是为了"长期可维护"。
 *
 * ============================ 相对原库的改进 ============================
 *
 * (1) 【修 bug】MakeJMP 的跨 2GB 判据
 *     原库：
 *         auto offset = GetRelativeOffset(dest, at + 1 + 4);   // uintptr_t
 *         if (offset > 0x7FFFFFFF) { ... 14 字节 FF 25 ... }
 *     offset 是【无符号】的，于是任何"向后（低地址）跳转"都被算成巨大无符号数，
 *     必然走 14 字节绝对形式。EU4 里 plugin64.dll 与 eu4.exe 距离远超 2GB，
 *     所以它的每一次 MakeJMP 实际都写 14 字节 —— 被覆盖区必须 ≥14 字节。
 *     本实现改用【有符号】比较：能写 5 字节就写 5 字节。
 *
 * (2) 【补漏】原库全程不调 FlushInstructionCache。本实现每次都调。
 *
 * (3) 【防坑】原库 WriteMemory/ReadMemory 的 vp 参数默认 false（不改页保护），
 *     而 MakeJMP 等默认 true —— 极易踩坑。本实现没有"默认值"这个坑：
 *     保护由 scoped_protect 显式管理，写操作的入口只有一个。
 *
 * (4) 【RAII】原库的 scoped_unprotect 是 RAII，但 write 路径自己内部配对；
 *     本实现把 RAII 提到调用者可见的位置，并保留一个"一步到位"的便捷入口。
 *
 * 跳转形式（与 EU4dll 相同）：
 *     E9 rel32                        5 字节   （目标在 ±2GB 内）
 *     FF 25 00 00 00 00 <8字节绝对>   14 字节  （目标超出 ±2GB）
 * 绝对形式里，[rip+0] 指向的下一条指令地址恰好就是紧跟其后的 8 字节目标本身
 * ——这就是原库唯一使用的"指针表"方案，不需要额外分配 thunk。
 */
#ifndef MNP_HOOKMEM_HPP
#define MNP_HOOKMEM_HPP

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <type_traits>

namespace mnp {

/* ==================================================================== */
/* 地址与指针：一个薄的类型安全包装                                       */
/* ==================================================================== */
/* 原库有一整套 memory_pointer / memory_pointer_raw / memory_pointer_tr /
 * address_manager（ASLR 翻译）。对 EU4 而言 pch.h 没定义
 * INJECTOR_GVM_HAS_TRANSLATOR，translator 是恒等函数 —— 那套类型的实际
 * 效果等于裸指针，却带来大量模板噪音。
 * 我们只需要"能当整数用、能解引用"的东西，所以用一个显式的小类。 */
class addr
{
public:
    constexpr addr() noexcept : v_(0) {}
    constexpr explicit addr(std::uintptr_t v) noexcept : v_(v) {}
    addr(const void *p) noexcept : v_(reinterpret_cast<std::uintptr_t>(p)) {}

    std::uintptr_t value() const noexcept { return v_; }
    bool is_null() const noexcept { return v_ == 0; }

    addr operator+(std::ptrdiff_t d) const noexcept { return addr(v_ + static_cast<std::uintptr_t>(d)); }
    addr operator-(std::ptrdiff_t d) const noexcept { return addr(v_ - static_cast<std::uintptr_t>(d)); }
    std::ptrdiff_t operator-(const addr &o) const noexcept {
        return static_cast<std::ptrdiff_t>(v_) - static_cast<std::ptrdiff_t>(o.v_);
    }

    bool operator==(const addr &o) const noexcept { return v_ == o.v_; }
    bool operator!=(const addr &o) const noexcept { return v_ != o.v_; }
    bool operator<(const addr &o) const noexcept { return v_ < o.v_; }

    template <class T> T *as() const noexcept { return reinterpret_cast<T *>(v_); }
    template <class T> T &ref() const noexcept { return *reinterpret_cast<T *>(v_); }

    explicit operator std::uintptr_t() const noexcept { return v_; }
    explicit operator bool() const noexcept { return v_ != 0; }

private:
    std::uintptr_t v_;
};

/* ==================================================================== */
/* scoped_protect —— RAII 页保护                                          */
/* ==================================================================== */
/* 语义与原库 scoped_unprotect 相同，但：
 *   - 不可拷贝、可移动（原库的 scoped_basic 有移动赋值但写得很绕）；
 *   - 明确报告 begin 是否成功；
 *   - 析构时恢复【原始的】保护值。
 * ★ 这里的"忘记配对"风险由析构消除 —— 这正是改用 C++ 的直接收益之一。 */
class scoped_protect
{
public:
    scoped_protect() noexcept : addr_(nullptr), size_(0), old_(0), active_(false) {}

    scoped_protect(void *p, std::size_t n, DWORD prot = PAGE_EXECUTE_READWRITE) noexcept
        : addr_(nullptr), size_(0), old_(0), active_(false)
    {
        begin(p, n, prot);
    }

    ~scoped_protect() { end(); }

    scoped_protect(const scoped_protect &) = delete;
    scoped_protect &operator=(const scoped_protect &) = delete;

    scoped_protect(scoped_protect &&o) noexcept
        : addr_(o.addr_), size_(o.size_), old_(o.old_), active_(o.active_)
    {
        o.active_ = false;
    }

    scoped_protect &operator=(scoped_protect &&o) noexcept
    {
        if (this != &o) {
            end();
            addr_ = o.addr_; size_ = o.size_; old_ = o.old_; active_ = o.active_;
            o.active_ = false;
        }
        return *this;
    }

    bool begin(void *p, std::size_t n, DWORD prot = PAGE_EXECUTE_READWRITE) noexcept
    {
        end();
        if (!p || n == 0) return false;
        if (!VirtualProtect(p, n, prot, &old_)) return false;
        addr_ = p; size_ = n; active_ = true;
        return true;
    }

    void end() noexcept
    {
        if (active_) {
            DWORD tmp = 0;
            VirtualProtect(addr_, size_, old_, &tmp);
            active_ = false;
        }
    }

    bool active() const noexcept { return active_; }

private:
    void *addr_;
    std::size_t size_;
    DWORD old_;
    bool active_;
};

/* ==================================================================== */
/* 基本读写                                                              */
/* ==================================================================== */

/* 写内存：自动开页保护 → 写 → 刷指令缓存 → 还原。
 * 返回 false 表示失败（此时【不会】有任何字节被写入）。 */
inline bool write_raw(void *dst, const void *src, std::size_t n)
{
    if (!dst || !src || n == 0) return n == 0;
    scoped_protect sp(dst, n);
    if (!sp.active()) return false;
    std::memcpy(dst, src, n);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return true;   /* sp 析构时自动还原保护 */
}

template <class T>
inline bool write(const addr at, const T &value)
{
    static_assert(std::is_trivially_copyable<T>::value,
                  "write<T> 只接受可平凡复制的类型（避免把有构造函数的对象塞进游戏内存）");
    return write_raw(at.as<void>(), &value, sizeof(T));
}

template <class T>
inline bool read(const addr at, T &out)
{
    static_assert(std::is_trivially_copyable<T>::value, "read<T> 同上");
    if (at.is_null()) return false;
    std::memcpy(&out, at.as<const void>(), sizeof(T));
    return true;
}

template <class T>
inline T read_or(const addr at, T fallback = T{})
{
    T v{};
    return read(at, v) ? v : fallback;
}

/* 填充字节（原库 MemoryFill） */
inline bool fill(void *dst, std::uint8_t value, std::size_t n)
{
    if (!dst || n == 0) return n == 0;
    scoped_protect sp(dst, n);
    if (!sp.active()) return false;
    std::memset(dst, value, n);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return true;
}

/* NOP 填充（原库 MakeNOP） */
inline bool make_nop(void *dst, std::size_t count) { return fill(dst, 0x90, count); }

/* ==================================================================== */
/* 分支目标读取（原库 GetBranchDestination）                              */
/* ==================================================================== */
/* 识别四类编码，返回该位置【原本】的分支目标；识别不了返回空 addr。
 *   E8/E9                        rel32 在 +1
 *   FF / 0F + 15|25|85|8D|84|8E  rel32 在 +2
 *   48|4C + 8B|8D + 0D|15        (mov/lea r64,[rip+disp32])  disp32 在 +3
 *
 * ★ 这个函数是"链式挂钩"的关键：旧程序可能已经在同一位置挂了钩子，
 *   读回它的目标，把我们的桩末端接回去 —— 比猜偏移可靠得多。 */
inline addr branch_dest(addr at)
{
    if (at.is_null()) return addr{};
    const auto *p = at.as<const std::uint8_t>();
    std::int32_t rel = 0;

    if (p[0] == 0xE8 || p[0] == 0xE9) {
        std::memcpy(&rel, p + 1, 4);
        return addr(at.value() + 5 + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(rel)));
    }
    if (p[0] == 0xFF || p[0] == 0x0F) {
        const std::uint8_t m = p[1];
        if (m == 0x15 || m == 0x25 || m == 0x85 || m == 0x8D || m == 0x84 || m == 0x8E) {
            std::memcpy(&rel, p + 2, 4);
            return addr(at.value() + 6 + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(rel)));
        }
    }
    if ((p[0] == 0x48 || p[0] == 0x4C) && (p[1] == 0x8B || p[1] == 0x8D)) {
        const std::uint8_t m = p[2];
        if (m == 0x0D || m == 0x15) {
            std::memcpy(&rel, p + 3, 4);
            return addr(at.value() + 7 + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(rel)));
        }
    }
    return addr{};
}

/* ==================================================================== */
/* 跳转写入                                                              */
/* ==================================================================== */

/* 预判 make_jmp 会写几字节。安装前先用它确认被覆盖区间够长，
 * 避免"写下去才发现切坏了后面的指令"——那时已无法回滚。 */
inline std::size_t jmp_len_for(addr site, addr dest) noexcept
{
    const std::int64_t rel =
        static_cast<std::int64_t>(dest.value()) - static_cast<std::int64_t>(site.value() + 5);
    return (rel >= INT32_MIN && rel <= INT32_MAX) ? 5u : 14u;
}

/* 写跳转。返回实际写入的字节数（0 = 失败）。
 * ★ 调用者必须保证被覆盖区间 >= 返回值。 */
inline std::size_t make_jmp(addr site, addr dest)
{
    if (site.is_null() || dest.is_null()) return 0;
    auto *p = site.as<std::uint8_t>();

    const std::int64_t rel =
        static_cast<std::int64_t>(dest.value()) - static_cast<std::int64_t>(site.value() + 5);

    if (rel >= INT32_MIN && rel <= INT32_MAX) {
        std::uint8_t code[5];
        code[0] = 0xE9;
        const auto r32 = static_cast<std::int32_t>(rel);
        std::memcpy(code + 1, &r32, 4);
        return write_raw(p, code, sizeof(code)) ? 5u : 0u;
    }

    /* FF 25 00000000  jmp qword ptr [rip+0]   ; rip = site+6，正好指向下面的 8 字节 */
    std::uint8_t code[14];
    code[0] = 0xFF;
    code[1] = 0x25;
    const std::int32_t zero = 0;
    std::memcpy(code + 2, &zero, 4);
    const std::uint64_t target = dest.value();
    std::memcpy(code + 6, &target, 8);
    return write_raw(p, code, sizeof(code)) ? 14u : 0u;
}

/* 写相对调用。原库 MakeCALL 的判据写成 `> 0xFFFFFFFF`（疑似 0x7FFFFFFF 的笔误），
 * 导致它事实上永远写 E8 rel32、没有 >2GB 回退。这里显式拒绝超范围调用。 */
inline std::size_t make_call(addr site, addr dest)
{
    if (site.is_null() || dest.is_null()) return 0;
    const std::int64_t rel =
        static_cast<std::int64_t>(dest.value()) - static_cast<std::int64_t>(site.value() + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return 0;

    std::uint8_t code[5];
    code[0] = 0xE8;
    const auto r32 = static_cast<std::int32_t>(rel);
    std::memcpy(code + 1, &r32, 4);
    return write_raw(site.as<void>(), code, sizeof(code)) ? 5u : 0u;
}

} /* namespace mnp */

#endif /* MNP_HOOKMEM_HPP */
