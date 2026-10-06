/*
 * bytepattern.hpp - 字节模式搜索（C++）
 *
 * 参照双字节补丁（EU4dll, matanki-saito/EU4dll）的 Plugin64/byte_pattern.*，
 *  【改写版】本文件在原作基础上按本工程需要做了删减、改名与结构调整，不代表原作者的原版实现；
 *            原作者、原许可与完整声明见 THIRD-PARTY.md。
 * 其核心注释写明源自 https://github.com/ThirteenAG/Hooking.Patterns 。
 *
 * 相对原库的取舍：
 *   + 去掉 boost 依赖（原库用 boost::string_view + boost::algorithm::split），
 *     改用 std::string_view + 手写 tokenizer；
 *   + 用 std::vector 收结果（原库也是），并显式提供"唯一命中"断言；
 *   - 原库用带 mask 的 Boyer-Moore-Horspool；我们的模式都很短（7~17 字节），
 *     朴素搜索在几 MB 的 .text 上耗时可忽略，且边界条件少得多 ——
 *     BMH 的失败表本身就是一类 bug 来源，这里不引入。
 *
 * 模式语法（与原库保持一致）：
 *     "48 8B 0D ? ? ? ? 4C 8B C3 33 D2"
 *   token 以空格分隔，每个 1~2 字符：
 *     ?? 或 ?   → 整字节通配        (mask 0x00)
 *     ?X        → 只比较低半字节      (mask 0x0F)
 *     X?        → 只比较高半字节      (mask 0xF0)
 *     XY        → 全字节匹配         (mask 0xFF)
 *   判据：(pattern[i] & mask[i]) == (target[i] & mask[i])
 *
 * 搜索范围：只扫模块的 .text 与 .rdata 节（与原库一致）。
 *   .rdata 是刻意纳入的 —— 版本号字符串之类的只读数据在那里。
 */
#ifndef MNP_BYTEPATTERN_HPP
#define MNP_BYTEPATTERN_HPP

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

namespace mnp {

/* -------------------------------------------------------------------- */
/* 解析后的模式                                                          */
/* -------------------------------------------------------------------- */
struct Pattern
{
    std::vector<std::uint8_t> value;   /* 期望值（已按 mask 归位） */
    std::vector<std::uint8_t> mask;    /* 0x00 = 整字节通配 */
    std::string_view          literal; /* 原始字面量，便于日志 */
    bool                      ok = false;

    std::size_t size() const noexcept { return value.size(); }

    bool matches(const std::uint8_t *p) const noexcept
    {
        for (std::size_t i = 0; i < value.size(); ++i) {
            if ((value[i] & mask[i]) != (p[i] & mask[i])) return false;
        }
        return true;
    }
};

/* 十六进制字符 → 0..15；非法返回 -1 */
inline int hexval(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 解析模式串。失败时返回的 Pattern.ok == false（不是异常）。
 * ★ 原库遇到非法字符会 throw std::invalid_argument，然后被 catch 吞掉并 clear()，
 *   表现为"静默失败、count()==0"。这里同样不抛异常，但拒绝的原因可以通过
 *   返回值的 ok 位判断，便于日志区分"模式写错"和"没搜到"。 */
inline Pattern parse_pattern(std::string_view literal)
{
    Pattern pat;
    pat.literal = literal;

    std::size_t i = 0;
    for (;;) {
        while (i < literal.size() && (literal[i] == ' ' || literal[i] == '\t')) ++i;
        if (i >= literal.size()) break;

        /* 取一个 token（到空格/结尾） */
        std::size_t start = i;
        while (i < literal.size() && literal[i] != ' ' && literal[i] != '\t') ++i;
        const std::string_view tok = literal.substr(start, i - start);

        if (tok.size() == 1) {
            if (tok[0] != '?') { pat.ok = false; return pat; }
            pat.value.push_back(0x00);
            pat.mask.push_back(0x00);            /* 整字节通配 */
        } else if (tok.size() == 2) {
            const char c0 = tok[0];
            const char c1 = tok[1];
            const int  hi = hexval(c0);
            const int  lo = hexval(c1);

            if (c0 == '?') {
                if (lo < 0) { pat.ok = false; return pat; }
                pat.value.push_back(static_cast<std::uint8_t>(lo));
                pat.mask.push_back(0x0F);        /* 只比低半字节 */
            } else if (c1 == '?') {
                if (hi < 0) { pat.ok = false; return pat; }
                pat.value.push_back(static_cast<std::uint8_t>(hi << 4));
                pat.mask.push_back(0xF0);        /* 只比高半字节 */
            } else {
                if (hi < 0 || lo < 0) { pat.ok = false; return pat; }
                pat.value.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
                pat.mask.push_back(0xFF);
            }
        } else {
            /* 3 个以上字符的 token（如 "48 8B" 之外误写）⇒ 拒绝 */
            pat.ok = false;
            return pat;
        }
    }

    if (pat.value.empty()) { pat.ok = false; return pat; }
    pat.ok = true;
    return pat;
}

/* 在 [beg, end) 内找出所有不重叠命中（与原库一致：命中后前进整个模式长度） */
inline std::vector<std::uint8_t *> find_all(const Pattern &pat,
                                            std::uint8_t *beg, std::uint8_t *end)
{
    std::vector<std::uint8_t *> out;
    if (!pat.ok || !beg || !end || end <= beg) return out;
    if (static_cast<std::size_t>(end - beg) < pat.size()) return out;

    auto *p = beg;
    while (p + pat.size() <= end) {
        if (pat.matches(p)) {
            out.push_back(p);
            p += pat.size();
        } else {
            ++p;
        }
    }
    return out;
}

/* -------------------------------------------------------------------- */
/* 模块节范围                                                            */
/* -------------------------------------------------------------------- */
struct SectionRange
{
    std::uint8_t *beg = nullptr;
    std::uint8_t *end = nullptr;
};

/* 只取 .text 与 .rdata（与原库一致）。module 为空则用主模块（eu4.exe）。 */
inline std::vector<SectionRange> module_ranges(void *module = nullptr)
{
    std::vector<SectionRange> out;
    auto *base = static_cast<std::uint8_t *>(module ? module : GetModuleHandleA(nullptr));
    if (!base) return out;

    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;

    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return out;

    auto *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) != 0 &&
            std::memcmp(sec->Name, ".rdata", 6) != 0) {
            continue;
        }
        std::uint32_t vsize = sec->Misc.VirtualSize;
        if (vsize == 0) vsize = sec->SizeOfRawData;
        if (vsize == 0) continue;

        SectionRange r;
        r.beg = base + sec->VirtualAddress;
        r.end = r.beg + vsize;
        out.push_back(r);
    }
    return out;
}

/* -------------------------------------------------------------------- */
/* 搜索结果                                                              */
/* -------------------------------------------------------------------- */
struct SearchResult
{
    bool                        parsed = false;  /* 模式本身合法？ */
    std::vector<std::uint8_t *> hits;            /* 所有命中（按节顺序） */

    std::size_t count() const noexcept { return hits.size(); }
    bool        empty() const noexcept { return hits.empty(); }
    std::uint8_t *first() const noexcept { return hits.empty() ? nullptr : hits.front(); }

    /* 唯一命中时返回该地址，否则 nullptr。
     * ★ 这是本项目最常用的一条判据：模式命中多处时"取第一个"是错的
     *   （签名漂移），必须先确认唯一再取 —— 这正是早期那次
     *   "gen     surn_len rva mismatch: got=0x1c605d want=0x3142f2" 的教训。 */
    std::uint8_t *unique() const noexcept { return hits.size() == 1 ? hits.front() : nullptr; }

    addr first_addr() const noexcept { return first() ? addr{first()} : addr{}; }
    addr unique_addr() const noexcept { return unique() ? addr{unique()} : addr{}; }
};

/* 在指定模块的 .text/.rdata 内搜索 */
inline SearchResult search(std::string_view literal, void *module = nullptr)
{
    SearchResult res;
    const Pattern pat = parse_pattern(literal);
    res.parsed = pat.ok;
    if (!pat.ok) return res;

    for (const auto &r : module_ranges(module)) {
        auto hits = find_all(pat, r.beg, r.end);
        res.hits.insert(res.hits.end(), hits.begin(), hits.end());
    }
    return res;
}

} /* namespace mnp */

#endif /* MNP_BYTEPATTERN_HPP */
