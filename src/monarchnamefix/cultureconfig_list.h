/*
 * cultureconfig_list.h —— 把【已载入的文化配置】整份列进日志
 *
 * 单一事实来源：生产 DLL（monarchnamefix.cpp）与离线工具（cultureconfigdump.cpp）
 * 共用这一个函数，所以"日志里会打出什么"可以在不启动游戏的情况下逐字验证。
 *
 * 为什么单独成一个头文件（2026-10-05 第二轮）：
 *   上一轮把这段列印代码写在 monarchnamefix.cpp 的 cc_lazy_ready()【成功分支】里，
 *   而那条分支在实机上【永远不会执行】——
 *   p4_transform 先用「按文化名查配置」(cc_lookup_name) 那条路，命中后直接 goto out，
 *   只有在 g_cult_name 还没捕获到、或配置条目为 0 时才会落到 cc_lazy_ready()。
 *   实机日志因此只有一行摘要（"[i] culture config: files=1 entries=45 bound=0"），
 *   一条 CFGENTRY 都没有 —— 功能等于没生效。
 *   ⇒ 现在由调用方在【解析完成之后】无条件调用 cc_list_dump()，与绑定成功与否无关。
 *
 * 输出形如：
 *   [i] ===== culture config loaded: 45 entries =====
 *   [i] CFGENTRY #0 "chihan" sf=1 sep_len=0 sep="" bound=0
 *   [i] CFGENTRY #43 "hungarian" sf=1 sep_len=1 sep="\x20" bound=1
 *   [i] ===== end culture config (entries=45 files=1 bind_state=0 bound=0) =====
 *
 *   bound = 该条目是否已解析出游戏内的文化对象（注册表建好前恒为 0）；
 *   sf    = surname_first；
 *   sep   = 配置的分隔符，逐字节打十六进制（非 ASCII 在日志里显示成点，肉眼分不出内容）。
 */
#ifndef CULTURECONFIG_LIST_H
#define CULTURECONFIG_LIST_H

#include <stdint.h>
#include "cultureconfig.h"

/* 日志输出回调。生产环境传 monarchnamefix.cpp 的 log_str，离线工具传自己的 writer。 */
typedef void (*cc_log_fn)(const char *s);

/* 无符号十进制 → 回调（不引入 sprintf：本文件被"只用 kernel32"的 DLL 共用） */
static void cc_list_num(cc_log_fn logfn, uint32_t v)
{
    char buf[11];
    char *p = buf + 10;
    *p = 0;
    if (v == 0) *--p = '0';
    while (v) { *--p = (char)('0' + (v % 10u)); v /= 10u; }
    logfn(p);
}

static void cc_list_dump(const cc_state_t *S, cc_log_fn logfn, uint32_t files)
{
    int i, x;

    if (!logfn) return;

    logfn("[i] ===== culture config loaded: ");
    cc_list_num(logfn, S ? (uint32_t)S->count : 0u);
    logfn(" entries =====\r\n");

    if (!S) { logfn("[i] ===== end culture config =====\r\n"); return; }

    for (i = 0; i < S->count; i++) {
        uint32_t k;
        int bound = 0;

        logfn("[i] CFGENTRY #");
        cc_list_num(logfn, (uint32_t)i);
        logfn(" \"");
        logfn(S->entry[i].name);
        logfn("\" sf=");
        cc_list_num(logfn, (uint32_t)S->entry[i].surname_first);
        logfn(" sep_len=");
        cc_list_num(logfn, (uint32_t)S->entry[i].sep.len);

        /* 分隔符只打十六进制：避免非 ASCII 在日志里显示成点而看不出内容 */
        logfn(" sep=\"");
        for (k = 0; k < S->entry[i].sep.len && k < NAME_SEP_MAX; k++) {
            static const char hx[] = "0123456789abcdef";
            unsigned ch = (unsigned char)S->entry[i].sep.b[k];
            char hb[8];
            hb[0] = '\\'; hb[1] = 'x';
            hb[2] = hx[(ch >> 4) & 0xF];
            hb[3] = hx[ch & 0xF];
            hb[4] = 0;
            logfn(hb);
        }
        logfn("\"");

        /* 该条目是否已解析出对应的游戏内文化对象 */
        for (x = 0; x < S->xref_n; x++) {
            if (S->xref[x].idx == i) { bound = 1; break; }
        }
        logfn(" bound=");
        cc_list_num(logfn, (uint32_t)bound);
        logfn("\r\n");
    }

    logfn("[i] ===== end culture config (entries=");
    cc_list_num(logfn, (uint32_t)S->count);
    logfn(" files=");
    cc_list_num(logfn, files);
    logfn(" bind_state=");
    cc_list_num(logfn, (uint32_t)S->bind_state);
    logfn(" bound=");
    cc_list_num(logfn, (uint32_t)S->xref_n);
    logfn(") =====\r\n");

    /* ★ 必须写清楚 bound=0 的含义，否则这一列会被读成"一条都没绑上"。
     *   本函数在【解析刚结束、注册表还没建好】时调用（见 cc_init），
     *   此时 xref_n 必然是 0；真正的绑定在第一次 P4 变换调用时懒执行，
     *   结果由 cc_lazy_ready() 的 "[i] culture bound lazily:" 那行报告。 */
    if (S->bind_state == CC_BIND_IDLE && S->xref_n == 0) {
        logfn("[i] (bind_state=IDLE/entries all bound=0 is EXPECTED here: "
              "the culture registry does not exist yet at install time; "
              "binding runs lazily at the first transform)\r\n");
    }
}

#endif /* CULTURECONFIG_LIST_H */
