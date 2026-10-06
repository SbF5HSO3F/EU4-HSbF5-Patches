/* cultureconfigdump.exe —— 离线核对：把【真实配置文件】解析后按 DLL 的日志格式打印
 *
 * 用途（为什么需要它）：
 *   生产 DLL 里那份"列出已载入配置"的代码，只有游戏运行时才会执行。
 *   要在不启动游戏的前提下确认"日志里会打出什么、shandong_culture 在不在、序号对不对"，
 *   就用这个工具：它与 DLL 共用同一个解析器（cultureconfig.h）和同一份列印实现
 *   （cultureconfig_list.h），所以输出与 DLL 写进 MonarchNameFix.log 的内容逐字一致。
 *
 * 用法：
 *   cultureconfigdump.exe <配置文件路径> [更多路径...]
 *   cultureconfigdump.exe --dir <目录>            （解析该目录下所有 *.txt）
 *
 * 注意：多个文件按命令行顺序解析，同名文化【后写覆盖先写】—— 与游戏里
 *       "模组覆盖基础游戏"的语义一致。
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nameorder.h"
#include "cultureconfig.h"
#include "cultureconfig_list.h"

/* 与 DLL 的 log_str 等价：直接写 stdout，便于重定向到文件后与日志对照 */
static void out_str(const char *s)
{
    fputs(s, stdout);
}

static cc_state_t g_cc;
static uint32_t   g_files = 0;
static uint8_t   *g_buf;
#define BUF_MAX (1u << 20)

static void load_one(const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t got;
    if (!f) { printf("[!] 打不开: %s\n", path); return; }
    got = fread(g_buf, 1, BUF_MAX - 1, f);
    fclose(f);
    g_buf[got] = 0;
    g_files++;
    cc_parse(&g_cc, (const char *)g_buf, (uint32_t)got);
}

/* 目录扫描：只取 *.txt（与 DLL 的 cc_scan_dir 判据一致） */
static void load_dir(const char *dir)
{
    char pat[MAX_PATH * 2];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    _snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) { printf("[!] 目录打不开: %s\n", dir); return; }
    do {
        char full[MAX_PATH * 2];
        size_t n;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        n = strlen(fd.cFileName);
        if (n < 4) continue;
        if (_stricmp(fd.cFileName + n - 4, ".txt") != 0) continue;
        _snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        printf("[i] file: %s\n", full);
        load_one(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int main(int argc, char **argv)
{
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);

    g_buf = (uint8_t *)VirtualAlloc(NULL, BUF_MAX, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_buf) { printf("[x] buffer alloc failed\n"); return 2; }
    memset(g_buf, 0, 64);

    /* 不接游戏内存：这里只做"解析 + 列印"，因此读回调留空。
     * cc_list_dump 不碰 rd，xref_n 恒为 0 ⇒ 全部 bound=0（与 DLL 安装期一致）。 */
    g_cc.modbase = NULL;
    g_cc.rd.rd = NULL;
    g_cc.rd.ok = NULL;
    g_cc.rd.ctx = NULL;

    if (argc < 2) {
        printf("用法: cultureconfigdump.exe <配置.txt> [...]  |  --dir <目录>\n");
        return 2;
    }

    if (!strcmp(argv[1], "--dir")) {
        if (argc < 3) { printf("--dir 需要一个目录参数\n"); return 2; }
        load_dir(argv[2]);
    } else {
        for (i = 1; i < argc; i++) { printf("[i] file: %s\n", argv[i]); load_one(argv[i]); }
    }

    printf("\n");
    cc_list_dump(&g_cc, out_str, g_files);
    printf("\n[i] files=%u entries=%d\n", g_files, g_cc.count);
    return 0;
}
