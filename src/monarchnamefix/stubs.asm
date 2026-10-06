; ============================================================================
; stubs.asm - 通用钩子 trampoline（MASM x64）
;
; 设计照搬双字节补丁（EU4dll）Plugin64/assembly.hpp 的 MakeInline：
;   "把所有通用寄存器压栈 → 把栈指针作为 reg_pack* 传给 C++ → 弹回"
; 于是每个钩子的【业务逻辑一行汇编都不用写】，桩里只剩：
;       MNP_ENTER / 设置 handler / call / MNP_EXIT / 重放原指令 / push ret
; 其中只有"重放"那 1~3 条是本钩子特有的。
;
; ★ 与 EU4dll 的关键差异（也是我们能工作的原因）：
;   它用 MakeCALL 写 5 字节 `E8 rel32`，要求 trampoline 在其 ±2GB 内。
;   而 trampoline 在 plugin64.dll 里、与 eu4.exe 相距 26GB，
;   所以它那套在 EU4 上根本装不上（这也是它自己没用 MakeInline 的原因）。
;   我们改成分层跳转，距离不再是障碍：
;
;       eu4.exe 站点  E9 rel32 → cave(贴近 exe)          5 字节
;       cave          FF 25 + 绝对地址 → 本文件的 trampoline  14 字节
;       trampoline    ... 业务逻辑全在 C++ ...
;       trampoline 尾 push <resume>; ret → 回到站点之后
;
; ★ reg_pack 的内存布局与 push 顺序互为镜像，改一处必须同时改另一处：
;   栈上从低到高： rdi rsi rbp rsp rbx rdx rcx rax r8 r9 r10 r11 r12 r13 r14 r15 flags
;   push 顺序（先→后）： flags r15 r14 r13 r12 r11 r10 r9 r8 rax rcx rdx rbx rsp rbp rsi rdi
;
; ★ 关于 rsp 槽的修正：
;   x64 的 `push rsp` 压入的是【递减之后】的 rsp，所以 `pop rsp` 恰好还原到它
;   自己的位置 —— 弹栈序列因此自洽无害。但这意味着 reg_pack::rsp 保存的
;   【不是】站点处原代码的 rsp。重放 `mov [rsp+8], rbx` 这类指令必须用真实值，
;   所以在建立好 reg_pack 后立刻修正：
;       reg_pack 起始 = S-136 ；rsp 槽 = S-112 ；目标 = S+8 ；差 = 120
;
; 栈对齐：入口 rsp ≡ 8（call 刚压返回地址）；17 条 push = 136 ≡ 8 ⇒ rsp ≡ 0；
;   `sub rsp,20h` 之后仍是 ≡ 0 ⇒ 满足 x64 的 call 前 ≡ 0 要求。
; ============================================================================

EXTERN mnpfn_gen_entry_culture      : QWORD
EXTERN mnpfn_gen_loop_decide       : QWORD
EXTERN mnpfn_gen_surn_len        : QWORD
EXTERN mnpfn_gen_reorder     : QWORD
EXTERN mnpfn_gen_exit_fallback    : QWORD
EXTERN mnpfn_disp_ruler_name      : QWORD
EXTERN mnpfn_modfix_pick_cult       : QWORD   ; 取模修复（PickNameFromCultureLists）
EXTERN mnpfn_modfix_pick_modidx       : QWORD   ; 取模修复（WeightedNameList_GetByModIndex）
EXTERN mnpfn_modfix_pick_idx       : QWORD   ; 随机值掩 21 位（PickByRandomIndex 序言）

EXTERN mnp_ret_gen_entry_culture            : QWORD
EXTERN mnp_ret_gen_loop_decide            : QWORD
EXTERN mnp_ret_gen_loop_decide_skip       : QWORD
EXTERN mnp_ret_modfix_pick_idx0           : QWORD
EXTERN mnp_ret_modfix_pick_idx1           : QWORD
EXTERN mnp_ret_gen_exit_fallback            : QWORD
EXTERN mnp_ret_disp_ruler_name            : QWORD
EXTERN mnp_ret_modfix_pick_cult            : QWORD
EXTERN mnp_ret_modfix_pick_modidx            : QWORD
EXTERN mnp_ret_modfix_pick_idx            : QWORD

; ----------------------------------------------------------------------------
; 进入：建立 reg_pack，并把 reg_pack* 放进 rcx（x64 第 1 个整型参数）
;
; ★★ reg_pack 的内存布局（从低地址到高地址），与 push 顺序互为镜像：
;       +0x00 rdi   +0x08 rsi   +0x10 rbp   +0x18 rsp   +0x20 rbx
;       +0x28 rdx   +0x30 rcx   +0x38 rax   +0x40 r8 .. +0x78 r15
;       +0x80 flags
;    总 136 字节。
;
; ★★ rsp 槽的修正量 = 104 (0x68) —— 2026-10-05 由实测【定标】得出
;
;   设 S = 刚进入 trampoline 时的 rsp。
;   站点是 `jmp` 过来的（经过 cave 的 FF25 也是 jmp），【不压栈】，
;   所以 S 就等于"站点处原代码的 rsp"。
;
;   `push rsp` 是第 14 条 push，执行前 rsp = S - 8*13 = S - 104。
;   槽里存的那个值加上修正量，就应当等于 S。
;
;   实测（gen     reorderCHK 自检，64 次样本全部一致）：
;       rbp - rsp_pack = 0xF8
;     而由 BuildFullName_Impl 的序言可证 rbp - rsp_real = 0x100：
;       push rbp/r14/r15 (rsp -= 0x18) → lea rbp,[rsp-0x10] → sub rsp,0x110
;       ⇒ rbp = R0-0x28, rsp = R0-0x128 ⇒ 差 = 0x100
;     ⇒ rsp_pack = rsp_real + 8
;     ⇒ 原先的 112 偏大 8，定标为 104。
;
;   实测同一份日志里还有第二重印证：
;       sp = rsp_pack + 0x30 = 0x...838
;       &Src = rbp - 0xD0    = 0x...830      ⇒ 正好差 +8
;   （sp 本应等于 &Src，见 gen     loop_decide 注释里的 [rbp-0D0h]。）
;
; ★ 这个 8 字节偏差就是三次实机崩溃的根因：
;   gen     reorder 读那个局部 CString 时整体错位 +8 ——
;       buf  = [&Src+0x08]  ← SSO 缓冲区中间，被当成"堆指针"
;       size = [&Src+0x18]  ← 真实的 cap
;       cap  = [&Src+0x20]  ← 越出 CString
;   Src 本身是 SSO 串（cap=15 < 0x10），错位后 cap 读成 48(>=0x10)
;   ⇒ 误判为堆串 ⇒ 把一个垃圾值当堆指针、把名字写进去 ⇒ 堆被破坏
;   ⇒ 随后 free() 崩在 ntdll!RtlFreeHeap，或表现为无 dump 的静默闪退。
;
;   历史：最初 120(0x78) → 以为 push rsp 压递减前的值，改 112(0x70)
;         → 实测仍偏大 8 ⇒ 定标 104(0x68)。
; ----------------------------------------------------------------------------
MNP_ENTER macro
    pushfq
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rsp
    push    rbp
    push    rsi
    push    rdi
    ; 此刻 rsp 指向 reg_pack 起始

    add     qword ptr [rsp+18h], 68h     ; 修正 reg_pack::rsp 为站点处的真实 rsp

    mov     rcx, rsp                    ; 第 1 参数 = reg_pack*
    sub     rsp, 20h                    ; shadow space（保持 16 字节对齐）
endm

; ----------------------------------------------------------------------------
; 离开：还原全部通用寄存器与 RFLAGS
;
; ★★★ 这里【不能】用 `pop rsp`。
;   `pop rsp` 的语义是"把栈顶的值【赋给】rsp"，不是"弹栈跳过 8 字节"：
;       pop rsp  ⇒  rsp = [rsp]
;   而 [reg_pack+0x18] 里存的是 S-104（见上），于是 rsp 会停在 S-104，
;   而它本应是 S —— 差 104 字节，导致后面 13 个 pop 全部取错位置，
;   重放原指令时写到错误的栈位置 ⇒ 进游戏直接闪退且不留崩溃信息
;   （栈被破坏后 ret 跳到非法处，游戏自己的异常处理也拿不到）。
;   ⇒ 正确做法是 `add rsp, 8` 跳过 rsp 槽：
;       pop rdi/rsi/rbp  ⇒ rsp = reg_pack + 24
;       add rsp, 8       ⇒ rsp = reg_pack + 32（正好是 rbx 槽）
;       再 pop 13 个 + popfq ⇒ rsp = reg_pack + 32 + 104 = S ✓
; ----------------------------------------------------------------------------
MNP_EXIT macro
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8                      ; ★ 跳过 rsp 槽（绝不用 pop rsp）
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    popfq
endm

.CODE

; ----------------------------------------------------------------------------
; modfix  pick_idx —— WeightedNameList_PickByRandomIndex 序言（RVA 0xDA989B，覆盖 5 字节）
; 原指令： 49 8B F8        mov  rdi, r8
;          8B F2           mov  esi, edx
; 回跳   0xDA98A0（mov rcx, r10）
;
; ★★★ 这是【继承人取名实际走的那条路径】，也是本轮用户报告的核心：
;
;   该函数的调用链（见 notes\继承人姓名子系统-调用链与未决事项.md §2）：
;       Country_CreateHeir_Impl
;         └─ GenerateMonarchNameAlt
;              └─ WeightedNameList_PickByRandomIndex(mode = 性别 byte)
;                   其中 mode == 1 ⇒ 0x140DA98CA `cdq; idiv ecx`   ← 缺陷
;
;   随机源是 `Random_GetGlobalMT()` 的【完整 32 位】，可以为负。
;   而 0x140DA98C3 `mov eax, edx` 直接把 edx 当被除数，
;   紧接着 `cdq; idiv ecx`（有符号除法）⇒ 随机值为负时余数为负
;   ⇒ 取样全部回落到第 0 号位 = "取第一号位的概率被放大"。
;
;   ⇒ 正解就是在这里把随机值【掩成 21 位非负数】：
;         and edx, 001FFFFFh
;   而 `esi` 是 mode 0/2 使用的副本，由紧随其后的 `mov esi, edx` 从
;   掩后的 edx 复制而来，所以【不需要单独掩 esi】——
;   掩码放在两条重放【之前】即可同时覆盖两条路径。
;
; 与 modfix  pick_cult/modfix  pick_modidx 的分工不同：这里整段都是数据操作，没有除法指令留在桩里，
; 所以掩码由 C++ handler 完成，桩只负责重放那两条 mov。
; ----------------------------------------------------------------------------
mnp_hook_modfix_pick_idx PROC
    MNP_ENTER
    mov     rax, mnpfn_modfix_pick_idx
    call    rax
    MNP_EXIT
    mov     rdi, r8                     ; 重放原指令 1
    mov     esi, edx                    ; 重放原指令 2（edx 已被 handler 掩过）
    push    mnp_ret_modfix_pick_idx
    ret
mnp_hook_modfix_pick_idx ENDP


; ----------------------------------------------------------------------------
; modfix  pick_cult —— PickNameFromCultureLists 的取模（RVA 0x280274，覆盖 6 字节）
; 原指令： 8B C7           mov  eax, edi
;          99              cdq                  ← 有符号扩展
;          41 F7 F8        idiv r8d             ← 有符号除法
; 回跳   0x28027A（cmp ecx, edx）
;
; ★★★ 为什么必须改（用户报告的"取第一号位的概率被放大"就是它）：
;   `idiv` 是有符号除法：当 eax 的高位为 1（即索引 > 0x7FFFFFFF）时，
;   余数 edx 会变成【负数】。而调用方随后用 `cmp ecx, edx / jge` 判断，
;   负余数直接被当成"越界"处理，全部回落到第 0 号位 —— 于是取第一号位的
;   概率被显著放大。
;   索引本不该为负，所以正解是把这段改成【无符号】：
;       mov  eax, edi
;       and  eax, 001FFFFFh     ; 掩掉高位（与旧实现一致）
;       xor  edx, edx           ; 无符号除法的高 32 位
;       div  r8d                ; 无符号除法
;
; 分工：掩码与清零由 C++ handler 改 reg_pack 完成（MNP_EXIT 会把它们写回
;       寄存器），`div r8d` 这条指令留在桩里执行 —— 因为 div 的溢出行为
;       （商放不下 32 位时报 #DE）必须与硬件一致，用 C++ 除法表达不了。
; ----------------------------------------------------------------------------
mnp_hook_modfix_pick_cult PROC
    MNP_ENTER
    mov     rax, mnpfn_modfix_pick_cult
    call    rax
    MNP_EXIT
    div     r8d                         ; ★ 无符号除法（替代原 idiv）
    push    mnp_ret_modfix_pick_cult
    ret
mnp_hook_modfix_pick_cult ENDP


; ----------------------------------------------------------------------------
; modfix  pick_modidx —— WeightedNameList_GetByModIndex 的取模（RVA 0xDA9A82，覆盖 6 字节）
; 原指令： 8B C2           mov  eax, edx
;          99              cdq
;          41 F7 F8        idiv r8d
; 回跳   0xDA9A88（lea (rdx,rdx,4), rax）
;
; 函数全貌（RVA 0xDA9A60，元素 40 字节）：
;     r9 = [rcx+0x18]        ; begin
;     r8 = [rcx+0x20] - r9   ; end - begin
;     r8 >>= 3; r8 *= 0xCCCCCCCCCCCCCCCD   ; ⇒ /5 ⇒ 元素数 = bytes/40
;     if (r8d == 0) return 0
;     eax = edx; cdq; idiv r8d             ; ★ 站点：index % count
;     rax = rdx*5; rax = r9 + rax*8        ; ⇒ begin + (index%count)*40
;     return rax
; 与 modfix  pick_cult 同一类错误（有符号除法），同样改成无符号。
; ----------------------------------------------------------------------------
mnp_hook_modfix_pick_modidx PROC
    MNP_ENTER
    mov     rax, mnpfn_modfix_pick_modidx
    call    rax
    MNP_EXIT
    div     r8d                         ; ★ 无符号除法（替代原 idiv）
    push    mnp_ret_modfix_pick_modidx
    ret
mnp_hook_modfix_pick_modidx ENDP


; ----------------------------------------------------------------------------
; gen     entry_culture —— BuildFullName_Impl 入口（RVA 0x313F40，覆盖 5 字节）
; 原指令 48 89 5C 24 08   mov [rsp+8], rbx      回跳 0x313F45
; C++ 侧从 reg_pack::r8（第 3 参数 = 文化对象）取文化名。
; ----------------------------------------------------------------------------
mnp_hook_gen_entry_culture PROC
    MNP_ENTER
    mov     rax, mnpfn_gen_entry_culture
    call    rax
    MNP_EXIT
    mov     qword ptr [rsp+8], rbx      ; 重放原指令
    push    mnp_ret_gen_entry_culture
    ret
mnp_hook_gen_entry_culture ENDP


; ----------------------------------------------------------------------------
; gen     loop_decide —— BuildFullName_Impl 循环前置位（RVA 0x314228，覆盖 8 字节）
; 原指令 85 C0 / 7E 59 / 49 8B DF / 90
;        test eax,eax ; jle 0x314285 ; mov rbx,r15 ; nop
; 回跳   0x314230
;
; ★★ 两个坑（详见 notes 交接文档 §0-L）：
;   坑 1：eax 是【循环计数】（0x314225 movslq %eax,%rsi 之后 test/jle 判的就是它）。
;         业务结论由 C++ 走全局变量给出，这里【不碰 eax】，原样重放 test/jle。
;   坑 2：r15 在本函数里只有 0x313F6E 的 xor r15d,r15d 写过一次，此后再无写入
;         ⇒ 语义值恒为 0（只是循环起始偏移）。旧实现"忠实重放" mov rbx,r15，
;         把语义交给了 r15 的运行时值；一旦被污染，循环首条 lea rdx,[r8+rbx]
;         就把"数组基址+野指针"算成野地址（C0000005 @ RVA 0x314237）。
;         ⇒ 这里直接 xor ebx,ebx —— 理解语义后的重新表达。
; ----------------------------------------------------------------------------
mnp_hook_gen_loop_decide PROC
    MNP_ENTER
    mov     rax, mnpfn_gen_loop_decide
    call    rax
    MNP_EXIT
    test    eax, eax                    ; 重放原指令（判断循环计数）
    jle     mnp_gen_loop_decide_skip
    xor     ebx, ebx                    ; 替代 mov rbx,r15
    push    mnp_ret_gen_loop_decide
    ret
mnp_gen_loop_decide_skip:
    push    mnp_ret_gen_loop_decide_skip
    ret
mnp_hook_gen_loop_decide ENDP


; ----------------------------------------------------------------------------
; gen     surn_len —— 存姓长度（RVA 0x3142F2，覆盖 5 字节）
; 原指令 48 8D 4C 24 30   lea rcx, [rsp+30h]   回跳 0x3142F7
; C++ 侧从 reg_pack::r8 取姓的字节数。
; ----------------------------------------------------------------------------
mnp_hook_gen_surn_len PROC
    MNP_ENTER
    mov     rax, mnpfn_gen_surn_len
    call    rax
    MNP_EXIT
    lea     rcx, [rsp+30h]              ; 重放原指令
    push    mnp_ret_modfix_pick_idx0
    ret
mnp_hook_gen_surn_len ENDP


; ----------------------------------------------------------------------------
; gen     reorder —— 就地重排（RVA 0x3142FC，覆盖 5 字节）
; 原指令 0F 10 44 24 30   movups xmm0, [rsp+30h]   回跳 0x314301
; ----------------------------------------------------------------------------
mnp_hook_gen_reorder PROC
    MNP_ENTER
    mov     rax, mnpfn_gen_reorder
    call    rax
    MNP_EXIT
    movups  xmm0, xmmword ptr [rsp+30h] ; 重放原指令
    push    mnp_ret_modfix_pick_idx1
    ret
mnp_hook_gen_reorder ENDP


; ----------------------------------------------------------------------------
; gen     exit_fallback —— BuildFullName_Impl 出口（RVA 0x314349，覆盖 5 字节）
; 原指令 41 5F / 41 5E / 5D   pop r15 ; pop r14 ; pop rbp   回跳 0x31434E (ret)
;
; ★★★ 这里曾经导致三次"运行很久之后才崩"的 C0000005 @ RVA 0x94F4A：
;   紧邻站点之前是 0x31432B `mov rax, rdi` —— rax 就是本函数的【返回值】。
;   旧桩用 `mov rax, imm64 / call rax` 调 C 函数，把 rax 冲掉且没有还原，
;   于是 Country_CreateNewMonarch 在 0x320483 `mov rax,rdx` 拿到的是 C 函数的
;   垃圾返回值，再传给 MoveAssign 就成了野指针。
;   ⇒ 用通用 trampoline 后这个问题【结构上消失】：rax 由寄存器包原样保存/恢复，
;     不存在"C 函数的返回值覆盖 rax"这回事。
;   旧桩还用 push rax / pop r15 冒充原指令的 pop r15，把调用者的 r15 也写坏了。
;   ⇒ 现在 r15 同样由寄存器包原样保存/恢复。
; ----------------------------------------------------------------------------
mnp_hook_gen_exit_fallback PROC
    MNP_ENTER
    mov     rax, mnpfn_gen_exit_fallback
    call    rax
    MNP_EXIT
    pop     r15                         ; 逐条重放原指令
    pop     r14
    pop     rbp
    push    mnp_ret_gen_exit_fallback
    ret
mnp_hook_gen_exit_fallback ENDP


; ----------------------------------------------------------------------------
; disp    ruler_name —— CMonarch_GetFullName 重排（RVA 0xA4B4A6，覆盖 7 字节）
; 原指令 C7 45 B0 01 00 00 00   mov dword ptr [rbp-50h], 1   回跳 0xA4B4AD
; C++ 侧从 reg_pack::rbx（out）与 reg_pack::rdi（cm）取参数。
; ----------------------------------------------------------------------------
mnp_hook_disp_ruler_name PROC
    MNP_ENTER
    mov     rax, mnpfn_disp_ruler_name
    call    rax
    MNP_EXIT
    mov     dword ptr [rbp-50h], 1      ; 重放原指令
    push    mnp_ret_disp_ruler_name
    ret
mnp_hook_disp_ruler_name ENDP

END
