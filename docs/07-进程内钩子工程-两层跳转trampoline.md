# 07 · 进程内钩子工程：两层跳转 trampoline 架构

> 目标：`eu4.exe` v1.37.5.0（Inca），`ImageBase 0x140000000`。全部地址为 **RVA**。
> 本文讲**怎么把一个 x64 进程内补丁做得不破坏游戏**：
> 站点怎么写、跳转为什么要两层、寄存器怎么保存、栈怎么配平。
>
> **本文最值钱的部分是 §5「血泪教训」** —— 每一条都对应过一次实机崩溃。

---

## 1. 为什么需要"两层跳转"

### 1.1 距离问题

补丁 DLL（如 `plugins\MonarchNameFix.dll`）与 `eu4.exe` 在**地址空间里相距约 26 GB**
（该项目实测 `delta = 0x6C3E50000`）。

x64 的近跳转 / 近调用（`E8 rel32` / `E9 rel32`）**只有 32 位有符号相对偏移**，即 **±2 GB**。
⇒ **从 `eu4.exe` 里的站点直接跳到 DLL 里的桩，够不着。**

而站点上能腾出的空间只有 **5~8 字节** ——
5 字节正好装一条 `E9 rel32`，**装不下 14 字节的绝对跳转** `FF 25 00000000 <8B 绝对地址>`。

### 1.2 解法：贴近 `eu4.exe` 分配一块 cave

```
eu4.exe 的站点（5~8 字节）
   │  ① 站点处写 5 字节 E9 rel32  ─────────────► cave
   │                                              （我们自己分配，紧邻 eu4.exe：
   │                                                base − 0x10000）
   │                                              ② cave 里写 14 字节
   │                                                FF 25 00000000 <8B 绝对地址>
   ▼
我们 DLL 里的桩（stubs.asm 的 mnp_hook_*）
   │  ③ MNP_ENTER：把 16 个通用寄存器 + RFLAGS 打包成 reg_pack
   │  ④ 调用 C++ handler（业务逻辑）
   │  ⑤ MNP_EXIT：还原寄存器
   │  ⑥ 重放被覆盖的原指令 + push 回跳点 + ret
   ▼
回到站点之后，游戏继续（控制流与寄存器副作用完全不变）
```

**为什么 cave 能贴到 `eu4.exe` 旁边**：
我们自己分配内存，主动请求靠近 `eu4.exe` 的地址 ⇒ `E9 rel32` 够得着。
cave 里再写**不受 ±2GB 限制**的 14 字节绝对跳转，就能到 DLL。

**cave 分配的具体做法**（`alloc_near_module`）：

```
以模块为中心、±0x4000000（±64 MB）
按 dwAllocationGranularity（0x10000）双向扫描
取第一块 RegionSize >= size 的 MEM_FREE
VirtualAlloc(MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)
```

槽位管理：`kTrampolineSize = 14` · `kSlotSize = 32` · 9 个站点 `need = 9 × 32 = 288`。

**★ 安装顺序（每一步都有断言）**：

```
① 校验 site_bytes
② 断言 site → cave 的 jmp_len == 5
③ 断言 cave → stub 的距离 ≤ 14
④ 先写回跳点 EXTERN 变量        ← 必须在改站点之前
⑤ 站点写 E9
⑥ cave 写 FF 25
── 每次打印 site(5) / cave(14) / stub(8) 的字节 dump
```

> ★ **为什么要 dump 字节**：**"装上了" ≠ "跳转是对的"。**
> 曾经出现过"模式命中、护栏放行、字节也写了"但**跳到别处**的情况（见 §5.4）。
> 三条断言 + 三次 dump，把"我认为我写了什么"变成"我确实写了什么"。

### 1.3 收尾为什么用 `push <retAddr>; ret` 而不是 `E9 rel32`

```
push mnp_ret_pN     ; 压入回跳地址
ret                 ; 弹进 RIP
```

**好处**：回跳点因此**可以是任意位置**，不受"桩末尾必须是 5 字节 `E9`"的约束。

> ★ 这一点在有多条收尾路径的桩里尤其重要 ——
> 例如 `mnp_hook_p7_decide` 有**两个**出口（正常重放 / 跳过追加姓），
> 每个出口各 `push` 自己的回跳点即可。

---

## 2. `MNP_ENTER` / `MNP_EXIT`：把业务逻辑完全赶出汇编

设计照搬双字节补丁（EU4dll）的 `Plugin64/assembly.hpp` 的 `MakeInline`：
**"把所有通用寄存器压栈 → 把栈指针作为 `reg_pack*` 传给 C++ → 弹回"**。

于是**每个钩子的业务逻辑一行汇编都不用写**，桩里只剩：

```
MNP_ENTER / 设置 handler / call / MNP_EXIT / 重放原指令 / push ret
```

**其中只有"重放"那 1~3 条是本钩子特有的。**

### 2.1 `MNP_ENTER`（MASM）

```asm
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

    add     qword ptr [rsp+18h], 68h     ; ★ 修正 reg_pack::rsp 为站点处的真实 rsp

    mov     rcx, rsp                    ; 第 1 参数 = reg_pack*
    sub     rsp, 20h                    ; shadow space（保持 16 字节对齐）
endm
```

**宏的净栈位移 = −136 − 0x20 = −0x20 之外的 136 字节**，
`ENTER` 与 `EXIT` 合起来必须为 **0**（见 §3）。

### 2.2 `MNP_EXIT`

```asm
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
```

### 2.3 `reg_pack` 的布局（**与 push 顺序互为镜像**）

```cpp
struct reg_pack {                 // sizeof == 136
    union {
        general_register arr[16];
        struct {
            general_register
                rdi, rsi, rbp, rsp, rbx, rdx, rcx, rax,
                r8, r9, r10, r11, r12, r13, r14, r15;
        };
    };
    flags_register ef;            // +0x80：pushfq 压入的 RFLAGS
};
static_assert(sizeof(reg_pack) == 136, "");
static_assert(offsetof(reg_pack, ef)  == 128, "");
static_assert(offsetof(reg_pack, rax) == 56,  "");
```

栈上从**低地址到高地址**（= 结构体从前往后）：

```
+0x00 rdi   +0x08 rsi   +0x10 rbp   +0x18 rsp   +0x20 rbx
+0x28 rdx   +0x30 rcx   +0x38 rax   +0x40 r8 .. +0x78 r15
+0x80 RFLAGS
```

**压栈顺序（先→后）**：
`flags  r15 r14 r13 r12 r11 r10 r9 r8  rax rcx rdx rbx rsp rbp rsi rdi`

> ★ **字段顺序是硬约定。** `reg_pack.hpp` 里的原话：
> *"The first field is the last to be pushed and first to be popped"* ——
> **改一处必须同时改另一处。**

**便捷访问器**（x64 Windows ABI 前 4 个整型参数）：

```cpp
inline std::uint64_t arg1(const reg_pack &r) { return r.rcx.i; }
inline std::uint64_t arg2(const reg_pack &r) { return r.rdx.i; }
inline std::uint64_t arg3(const reg_pack &r) { return r.r8.i;  }
inline std::uint64_t arg4(const reg_pack &r) { return r.r9.i;  }
```

**读写调用者栈上的内存**（重放 `mov [rsp+N], reg` 这类指令时用）：

```cpp
inline std::uint64_t *stack_slot(reg_pack &r, std::ptrdiff_t off) {
    return reinterpret_cast<std::uint64_t *>(r.rsp.i + off);
}
```

> ★ `r.rsp` 是"**进入 trampoline 时**的 rsp"，不是当前 rsp —— 见 §2.4。

### 2.4 ★★ `reg_pack::rsp` 的修正量 = **104（`0x68`）**

**这是整个 trampoline 里最容易算错的一个数**，算错的代价是实机崩溃（见 §5.2）。

**推导**：

设 `S` = 刚进入 trampoline 时的 `rsp`。

```
1. 站点是 jmp 过来的（经过 cave 的 FF25 也是 jmp），【不压栈】
   ⇒ S 就等于"站点处原代码的 rsp" ✓

2. `push rsp` 是第 14 条 push，执行前 rsp = S − 8×13 = S − 104

3. x86 的 `push rsp` 压入的是【递减前】的值
   ⇒ 槽里存的是 S − 104

   ⇒ 要让它变成 S，修正量 = S − (S − 104) = 104 = 0x68 ✓
```

**为什么"看起来"该是 112 或 120**（两个都被试过、都错）：

- 若误以为 `push rsp` 压的是**递减后**的值 `S − 112`，就会算成 `S − (S−112) = 112` ✗
- 若又把 `reg_pack` 起始位置也算错，就会得到 120 ✗

⇒ **正解是 104。** 并且它**不是纯推理出来的**，是**实机定标**得到的（见下）。

**双重实测印证**（两条独立数据指向同一个 +8 偏差）：

| 来源 | 观测 | 应有值 | 结论 |
|---|---|---|---|
| P11 自检，**64 次样本全部一致** | `rbp − rsp_pack = 0xF8` | 由 `BuildFullName_Impl` 序言可证 `rbp − rsp_real = 0x100` | `rsp_pack = rsp_real + 8` |
| 同一份日志 | `sp = rsp_pack + 0x30` 与 `&Src = rbp − 0xD0` **正好差 +8** | `sp` 本应等于 `&Src` | 同上 |

**`rbp − rsp_real = 0x100` 怎么来的**（`BuildFullName_Impl` 序言）：

```
push rbp / r14 / r15     ⇒ rsp -= 0x18
lea  rbp, [rsp - 0x10]
sub  rsp, 0x110
⇒ 设进入时 rsp = R0：
    rbp = R0 − 0x28
    rsp = R0 − 0x128
⇒ rbp − rsp = 0x100 ✓
```

**历史演进**：`120 (0x78)` → `112 (0x70)` → **`104 (0x68)`**（实测定标）。

> ⚠️ **一处必须知道的源码自相矛盾（本项目真实存在的文档债）**
>
> `stubs.asm` 的**文件头注释**同时写着三个值，互相冲突：
>
> | 位置 | 说法 |
> |---|---|
> | 第 25–31 行（旧推导块） | "修正量 = **120**"，且称"`push rsp` 压入的是**递减之后**的 rsp" |
> | 第 66–81 行（新推导块） | "由实测定标得出 **104**" |
> | 第 97–98 行（历史记录） | "最初 **120** → 改 **112** → 实测仍偏大 8 ⇒ 定标 **104**" |
> | **第 120 行（真正的代码）** | **`add qword ptr [rsp+18h], 68h`** |
> | `verify_trampoline_stack.py` 的**断言** | **`want = 104`** |
> | 同文件的 **docstring 注释** | 仍写 112 |
>
> **权威 = 104**（代码 + 脚本断言一致，且有两条独立实机数据支持）。
>
> **为什么值得把这个矛盾写出来**：这正是**长期逆向项目里最常见的文档债** ——
> 结论更新了、推导块忘了删。
> ⇒ **判据永远以"可执行的断言"为准，不以注释为准。**
> ⇒ 这也是为什么 `verify_trampoline_stack.py` 会用**正则解析 `.asm` 文本**去断言那个数 ——
> **把结论写成机器可检查的形式，它才不会腐烂。**

---

## 3. 栈平衡：为什么必须精确为 0，以及怎么机器校验

**`MNP_ENTER` + `MNP_EXIT` 的净栈位移必须精确为 0** ——
桩执行完回到游戏时，`rsp` 必须与进入时**逐字节一致**。

**否则**："重放原指令"会写到**错误的栈位置** ⇒
表现为**进游戏直接闪退且不留崩溃信息**
（栈被破坏后 `ret` 跳到非法处，游戏自己的异常处理也拿不到）。

### 3.1 校验脚本

```powershell
python scripts\verify_trampoline_stack.py
```

它做三件事：

1. 逐条列出 `MNP_ENTER` / `MNP_EXIT` 里每个 `push`/`pop`/`add rsp`/`sub rsp` 的**累计位移**；
2. **断言两者之和为 0**；
3. **断言 `reg_pack::rsp` 修正量为 `104`**；
4. **发现 `pop rsp` 直接报错**。

> ⚠️ 脚本注释里有一处历史遗留的错误说法
> （"`push rsp` 压的是递减前的值，正确修正量是 112"）——
> **代码里的断言是正确的 104**，以代码为准。

**另外两个必须跑的**：

```powershell
python scripts\verify_site_order.py    # 五处文件的站点排列顺序是否一致
python scripts\verify_newhook.py       # 9 个站点的模式能否【唯一且 RVA 匹配】地定位
```

---

## 4. 站点表：五处文件必须同序

一个站点在**五处**文件里出现，用**同一个名字**，格式固定为 `<前缀>_pN_<动作>`：

| 位置 | 形态 | 作用 |
|---|---|---|
| `stubs.asm` | `mnp_hook_pN_<动作>` | PROC 本体（桩） |
| `monarchnamefix.cpp` | `mnp_h_pN_<动作>` | 处理器（业务逻辑） |
| `hookvars.cpp` | `mnpfn_pN_<动作>` | 桩要调用的函数指针变量 |
| `hookvars.cpp` | `mnp_ret_pN` | 回跳点槽（不带动作名） |
| `install.cpp` | `"PN  <动作>  …"` | `kSites[]` 显示名（进日志） |

**五处的排列顺序必须一致**，由 `scripts/verify_site_order.py` 校验。

> **编号 `P1..P11` 是【按添加时间】编的，不是执行顺序**（P4 是出口却编号在 P6 之前，
> P1/P2/P3 反而是最后补的）。编号不改 —— 旧笔记里有 500+ 处引用，
> 重编号会让旧笔记全部失准。**顺序靠文档里的分组表达。**

### 4.1 站点表条目包含什么

```c
struct SiteDecl {
    uint32_t    site_rva;       // ★ 权威判据
    uint32_t    cover;          // 覆盖字节数（必须是完整指令）
    uint32_t    resume_rva;     // 回跳点 = site_rva + cover
    const char *site_bytes;     // 字节模式（`?` 为通配）
    int         pattern_to_site;// 模式命中点到站点的偏移（模式可早于站点）
    // …
};
```

**定位规则**（`bytepattern.hpp`）：

| 模式命中次数 | 处理 |
|---|---|
| 恰好 **1** 次 | 直接采用 |
| **多次** | 在命中集合里挑 `RVA == site_rva` 的那个（**RVA 是权威判据**） |
| **0** 次 | **报错，不猜** |

**安装前逐字节比对**，对不上就**拒绝安装**——而不是"取签名第一个命中"。

---

## 5. 血泪教训（每条对应过一次实机崩溃）

### 5.1 `pop rsp` 不是"跳过 8 字节"，是**赋值**

```
pop rsp   ⇒   rsp = [rsp]
```

而 `[reg_pack+0x18]` 里存的是 `S − 104` ⇒ `rsp` 会停在 `S − 104`，
而它本应是 `S` —— **差 104 字节**，导致后面 13 个 `pop` 全部取错位置。

**症状**：**进游戏静默闪退**。

**正解**：

```
pop rdi/rsi/rbp  ⇒ rsp = reg_pack + 24
add rsp, 8       ⇒ rsp = reg_pack + 32（正好是 rbx 槽）
再 pop 13 个 + popfq ⇒ rsp = reg_pack + 32 + 104 = S ✓
```

⇒ **`add rsp, 8`，绝不用 `pop rsp`。** 校验脚本会把 `pop rsp` 当致命错误。

### 5.2 `rsp` 修正量错 8 字节 ⇒ **堆被写坏**（最难查的一次）

修正量偏大 8（用了 112 而非 104）时，`reg_pack::rsp` 指向 `S+8`。
于是桩"重放"读局部 `CString` 时**整体错位 +8**：

```
buf  = [&Src+0x08]   ← SSO 缓冲区中间，被当成"堆指针"
size = [&Src+0x18]   ← 真实的 cap
cap  = [&Src+0x20]   ← 越出 CString
```

而 `Src` 本身是 **SSO 串（cap = 15 < 0x10）**，错位后 `cap` 读成 **48（≥ 0x10）**
⇒ **误判为堆串** ⇒ 把一个垃圾值当堆指针、把名字写进去 ⇒ **堆被破坏**
⇒ 随后 **`free()` 崩在 `ntdll!RtlFreeHeap`**，或表现为**无 dump 的静默闪退**。

⇒ **教训**：栈偏移错 8 字节，症状会出现在**堆**上。
**这类错误靠读代码看不出来，必须靠"实测自检 + 与序言推导对照"定标。**

### 5.3 `push rsp` 压的是**递减前**的值

这是 §2.4 的正解依据。误以为它压递减后的值，会直接导致 5.2 那次崩溃。

### 5.4 模式太短 ⇒ 装错地方，而且**不报错**

- 第一版模式只用 5~8 字节：`48 89 5C 24 08` 在 `.text` 里命中 **15437 次**，
  **6 个钩子只装上 1 个**，表现为"姓被追加了却没人重排"、**名字全乱**；
- 另一例：实际落在 `0x1c605d` 而不是期望的 `0x3142f2` ——
  模式匹配到了别处，**装上了、没报错**。

⇒ 现在模式取 **16~37 字节**，且**安装前逐字节比对**。

**★ 实测命中计数**（这批站点的真实数据，可作为"你的模式够不够长"的参照）：

| 站点 | 模式长度 | `.text` 内命中次数 |
|---|---|---|
| P1 / P2 | 16 B | 1 |
| P3 | 18 B | 1 |
| **P6** | **37 B** | **4** ← 编译器标准模板，必须靠 RVA 筛 |
| P7 | 19 B | 1 |
| P10 | 23 B（跨 `call` 的 `rel32` 用 `?`） | 1 |
| P11 | 21 B | 1 |
| **P4** | **36 B** | 1，但**命中点不是站点**（`pattern_to_site = 0x1E`） |
| P8 | 20 B | 1 |

⇒ 两条判据分得很清楚：

1. **命中 4 次是正常的**（编译器会为不同函数生成同样的序言）⇒ **必须靠 RVA 筛选**；
2. **命中 1 次也可能是"命中点 ≠ 站点"** ⇒ 必须用 `pattern_to_site` 显式表达偏移。

**为什么 P10 的模式里有 `?`**：它跨过一条 `call`，而 `rel32` 会随版本变
⇒ 用通配符盖掉，只保留稳定的前后字节。

### 5.5 "忠实重放"有时是错的 —— 要**理解语义后重新表达**

`mnp_hook_p7_decide` 里被覆盖的指令含 `mov rbx, r15`。
旧实现"忠实重放"了这一条，把语义交给了运行时值。

但 `BuildFullName_Impl` 里 **`r15` 只被 `0x313F6E xor r15d,r15d` 写过一次**，
此后无写入 ⇒ **语义值恒为 0**。

一旦被污染，循环首条 `lea rdx,[r8+rbx]` 就把"数组基址 + 野指针"算成野地址
（`C0000005 @ RVA 0x314237`）。

⇒ 正解：**直接 `xor ebx, ebx`** ——
**理解语义后的重新表达**，而不是机械重放。

### 5.6 注意哪些寄存器是"活"的

`mnp_hook_p7_decide` 的另一个坑：**`eax` 是循环计数**
（`0x314225 movslq` 之后 `test eax,eax / jle` 判的就是它）。

业务结论由 C++ 走全局变量给出，所以桩里**不碰 `eax`**，原样重放 `test/jle`。
（handler 是 `void(reg_pack&)`，`MNP_EXIT` 会把 `rax` **原样还原** ⇒ 原值存活 ✓）

```asm
mnp_hook_p7_decide PROC
    MNP_ENTER
    mov     rax, mnpfn_p7_decide_sf
    call    rax
    MNP_EXIT
    test    eax, eax        ; 重放原指令（判循环计数）
    jle     mnp_p7_skip
    xor     ebx, ebx        ; ★ 替代 mov rbx,r15（理解语义后的重新表达）
    push    mnp_ret_p7
    ret
mnp_p7_skip:
    push    mnp_ret_p7_skip
    ret
mnp_hook_p7_decide ENDP
```

### 5.7 分工原则：什么留在汇编，什么搬到 C++

| 操作类型 | 放在哪 | 为什么 |
|---|---|---|
| **纯数据操作**（掩码、清零、标志） | **C++ handler** 改 `reg_pack` | 可读、可测、可讨论 |
| **除法指令**（`div` / `idiv`） | **留在桩里重放** | ★ `div` 的溢出行为（商放不下 32 位时抛 `#DE`）**必须与硬件一致**，C 的 `/` 表达不了 |
| **被覆盖指令的重放** | 桩里（1~3 条） | 必须逐字节等价 |

### 5.8 重写之前先对照站点清单

2026-10-05 那次重写**漏掉 P1/P2/P3**，直接导致"取第一号位概率被放大"复发 ——
而当时笔记里**两天前就把这三处写清楚了**。

⇒ **动手改之前，先把站点清单过一遍。**

### 5.9 机器能算的就别用眼睛看

栈平衡、模式唯一性、站点顺序**都已脚本化**。
这类错误**肉眼看不出来**，而代价是一次实机闪退。

---

## 6. 内存改写本身的四个细节

| 细节 | 做法 |
|---|---|
| **页保护** | RAII 包装 `VirtualProtect`，作用域结束自动还原 |
| **跳转写入** | `MakeJMP` 用**有符号**判据决定写 5 字节 `E9 rel32` 还是 14 字节绝对跳转 |
| **指令缓存** | 写完**必须刷新**（`FlushInstructionCache`），否则 CPU 可能执行旧字节 |
| **站点校验** | 写之前**逐字节比对** `site_bytes` |

### 6.1 ★★ 安装必须"两阶段"，否则会静默失败

**`VirtualProtect` 影响的是整页，不是那几字节。**
这一条造成了本工程最难查的一次故障。

**现场**：写完 P1 的站点后，把**同一个页面**设回 `RX`；随后再写 P2（落在同一页）
⇒ 访问违例 ⇒ **异常逃出 `DllMain`** ⇒ **加载器静默判定 DLL 加载失败**
（**无弹窗、无日志**）。

**症状**：**游戏正常启动 + 部分补丁生效 + 日志被截断。**

⇒ 排查时会以为"补丁基本能用，只是日志有点问题"，
而实际上 **DLL 已经加载失败了**，且**游戏内存已被改了一半**。

**正解：两阶段安装** ——

```
① 全部写桩（把所有要改的字节一次写完）
② 一次性改页保护 + FlushInstructionCache
③ 才去改站点
```

**回归用例**：`[regress] write to same page after VirtualProtect(RX): FAULT`

### 6.2 ★ 静默失败比崩溃更贵

⇒ 三阶段都包 `__try/__except`，异常时写 `[!] unexpected exception, code=0x…`。

> ★ 另一条同源教训：**日志格式化的缺陷会误导排查。**
> 曾经有 `cave=0xffff0000` 这样的日志，实际是 `cave − mod` 被按 `uint32` 打印
> （cave 在基址下方 64 KB）⇒ 看着像野指针，其实一切正常。
> **日志里的每个值都要能对上它的类型。**

### 6.3 `DllMain` 里的纪律

`DllMain` 跑在 **loader lock** 之下（这个工程的做法是**全部工作在 `DllMain` 里做完**）：

- **不做重活、不 `LoadLibrary`、不建线程**；
- `/MT` 静态链接 + 纯 `CreateFileW`/`WriteFile` 写日志（**正是为了避开 loader lock 下的 CRT/堆问题**）；
- 改页保护本身**需要**在 `DllMain` 里做，但要按 §6.1 的两阶段方式。

### 6.4 桩要放在 `.asm` 里，不要"手写机器码"

**第三方框架（EU4dll / Plugin64）的另一条经验：把桩改成 `.asm` 是防 bug 最有效的一招。**

本工程同样用 MASM（`ml64`）：`stubs.asm` 里 `MNP_ENTER` / `MNP_EXIT` 是**宏**，
九个桩共用同一骨架，只有"重放被覆盖指令"那 1~3 条不同。

**对比"手写机器码"**：后者无法在源码层表达栈平衡、无法被静态校验脚本解析
（本工程的 `verify_trampoline_stack.py` **正是靠解析 `.asm` 文本来做栈平衡校验的**）。

---

## 6.5 ★★★ 一条总纲：**要么理解语义、要么保持不动**
> **绝不要"抄一条自己没完全理解的指令"。**

这条是从三次崩溃里总结出来的，值得单独强调。

**第三方框架的桩之所以简单，是因为它彻底理解了被覆盖的指令，
并把语义用新代码重新表达 —— 它不做机械重放。**

本工程曾经反其道而行：

| 做法 | 后果 |
|---|---|
| "忠实重放" `mov rbx, r15`（**r15 语义恒 0**，见 §5.5） | `C0000005 @ RVA 0x314237`（野地址） |
| 桩里 `push`/`pop` 调 C 函数，冲掉了 `rax`（**它是返回值**，`0x31432B mov rax,rdi`） | **三次** `C0000005 @ RVA 0x94F4A` |
| 用手写 `push rax / pop r15` 冒充 `pop r15` | **写坏调用者的 r15** |

**正解分三种**：

1. **理解语义后重新表达**（`mov rbx,r15` → `xor ebx,ebx`）；
2. **让 trampoline 结构性地消灭问题**（通用 `MNP_ENTER/EXIT` 之后，
   "桩调 C 函数冲掉 `rax`"这类错误在结构上不可能再发生）；
3. **不确定就保持不动**（不要改那一处）。

---

## 7. 验证体系总表

| 脚本 / 程序 | 校验什么 |
|---|---|
| `scripts\verify_site_order.py` | 五处文件（`kSites[]` / `stubs.asm` / handler / `hookvars` / `stubs.hpp`）的站点排列顺序是否一致 |
| `scripts\verify_newhook.py` | 9 个站点的模式能否**唯一且 RVA 匹配**地定位（从 `install.cpp` 直接提取模式） |
| `scripts\verify_patch_targets.py` | 站点字节与回跳点 |
| `scripts\verify_trampoline_stack.py` | `MNP_ENTER + MNP_EXIT` 净栈位移必须为 0；`reg_pack::rsp` 修正量必须 = **104**；出现 `pop rsp` 直接报错 |
| `nameordertest.exe` | 姓名变换 39 项 |
| `cultureconfigtest.exe` | 配置解析 61 项 |
| `cultureconfigdump.exe <配置>` | 离线按 DLL 的日志格式打印配置（与 DLL **共用同一份实现**）⇒ 不启动游戏就能核对"日志里会打出什么" |

### 7.1 ★★ 一条"改完了却不生效"的排查铁律

**先做破坏性可见标记实验，别继续读反编译。**

本项目有一次真实的教训：补丁改完了、日志显示代码**确实执行了**，
但游戏里没变化。于是反复读反编译找问题 —— 花了四轮实机反馈。

**最后靠一个探针一次定论**：把输出改成 `姓@ZZZ@名`
⇒ 如果游戏里**出现了 `@ZZZ@`**，说明这条路**确实是显示路径**（问题在下游把空格吃掉了）；
⇒ 如果**没出现**，说明**另有路径**。

**同时必须先确认一件事**：**"要改的东西真的在你 hook 的那个数据结构里吗？"**

> 本项目曾有一处把"加权条目的 `+36` 标志"当作"姓氏在前"的判据去反转数组 ——
> 但**那个数组里根本没有姓**，所以四轮改动**零贡献**。
> 根因是**没先确认数据结构里有没有你要改的东西**。

### 7.2 ★★ 另一条铁律：改站点必须搜索"谁依赖这个补丁"

**症状**：两个站点都装上了，但**互相抵消**，行为退回改之前。

**根因**：另一处代码里**硬编码了本补丁的站点地址**（`0x31422C`）来判断
"P7 是否生效"；重写后该地址变了，于是那个判断恒为假 ⇒
P7 挂上了却被认为"没生效" ⇒ P4 的兜底路径反过来把结果改回去。

**⇒ 耦合一律按【补丁身份】判定，不要按【具体地址】判定。**
**⇒ 每次改站点，都要 grep 一遍"有没有别处引用了这个地址 / 依赖这个补丁"。**

### 7.3 ★★ 桩交回寄存器差一个槽，就是一次跳野地址

**现场**：桩里多了一条 `add rsp, 8` ⇒ **结果指针被写进了 `r14` 槽** ⇒ 跳到野地址。

**现在的三条硬断言**（`verify_nameorder_target.py`）：

1. 桩内**不得有 RIP 相对写**；
2. `call` 前 `rsp ≡ 0 (mod 16)`；
3. **跳回时 `rsp − 入口 rsp` 必须精确等于设计值**（各站点各自登记）。

> ★ 第 3 条是"栈位移必须为 0"的**逐站点强化版**：
> §3 校验的是 `ENTER + EXIT` 内部配平，这一条校验的是**对外净效果**。

> **新增站点、改桩、或调整顺序之后，前四条必须跑。**

---

## 8. 诊断开关与日志策略

### 8.1 开关（在 `plugins\` 下放空文件即可，删掉即恢复）

| 文件 | 作用 |
|---|---|
| `MonarchNameFix.off` | **连日志都不开**，完全不碰游戏 |
| `MonarchNameFix.nohook` | 只做初始化，**不安装任何钩子**（把"初始化副作用"与"改了游戏代码"分开） |
| `MonarchNameFix.nomod` | 跳过取模修复 |
| `MonarchNameFix.noconf` | 不做"按文化取配置" |
| `MonarchNameFix.noxform` | 连变换都不做，只记日志（钩子仍挂载） |
| `MonarchNameFix.noP1` … `noP8` | 按站点跳过（**二分定位**） |

> ★ 这套开关的价值在于**可二分**：出问题时能快速把范围缩到单个站点。
> 尤其是 `.nohook` —— 它把"初始化本身有问题"和"钩子改坏了游戏"分开。

### 8.2 日志策略：每次启动一个干净文件，但崩溃前仍写得进去

```
启动时：先以 CREATE_ALWAYS 打开再关闭（截断旧日志）
       然后以 APPEND 长期持有句柄
```

⇒ 既有"每次启动一个干净文件"，又保留"**崩溃前仍写得进去**"的能力。

### 8.3 采样：热路径不能全记

变换是热路径。诊断用**两段式采样**：

- 前 `MNP_LOG_WINDOW`（2000）次**全记**；
- 之后每 `MNP_LOG_STRIDE`（64）次记一次；
- **并且状态变化（文化切换、标志翻转）无条件记**。

> ⚠️ **一个坑**：早期用"配额用完即永久静默"的策略，导致日志尾部
> **只剩配额没耗尽的那些灯还亮着**，把"最后一条"误读成"最后发生的事"。
> ⇒ **采样必须保证"状态变化"不被采样掉。**

---

## 9. 相关文档

- `docs\01` —— 目标指纹、地址换算、五层证据链
- `docs\03` —— 取模修复案例（三个站点的分工实例）
- `docs\06` —— 姓名顺序机制（生成期/显示期站点的语义）
- `docs\08` —— 命名规范与证据等级
