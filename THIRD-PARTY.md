# 第三方作品与署名

本仓库的**部分文件衍生自第三方作品**。下面逐项列出作者、许可与声明。
它们都是**宽松许可**，与本仓库的 MIT 许可兼容；使用时已按要求保留声明、并标注为改写版。

---

## 1. LINK/2012 — "Injectors"

- **原作**：Injectors — Useful Assembly Stuff
- **作者**：LINK/2012 `<dma_2012@hotmail.com>`
- **许可**：zlib
- **涉及本仓库文件**：`src/monarchnamefix/reg_pack.hpp`、`bytepattern.hpp`、`hookmem.hpp`
- **取得渠道**：经 matanki-saito/EU4dll 的 `Plugin64/` 内嵌副本

> **本仓库中的版本为改写版（altered version）**：在原作基础上按本工程需要做了删减、
> 改名与结构调整，**不代表原作者的原版实现**。原声明保留如下。

```
Copyright (C) 2012-2014 LINK/2012 <dma_2012@hotmail.com>

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
```

---

## 2. matanki-saito/EU4dll

- **仓库**：https://github.com/matanki-saito/EU4dll
- **许可**：MIT
- **关系**：本仓库的钩子辅助代码经该仓库取得（其 `Plugin64/` 内嵌了上一条的 Injectors）

MIT 许可要求保留其版权与许可声明。**上游完整许可文本与版权行**：

https://github.com/matanki-saito/EU4dll/blob/master/LICENSE

> 维护者注：首次发布前请把该文件里的版权行原样补写到本段（MIT 要求保留版权声明）。

---

## 3. bruceCzK — 双字节编码方案（specialEscape）

- **作者**：bruceCzK（gist）
- **关系**：本工程的双字节转义方案参照该方案，并由 matanki-saito/EU4SpecialEscape 移植
- **涉及本仓库文件**：`src/monarchnamefix/monarchnamefix.cpp`（编码处理段）、`scripts/encode_eu4_special.py`

---

## 4. VulonLok — EU4-Menu-Patch / EU4-Unicode-Patch

- **作者**：VulonLok
- **许可**：MIT
- **关系**：本工程的文档在**交叉验证**处引用了其公开的地址断言（202 条「改前字节」在本工程 IDB 中逐条比对，202/202 命中），
  作为独立证据来源；**本仓库不包含其源代码或二进制**。

---

## 关于 EU4DLL 本身

本仓库**不含** EU4DLL / 双字节补丁的二进制或源代码（`Plugin` / `Plugin64` / `version.dll` 均不含）。
本补丁只是运行在其提供的 `plugins\` 加载机制之上。