# EU4 Patches

Europa Universalis IV 的**运行时补丁集合**：以 DLL 放入游戏的 `plugins\`，
由双字节补丁（EU4DLL）的 `version.dll` 在启动时自动加载 —— **不修改 eu4.exe**。

支持版本：**EU4 v1.37.5.0 (Inca)**
启动时校验 `SizeOfImage=0x025E0000` 与 `TimeDateStamp=1727949497`；不符则**一个字节都不改**，只写日志。

## 目前修复的问题

- `MonarchNameFix.dll`

    **1. 继承人随机姓名的概率偏置**
    加权姓名表在取随机索引时受位运算影响，导致列表中**第一位名称被过度选中**。本补丁修正该取模路径。

    **2. 顾问 / 将领 / 外交官等特使 / 共和制统治者的姓名顺序**
    EU4 本身不支持"姓前名后"。本补丁在姓名合成处做重排，使这些角色显示为**姓 + 名**，
    并支持**按文化**配置：

    - 哪些文化姓前名后
    - 姓与名之间的分隔符（中文用 `""`，匈牙利语等需要空格的用 `" "`）

    ### 安装

    1. 确认游戏根目录已有 `version.dll`，且存在 `plugins\` 目录（即已安装双字节补丁）
    2. 把 `MonarchNameFix.dll` 复制到 `<游戏根目录>\plugins\`
    3. 启动游戏

    补丁会同时读取**游戏目录**与**所有已启用模组**的 `common\cultures_name\`。

    ### 确认是否生效

    看 `<游戏根目录>\plugins\MonarchNameFix.log` 末尾：

    ```
    [i] ready P1 ...            ← 站点定位成功
    [+] patched P1 ...          ← 已改写
    [i] result: N/N patches applied
    ```

    `N/N` 全中即为全部安装成功。若出现 `[!] ... mismatch`，说明游戏版本不符 —— **请不要使用**。

    ### 卸载

    删除 `plugins\MonarchNameFix.dll` 即可。

## 风险

- 本补丁在**运行时修改游戏进程内存**，请自行评估风险。
- 需要你**自有机票/正版游戏**。本仓库**不含任何游戏文件**。
- 与 Paradox Interactive **无关联**。
- Steam「验证游戏文件完整性」会回滚对 `eu4.exe` 的改动；本方案走 `plugins\` 路线，**不受影响**。

## 目录

| 目录 | 内容 |
|---|---|
| `src/monarchnamefix/` | 补丁本体（C++，仅依赖 kernel32；含钩子框架与离线测试） |
| `scripts/` | 离线校验器与工具（见 `scripts/README.md`） |
| `docs/` | 分析文档（见 `docs/README.md`） |

## 构建

MSVC x64。运行 `src\monarchnamefix\build.bat`（需要环境变量 `VCVARS64` 指向 `vcvars64.bat`）。

## 致谢

- **EU4DLL / 双字节补丁**：提供 `plugins\` 加载机制与 CJK 显示基础，本补丁运行在其之上。
- 所有把 EU4 逆向成果公开分享的人。

重要声明见 [NOTICE](NOTICE)。