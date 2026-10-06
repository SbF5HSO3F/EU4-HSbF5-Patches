#Requires -Version 5.1
<#
.SYNOPSIS
    MonarchNameFix 部署 / 卸载 / 状态检查

.DESCRIPTION
    把 MonarchNameFix.dll 放进 <游戏目录>\plugins\ ，由 EU4DLL 的 version.dll
    在启动时自动 LoadLibraryW 载入 eu4.exe 进程。

    本脚本【只操作 plugins\MonarchNameFix.dll 这一个文件】：
      - 不修改 eu4.exe
      - 不修改 version.dll / plugin64.dll（EU4DLL 的文件）
      - 不写入注册表

.PARAMETER Action
    Install | Uninstall | Status

.PARAMETER GameDir
    游戏安装目录。默认取 Steam 默认路径。

.EXAMPLE
    .\deploy.ps1 -Action Status
    .\deploy.ps1 -Action Install
    .\deploy.ps1 -Action Uninstall
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status')]
    [string]$Action = 'Status',

    [string]$GameDir = '%EU4_GAME_DIR%'
)

$ErrorActionPreference = 'Stop'

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$DllName   = 'MonarchNameFix.dll'
$OffName   = 'MonarchNameFix.off'
$LogName   = 'MonarchNameFix.log'

$Candidates = @(
    (Join-Path $RepoRoot "dist\$DllName"),
    (Join-Path $RepoRoot "src\monarchnamefix\$DllName")
)

$PluginsDir = Join-Path $GameDir 'plugins'
$TargetDll  = Join-Path $PluginsDir $DllName
$TargetOff  = Join-Path $PluginsDir $OffName
$TargetLog  = Join-Path $PluginsDir $LogName

function Get-SourceDll {
    foreach ($c in $Candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    throw "找不到源 DLL，请先运行 src\monarchnamefix\build.bat。已查找：`n  " + ($Candidates -join "`n  ")
}

function Show-Status {
    Write-Host "== MonarchNameFix 状态 ==" -ForegroundColor Cyan
    Write-Host ("游戏目录        : {0}  (存在={1})" -f $GameDir, (Test-Path -LiteralPath $GameDir))
    Write-Host ("version.dll     : {0}" -f (Test-Path -LiteralPath (Join-Path $GameDir 'version.dll')))
    Write-Host ("plugins\ 目录   : {0}" -f (Test-Path -LiteralPath $PluginsDir))
    Write-Host ("plugin64.dll    : {0}" -f (Test-Path -LiteralPath (Join-Path $PluginsDir 'plugin64.dll')))

    if (Test-Path -LiteralPath $TargetDll) {
        $h = (Get-FileHash -LiteralPath $TargetDll -Algorithm SHA256).Hash
        $f = Get-Item -LiteralPath $TargetDll
        Write-Host ("已安装          : 是  大小={0}  时间={1}" -f $f.Length, $f.LastWriteTime) -ForegroundColor Green
        Write-Host ("  SHA256        : {0}" -f $h)
    } else {
        Write-Host "已安装          : 否" -ForegroundColor Yellow
    }

    Write-Host ("开关 (.off)     : {0}" -f $(if (Test-Path -LiteralPath $TargetOff) { '存在 -> 已禁用' } else { '不存在 -> 已启用' }))
    if (Test-Path -LiteralPath $TargetLog) {
        Write-Host "运行日志（末尾 20 行）：" -ForegroundColor Cyan
        Get-Content -LiteralPath $TargetLog -Tail 20 | ForEach-Object { "   $_" }
    } else {
        Write-Host "运行日志        : 尚未生成（游戏启动一次后出现）"
    }
}

switch ($Action) {

    'Status' { Show-Status }

    'Install' {
        if (-not (Test-Path -LiteralPath $PluginsDir)) {
            throw "找不到 $PluginsDir —— 请确认游戏目录，以及 EU4DLL（提供 version.dll 与 plugins\）已安装。"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $GameDir 'version.dll'))) {
            Write-Warning "游戏目录没有 version.dll。没有 EU4DLL 的加载链，plugins\ 里的 DLL 不会被载入。"
        }
        $src = Get-SourceDll
        Copy-Item -LiteralPath $src -Destination $TargetDll -Force
        $h = (Get-FileHash -LiteralPath $TargetDll -Algorithm SHA256).Hash
        Write-Host "[ok] 已安装 $TargetDll" -ForegroundColor Green
        Write-Host "     SHA256 = $h"
        Write-Host "     回滚：.\deploy.ps1 -Action Uninstall"
        Write-Host "     临时禁用：在 plugins\ 下新建空文件 $OffName"
    }

    'Uninstall' {
        if (Test-Path -LiteralPath $TargetDll) {
            Remove-Item -LiteralPath $TargetDll -Force
            Write-Host "[ok] 已删除 $TargetDll" -ForegroundColor Green
        } else {
            Write-Host "未安装，无需删除。"
        }
        foreach ($extra in @($TargetOff)) {
            if (Test-Path -LiteralPath $extra) { Remove-Item -LiteralPath $extra -Force; Write-Host "[ok] 已删除 $extra" }
        }
        if (Test-Path -LiteralPath $TargetLog) {
            Write-Host "（保留日志 $TargetLog，如需清理请手动删除）"
        }
    }
}
