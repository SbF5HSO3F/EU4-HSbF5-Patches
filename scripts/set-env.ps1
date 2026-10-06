#Requires -Version 5.1
<#
.SYNOPSIS
    设置本仓库脚本所需的环境变量（当前会话）。用法： . .\scripts\set-env.ps1
.DESCRIPTION
    用法示例（点号加载，让变量留在当前会话）：
        . .\scripts\set-env.ps1
        . .\scripts\set-env.ps1 -GameDir "D:\Steam\steamapps\common\Europa Universalis IV"
    未显式给出的项会尽量自动推断（仓库根由脚本位置推出；用户目录取 %USERPROFILE%；
    vcvars64.bat 由 vswhere 查找）。
#>
param(
    [string]$GameDir,
    [string]$UserDir,
    [string]$RepoRoot
)

if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$env:EU4_REPO_ROOT = $RepoRoot

if (-not $UserDir) { $UserDir = Join-Path $env:USERPROFILE 'Documents\Paradox Interactive\Europa Universalis IV' }
$env:EU4_USER_DIR = $UserDir

if (-not $GameDir) {
    $cands = @(
        'C:\Program Files (x86)\Steam\steamapps\common\Europa Universalis IV',
        'D:\Steam\steamapps\common\Europa Universalis IV',
        'E:\Steam\steamapps\common\Europa Universalis IV'
    )
    $GameDir = $cands | Where-Object { Test-Path (Join-Path $_ 'eu4.exe') } | Select-Object -First 1
    if (-not $GameDir) {
        Write-Warning 'EU4_GAME_DIR 未自动找到，请用 -GameDir "<游戏目录>" 指定'
        $GameDir = ''
    }
}
$env:EU4_GAME_DIR = $GameDir

if (-not $env:VCVARS64) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vs) {
            $cand = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $cand) { $env:VCVARS64 = $cand }
        }
    }
    if (-not $env:VCVARS64) { Write-Warning 'VCVARS64 未自动找到，请手动设置 $env:VCVARS64' }
}

Write-Host '已设置：'
Write-Host ("  EU4_REPO_ROOT = " + $env:EU4_REPO_ROOT)
Write-Host ("  EU4_GAME_DIR  = " + $env:EU4_GAME_DIR)
Write-Host ("  EU4_USER_DIR  = " + $env:EU4_USER_DIR)
Write-Host ("  VCVARS64      = " + $env:VCVARS64)