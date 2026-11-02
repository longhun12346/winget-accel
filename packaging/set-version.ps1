#Requires -Version 5.1
<#
.SYNOPSIS
    把版本号写进 Cargo.toml（唯一需要改版本的地方）。

.DESCRIPTION
    设计取舍：**tag 是唯一事实来源**。

    `Cargo.toml` 的 version 是 `env!("CARGO_PKG_VERSION")` 的来源，所以必须有人写它；
    但让它当"真相"意味着每发一版都要手工改一次，而 tag 与 Cargo.toml 不一致时
    CI 也不会报错 —— 之前 0.1.0/0.1.1/0.1.2 三版都是我手改的，纯靠记性。

    现在：
      - CI：从 `GITHUB_REF_NAME`（形如 v0.1.3）推导，构建前写回
      - 本地：`.\packaging\set-version.ps1 -FromTag v0.1.3` 或 `-Version 0.1.4`

.PARAMETER FromTag
    git tag 名，允许带 `v` 前缀。优先级低于 -Version。

.PARAMETER Version
    直接指定版本号（不带 v）。

.PARAMETER Check
    只校验不写入：检查 Cargo.toml 是否已等于目标版本。CI 里可用于加严校验。
#>
[CmdletBinding(DefaultParameterSetName = 'Tag')]
param(
    [Parameter(ParameterSetName = 'Tag', Position = 0)]
    [string]$FromTag,

    [Parameter(ParameterSetName = 'Version')]
    [string]$Version,

    [switch]$Check
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path $PSScriptRoot -Parent
$cargoPath = Join-Path $repo 'Cargo.toml'

# 目标版本
$target = if ($Version) {
    $Version
} elseif ($FromTag) {
    $FromTag -replace '^v', ''
} elseif ($env:GITHUB_REF_NAME) {
    # CI 里不带参数时自动从 tag 推导
    $env:GITHUB_REF_NAME -replace '^v', ''
} else {
    throw '未提供版本：请用 -FromTag v0.1.3 或 -Version 0.1.4，或在 CI 里设置 GITHUB_REF_NAME'
}

# 语义化版本校验：正式版 X.Y.Z 或带预发布后缀 X.Y.Z-suffix
if ($target -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') {
    throw "版本号格式非法: '$target'（要求 X.Y.Z 或 X.Y.Z-pre）"
}

$text = [System.IO.File]::ReadAllText($cargoPath)
if ($text -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
    throw 'Cargo.toml 里找不到 version 字段'
}
$current = $Matches[1]

if ($Check) {
    if ($current -ne $target) {
        throw "版本不一致：Cargo.toml=$current，期望=$target"
    }
    Write-Host "版本一致: $current"
    exit 0
}

if ($current -eq $target) {
    Write-Host "版本已是 $target，无需改动"
} else {
    # 只替换第一个 version 行，且用 WriteAllText 而非 Set-Content：
    # 后者会追加空行、并可能改变换行符，导致无关的 diff 噪声。
    $updated = [regex]::Replace($text, '(?m)^version\s*=\s*"[^"]+"', "version = `"$target`"", 1)
    [System.IO.File]::WriteAllText($cargoPath, $updated)
    Write-Host "版本: $current -> $target"
}

# 供 CI 后续步骤使用
if ($env:GITHUB_OUTPUT) {
    "version=$target" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
