#Requires -Version 5.1
<#
.SYNOPSIS
    组装发布产物：dist\winget-accel-<版本>-win-x64.zip

.DESCRIPTION
    本地和 CI 共用这一个脚本，避免两边产出的包结构不一致。

    包内容：
      winget-accel.exe          单文件二进制（静态 CRT，无运行时依赖）
      QUICKSTART.txt            三步上手 + 排障
      LICENSE                   许可证
      THIRD-PARTY-NOTICES.md    第三方许可
      SHA256.txt                校验和（针对 zip 内的 exe）

.PARAMETER SkipBuild
    跳过 cargo build（CI 里已单独构建过时使用）。

.PARAMETER OutDir
    产物目录，默认 dist。
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    # 版本号以 Cargo.toml 为唯一来源
    $cargo = Get-Content 'Cargo.toml' -Raw
    if ($cargo -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw 'Cargo.toml 里找不到 version'
    }
    $version = $Matches[1]
    Write-Host "版本: $version"

    if (-not $SkipBuild) {
        Write-Host '构建 release...'
        & cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build 失败（退出码 $LASTEXITCODE）" }
    }

    $exe = Join-Path $repo 'target\release\winget-accel.exe'
    if (-not (Test-Path $exe)) { throw "找不到构建产物: $exe" }

    $name = "winget-accel-$version-win-x64"
    $stage = Join-Path $OutDir $name
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    Copy-Item $exe $stage
    Copy-Item (Join-Path $repo 'packaging\QUICKSTART.txt') $stage
    foreach ($doc in @('LICENSE', 'THIRD-PARTY-NOTICES.md')) {
        $src = Join-Path $repo $doc
        if (Test-Path $src) { Copy-Item $src $stage }
    }

    # 校验和写在包内，针对 exe
    $hash = (Get-FileHash (Join-Path $stage 'winget-accel.exe') -Algorithm SHA256).Hash.ToLower()
    $lines = @(
        "winget-accel.exe  SHA256 = $hash",
        "大小 = $((Get-Item (Join-Path $stage 'winget-accel.exe')).Length) 字节",
        "版本 = $version"
    )
    Set-Content -Path (Join-Path $stage 'SHA256.txt') -Value $lines -Encoding UTF8

    $zip = Join-Path $OutDir "$name.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal

    $zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    $zipSize = (Get-Item $zip).Length

    Write-Host ''
    Write-Host '产物:' -ForegroundColor Green
    Write-Host "  $zip"
    Write-Host ("  {0:N0} B  SHA256 {1}" -f $zipSize, $zipHash)
    Write-Host ''
    Write-Host '包内清单:'
    Get-ChildItem $stage | ForEach-Object {
        Write-Host ("  {0,-26} {1,10:N0} B" -f $_.Name, $_.Length)
    }

    # 供 CI 后续步骤读取
    if ($env:GITHUB_OUTPUT) {
        "zip=$zip" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
        "zip_hash=$zipHash" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
        "version=$version" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    }
}
finally {
    Pop-Location
}
