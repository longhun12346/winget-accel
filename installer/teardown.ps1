#Requires -Version 5.1
<#
.SYNOPSIS
    卸载 winget-accel：还原 PAC、移除本机 CA、停止进程，并自检不留残留。

.DESCRIPTION
    幂等：没有安装记录时也会尝试清理残留，然后报告结果。
    任何残留都会以退出码 1 结束，便于脚本化判断。
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$stateDir  = Join-Path $env:LOCALAPPDATA 'winget-accel'
$stateFile = Join-Path $stateDir 'state.json'
$certDir   = Join-Path $stateDir 'certs'
$inetKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

function Write-Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

function Update-WinInet {
    if (-not ('WinInet.Native' -as [type])) {
        Add-Type -Namespace WinInet -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);
'@
    }
    [void][WinInet.Native]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][WinInet.Native]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

$state = $null
if (Test-Path $stateFile) {
    $state = Get-Content $stateFile -Raw | ConvertFrom-Json
} else {
    Write-Warn2 "没有安装记录（$stateFile），仍尝试清理残留"
}

# ------------------------------------------------------------------ 停进程
Write-Step '停止代理进程'
$killed = 0
if ($state -and $state.pid) {
    $proc = Get-Process -Id $state.pid -ErrorAction SilentlyContinue
    if ($proc) {
        Stop-Process -Id $state.pid -Force -ErrorAction SilentlyContinue
        $killed++
    }
}
# 兜底：按进程名清理（安装记录丢失时也能收尾）
Get-Process -Name 'winget-accel' -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    $killed++
}
Start-Sleep -Milliseconds 300
$left = @(Get-Process -Name 'winget-accel' -ErrorAction SilentlyContinue)
if ($left.Count -gt 0) { Write-Warn2 "仍有 $($left.Count) 个进程存活" } else { Write-Ok "已停止（清理 $killed 个）" }

# -------------------------------------------------------------------- 还原 PAC
Write-Step '还原系统 PAC 设置'
if (Test-Path $inetKey) {
    $priorPac = if ($state) { $state.priorPac } else { $null }
    if ($priorPac) {
        Set-ItemProperty -Path $inetKey -Name AutoConfigURL -Value $priorPac
        Write-Ok "已还原为原值: $priorPac"
    } else {
        Remove-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue
        Write-Ok '已删除 AutoConfigURL'
    }
    Update-WinInet
} else {
    Write-Warn2 'Internet Settings 键不存在，跳过'
}

# ------------------------------------------------------------------ 移除 CA
Write-Step '从用户根存储移除本机 CA'
$thumb = $null
if ($state -and $state.thumbprint) {
    $thumb = $state.thumbprint
} elseif (Test-Path (Join-Path $certDir 'ca-cert.pem')) {
    $thumb = (Get-PfxCertificate -FilePath (Join-Path $certDir 'ca-cert.pem')).Thumbprint
}

if ($thumb) {
    # Remove-Item 会报「此操作中针对用户根存储，不允许使用 UI」，必须用 certutil
    & certutil.exe -user -delstore Root $thumb 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "已移除 $thumb"
    } else {
        Write-Warn2 "certutil 返回 $LASTEXITCODE（可能本就不在存储里）"
    }
} else {
    Write-Warn2 '拿不到指纹，跳过（需要时可手工 certutil -user -delstore Root <指纹>）'
}

# --------------------------------------------------------------- 清安装目录
Write-Step '清理安装目录'
if (Test-Path $stateFile) { Remove-Item $stateFile -Force }
if (Test-Path $stateDir) {
    if (Test-Path $certDir) {
        # 证书目录里是私钥，直接删；但先提示一句，避免误以为还能恢复
        Remove-Item $certDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $rest = Get-ChildItem $stateDir -Force -ErrorAction SilentlyContinue
    if ($rest.Count -eq 0) {
        Remove-Item $stateDir -Force -ErrorAction SilentlyContinue
        Write-Ok '已删除安装目录'
    } else {
        Write-Warn2 "目录里还有 $($rest.Count) 个文件，保留 $stateDir"
    }
}

# ------------------------------------------------------------------- 自检
Write-Step '自检残留'
$residue = 0
$pac = if (Test-Path $inetKey) { (Get-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL } else { $null }
if ($pac -and $pac -like 'http://127.0.0.1:*') { Write-Warn2 "AutoConfigURL 仍指向本机: $pac"; $residue++ }
if ($thumb -and (Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb })) {
    Write-Warn2 "根证书仍在存储里: $thumb"; $residue++
}
if (@(Get-Process -Name 'winget-accel' -ErrorAction SilentlyContinue).Count -gt 0) {
    Write-Warn2 '仍有代理进程'; $residue++
}

Write-Host ''
if ($residue -eq 0) {
    Write-Host '卸载完成，无残留。' -ForegroundColor Green
    exit 0
} else {
    Write-Host "卸载完成，但有 $residue 项残留（见上）。" -ForegroundColor Yellow
    exit 1
}
