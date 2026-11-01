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

function Get-PacUrl {
    # StrictMode 下不能直接 (Get-ItemProperty ...).AutoConfigURL：
    # 属性不存在时取属性会抛错而不是给 $null。
    if (-not (Test-Path $inetKey)) { return $null }
    $item = Get-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties['AutoConfigURL']
    if ($null -eq $prop) { return $null }
    return [string]$prop.Value
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
    # 安装记录丢失、证书目录也没了：退回按主题扫描，否则会留下一张受信任的 CA
    $found = @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like '*winget-accel local CA*' })
    if ($found.Count -eq 0) {
        Write-Ok '存储里没有本工具的 CA'
    } else {
        foreach ($cert in $found) {
            & certutil.exe -user -delstore Root $cert.Thumbprint 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "按主题移除 $($cert.Thumbprint)"
            } else {
                Write-Warn2 "移除 $($cert.Thumbprint) 失败（$LASTEXITCODE）"
            }
        }
    }
}

# --------------------------------------------------------------- 清安装目录
Write-Step '清理安装目录'
if (Test-Path $stateFile) { Remove-Item $stateFile -Force }
if (Test-Path $stateDir) {
    # 整个目录都删：证书（私钥）、状态、日志。日志如需保留请先自行拷走。
    Remove-Item $stateDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $stateDir) {
        Write-Warn2 "目录未能完全删除: $stateDir"
    } else {
        Write-Ok '已删除安装目录'
    }
}

# ------------------------------------------------------------------- 自检
Write-Step '自检残留'
$residue = 0
$pac = Get-PacUrl
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
