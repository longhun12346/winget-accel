#Requires -Version 5.1
<#
.SYNOPSIS
    安装 winget-accel：启动代理、信任本机 CA、把 PAC 指到代理。

.DESCRIPTION
    三步都发生在用户级（HKCU + CurrentUser\Root），不需要管理员。
    唯一需要人工介入的是"信任根证书"——Windows 会弹一次确认框，无法静默。

    任何一步失败都会回滚已做的改动，不留下半装状态。

.PARAMETER Exe
    winget-accel.exe 路径。

.PARAMETER Port
    监听端口，同时被写进 PAC。

.PARAMETER Uninstall
    安装前先执行卸载，用于修复半装状态。
#>
[CmdletBinding()]
param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\target\release\winget-accel.exe'),
    [int]$Port = 8443,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$stateDir  = Join-Path $env:LOCALAPPDATA 'winget-accel'
$stateFile = Join-Path $stateDir 'state.json'
$certDir   = Join-Path $stateDir 'certs'
$logFile   = Join-Path $stateDir 'proxy.log'
$inetKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

function Update-WinInet {
    # 改完注册表必须通知 WinINet，否则已运行的进程（含 winget）读不到新 PAC
    if (-not ('WinInet.Native' -as [type])) {
        Add-Type -Namespace WinInet -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);
'@
    }
    [void][WinInet.Native]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)  # SETTINGS_CHANGED
    [void][WinInet.Native]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)  # REFRESH
}

function Get-PacUrl {
    # StrictMode 下不能直接 (Get-ItemProperty ...).AutoConfigURL：
    # 属性不存在时返回 $null，取属性会抛错而不是给 $null。
    if (-not (Test-Path $inetKey)) { return $null }
    $item = Get-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties['AutoConfigURL']
    if ($null -eq $prop) { return $null }
    return [string]$prop.Value
}

# ------------------------------------------------------------------ 前置检查
if ($Uninstall -and (Test-Path $stateFile)) {
    Write-Step '先卸载已有安装'
    & (Join-Path $PSScriptRoot 'teardown.ps1')
}

Write-Step '检查前置条件'
if (-not (Test-Path $Exe)) {
    throw "找不到 $Exe。先运行 cargo build --release。"
}
$Exe = (Resolve-Path $Exe).Path
Write-Ok "二进制: $Exe"

if (Test-Path $stateFile) {
    throw "已存在安装记录 $stateFile。先运行 teardown.ps1，或用 -Uninstall 修复。"
}

$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
try { $probe.Start() } catch { throw "端口 $Port 已被占用：$($_.Exception.Message)" }
finally { $probe.Stop() }
Write-Ok "端口 $Port 可用"

# 记录原状，供卸载还原
$hadKey = Test-Path $inetKey
$priorPac = Get-PacUrl

New-Item -ItemType Directory -Force -Path $stateDir, $certDir | Out-Null

# ------------------------------------------------------------- 启动代理进程
Write-Step '启动代理'
$proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--port', $Port,
    '--cert-dir', $certDir,
    '--log', $logFile
)
Write-Ok "PID $($proc.Id)"

$healthUrl = "http://127.0.0.1:$Port/health"
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    try {
        $null = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
        $ready = $true
        break
    } catch {
        if ($proc.HasExited) { throw "代理启动即退出（退出码 $($proc.ExitCode)），见 $logFile" }
    }
}
if (-not $ready) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    throw "代理在 15 秒内没有响应 $healthUrl"
}
Write-Ok '代理已就绪'

$rollback = {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    if ($hadKey) {
        if ($null -ne $priorPac) {
            Set-ItemProperty -Path $inetKey -Name AutoConfigURL -Value $priorPac
        } else {
            Remove-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue
        }
        Update-WinInet
    }
}

# ----------------------------------------------------------- 信任本机 CA
Write-Step '信任本机 CA（会弹一次 Windows 确认框）'
$caPem = Join-Path $certDir 'ca-cert.pem'
if (-not (Test-Path $caPem)) { & $rollback; throw "代理没生成 $caPem" }

$thumb = (Get-PfxCertificate -FilePath $caPem).Thumbprint
Write-Ok "指纹 $thumb"

$already = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb }
if ($already) {
    Write-Ok '该 CA 已被信任，跳过导入'
} else {
    # certutil 在没有可见桌面的会话里不会报错，而是**永久阻塞**在确认框上，
    # 所以必须放到子进程里加超时，超时后给出可手工执行的命令。
    $job = Start-Process -FilePath 'certutil.exe' `
        -ArgumentList @('-user', '-addstore', 'Root', $caPem) `
        -PassThru -WindowStyle Hidden
    if (-not $job.WaitForExit(45000)) {
        Stop-Process -Id $job.Id -Force -ErrorAction SilentlyContinue
        & $rollback
        Write-Host ''
        Write-Host '导入根证书需要一次交互确认，但等待 45 秒仍未完成。' -ForegroundColor Yellow
        Write-Host '请在本会话里手动执行下面这条命令，点「是」，然后重新运行本脚本：' -ForegroundColor Yellow
        Write-Host "  certutil -user -addstore Root `"$caPem`"" -ForegroundColor White
        exit 1
    }
    if ($job.ExitCode -ne 0) {
        & $rollback
        throw "导入根证书失败（certutil 退出码 $($job.ExitCode)）"
    }
    Write-Ok 'CA 已导入用户根存储'
}

# ------------------------------------------------------------------- 设置 PAC
Write-Step '设置系统 PAC'
$pacUrl = "http://127.0.0.1:$Port/proxy.pac"
Set-ItemProperty -Path $inetKey -Name AutoConfigURL -Value $pacUrl
Update-WinInet

$check = Get-PacUrl
if ($check -ne $pacUrl) { & $rollback; throw "PAC 写入后读回不一致：$check" }
Write-Ok "AutoConfigURL = $pacUrl"

# --------------------------------------------------------------- 保存状态
@{
    exe          = $Exe
    port         = $Port
    pid          = $proc.Id
    thumbprint   = $thumb
    priorPac     = $priorPac
    priorHadKey  = $hadKey
    certDir      = $certDir
    logFile      = $logFile
    installedAt  = (Get-Date).ToString('o')
} | ConvertTo-Json | Set-Content -Path $stateFile -Encoding UTF8

Write-Host ''
Write-Host '安装完成。' -ForegroundColor Green
Write-Host "  PAC : $pacUrl"
Write-Host "  日志: $logFile"
Write-Host "  自检: & '$Exe' --doctor"
Write-Host "  卸载: & '$PSScriptRoot\teardown.ps1'"
