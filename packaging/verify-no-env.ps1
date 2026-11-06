#Requires -Version 7.0
<#
.SYNOPSIS
    验证 `--no-env` 的承诺：只跑代理，**不改任何系统设置**。

.DESCRIPTION
    为什么单列一个脚本：`--no-env` 是"我想先试试但别动我系统"这个用法的基础，
    而这条承诺此前只有代码可读、没有实测。它要读注册表与证书存储才能判断，
    不适合作单元测试（会依赖机器状态），所以做成可手动复跑的脚本。

    检查三处，跑前/运行中/退出后各取一次：
      1. HKCU\...\Internet Settings\AutoConfigURL（PAC 落点）
      2. 受信任根里本工具 CA 的数量
      3. 用户级 PAC 日志/锁是否保持原状，临时目录下是否残留 state.json

    同时施加真实负载（默认 2 次 Range 请求），确保程序确实执行了
    "生成 CA → 终止 TLS → 改写 → 转发"这条链路——否则"什么都没改"可能只是因为它没跑起来。

.PARAMETER Requests
    施加的请求数（默认 2）。

.PARAMETER Port
    代理端口（默认自动挑空闲端口）。

.PARAMETER RoutingMode
    默认 accelerator 固定验证加速链；auto 额外执行真实直连探测。

.EXAMPLE
    ./packaging/verify-no-env.ps1
#>
[CmdletBinding()]
param(
    [int]$Requests = 2,
    [int]$Port = 0,
    [ValidateSet('auto', 'accelerator')]
    [string]$RoutingMode = 'accelerator'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# 0 次负载等于"什么都没验证"——它会以 0/0 通过，制造虚假的安全感。
if ($Requests -lt 1) { throw "-Requests 必须 >= 1（0 次负载无法证明链路跑通）" }

$repo = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repo 'target\release\winget-accel.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe（先 cargo build --release）" }
if (Get-Process winget-accel -ErrorAction SilentlyContinue) {
    throw '有 winget-accel 进程在运行，先停掉再测（避免与本次实例混淆）'
}

function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
}
if ($Port -eq 0) { $Port = Get-FreePort }

$inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$failures = [System.Collections.Generic.List[string]]::new()

function Read-State {
    # 用 Get-ItemPropertyValue 并兜住异常：StrictMode 下访问不存在的属性会直接抛错，
    # 而"AutoConfigURL 不存在"正是我们要识别的正常状态（用户本来就没设 PAC）。
    $auto = $null
    try {
        $auto = Get-ItemPropertyValue -Path $inet -Name AutoConfigURL -ErrorAction Stop
    }
    catch {
        $auto = $null
    }
    $cas = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'winget-accel' })
    $pacDir = Join-Path $env:LOCALAPPDATA 'winget-accel'
    $journal = Join-Path $pacDir 'state.json'
    [pscustomobject]@{
        AutoConfigURL = if ($null -eq $auto) { '<不存在>' } else { $auto }
        CaCount       = $cas.Count
        Journal       = if (Test-Path -LiteralPath $journal) {
            (Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash
        } else { '<不存在>' }
        PacLock       = Test-Path -LiteralPath (Join-Path $pacDir 'pac.lock')
    }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("wg-noenv-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$certDir = Join-Path $work 'certs'
$cfgPath = Join-Path $work 'config.json'
$proxyProc = $null

try {
    $before = Read-State
    Write-Host ("基线：AutoConfigURL={0}  CA={1} 张" -f $before.AutoConfigURL, $before.CaCount)

    @{
        listen       = "127.0.0.1:$Port"
        rewriteHosts = @('github.com', 'objects.githubusercontent.com', 'codeload.github.com', 'release-assets.githubusercontent.com')
        accelerators = @(@{ name = 'A'; template = 'https://gh-proxy.com/{url}'; priority = 1 })
        certDir      = $certDir
        logPath      = Join-Path $work 'proxy.log'
        health       = @{ enabled = $false }
        routing      = @{ mode = $RoutingMode }
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgPath -Encoding UTF8

    $proxyProc = Start-Process $exe -ArgumentList '--config', ('"{0}"' -f $cfgPath), '--no-env' -PassThru -WindowStyle Hidden

    $caPath = Join-Path $certDir 'ca-cert.pem'
    $deadline = (Get-Date).AddSeconds(40)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($proxyProc.HasExited) { break }
        if (Test-Path $caPath) {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -NoProxy -TimeoutSec 1
                if ($health.version) { $ready = $true; break }
            }
            catch { }
        }
        Start-Sleep -Milliseconds 200
    }
    if ($proxyProc.HasExited) { throw "代理启动失败（退出码 $($proxyProc.ExitCode)）" }
    if (-not $ready) { throw "40 秒内代理未就绪；等待 CA 和 /health 失败" }
    if ($health.routing.mode -ne $RoutingMode) { throw "运行中的 routing.mode 与配置不一致" }
    Write-Host ("路由：mode={0}  {1}" -f $health.routing.mode,
        (($health.routing.hosts | ForEach-Object {
            "{0}={1}({2}, {3} KiB/s)" -f $_.host,
                $(if ($_.direct) { 'DIRECT' } else { 'ACCELERATOR' }), $_.reason, $_.kbps
        }) -join ', '))

    # 施加真实负载：证明它确实在干活，而不是"没跑起来所以没改系统"。
    #
    # 必须用**真实存在**的资产：随便编一个路径会拿到加速器的 404（那是正常回答），
    # 会被误判成"链路没跑通"。第一版就是这么错的。
    $asset = 'https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe'
    $ok = 0
    $codes = @()
    for ($i = 1; $i -le $Requests; $i++) {
        # 显式覆盖 NO_PROXY，确保 GitHub 负载不会绕过本次代理。
        $response = & curl.exe -sS --max-time 30 --noproxy 'localhost,127.0.0.1' `
            -x "http://127.0.0.1:$Port" --ssl-no-revoke `
            --cacert $caPath -r 0-65535 -o NUL -w '%{http_code}:%{size_download}' `
            $asset 2>&1
        $curlExit = $LASTEXITCODE
        $code = ($response | Out-String).Trim()
        $codes += $code
        if ($curlExit -eq 0 -and $code -eq '206:65536') { $ok++ }
    }
    Write-Host ("负载：{0}/{1} 次请求成功（状态码:字节数 {2}）" -f $ok, $Requests, ($codes -join ','))
    if ($ok -ne $Requests) {
        $failures.Add("只有 $ok/$Requests 次请求成功（状态码 $($codes -join ',')），无法证明链路跑通")
    }
    $proxyLog = Get-Content -LiteralPath (Join-Path $work 'proxy.log') -Raw
    $rewrites = [regex]::Matches($proxyLog, '(?m) INF REWRITE .* -> 206 ').Count
    if ($rewrites -lt $Requests) {
        $failures.Add("代理只记录了 $rewrites 次成功改写，少于 $Requests 次负载，无法证明请求经过代理")
    }

    $during = Read-State
    Write-Host ("运行中：AutoConfigURL={0}  CA={1} 张" -f $during.AutoConfigURL, $during.CaCount)
    if ($during.AutoConfigURL -ne $before.AutoConfigURL) {
        $failures.Add("运行中 AutoConfigURL 被改动：$($before.AutoConfigURL) → $($during.AutoConfigURL)")
    }
    if ($during.CaCount -ne $before.CaCount) {
        $failures.Add("运行中受信任根 CA 数量变了：$($before.CaCount) → $($during.CaCount)")
    }
    if ($during.Journal -ne $before.Journal -or $during.PacLock -ne $before.PacLock) {
        $failures.Add('运行中用户级 PAC 日志或锁被改动')
    }
    if (Test-Path (Join-Path $work 'state.json')) {
        $failures.Add('--no-env 下不该写 state.json（那是接管系统时才写的）')
    }

    Stop-Process -Id $proxyProc.Id -Force
    Start-Sleep -Milliseconds 500
    $proxyProc = $null

    $after = Read-State
    Write-Host ("退出后：AutoConfigURL={0}  CA={1} 张" -f $after.AutoConfigURL, $after.CaCount)
    if ($after.AutoConfigURL -ne $before.AutoConfigURL) {
        $failures.Add("退出后 AutoConfigURL 与基线不一致：$($before.AutoConfigURL) → $($after.AutoConfigURL)")
    }
    if ($after.CaCount -ne $before.CaCount) {
        $failures.Add("退出后受信任根 CA 数量与基线不一致：$($before.CaCount) → $($after.CaCount)")
    }
    if ($after.Journal -ne $before.Journal -or $after.PacLock -ne $before.PacLock) {
        $failures.Add('退出后用户级 PAC 日志或锁与基线不一致')
    }

    Write-Host ''
    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Host "::error::$f" }
        exit 1
    }
    Write-Host '通过：--no-env 全程未改动 AutoConfigURL / 受信任根，也没有留下 state.json' -ForegroundColor Green
}
finally {
    if ($null -ne $proxyProc -and -not $proxyProc.HasExited) {
        Stop-Process -Id $proxyProc.Id -Force -ErrorAction SilentlyContinue
    }
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $cleanup = [System.IO.Path]::GetFullPath($work)
    if (-not $cleanup.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($cleanup) -notmatch '^wg-noenv-[0-9a-f]{8}$') {
        throw "拒绝清理非预期临时目录：$cleanup"
    }
    Remove-Item -LiteralPath $cleanup -Recurse -Force -ErrorAction SilentlyContinue
}
