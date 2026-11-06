#Requires -Version 7.0
<#
.SYNOPSIS
    长跑压测：用本地模拟加速器跑 N 次 Range 请求，检查计数、线程与内存是否平稳。

.DESCRIPTION
    为什么需要它：design.md §11 那组"600 次请求无泄漏"的数字，如果只能靠手搓命令复现，
    下次就没人能验证它是否仍然成立。这个脚本把同样的流程固化下来，跑一次几十秒。

    设计要点：
    1. **不依赖外网**：本地起一个"对任何请求回 206 + 64 KiB"的服务器当加速器。
       外网波动会让"内存/线程"这类结论变得没法解释。
    2. 走真实链路：curl → 我们的代理（CONNECT + MITM + 改写）→ 本地加速器。
       所以它同时覆盖了 TLS 终止、改写、转发三段的资源行为。
    3. 断言而不只是打印：请求失败、`errors` 非 0、`bytes` 与 `mitm × 64 KiB` 不符、
       线程数增长、工作集持续增长——任一成立就以非零退出码失败。

.PARAMETER Requests
    总请求数（默认 200）。每 1/4 取一次快照。

.PARAMETER Port
    代理监听端口（默认自动挑一个空闲端口）。

.PARAMETER Binary
    被测二进制路径（默认 target\release\winget-accel.exe）。

.EXAMPLE
    ./packaging/soak.ps1 -Requests 600
#>
[CmdletBinding()]
param(
    [int]$Requests = 200,
    [int]$Port = 0,
    [string]$Binary = "target\release\winget-accel.exe"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Requests -lt 1) { throw '-Requests 必须 >= 1' }

trap {
    Write-Host "::error::压测脚本异常终止：$($_.Exception.Message)"
    exit 1
}

$repo = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $repo $Binary))) {
    throw "找不到被测二进制：$(Join-Path $repo $Binary)（先 cargo build --release）"
}
$exe = (Resolve-Path (Join-Path $repo $Binary)).Path

function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $p = $l.LocalEndpoint.Port
    $l.Stop()
    return $p
}

if ($Port -eq 0) { $Port = Get-FreePort }
$upstreamPort = Get-FreePort
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wg-soak-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$certDir = Join-Path $tmp 'certs'
$cfgPath = Join-Path $tmp 'config.json'
$logPath = Join-Path $tmp 'proxy.log'
$srvPath = Join-Path $tmp 'echo-server.ps1'

$proxyProc = $null
$srvProc = $null

try {
    # ---- 本地模拟加速器 ----
    @'
param([int]$Port)
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
$payload = New-Object byte[] 65536
for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = [byte](65 + ($i % 26)) }
while ($true) {
    $client = $listener.AcceptTcpClient()
    try {
        $stream = $client.GetStream()
        $buf = New-Object byte[] 4096
        $sb = New-Object System.Text.StringBuilder
        while ($true) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n))
            if ($sb.ToString().Contains("`r`n`r`n")) { break }
        }
        $head = "HTTP/1.1 206 Partial Content`r`nContent-Length: 65536`r`nContent-Range: bytes 0-65535/65536`r`nConnection: close`r`n`r`n"
        $hb = [System.Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($hb, 0, $hb.Length)
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush()
    }
    catch { }
    finally { $client.Close() }
}
'@ | Set-Content -Path $srvPath -Encoding UTF8

    $srvProc = Start-Process pwsh -ArgumentList '-NoProfile', '-File', $srvPath, $upstreamPort -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1200

    # ---- 被测代理 ----
    @{
        listen       = "127.0.0.1:$Port"
        accelerators = @(@{ name = 'local'; template = "http://127.0.0.1:$upstreamPort/{url}"; priority = 1 })
        certDir      = $certDir
        logPath      = $logPath
        health       = @{ enabled = $false }
        routing      = @{ mode = 'accelerator' }
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgPath -Encoding UTF8

    $proxyProc = Start-Process $exe -ArgumentList '--config', $cfgPath, '--no-env' -PassThru -WindowStyle Hidden

    # 等 CA 和本地 HTTP 端点均就绪，不能把“证书已生成”当成启动完成。
    $caPath = Join-Path $certDir 'ca-cert.pem'
    $deadline = (Get-Date).AddSeconds(40)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($proxyProc.HasExited) { break }
        if (Test-Path -LiteralPath $caPath) {
            try {
                $health = (Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -NoProxy -TimeoutSec 1).Content | ConvertFrom-Json
                if ($health.status -eq 'ok') { $ready = $true; break }
            }
            catch { }
        }
        Start-Sleep -Milliseconds 200
    }
    if ($proxyProc.HasExited) { throw "代理启动失败（退出码 $($proxyProc.ExitCode)）" }
    if (-not $ready) { throw "40 秒内代理未就绪：$(Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue)" }

    Write-Host "代理: 127.0.0.1:$Port   模拟加速器: 127.0.0.1:$upstreamPort   请求数: $Requests"

    # 取基线前先等线程数**稳定**。
    #
    # 直接"CA 一生成就测"会测到 4，而随后探测器/监听线程起来后是 6——
    # 实测 5 次里有 3 次基线是 4、2 次是 6，而峰值恒为 6。
    # 于是 `base+2` 这个阈值永远卡在边界：多一个线程就误报，真泄漏 1 个又看不出来。
    # 这里要求"连续两次采样相同"才算稳定（最多等 5 秒）。
    $stableDeadline = (Get-Date).AddSeconds(5)
    $prev = -1
    $baseThreads = -1
    while ((Get-Date) -lt $stableDeadline) {
        $now = (Get-Process -Id $proxyProc.Id).Threads.Count
        if ($now -eq $prev) { $baseThreads = $now; break }
        $prev = $now
        Start-Sleep -Milliseconds 250
    }
    if ($baseThreads -lt 0) {
        # 5 秒都没稳定就取当前值，并在输出里说明（不静默）
        $baseThreads = (Get-Process -Id $proxyProc.Id).Threads.Count
        Write-Host "注意：5 秒内线程数未稳定，基线取当前值 $baseThreads"
    }
    $baseline = Get-Process -Id $proxyProc.Id
    $baseWs = [math]::Round($baseline.WorkingSet64 / 1MB, 1)
    Write-Host ("基线：线程 {0}，工作集 {1} MB" -f $baseThreads, $baseWs)
    Write-Host ("{0,-8} {1,-8} {2,-8} {3}" -f '批次', '累计', '线程', '工作集MB')

    $ok = 0
    $bad = 0
    $snapshots = @()
    $perBatch = [Math]::Max(1, [int]($Requests / 4))
    $batch = 0
    for ($i = 1; $i -le $Requests; $i++) {
        $code = & curl.exe -sS --max-time 30 --noproxy 'localhost,127.0.0.1' `
            -x "http://127.0.0.1:$Port" --ssl-no-revoke `
            --cacert $caPath -r 0-65535 -o NUL -w '%{http_code}:%{size_download}' `
            "https://github.com/o/r/releases/download/v1/f$i.bin" 2>&1
        $curlExit = $LASTEXITCODE
        if ($curlExit -eq 0 -and "$code" -eq '206:65536') { $ok++ }
        else {
            $bad++
            if ($bad -eq 1) { Write-Host "首个失败：curl exit=$curlExit response=$code" }
        }

        if ($i % $perBatch -eq 0) {
            $batch++
            $cur = Get-Process -Id $proxyProc.Id
            $ws = [math]::Round($cur.WorkingSet64 / 1MB, 1)
            $snapshots += [pscustomobject]@{ Batch = $batch; Done = $i; Threads = $cur.Threads.Count; MB = $ws }
            Write-Host ("{0,-8} {1,-8} {2,-8} {3}" -f $batch, $i, $cur.Threads.Count, $ws)
        }
    }

    # ---- 结论 ----
    $health = (Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -NoProxy -TimeoutSec 5).Content | ConvertFrom-Json
    $final = Get-Process -Id $proxyProc.Id
    $failures = @()

    if ($bad -ne 0) { $failures += "有 $bad 次请求失败（成功 $ok / 共 $Requests）" }
    if ($health.errors -ne 0) { $failures += "proxy 记录了 $($health.errors) 个错误" }
    $expected = [int64]$health.mitm * 65536
    if ($health.bytes -ne $expected) {
        $failures += "bytes=$($health.bytes) 与 mitm×64KiB=$expected 不一致"
    }
    # 基线已等稳定，余量收紧到 +1（并发尖峰时临时多一个线程是正常的）。
    # 之前是 +2，而基线本身会在 4/6 之间跳——既可能误报又可能掩盖 1 个线程的泄漏。
    $maxThreads = ($snapshots | Measure-Object -Property Threads -Maximum).Maximum
    if ($maxThreads -gt ($baseThreads + 1)) {
        $failures += "线程数从 $baseThreads 增到 $maxThreads（疑似未回收；请求结束后应回落到基线附近）"
    }
    $maxMB = ($snapshots | Measure-Object -Property MB -Maximum).Maximum
    # 工作集允许 8 MB 的波动（.NET/rustls 的分配器不会立刻还给系统）
    if ($maxMB -gt ($baseWs + 8)) {
        $failures += "工作集从 $baseWs MB 增到 $maxMB MB（疑似泄漏）"
    }

    Write-Host ''
    Write-Host "成功 $ok / $Requests，线程 $baseThreads -> $($final.Threads.Count)，工作集 $baseWs -> $([math]::Round($final.WorkingSet64/1MB,1)) MB"
    Write-Host "mitm=$($health.mitm) rewrites=$($health.rewrites) bytes=$($health.bytes) errors=$($health.errors) pinSaturated=$($health.pinSaturated)"

    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Host "::error::$f" }
        Select-String -LiteralPath $logPath -Pattern 'ALL-ACCEL-DOWN|ACCEL-COOLDOWN|RELAY-ERR|UPSTREAM-FAIL' |
            ForEach-Object { Write-Host $_.Line }
        Get-Content -LiteralPath $logPath -Tail 12 -ErrorAction SilentlyContinue | Write-Host
        exit 1
    }
    Write-Host '通过：无失败请求、计数精确、线程与内存平稳' -ForegroundColor Green
}
finally {
    foreach ($p in @($proxyProc, $srvProc)) {
        if ($null -ne $p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $resolvedTemp = [System.IO.Path]::GetFullPath($tmp)
    if ((Split-Path -Parent $resolvedTemp) -eq [System.IO.Path]::GetTempPath().TrimEnd('\', '/') -and
        (Split-Path -Leaf $resolvedTemp).StartsWith('wg-soak-')) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
