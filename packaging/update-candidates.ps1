#Requires -Version 7.0
<#
.SYNOPSIS
    从上游抓候选域名，全量实测，重写 candidates.json。

.DESCRIPTION
    设计要点（每条都对应一次实际踩坑或一次明确的安全判断）：

    1. **上游只有一个**：https://hubp.tbedu.top/nodes.json（标准 JSON）。
       社区加速器列表事实上由 hubporg 一家维护（nodes.json 与 ghproxy-next 的
       nodes.ts 是同一批数据），不存在"更可靠的第二个源"。接受这一点，
       用「内嵌兜底 + 逐个实测」把上游失效的影响限制在"候选池不再增长"。

    2. **所有域名每次都全量重测**，不是只测新增的。
       域名可用性变化很快（实测过同一天 703 → 104 KB/s、可用 → 429 → 可用），
       只测增量会长期保留过期的判断。

    3. **投毒靠机械判据，不靠人**。
       人工看 80 个域名无法判断哪个被攻击者控制——`gh-abcd.xyz` 和
       `gh-proxy.com` 在外观上没有区别。真正能自动判定的是
       「它返回的字节是否与直连 GitHub 一致」：
       取同一段 64 KB，比对 SHA-256。不一致的无论坏掉还是投毒一律拒绝。
       （这挡不住"只对探测资产正常、对其它资产投毒"的定向攻击，
        那一层由 winget 官方的 InstallerSha256 校验兜底。）

    4. **内嵌候选（builtin: true）即使本次实测失败也保留**。
       它们是离线兜底：上游消失/断网时程序还得能启动。
       失败情况记进 verified.note，但不移出。

.PARAMETER DryRun
    只打印结果，不写文件。

.PARAMETER Limit
    只测前 N 个域名（本地调试用，CI 不传）。

.PARAMETER FirstPassOnly
    新通过的域名先留在 watchlist 观察，不直接启用。默认是**自动启用**：
    通过实测（206 + 64 KiB + 与直连 GitHub 字节一致）即进入 candidates。
    保留这个开关只为排障时对比行为。
#>
[CmdletBinding()]
param(
    [string]$OutFile = 'candidates.json',
    [string]$Upstream = 'https://hubp.tbedu.top/nodes.json',
    [int]$Limit = 0,
    [switch]$DryRun,
    [switch]$FirstPassOnly
)

function Get-HostFromTemplate([string]$template) {
    if ($template -notmatch '^https?://([^/:]+)') { return $null }
    return $Matches[1].ToLower()
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# 探测资产：固定 tag 的 release 资产（CDN 静态文件）。
# 不用 codeload 的 tag 归档：实测 5 个候选里 4 个对它返回 403/404/超时。
$Asset = 'https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe'
$SampleBytes = 65536
# curl 的 -r 自己会加 "bytes=" 前缀；写成 "bytes=0-N" 会变成 "bytes=bytes=0-N"，
# 服务器直接回 501 Unsupported client range（实测踩过）。
$Range = "0-$($SampleBytes - 1)"
$Ua = 'winget-accel-candidates-check'
$PerDomainTimeout = 20

$repo = Split-Path $PSScriptRoot -Parent
$outPath = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path $repo $OutFile }

Write-Host "上游: $Upstream"

# ---------------------------------------------------------------- 读取现有清单
$existing = $null
$comment = $null
$builtinTemplates = @{}
$known = @{}
$failures = @{}

if (Test-Path $outPath) {
    $raw = Get-Content $outPath -Raw | ConvertFrom-Json
    $existing = $raw
    if ($raw.PSObject.Properties.Name -contains '_comment') { $comment = $raw._comment }
    foreach ($c in @($raw.candidates)) {
        $h = Get-HostFromTemplate $c.template
        $known[$h] = $c
        if ($c.builtin -eq $true) { $builtinTemplates[$c.template] = $c }
    }
    foreach ($w in @($raw.watchlist)) {
        if (-not $w) { continue }
        $h = Get-HostFromTemplate $w.template
        if (-not $known.ContainsKey($h)) { $known[$h] = $w }
        if ($w.PSObject.Properties.Name -contains 'failures') { $failures[$h] = [int]$w.failures }
    }
    Write-Host "现有清单: $(@($raw.candidates).Count) 个候选 + $(@($raw.watchlist).Count) 个观察项"
}
else {
    throw "找不到 $outPath，无法在现有清单基础上更新"
}

# ---------------------------------------------------------------- 抓上游域名


$upstreamHosts = @()
try {
    $resp = Invoke-RestMethod -Uri $Upstream -TimeoutSec 20 -Headers @{ 'User-Agent' = $Ua }
    if ($resp.PSObject.Properties.Name -contains 'data') {
        $upstreamHosts = @($resp.data) | Where-Object { $_ -match '^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$' }
    }
    else {
        Write-Warning "上游 JSON 没有 data 字段，跳过发现（只重测现有清单）"
    }
    Write-Host "上游域名: $($upstreamHosts.Count) 个"
}
catch {
    # 上游挂了不该让整个任务失败：现有清单仍然可以重测
    Write-Warning "抓取上游失败（$($_.Exception.Message)），本轮只重测现有清单"
}

# ---------------------------------------------------------------- 汇总待测域名
$allHosts = [System.Collections.Generic.List[string]]::new()
$seen = @{}
foreach ($h in @($upstreamHosts) + @($known.Keys)) {
    $hl = "$h".ToLower()
    if ([string]::IsNullOrWhiteSpace($hl)) { continue }
    if ($seen.ContainsKey($hl)) { continue }
    $seen[$hl] = $true
    $allHosts.Add($hl)
}
if ($Limit -gt 0) { $allHosts = $allHosts.GetRange(0, [Math]::Min($Limit, $allHosts.Count)) }
Write-Host "待测域名合计: $($allHosts.Count) 个（上游 + 现有清单，去重）"

# ---------------------------------------------------------------- 基准字节
Write-Host "取基准字节（直连 GitHub，$SampleBytes B）..."
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "wg-cand-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $refFile = Join-Path $tmp 'ref.bin'
    $refCode = & curl.exe -sSL --max-time 120 -r $Range -A $Ua -o $refFile -w '%{http_code}' $Asset 2>$null
    if (-not (Test-Path $refFile) -or (Get-Item $refFile).Length -ne $SampleBytes) {
        throw "基准字节获取失败（HTTP $refCode，$(if (Test-Path $refFile) { (Get-Item $refFile).Length } else { 0 }) B）。直连 GitHub 不通时无法做投毒比对，本轮放弃。"
    }
    $refHash = (Get-FileHash $refFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "基准 SHA256 = $refHash"

    # ------------------------------------------------------------ 逐个实测
    $results = $allHosts | ForEach-Object -ThrottleLimit 6 -Parallel {
        $host_ = $_
        $asset = $using:Asset
        $range = $using:Range
        $ua = $using:Ua
        $want = $using:SampleBytes
        $refHash = $using:refHash
        $timeout = $using:PerDomainTimeout
        $work = Join-Path $using:tmp ("probe-" + ($host_ -replace '[^a-z0-9.-]', '_') + ".bin")

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        # -L：不少加速器用 302 跳到真实资产（正常行为），不跟随会误判为不可用。
        # --max-redirs 3：限制跳数，防止恶意域名用无限重定向拖死探测。
        # %{http_code} 带 -L 时取的是最终响应码，所以 206 才算通过。
        $out = & curl.exe -sS -L --max-redirs 3 --max-time $timeout -r $range -A $ua -D "$work.h" -o $work -w '%{http_code}' "https://$host_/$asset" 2>$null
        $sw.Stop()
        $secs = $sw.Elapsed.TotalSeconds

        $len = if (Test-Path $work) { (Get-Item $work).Length } else { 0 }
        $hasRange = if (Test-Path "$work.h") { (Select-String -Path "$work.h" -Pattern '^content-range:' -Quiet) } else { $false }
        $hash = if ($len -gt 0) { (Get-FileHash $work -Algorithm SHA256).Hash.ToLower() } else { '' }
        Remove-Item $work, "$work.h" -Force -ErrorAction SilentlyContinue

        $kbps = if ($secs -gt 0 -and $len -gt 0) { [int](($len / 1024.0) / $secs) } else { 0 }

        # 判定顺序：状态码 → 字节数 → **内容哈希**。
        #
        # Content-Range 不作为否决条件：实测 cdn.akaere.online 返回
        # 206 + 65536 B + 哈希与直连完全一致，只是没给 Content-Range 头。
        # 内容是本质，那个头只是辅助信号——用它否决会误杀正常候选。
        # 但会记进 note，便于发现行为异常的候选。
        $status = if ($out -match '^\d+$') { [int]$out } else { 0 }
        $verdict =
        if ($status -eq 429 -or $status -eq 503) { 'ratelimited' }
        elseif ($status -ne 206) { 'dead' }
        elseif ($len -ne $want) { 'dead' }
        elseif ($hash -ne $refHash) { 'mismatch' }
        else { 'ok' }

        [pscustomobject]@{
            host    = $host_
            verdict = $verdict
            status  = $status
            bytes   = $len
            kbps    = $kbps
            secs    = [Math]::Round($secs, 2)
            noRange = (-not $hasRange)
        }
    }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- 分类汇总
$ok = @($results | Where-Object { $_.verdict -eq 'ok' } | Sort-Object -Property kbps -Descending)
$limited = @($results | Where-Object { $_.verdict -eq 'ratelimited' })
$dead = @($results | Where-Object { $_.verdict -eq 'dead' })
$mismatch = @($results | Where-Object { $_.verdict -eq 'mismatch' })

Write-Host ''
Write-Host "=== 结果 ===" -ForegroundColor Cyan
Write-Host "  通过（字节与 GitHub 一致）: $($ok.Count)"
foreach ($r in $ok | Select-Object -First 15) { Write-Host ("    {0,-34} {1,5} KB/s  {2}s" -f $r.host, $r.kbps, $r.secs) }
Write-Host "  限流 429/503: $($limited.Count)"
foreach ($r in $limited) { Write-Host ("    {0}（状态 {1}）" -f $r.host, $r.status) }
Write-Host "  不可用: $($dead.Count)"
foreach ($r in $dead) { Write-Host ("    {0}（状态 {1}，{2} B）" -f $r.host, $r.status, $r.bytes) }
if ($mismatch.Count -gt 0) {
    Write-Host "  ⚠ 内容与 GitHub 不一致（拒绝）: $($mismatch.Count)" -ForegroundColor Red
    foreach ($r in $mismatch) { Write-Host ("    {0} —— 返回的字节与直连不同，视为可疑" -f $r.host) -ForegroundColor Red }
}

# ---------------------------------------------------------------- 生成新清单
$today = (Get-Date).ToString('yyyy-MM-dd')
$byHost = @{}
foreach ($r in $results) { $byHost[$r.host] = $r }

$newCandidates = [System.Collections.Generic.List[object]]::new()
$newWatchlist = [System.Collections.Generic.List[object]]::new()

# 1) 内置候选：无论如何保留
foreach ($tpl in $builtinTemplates.Keys | Sort-Object) {
    $b = $builtinTemplates[$tpl]
    $h = Get-HostFromTemplate $tpl
    $r = $byHost[$h]
    $note = if ($r -and $r.verdict -eq 'ok') {
        "实测 $($r.kbps) KB/s"
    }
    elseif ($r) {
        "本轮实测失败（$($r.verdict)/$($r.status)），仍作为离线兜底保留"
    }
    else {
        '本轮未测'
    }
    $newCandidates.Add([ordered]@{
            name     = $b.name
            template = $tpl
            builtin  = $true
            verified = [ordered]@{ date = $today; kbps = if ($r) { $r.kbps } else { 0 }; note = $note }
        })
}

# 2) 已在 candidates 里的非内置项：通过则保留，失败则降级到 watchlist
foreach ($c in @($existing.candidates)) {
    if ($c.builtin -eq $true) { continue }
    $h = Get-HostFromTemplate $c.template
    $r = $byHost[$h]
    if ($r -and $r.verdict -eq 'ok') {
        $newCandidates.Add([ordered]@{
                name     = $c.name
                template = $c.template
                builtin  = $false
                verified = [ordered]@{ date = $today; kbps = $r.kbps; note = "CI 侧实测 $($r.kbps) KB/s（Azure 美国，不代表用户网络）" }
            })
    }
    else {
        $f = 1 + [int]($failures[$h])
        if ($f -lt 3) {
            $newWatchlist.Add([ordered]@{
                    name     = $c.name
                    template = $c.template
                    reason   = "曾通过实测，本轮 $($r.verdict)（状态 $($r.status)）；连续失败 $f 次，达 3 次移除"
                    failures = $f
                })
        }
    }
}

# 3) 新通过实测的域名
$builtinHosts = @($builtinTemplates.Keys | ForEach-Object { Get-HostFromTemplate $_ })
$alreadyListed = @($newCandidates | ForEach-Object { Get-HostFromTemplate $_.template }) +
@($newWatchlist | ForEach-Object { Get-HostFromTemplate $_.template })
foreach ($r in $ok) {
    if ($alreadyListed -contains $r.host) { continue }
    $tpl = "https://$($r.host)/{url}"
    $name = $r.host -replace '\.[^.]+$', '' -replace '[^a-z0-9]+', '-'

    # 通过实测即启用。不加任何"观察期/第二轮"之类的额外门槛：
    # 判据本身已经够严（206 + 64 KiB + 与直连 GitHub 字节一致），
    # 且运行时会再探测一次，失败会被换候选重试兜住。
    # 早先我擅自加过"连续两轮通过才启用"，那等于把"自动启用"变成延迟一天，是错的。
    if ($FirstPassOnly) {
        $newWatchlist.Add([ordered]@{
                name     = $name
                template = $tpl
                reason   = "实测通过（$($r.kbps) KB/s）；-FirstPassOnly 下仅观察不启用"
                failures = 0
            })
    }
    else {
        $newCandidates.Add([ordered]@{
                name     = $name
                template = $tpl
                builtin  = $false
                verified = [ordered]@{ date = $today; kbps = $r.kbps; note = "实测通过（CI 侧 $($r.kbps) KB/s，不代表用户网络）" }
            })
    }
}

# 4) 其余（限流 / 死 / 内容不符）
foreach ($r in @($limited) + @($dead) + @($mismatch)) {
    if ($alreadyListed -contains $r.host) { continue }
    if ($builtinHosts -contains $r.host) { continue }
    $tpl = "https://$($r.host)/{url}"
    $name = $r.host -replace '\.[^.]+$', '' -replace '[^a-z0-9]+', '-'
    $f = 1 + [int]($failures[$r.host])
    if ($f -ge 3) { continue }   # 连续 3 次不可用才移除

    $reason = switch ($r.verdict) {
        'ratelimited' { "实测限流（状态 $($r.status)）。429 是『活着但拒绝』，不永久剔除；连续失败 $f 次" }
        'mismatch' { "⚠ 返回内容与直连 GitHub 不一致，严禁启用；连续失败 $f 次" }
        default { "实测不可用（状态 $($r.status)）；连续失败 $f 次，达 3 次移除" }
    }
    $newWatchlist.Add([ordered]@{
            name     = $name
            template = $tpl
            reason   = $reason
            failures = $f
        })
}

if ($mismatch.Count -gt 0) {
    # 内容不一致是安全事故级别的信号，不能只写在 JSON 里
    Write-Host ''
    Write-Host "::warning::发现 $($mismatch.Count) 个候选返回内容与 GitHub 不一致：$($mismatch.host -join ', ')"
}

$doc = [ordered]@{}
if ($comment) { $doc['_comment'] = $comment }
$doc['version'] = 2
$doc['updated'] = $today
$doc['candidates'] = @($newCandidates)
$doc['watchlist'] = @($newWatchlist)

$json = $doc | ConvertTo-Json -Depth 8
if ($DryRun) {
    Write-Host ''
    Write-Host "=== DryRun：不写文件。生成的清单预览 ===" -ForegroundColor Yellow
    Write-Host "  candidates: $($newCandidates.Count)  watchlist: $($newWatchlist.Count)"
    if ($env:GITHUB_OUTPUT) {
        "candidates=$($newCandidates.Count)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
        "watchlist=$($newWatchlist.Count)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
        "mismatch=$($mismatch.Count)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    }
    exit 0
}

$json | Set-Content $outPath -Encoding UTF8
Write-Host ''
Write-Host "已写入 $outPath（candidates: $($newCandidates.Count)，watchlist: $($newWatchlist.Count)）" -ForegroundColor Green

if ($env:GITHUB_OUTPUT) {
    "candidates=$($newCandidates.Count)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    "watchlist=$($newWatchlist.Count)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    "mismatch=$($mismatch.Count)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
}










