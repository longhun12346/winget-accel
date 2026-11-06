#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/candidate-catalog.ps1"

function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Roundtrip($Document) {
    $Document | ConvertTo-Json -Depth 8 | ConvertFrom-Json
}
function Result([string]$Verdict) {
    [pscustomobject]@{ host = 'test.example'; verdict = $Verdict; status = 206; kbps = 100 }
}

foreach ($builtin in @($true, $false)) {
    $existing = Roundtrip @{
        candidates = @(@{ name = 'test'; template = 'https://test.example/{url}'; builtin = $builtin })
        watchlist = @()
    }
    $doc = New-CandidateCatalog $existing @((Result 'mismatch'))
    Assert-True ($doc.candidates.Count -eq 0 -and $doc.watchlist.Count -eq 1) '内容不符的候选必须隔离（含内置）'
    Assert-True ($doc.watchlist[0].quarantined) '隔离必须持久化'
    foreach ($verdict in @('dead', 'ratelimited', 'dead', 'unmeasured')) {
        $results = @(if ($verdict -ne 'unmeasured') { Result $verdict })
        $doc = New-CandidateCatalog (Roundtrip $doc) $results
        Assert-True ($doc.candidates.Count -eq 0 -and $doc.watchlist.Count -eq 1) '失败、三次阈值和未测都不能抹除隔离'
    }
    $doc = New-CandidateCatalog (Roundtrip $doc) @((Result 'ok'))
    Assert-True ($doc.candidates.Count -eq 1 -and $doc.watchlist.Count -eq 0) '重新通过哈希校验后应解除隔离'
    Assert-True ($doc.candidates[0].builtin -eq $builtin) '隔离往返必须保留内置身份'
}
$doc = New-CandidateCatalog $existing @((Result 'dead'))
Assert-True ($doc.candidates.Count -eq 0 -and $doc.watchlist[0].failures -eq 1) '普通候选失败应降级观察'
$doc = New-CandidateCatalog (Roundtrip $doc) @()
Assert-True ($doc.watchlist[0].failures -eq 1) '未测不能累计失败'
1..2 | ForEach-Object { $doc = New-CandidateCatalog (Roundtrip $doc) @((Result 'dead')) }
Assert-True ($doc.watchlist.Count -eq 0) '普通故障连续三次应移除'
$existing.candidates[0].builtin = $true
$doc = New-CandidateCatalog $existing @((Result 'dead'))
Assert-True ($doc.candidates.Count -eq 1) '内置候选的临时故障仍可保留兜底'
$empty = Roundtrip @{ candidates = @(); watchlist = @() }
$doc = New-CandidateCatalog $empty @((Result 'ok')) -FirstPassOnly
Assert-True ($doc.candidates.Count -eq 0 -and $doc.watchlist.Count -eq 1) '仅观察模式不能启用新候选'
Write-Host '候选分类回归通过（隔离、恢复、兜底、失败计数、仅观察）'
