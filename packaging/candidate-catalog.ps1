# 候选分类纯函数：输入已完成的探测结果，不联网、不写文件。
function Get-HostFromTemplate([string]$Template) {
    if ($Template -notmatch '^https?://([^/:]+)') { return $null }
    return $Matches[1].ToLowerInvariant()
}

function New-CandidateCatalog {
    param(
        [Parameter(Mandatory)]$Existing,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results,
        [switch]$FirstPassOnly
    )
    $today = (Get-Date).ToString('yyyy-MM-dd')
    $known = @{}
    $byHost = @{}
    foreach ($item in @($Existing.watchlist) + @($Existing.candidates)) {
        if ($item) { $known[(Get-HostFromTemplate $item.template)] = $item }
    }
    foreach ($result in $Results) { $byHost[$result.host] = $result }
    $hosts = @(@($known.Keys) + @($byHost.Keys) | Sort-Object -Unique)
    $candidates = [System.Collections.Generic.List[object]]::new()
    $watchlist = [System.Collections.Generic.List[object]]::new()
    foreach ($hostName in $hosts) {
        $item = $known[$hostName]
        $result = $byHost[$hostName]
        $builtin = $item -and $item.PSObject.Properties.Name -contains 'builtin' -and $item.builtin
        $quarantined = $item -and $item.PSObject.Properties.Name -contains 'quarantined' -and $item.quarantined
        $failures = if ($item -and $item.PSObject.Properties.Name -contains 'failures') { [int]$item.failures } else { 0 }
        $template = if ($item) { $item.template } else { "https://$hostName/{url}" }
        $name = if ($item) { $item.name } else { $hostName -replace '\.[^.]+$', '' -replace '[^a-z0-9]+', '-' }
        $passed = $result -and $result.verdict -eq 'ok'
        if ($result -and $result.verdict -eq 'mismatch') { $quarantined = $true }
        # 内容不符的证据不能被内置身份、临时故障、漏测或累计失败次数抹掉。
        # 只有重新通过完整的样本哈希校验才允许解除隔离。
        if ($quarantined -and -not $passed) {
            $watchlist.Add([ordered]@{
                    name = $name; template = $template; builtin = [bool]$builtin
                    quarantined = $true
                    reason = '返回内容曾与直连 GitHub 不一致；重新通过样本哈希校验前严禁启用'
                    failures = $failures + [int][bool]$result
                })
            continue
        }
        $wasCandidate = @($Existing.candidates | Where-Object { $_.template -eq $template }).Count -gt 0
        if (($builtin -or $passed) -and -not ($FirstPassOnly -and -not $builtin -and -not $wasCandidate)) {
            $note = if ($passed) { '可用性校验通过（206 + 64 KiB + 样本 SHA-256 一致）' }
            elseif ($result) { "本轮实测失败（$($result.verdict)/$($result.status)），保留内置离线兜底" }
            else { '本轮未测，保留内置离线兜底' }
            $candidates.Add([ordered]@{
                    name = $name; template = $template; builtin = [bool]$builtin
                    verified = [ordered]@{ date = $today; note = $note }
                })
            continue
        }
        if ($passed) {
            $failures = 0
            $reason = '可用性校验通过；-FirstPassOnly 下仅观察不启用'
        }
        else {
            if ($result) { $failures++ }
            if ($failures -ge 3) { continue }
            $reason = if ($result) { "本轮 $($result.verdict)（状态 $($result.status)）；连续失败 $failures 次，达 3 次移除" }
            else { "本轮未测；连续失败 $failures 次，达 3 次移除" }
        }
        $watchlist.Add([ordered]@{ name = $name; template = $template; reason = $reason; failures = $failures })
    }
    $doc = [ordered]@{}
    if ($Existing.PSObject.Properties.Name -contains '_comment') { $doc['_comment'] = $Existing._comment }
    $doc['version'] = 2
    $doc['updated'] = $today
    $doc['candidates'] = @($candidates)
    $doc['watchlist'] = @($watchlist)
    return $doc
}
