#Requires -Version 7.0
<#
.SYNOPSIS
    核对"文档承诺"与"代码实际"是否一致：CLI 参数、配置键、日志标签。

.DESCRIPTION
    为什么需要它：这个仓库的文档密度很高（README / design.md / QUICKSTART / 示例配置），
    而"文档写了但代码没有""代码改了但文档没跟上"是最容易积累的一类漂移。
    靠人肉比对 40 多个标签不现实，靠 grep 又容易被格式差异误导
    （我第一次查 MITM-HANDSHAKE-FAIL 就因为它嵌在格式串里而误判为缺失）。

    检查六组，任何一组不一致就以非零退出码失败：
      1. CLI 参数：README/design.md/QUICKSTART 提到的 --flag 必须被 main.rs 解析
      2. 配置键：config.example.json 用到的键必须出现在 config.rs 的 *_KEYS 里
      3. 日志标签：文档里出现的全大写标签必须能在 src/*.rs 里找到
      4. ADR 引用：文档里提到的 ADR-NNN 必须在 decisions.md 里有对应小节或废弃表条目
      5. 源码卫生：`#[test]` 后面不能夹着注释再接另一个 `#[test]`（属性错位）
      6. 行尾统一 + 乱码：受版本控制的文本文件不得含 CRLF，也不得含连续问号

    注意：这个脚本只做"存在性"核对，不判断语义是否仍然正确——
    后者只能靠读代码与实测。

.EXAMPLE
    ./packaging/check-docs-sync.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    $failures = [System.Collections.Generic.List[string]]::new()

    # ---------------------------------------------------------------- 1) CLI 参数
    # 只收集本程序自己的参数（--config/--doctor…），排除 cargo/curl 的参数。
    #
    # 必须**去掉 `#[cfg(test)]` 之后的部分**：那里有一份"已删除参数"的列表
    # （`rejects_removed_flags` 挨个断言它们被拒绝），如果把它们也算成"代码支持"，
    # 检查器就会以为 `--listen`/`--port` 之类仍然可用——有人把它们写回文档时不会报错。
    # 第一版就是这样，统计出"代码 15 个"，其中 8 个其实已删除。
    $srcMain = Get-Content 'src\main.rs' -Raw
    $cfgTestAt = $srcMain.IndexOf('#[cfg(test)]')
    if ($cfgTestAt -ge 0) { $srcMain = $srcMain.Substring(0, $cfgTestAt) }
    $codeFlags = [regex]::Matches($srcMain, '"(--[a-z][a-z-]+)"') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    $docsText = @('README.md', 'docs\design.md', 'packaging\QUICKSTART.txt') |
        ForEach-Object { Get-Content $_ -Raw }
    $docFlags = [regex]::Matches(($docsText -join "`n"), '--[a-z][a-z-]+') |
        ForEach-Object { $_.Value } | Sort-Object -Unique

    # 明确属于其它工具的开关，不参与核对
    # 注意核对方向是**单向**的：只检查"文档提到 → 代码必须支持"。
    # 代码里有而文档没有是允许的——`--watchdog` 就是程序自己拉起子进程用的内部参数，
    # 不该出现在用户文档里。所以别为了"齐全"去补它。
    $external = @(
        '--all', '--check', '--all-targets', '--release', '--bin', '--offline', '--locked', '--test', '--test-threads', '--tb', '--nocapture',
        '--ssl-no-revoke', '--max-time', '--output', '--no-run', '--collect-only', '--id',
        '--download-directory', '--version-check', '--help-docs',
        # curl 与 winget 自己的参数（design.md §12 的对比实验里会写到）
        '--cacert', '--exact'
    )
    foreach ($f in $docFlags) {
        if ($external -contains $f) { continue }
        # 文档提到但代码没有 —— 只报"看起来属于本程序"的（winget-accel 附近）
        if ($docFlags -contains $f -and -not ($codeFlags -contains $f)) {
            $failures.Add("CLI 参数 $f 在文档中出现，但 main.rs 没有解析它")
        }
    }
    Write-Host ("CLI 参数：代码 {0} 个，文档 {1} 个" -f $codeFlags.Count, $docFlags.Count)

    # ---------------------------------------------------------------- 2) 配置键
    $cfgSrc = Get-Content 'src\config.rs' -Raw
    $knownKeys = @()
    foreach ($m in [regex]::Matches($cfgSrc, '(?s)const \w+_KEYS[^=]*=\s*\[(.*?)\];')) {
        $knownKeys += [regex]::Matches($m.Groups[1].Value, '"([A-Za-z]+)"') |
            ForEach-Object { $_.Groups[1].Value }
    }
    $knownKeys = $knownKeys | Sort-Object -Unique

    $example = Get-Content 'config.example.json' -Raw | ConvertFrom-Json
    $usedKeys = @()
    foreach ($p in $example.PSObject.Properties) {
        if ($p.Name -notlike '$*') { $usedKeys += $p.Name }
    }
    foreach ($p in $example.health.PSObject.Properties) {
        if ($p.Name -notlike '$*') { $usedKeys += $p.Name }
    }
    foreach ($p in $example.accelerators[0].PSObject.Properties) {
        if ($p.Name -notlike '$*') { $usedKeys += $p.Name }
    }
    foreach ($k in ($usedKeys | Sort-Object -Unique)) {
        if (-not ($knownKeys -contains $k)) {
            $failures.Add("配置键 $k 出现在 config.example.json，但 config.rs 的 *_KEYS 里没有它")
        }
    }
    Write-Host ("配置键：代码 {0} 个，示例配置用到 {1} 个" -f $knownKeys.Count, ($usedKeys | Sort-Object -Unique).Count)

    # ---------------------------------------------------------------- 3) 日志标签
    $allSrc = (Get-ChildItem 'src\*.rs' | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
    $allDocs = (Get-ChildItem 'README.md', 'docs\design.md' | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"

    # 只看"像日志标签"的：全大写、至少两个词、带连字符（如 ACCEL-COOLDOWN）。
    # 排除 HTTP 头、文件名等已知的非标签词。
    #
    # 注意：`ADR-NNN` 也符合"全大写+连字符"，曾经靠在下面逐个列出才排除——
    # 那样每加一条 ADR 都会漏一个新编号（反向验证时就误报了 ADR-099）。
    # 现在用负向断言在正则层面直接排除前缀。
    $notTags = @(
        'SHA-256', 'UTF-8', 'YYYY-MM-DD',
        'THIRD-PARTY-NOTICES', 'LICENSE-APACHE', 'windows-latest', 'win-x64', 'api-ms-win-core-synch-l1-2-0',
        'If-None-Match', 'If-Range', 'User-Agent', 'Content-Length', 'Transfer-Encoding',
        'Proxy-Connection', 'Keep-Alive', 'no-env'
    )
    $docTags = [regex]::Matches($allDocs, '\b((?!ADR-)[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)\b') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $missing = @()
    foreach ($t in $docTags) {
        if ($notTags -contains $t) { continue }
        # 必须真的出现在某个 src 文件里（不要求带引号——标签常嵌在格式串中间）
        if (-not $allSrc.Contains($t)) { $missing += $t }
    }
    foreach ($m in $missing) {
        $failures.Add("日志标签 $m 在文档中出现，但 src\*.rs 里找不到")
    }
    Write-Host ("日志标签：文档 {0} 个，缺失 {1} 个" -f $docTags.Count, $missing.Count)

    # ---------------------------------------------------------------- 4) ADR 引用
    # decisions.md 只保留"仍在生效"的决策（正文小节），废弃的压进 §6 的表格里。
    # 两类都算"存在"；引用了既不在正文也不在废弃表里的编号就是悬空引用。
    $decisions = Get-Content 'docs\decisions.md' -Raw
    # 标题允许带序号，也允许直接写 `## ADR-012`；两种写法都属于现行决策。
    $activeAdr = @([regex]::Matches($decisions, '(?m)^##\s*(?:\d+\.\s*)?ADR-(\d+)') |
        ForEach-Object { $_.Groups[1].Value }
    )
    $tableAdr = @([regex]::Matches($decisions, '(?m)^\|\s*ADR-(\d+)') |
        ForEach-Object { $_.Groups[1].Value }
    )
    $knownAdr = @($activeAdr + $tableAdr) | Sort-Object -Unique

    # 扫引用时要**先去掉行内代码**（反引号包起来的部分）。
    #
    # 原因：说明文字里常把编号当例子写，比如 CHANGELOG 里记"塞入 `ADR-099` → exit=1"。
    # 那是字面举例，不是真的引用某个决策。用反引号包起来正是"这是字面量"的约定，
    # 所以检查器尊重它——否则每写一次验证记录都要被迫编个假 ADR。
    $allDocText = (Get-ChildItem 'README.md', 'docs\*.md', 'CHANGELOG.md' |
        ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
    $proseOnly = [regex]::Replace($allDocText, '`[^`]*`', '')
    $refAdr = [regex]::Matches($proseOnly, 'ADR-(\d+)') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $dangling = @($refAdr | Where-Object { -not ($knownAdr -contains $_) })
    foreach ($d in $dangling) {
        $failures.Add("ADR-$d 被引用，但 decisions.md 里既没有现行小节、也不在废弃表里")
    }
    # 同一个编号同时出现在"现行"和"废弃表"里，说明编号被复用——读者无法判断哪个有效。
    foreach ($dup in @($activeAdr | Where-Object { $tableAdr -contains $_ })) {
        $failures.Add("ADR-$dup 同时出现在现行小节与废弃表里（编号复用，需要换号）")
    }
    Write-Host ("ADR：现行 {0} 条（{1}），废弃表 {2} 条，文档引用 {3} 个编号，悬空 {4} 个" -f `
            $activeAdr.Count, (($activeAdr | Sort-Object) -join '/'), $tableAdr.Count, $refAdr.Count, $dangling.Count)

    # ---------------------------------------------------------------- 5) 源码卫生：孤立的 #[test]
    # 我的编辑器习惯是"用上一行做锚点插入新测试"，而 `#[test]\n    fn x() {` 这种锚点
    # 容易把**上一个**测试的 `#[test]` 挤到注释上面去。实际已经犯过 5 次以上，
    # 每次都是 clippy 报 `duplicated attribute` 才被发现。
    # 这里做一条机械检查：`#[test]` 之后必须很快出现 `fn`（允许中间有属性行），
    # 若中间夹了文档注释，就说明属性被错位了。
    $strayTest = 0
    Get-ChildItem 'src\*.rs' | ForEach-Object {
        $lines = Get-Content $_.FullName
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '^\s*#\[test\]\s*$') { continue }
            # 往后跳过注释与其它属性，直到遇到 `fn` 或别的 `#[test]`。
            # 关键判据：**又碰到一个 #[test]** 说明这一个被错位了
            # （典型形态：`#[test]` + 文档注释 + `#[test]`，注释属于后一个测试）。
            $j = $i + 1
            $stray = $false
            while ($j -lt $lines.Count) {
                $line = $lines[$j]
                if ($line -match '^\s*#\[test\]\s*$') { $stray = $true; break }
                if ($line -match '^\s*(#\[|//)') { $j++; continue }
                break
            }
            if ($stray -or ($j -lt $lines.Count -and $lines[$j] -notmatch '^\s*(pub\s+)?fn\s')) {
                $strayTest++
                $failures.Add("$($_.Name):$($i + 1) 的 #[test] 后面没有紧接 fn（属性被错位了？）")
            }
        }
    }
    Write-Host ("源码卫生：孤立的 #[test] {0} 处" -f $strayTest)
    # ---------------------------------------------------------------- 6) 行尾统一
    # 仓库里曾经有 1 个源文件是 CRLF、其余是 LF（第 64 轮才发现）。混合行尾的实际代价：
    # 用一个"读全文 → 写回"的脚本改那个文件时，整篇行尾都会变，diff 变成几百行假改动
    # （实测 `main.rs` 出现过 685 行改动、忽略空白后只有 7 行）。
    # 现在有 `.gitattributes`（`* text=auto eol=lf`）兜底，这里再加一条即时检查。
    $crlfFiles = @()
    # **不按扩展名过滤**：第一版只查 `rs|md|json|ps1|py|yml|toml|txt`，于是
    # `.gitignore` 与 `LICENSE`（无扩展名/非常见扩展名）漏掉了——它们也是混合行尾。
    # 跳过 git 明确标为 binary 的路径即可（.gitattributes 里已标 exe/zip/png/ico）。
    $binaryExt = @('.exe', '.zip', '.png', '.ico', '.dll', '.pdb')
    $tracked = git ls-files 2>$null | Where-Object {
        $ext = [System.IO.Path]::GetExtension($_).ToLower()
        $binaryExt -notcontains $ext
    }
    # 顺手做乱码扫描：CI 里原来只查 src\*.rs + docs\*.md + README.md（19 个文件），
    # 而 CHANGELOG.md（本仓库中文最多的地方）和 packaging\*.ps1 都没查——
    # 恰恰是我改得最多的地方。既然这里已经遍历了全部文本文件，就一起查掉。
    $mojibake = @()
    foreach ($file in $tracked) {
        if (-not (Test-Path $file)) { continue }
        $bytes = [System.IO.File]::ReadAllBytes($file)
        for ($i = 1; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -eq 10 -and $bytes[$i - 1] -eq 13) {
                $crlfFiles += $file
                break
            }
        }
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        # 用 '?' * 3 而不是写字面量：否则这段检测代码自己会被扫到，
        # 报出一条"本文件含连续问号"的自我指涉误报（第一次跑就这样被自己抓了）。
        if ($text.Contains('?' * 3)) { $mojibake += $file }
    }
    foreach ($f in $mojibake) {
        $failures.Add("$f 含连续问号（疑似被编码转换吞掉的中文）")
    }
    Write-Host ("乱码：检查 {0} 个文本文件，命中 {1} 个" -f $tracked.Count, $mojibake.Count)
    foreach ($f in $crlfFiles) {
        $failures.Add("$f 含 CRLF 行尾（仓库约定是 LF）")
    }
    Write-Host ("行尾：检查 {0} 个文本文件，含 CRLF 的 {1} 个" -f $tracked.Count, $crlfFiles.Count)
    # ---------------------------------------------------------------- 结论
    Write-Host ''
    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Host "::error::$f" }
        exit 1
    }
    Write-Host '通过：CLI 参数、配置键、日志标签、ADR 引用、源码卫生、行尾与乱码六组均一致' -ForegroundColor Green
    # 显式退出码：纯 cmdlet 脚本不设 $LASTEXITCODE，调用方（CI）读不到成功信号。
    exit 0
}
finally {
    Pop-Location
}
