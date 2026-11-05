#Requires -Version 7.0
<#
.SYNOPSIS
    验证**交付物**（dist 里的 zip）：解压到独立目录后是否真的能独立用起来。

.DESCRIPTION
    为什么需要它：此前所有测试跑的都是 `target\release` 下的产物，而用户拿到的是 zip。
    两者可能不一致——打包漏了文件、哈希写错、程序依赖仓库目录里的某个东西，
    这些都不会被 `cargo test` 或协议用例发现。第 70 轮手工验证过一次，这轮固化成脚本。

    检查项：
      1. 包内文件齐全（exe / QUICKSTART / 两个 LICENSE / THIRD-PARTY-NOTICES / SHA256.txt）
      2. SHA256.txt 里声明的哈希与包内 exe 一致
      3. 解压到临时目录后能独立运行 `--version` 与 `--help`
      4. `--doctor --quick` 能跑完（退出码允许 1：那代表有 FAIL 项，不是崩溃）
      5. `--no-env` 启动后确实在监听，且 `certs/` 与 `proxy.log` 落在**包目录**（自包含）
      6. QUICKSTART 含关键指引（放可写目录、核对哈希、--doctor、--remove-ca）

.PARAMETER Zip
    指定 zip 路径；不给就用 dist 下最新的一个。

.PARAMETER SkipBuild
    跳过 make-release，直接用现有 zip。

.EXAMPLE
    ./packaging/verify-package.ps1
#>
[CmdletBinding()]
param(
    [string]$Zip = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo

$failures = [System.Collections.Generic.List[string]]::new()
$work = $null
$proxyProc = $null

try {
    if (-not $SkipBuild) {
        Write-Host '=== 打包 ===' -ForegroundColor Cyan
        & ./packaging/make-release.ps1
        if ($LASTEXITCODE -ne 0) { throw 'make-release.ps1 失败' }
    }

    if (-not $Zip) {
        $Zip = Get-ChildItem 'dist\*.zip' | Sort-Object LastWriteTime -Descending |
            Select-Object -First 1 -ExpandProperty FullName
        if (-not $Zip) { throw '找不到 dist\*.zip（先跑 packaging\make-release.ps1）' }
    }
    if (-not (Test-Path $Zip)) { throw "找不到 zip：$Zip" }

    Write-Host ''
    Write-Host "=== 验证 $([System.IO.Path]::GetFileName($Zip)) ===" -ForegroundColor Cyan

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("wg-pkg-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    Expand-Archive -Path $Zip -DestinationPath $work

    # ---- 1) 文件齐全 ----
    $expected = @(
        'winget-accel.exe', 'QUICKSTART.txt', 'SHA256.txt',
        'LICENSE', 'LICENSE-APACHE.txt', 'THIRD-PARTY-NOTICES.md'
    )
    foreach ($name in $expected) {
        if (-not (Test-Path (Join-Path $work $name))) {
            $failures.Add("包内缺少 $name")
        }
    }
    $present = @(Get-ChildItem $work -File | ForEach-Object { $_.Name })
    Write-Host ("包内文件 {0} 个：{1}" -f $present.Count, ($present -join ', '))

    # ---- 2) 哈希自洽 ----
    $shaPath = Join-Path $work 'SHA256.txt'
    if (Test-Path $shaPath) {
        $m = Select-String -Path $shaPath -Pattern 'SHA256 = ([0-9a-f]+)'
        if ($m) {
            $declared = $m.Matches.Groups[1].Value
            $actual = (Get-FileHash (Join-Path $work 'winget-accel.exe') -Algorithm SHA256).Hash.ToLower()
            Write-Host "声明 = $declared"
            Write-Host "实际 = $actual"
            if ($declared -ne $actual) {
                $failures.Add("SHA256.txt 声明与实际 exe 不一致：$declared != $actual")
            }
        }
        else {
            $failures.Add('SHA256.txt 里找不到 "SHA256 = …" 这一行')
        }
    }

    $exe = Join-Path $work 'winget-accel.exe'
    if (-not (Test-Path $exe)) {
        throw '包内没有 winget-accel.exe，后面的检查无法继续'
    }

    # ---- 3) 独立运行 --version / --help ----
    $ver = (& $exe --version 2>&1) -join ' '
    Write-Host "版本输出：$ver"
    if ($ver -notmatch 'winget-accel \d+\.\d+\.\d+') {
        $failures.Add("--version 输出不符合预期：$ver")
    }
    $help = (& $exe --help 2>&1) -join "`n"
    foreach ($flag in '--config', '--doctor', '--no-env', '--remove-ca') {
        if ($help -notmatch [regex]::Escape($flag)) {
            $failures.Add("--help 里没有列出 $flag")
        }
    }

    # ---- 4) --doctor --quick 能跑完 ----
    # 退出码 1 是正常的（有 FAIL 项，比如还没生成 CA），只要不是崩溃/无输出即可。
    $docOut = & $exe --doctor --quick 2>&1
    $docText = $docOut -join "`n"
    if ($docText -notmatch 'winget-accel \d+\.\d+\.\d+') {
        $failures.Add('--doctor 没有打印抬头（可能崩溃了）')
    }
    if ($docText -notmatch 'chain') {
        $failures.Add('--doctor 输出里没有 chain 检查项')
    }
    Write-Host ("--doctor --quick 已跑完（退出码 {0}，行数 {1}）" -f $LASTEXITCODE, ($docOut | Measure-Object).Count)

    # ---- 5) --no-env 启动：监听 + 自包含 ----
    # 先确认 8443 空闲：CI runner 上一般没事，但若被占用，程序会正常报"端口被占用"退出，
    # 那**不是交付物的问题**。这种情况跳过该项并说明，别把环境问题算到包上。
    $portFree = $false
    try {
        $probe = [System.Net.Sockets.TcpClient]::new()
        $probe.Connect('127.0.0.1', 8443)
        $probe.Close()
    }
    catch {
        $portFree = $true
    }
    if (-not $portFree) {
        Write-Host '8443 已被占用：跳过"启动并监听"这一项（环境原因，不是包的问题）' -ForegroundColor Yellow
    }
    else {
    $proxyProc = Start-Process $exe -ArgumentList '--no-env' -PassThru -WindowStyle Hidden -WorkingDirectory $work
    $deadline = (Get-Date).AddSeconds(12)
    $listening = $false
    while ((Get-Date) -lt $deadline) {
        if ($proxyProc.HasExited) { break }
        try {
            $t = [System.Net.Sockets.TcpClient]::new()
            $t.Connect('127.0.0.1', 8443)
            $t.Close()
            $listening = $true
            break
        }
        catch { Start-Sleep -Milliseconds 300 }
    }
    if ($proxyProc.HasExited) {
        $failures.Add("--no-env 启动后进程退出（退出码 $($proxyProc.ExitCode)），8443 可能被占用")
    }
    elseif (-not $listening) {
        $failures.Add('12 秒内没有在 8443 上监听')
    }
    else {
        Write-Host '8443 已监听'
        # 自包含：certs/ 与 proxy.log 必须落在包目录，而不是仓库
        foreach ($artifact in 'certs', 'proxy.log') {
            if (Test-Path (Join-Path $work $artifact)) {
                Write-Host "自包含检查：包目录下出现了 $artifact"
            }
            else {
                $failures.Add("运行后包目录下没有 $artifact（说明它写到了别处）")
            }
        }
    }
    if ($null -ne $proxyProc -and -not $proxyProc.HasExited) {
        Stop-Process -Id $proxyProc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
    }
    $proxyProc = $null
    }  # end: 8443 空闲时才做启动验证

    # ---- 6) QUICKSTART 的关键指引 ----
    $qsPath = Join-Path $work 'QUICKSTART.txt'
    if (Test-Path $qsPath) {
        $qs = Get-Content $qsPath -Raw
        $mustHave = [ordered]@{
            '--doctor'            = '让用户知道有体检命令'
            '--remove-ca'         = '让用户知道怎么卸证书'
            'Program Files'       = '说明不要放在不可写目录'
            'SHA256'              = '说明怎么核对包'
        }
        foreach ($needle in $mustHave.Keys) {
            if ($qs -notmatch [regex]::Escape($needle)) {
                $failures.Add("QUICKSTART 缺少「$needle」（$($mustHave[$needle])）")
            }
        }
        Write-Host ("QUICKSTART {0} B，已检查 {1} 项关键指引" -f (Get-Item $qsPath).Length, $mustHave.Count)
    }
}
catch {
    $failures.Add($_.Exception.Message)
}
finally {
    if ($null -ne $proxyProc -and -not $proxyProc.HasExited) {
        Stop-Process -Id $proxyProc.Id -Force -ErrorAction SilentlyContinue
    }
    # 只结束本脚本持有的子进程，避免影响用户正在运行的实例。
    if ($work) {
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        $cleanup = [System.IO.Path]::GetFullPath($work)
        if ($cleanup.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            [System.IO.Path]::GetFileName($cleanup) -match '^wg-pkg-[0-9a-f]{8}$') {
            Remove-Item -LiteralPath $cleanup -Recurse -Force -ErrorAction SilentlyContinue
        }
        else { $failures.Add("拒绝清理非预期临时目录：$cleanup") }
    }
    Write-Host ''
    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Host "::error::$f" }
        Pop-Location
        exit 1
    }
    Write-Host '通过：交付物可独立解压运行，哈希自洽，运行产物自包含' -ForegroundColor Green
    Pop-Location
    exit 0
}
