#Requires -Version 7.0
<#
.SYNOPSIS
    本地一键复跑：格式 / clippy / Rust 测试 / 文档一致性 / 可复现构建。

.DESCRIPTION
    为什么需要它：这些检查我每轮都手敲一遍，敲漏一项就可能放过问题
    （实际发生过：只跑 cargo test 不跑协议用例，差点提交一个"整包当分片"的静默错误）。
    把它们固化成一条命令，顺序与 CI 一致，任何一项失败就停。

    有意**不**包含的（避免给人"跑过了就万事大吉"的错觉）：
    - 真实公共加速服务：依赖第三方服务存活，适合手动排障
    - 真实 `winget` 端到端：需要真的装 CA、改系统 PAC
    - 长跑压测：用 `-Soak` 显式开启（默认不跑，几十秒起）

.PARAMETER Soak
    额外跑一次长跑压测（`soak.ps1`，默认 100 次请求）。

.PARAMETER SkipRepro
    跳过可复现构建检查（它要重新编译一次 release，约 20 秒）。

.PARAMETER NoEnv
    额外验证 `--no-env` 全程不改系统设置（需要真实网络与可用加速器，约 5 秒）。

.PARAMETER Package
    额外验证**交付物**：`dist` 里的 zip 解压后能否独立运行、哈希是否自洽、运行产物是否
    落在包目录（约 20 秒，含重新打包）。

.PARAMETER Offline
    使用已缓存的 Cargo 依赖，跳过联网获取。其余构建和测试始终离线执行。

.EXAMPLE
    ./packaging/verify.ps1
    ./packaging/verify.ps1 -Soak
    ./packaging/verify.ps1 -Package
#>
[CmdletBinding()]
param(
    [switch]$Soak,
    [switch]$SkipRepro,
    [switch]$NoEnv,
    [switch]$Package,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo

$results = [System.Collections.Generic.List[object]]::new()
$failed = $false

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    Write-Host ''
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
        $sw.Stop()
        $results.Add([pscustomobject]@{ Step = $Name; Ok = $true; Secs = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
    }
    catch {
        $sw.Stop()
        $results.Add([pscustomobject]@{ Step = $Name; Ok = $false; Secs = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
        Write-Host "::error::$Name 失败：$($_.Exception.Message)" -ForegroundColor Red
        $script:failed = $true
        throw
    }
}

try {
    # 先检查有没有残留进程锁着 exe。
    # 踩过：cargo build 报 "拒绝访问 (os error 5)"，其实是上一轮的代理还在跑，
    # 而那个错误看起来像权限问题，容易往错方向查。
    $running = Get-Process winget-accel -ErrorAction SilentlyContinue
    if ($running) {
        $ids = ($running | ForEach-Object { $_.Id }) -join ', '
        throw "有 winget-accel 进程还在运行（PID $ids），会锁住 target\release 下的 exe 导致构建失败。请先停掉它们。"
    }

    Invoke-Step 'cargo fmt --check' {
        cargo fmt --all -- --check
        if ($LASTEXITCODE -ne 0) { throw "格式不一致（执行 cargo fmt --all）" }
    }

    if (-not $Offline) {
        Invoke-Step '获取锁定依赖' {
            cargo fetch --locked
            if ($LASTEXITCODE -ne 0) { throw '依赖获取失败；已有缓存可用 -Offline 跳过' }
        }
    }

    Invoke-Step 'cargo clippy -D warnings' {
        cargo clippy --all-targets --offline -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'clippy 有警告' }
    }

    Invoke-Step 'Rust 单元测试' {
        $out = cargo test --bin winget-accel --offline 2>&1
        $out | Select-String -Pattern 'test result' | ForEach-Object { Write-Host $_.Line }
        if ($LASTEXITCODE -ne 0) { throw '单元测试失败' }
    }

    Invoke-Step '文档与代码一致性' {
        & ./packaging/check-docs-sync.ps1
        if ($LASTEXITCODE -ne 0) { throw '文档与代码不一致' }
    }

    Invoke-Step '候选分类回归（离线）' {
        & ./packaging/test-candidate-catalog.ps1
        if ($LASTEXITCODE -ne 0) { throw '候选分类回归失败' }
    }

    Invoke-Step '构建 release' {
        cargo build --release --offline
        if ($LASTEXITCODE -ne 0) { throw 'release 构建失败' }

        # 构建"成功"不等于"重编了"：cargo 按 mtime 判断，而用 Copy-Item 从备份恢复源文件会
        # 保留**旧的** mtime，于是它认为没变化、根本不编译。实测踩过：这样跑出来的
        # exe 还是旧代码，而可复现性检查会报"两次构建不一致"（它其实抓到了二进制与源码不符，
        # 但报错文字会把人引向"构建不可复现"这个错误方向）。
        $exeItem = Get-Item 'target\release\winget-accel.exe'
        $newer = Get-ChildItem src -Recurse -File -Filter '*.rs' |
            Where-Object { $_.LastWriteTime -gt $exeItem.LastWriteTime }
        if ($newer) {
            $names = ($newer | ForEach-Object { $_.Name }) -join ', '
            throw "有源文件比 exe 新（$names）：cargo 可能没重编（常见原因是用 Copy-Item 恢复了旧 mtime 的备份）。先 touch 一下再重跑。"
        }
    }

    Invoke-Step 'Rust 协议集成测试（离线）' {
        cargo test --test protocol --offline -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { throw '协议用例失败' }
    }

    if (-not $SkipRepro) {
        Invoke-Step '可复现构建' {
            $exe = 'target\release\winget-accel.exe'
            $h1 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
            # 改 mtime 让指纹失效：不这么做 cargo 会认为已是最新，
            # 比出来的"相同"毫无意义（这个坑踩过一次）。
            # 关闭 ANSI 颜色，避免 `Compiling` 与包名之间的转义码影响匹配。
            $env:CARGO_TERM_COLOR = 'never'
            (Get-Item src\main.rs).LastWriteTime = (Get-Date).AddMinutes(2)
            $out = cargo build --release --offline 2>&1
            if (-not ($out | Select-String -Pattern 'Compiling winget-accel')) {
                throw '没有真正重编（cargo 认为已是最新），本次比较无效'
            }
            $h2 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
            Write-Host "first  = $h1"
            Write-Host "second = $h2"
            if ($h1 -ne $h2) { throw "构建不可复现：$h1 != $h2" }
        }
    }

    if ($Soak) {
        Invoke-Step '长跑压测（100 次请求）' {
            & ./packaging/soak.ps1 -Requests 100
            if ($LASTEXITCODE -ne 0) { throw '压测未通过' }
        }
    }

    # 验证**交付物**（dist 里的 zip）：解压后能否独立运行。默认不跑（要打包，约 20 秒）。
    if ($Package) {
        Invoke-Step '交付物（zip 解压后可独立运行）' {
            & ./packaging/verify-package.ps1
            if ($LASTEXITCODE -ne 0) { throw '交付物验证失败' }
        }
    }

    # 需要真实网络与可用加速器，所以默认不跑。
    if ($NoEnv) {
        Invoke-Step '--no-env 不触碰系统设置' {
            & ./packaging/verify-no-env.ps1
            if ($LASTEXITCODE -ne 0) { throw '--no-env 改动了系统设置或链路没跑通' }
        }
    }
}
catch {
    # Invoke-Step 内部已经记录了失败并打印过 ::error::；但**守卫**（例如残留进程检查）
    # 是在 Invoke-Step 之外抛的，没有记录也没打印。这里统一兜住：
    # 不设 $failed 的话，finally 会看到"0/0 项通过"并报告"全部通过"——把真失败掩盖掉。
    # （第一版就是这样：有残留进程时脚本 exit 0，实测发现。）
    $script:failed = $true
    if ($results.Count -eq 0) {
        Write-Host "::error::$($_.Exception.Message)" -ForegroundColor Red
    }
}
finally {
    Write-Host ''
    Write-Host '=== 汇总 ===' -ForegroundColor Cyan
    $results | Format-Table -AutoSize | Out-String | Write-Host
    $okCount = @($results | Where-Object { $_.Ok }).Count
    Write-Host ("{0} / {1} 项通过" -f $okCount, @($results).Count)
    if ($failed -or $okCount -ne $results.Count) {
        Write-Host '未全部通过 —— 先修上面的 ::error:: 再提交' -ForegroundColor Red
        Pop-Location
        exit 1
    }
    Write-Host '全部通过' -ForegroundColor Green
    Write-Host ''
    Write-Host '注意：这里不包含真实公共加速服务与真实 winget 端到端——' -ForegroundColor Yellow
    Write-Host '      前者依赖第三方服务存活，后者需要真的装 CA 并改系统 PAC。' -ForegroundColor Yellow
    Pop-Location
    exit 0
}
