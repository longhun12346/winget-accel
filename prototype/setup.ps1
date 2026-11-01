param(
    [int]$Port = 8443,
    [string]$Accel = 'gh-proxy.com',
    [int]$CaTimeoutSeconds = 45
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $here '.venv\Scripts\python.exe'
$caFile = Join-Path $here 'certs\ca-cert.pem'
$stateFile = Join-Path $here 'state.json'
$reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

if (-not (Test-Path $python)) {
    throw "缺少虚拟环境。先执行：uv venv --python 3.12 .venv; uv pip install --python .venv\Scripts\python.exe cryptography"
}

function Get-CaThumbprint([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path).Thumbprint
}

# ---------------------------------------------------------------- 1) 启动代理
$existing = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*wgaccel.py*" }
if ($existing) {
    Write-Host "[1/5] 代理已在运行 (PID $(($existing.ProcessId) -join ','))，复用"
    $proxyPid = ($existing.ProcessId | Select-Object -First 1)
} else {
    Write-Host "[1/5] 启动原型代理 :$Port (accel=$Accel)"
    $proc = Start-Process $python -ArgumentList @('wgaccel.py', '--port', "$Port", '--accel', $Accel,
        '--cert-dir', 'certs', '--log', 'proxy.log') -WorkingDirectory $here -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $here 'proxy.stdout.txt') -RedirectStandardError (Join-Path $here 'proxy.stderr.txt')
    $proxyPid = $proc.Id
    Start-Sleep -Seconds 3
}

# ---------------------------------------------------------------- 2) 健康检查
$health = $null
for ($i = 0; $i -lt 10; $i++) {
    try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3; break } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $health) { throw "代理未就绪（127.0.0.1:$Port/health 不可达）。看 proxy.stderr.txt" }
Write-Host "[2/5] 代理健康: $($health | ConvertTo-Json -Compress)"

# ---------------------------------------------------------------- 3) 装 CA
$thumb = Get-CaThumbprint $caFile
if (-not $thumb) { throw "找不到 $caFile —— 代理首次启动时会自动生成" }

$already = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb }
if ($already) {
    Write-Host "[3/5] CA 已在用户根存储中 ($thumb)，跳过"
} else {
    Write-Host "[3/5] 安装 CA 到 CurrentUser\Root —— 会弹出 Windows 安全警告，请点『是』"
    # 用子进程 + 超时：根证书安装需要一次交互确认，无 UI 会话下 API 会阻塞而不是报错
    $tmp = Join-Path $env:TEMP 'wgaccel-ca-import.ps1'
    $outFile = Join-Path $env:TEMP 'wgaccel-ca-out.txt'
    $errFile = Join-Path $env:TEMP 'wgaccel-ca-err.txt'
    @"
try {
    Import-Certificate -FilePath '$caFile' -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    Write-Output 'OK'
} catch {
    Write-Output ('FAIL ' + `$_.Exception.Message)
}
"@ | Set-Content $tmp -Encoding utf8

    $child = Start-Process pwsh -ArgumentList @('-NoProfile', '-File', $tmp) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $finished = $child.WaitForExit($CaTimeoutSeconds * 1000)
    if (-not $finished) {
        try { $child.Kill() } catch { }
        Write-Host ""
        Write-Host "!! CA 安装超时（${CaTimeoutSeconds}s）：系统在等待一个安全警告的确认，但看不到弹窗。" -ForegroundColor Yellow
        Write-Host "   请在一个可见的终端里手动执行一次：" -ForegroundColor Yellow
        Write-Host "     certutil -user -addstore Root `"$caFile`"" -ForegroundColor Yellow
        Write-Host "   然后重新运行 .\setup.ps1（已装好会跳过）" -ForegroundColor Yellow
        exit 1
    }
    $result = ((Get-Content $outFile -Raw -ErrorAction SilentlyContinue) -replace "`r?`n", ' ').Trim()
    $nowTrusted = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb }
    if (-not $nowTrusted) {
        Write-Host "!! CA 安装失败: $result" -ForegroundColor Red
        Write-Host "   手动执行：certutil -user -addstore Root `"$caFile`"" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "      CA 已导入 ($thumb)"
}

# ---------------------------------------------------------------- 4) 记录原状态
$orig = Get-ItemProperty $reg
$prior = if ($orig.AutoConfigURL) { $orig.AutoConfigURL } else { '' }
[pscustomobject]@{
    autoConfigUrlPrior = $prior
    caThumbprint       = $thumb
    proxyPid           = $proxyPid
    port               = $Port
} | ConvertTo-Json | Set-Content $stateFile -Encoding utf8
Write-Host "[4/5] 原 AutoConfigURL = '$prior'（已记入 state.json）"

# ---------------------------------------------------------------- 5) 指向 PAC
Set-ItemProperty $reg -Name AutoConfigURL -Value "http://127.0.0.1:$Port/proxy.pac" -Type String
Set-ItemProperty $reg -Name ProxyEnable -Value 0 -Type DWord
Write-Host "[5/5] AutoConfigURL = http://127.0.0.1:$Port/proxy.pac"

Write-Host ""
Write-Host "就绪。PAC 只把这 4 个 host 指向代理，其余全部 DIRECT：" -ForegroundColor Green
Write-Host "  github.com / objects.githubusercontent.com / codeload.github.com / release-assets.githubusercontent.com"
Write-Host ""
Write-Host "试一下： winget download --id sharkdp.fd -d `$env:TEMP\fdtest --accept-source-agreements"
Write-Host "看日志： Get-Content '$here\proxy.log' -Tail 20"
Write-Host "还原：   .\teardown.ps1"
