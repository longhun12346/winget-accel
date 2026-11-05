param([int]$Port = 0)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateFile = Join-Path $here 'state.json'
$caFile = Join-Path $here 'certs\ca-cert.pem'
$reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$problems = 0

$state = $null
if (Test-Path $stateFile) {
    try { $state = Get-Content $stateFile -Raw | ConvertFrom-Json } catch { $state = $null }
}
if ($Port -le 0) { $Port = if ($state -and $state.port) { $state.port } else { 8443 } }

# 1) 还原 AutoConfigURL（只在确实指向我们时才动）
$cur = (Get-ItemProperty $reg).AutoConfigURL
if ($cur -like "*127.0.0.1:$Port*") {
    $prior = if ($state) { $state.autoConfigUrlPrior } else { '' }
    if ($prior) { Set-ItemProperty $reg -Name AutoConfigURL -Value $prior -Type String }
    else { Remove-ItemProperty $reg -Name AutoConfigURL -ErrorAction SilentlyContinue }
    Write-Host "[1/4] AutoConfigURL 已还原为 '$prior'"
} else {
    Write-Host "[1/4] AutoConfigURL 未指向本原型（'$cur'），跳过"
}

# 2) 移除 CA
$thumbs = @()
if ($state -and $state.caThumbprint) { $thumbs += $state.caThumbprint }
$fromFile = $null
if (Test-Path $caFile) {
    $fromFile = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($caFile).Thumbprint
    if ($fromFile) { $thumbs += $fromFile }
}
# 兜底：按主题名找
$bySubject = Get-ChildItem Cert:\CurrentUser\Root |
    Where-Object { $_.Subject -like '*winget-accel prototype CA*' } |
    Select-Object -ExpandProperty Thumbprint
$thumbs += $bySubject
$thumbs = $thumbs | Where-Object { $_ } | Select-Object -Unique

if (-not $thumbs) {
    Write-Host "[2/4] 用户根存储中未发现原型 CA"
} else {
    foreach ($t in $thumbs) {
        certutil -user -delstore Root $t | Out-Null
        $still = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $t }
        if ($still) { Write-Host "[2/4] !! 删除失败: $t"; $problems++ }
        else { Write-Host "[2/4] 已移除 CA $t" }
    }
}

# 3) 停止代理
$stopped = 0
$procs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*wgaccel.py*" }
foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $stopped++ } catch { }
}
if ($stopped -eq 0) { Write-Host "[3/4] 未发现运行中的代理进程" }
else { Write-Host "[3/4] 已停止 $stopped 个代理进程" }

# 4) 收尾校验
if (Test-Path $stateFile) { Remove-Item $stateFile -Force }
$now = Get-ItemProperty $reg
$leftCa = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like '*winget-accel prototype*' }
$leftProc = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*wgaccel.py*" }
Write-Host "[4/4] 状态: ProxyEnable=$($now.ProxyEnable) AutoConfigURL='$($now.AutoConfigURL)' CA残留=$([bool]$leftCa) 进程残留=$([bool]$leftProc)"

if ($leftCa -or $leftProc -or $problems -gt 0) {
    Write-Host "!! 仍有残留，请手动检查" -ForegroundColor Yellow
    exit 1
}
Write-Host "已完全还原。" -ForegroundColor Green
