$ErrorActionPreference = 'Continue'
$dir = 'D:\workspace\github\winget-accel\prototype'
$py = "$dir\.venv\Scripts\python.exe"
$ca = "$dir\certs\ca-cert.pem"
$reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$settingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json"
$log = "$dir\proxy-pac.log"
$pkg = 'junegunn.fzf'
$dl = "$env:TEMP\wgaccel-pac-test"

$orig = Get-ItemProperty $reg
$origPAC = $orig.AutoConfigURL
$origEnable = $orig.ProxyEnable
$origSettings = if (Test-Path $settingsPath) { Get-Content $settingsPath -Raw } else { $null }
$thumb = $null
$proc = $null

Write-Output "  实验前: ProxyEnable=$origEnable AutoConfigURL='$origPAC'"

try {
    Write-Output "`n=== 1) 启动原型（8443）==="
    Remove-Item $log -ErrorAction SilentlyContinue
    $proc = Start-Process $py -ArgumentList @('wgaccel.py','--port','8443','--cert-dir','certs','--log','proxy-pac.log') `
        -WorkingDirectory $dir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput "$dir\pac.out" -RedirectStandardError "$dir\pac.err"
    Start-Sleep -Seconds 3

    Write-Output "=== 2) 装 CA 到用户根存储（免管理员）==="
    $imported = Import-Certificate -FilePath $ca -CertStoreLocation Cert:\CurrentUser\Root
    $thumb = $imported.Thumbprint
    Write-Output "   thumbprint=$thumb"

    Write-Output "=== 3) 配置 PAC（只对 4 个 host 走代理，其余 DIRECT）==="
    Set-ItemProperty $reg -Name AutoConfigURL -Value 'http://127.0.0.1:8443/proxy.pac' -Type String
    Set-ItemProperty $reg -Name ProxyEnable -Value 0 -Type DWord
    Write-Output "   AutoConfigURL=http://127.0.0.1:8443/proxy.pac"

    Write-Output "`n=== 4) winget download（包: $pkg，未缓存过）==="
    Remove-Item $dl -Recurse -Force -ErrorAction SilentlyContinue
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process winget -ArgumentList @('download','--id',$pkg,'-d',$dl,
        '--accept-source-agreements','--disable-interactivity') -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput "$dir\wg-pac.out.txt" -RedirectStandardError "$dir\wg-pac.err.txt"
    $exited = $p.WaitForExit(100000)
    $sw.Stop()
    if (-not $exited) { try { $p.Kill() } catch {}; Write-Output "   超时 $($sw.Elapsed.TotalSeconds.ToString('0.0'))s 已终止" }
    else { Write-Output "   退出码 $($p.ExitCode) 用时 $($sw.Elapsed.TotalSeconds.ToString('0.0'))s" }

    $out = if (Test-Path "$dir\wg-pac.out.txt") { Get-Content "$dir\wg-pac.out.txt" -Raw } else { '' }
    if ($out) { Write-Output "   [winget 输出]"; ($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 8) | ForEach-Object { "      $_" } }

    Write-Output "`n=== 5) 下载结果 ==="
    $files = Get-ChildItem $dl -Recurse -File -ErrorAction SilentlyContinue
    if ($files) { $files | ForEach-Object { "   {0}  {1:N0} B" -f $_.Name, $_.Length } } else { "   无文件" }

    Write-Output "`n=== 6) 代理日志（关注 PAC-SERVED / REWRITE / TUNNEL）==="
    if (Test-Path $log) { Get-Content $log | Where-Object { $_ -notmatch 'CA thumbprint|改写范围' } | Select-Object -Last 20 | ForEach-Object { "   $_" } }
}
finally {
    Write-Output "`n=== 清理 ==="
    if ($null -ne $origPAC -and $origPAC -ne '') { Set-ItemProperty $reg -Name AutoConfigURL -Value $origPAC -Type String }
    else { Remove-ItemProperty $reg -Name AutoConfigURL -ErrorAction SilentlyContinue }
    Set-ItemProperty $reg -Name ProxyEnable -Value $origEnable -Type DWord
    if ($thumb) { certutil -user -delstore Root $thumb | Out-Null }
    if ($null -ne $origSettings) { Set-Content $settingsPath $origSettings -Encoding utf8 -NoNewline }
    if ($proc) { try { $proc.Kill() } catch {} }
    Remove-Item $dl -Recurse -Force -ErrorAction SilentlyContinue
    $now = Get-ItemProperty $reg
    $caStill = if ($thumb) { [bool](Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb }) } else { $false }
    Write-Output "   ProxyEnable=$($now.ProxyEnable) AutoConfigURL='$($now.AutoConfigURL)' CA残留=$caStill 进程=$([bool](Get-Process -Id $proc.Id -ErrorAction SilentlyContinue))"
}
