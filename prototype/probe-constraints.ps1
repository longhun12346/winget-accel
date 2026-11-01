$ErrorActionPreference = 'Continue'
$dir = 'D:\workspace\github\winget-accel\prototype'
$py = "$dir\.venv\Scripts\python.exe"
$ca = "$dir\certs\ca-cert.pem"

function Start-Proxy($port, $extra) {
    $a = @('wgaccel.py','--port',"$port",'--cert-dir','certs','--log',"probe-$port.log")
    if ($extra) { $a += @('--mitm-extra', $extra) }
    return Start-Process $py -ArgumentList $a -WorkingDirectory $dir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput "$dir\p-$port.out" -RedirectStandardError "$dir\p-$port.err"
}

Write-Output "=== A) 隧道路径（非白名单 host，用系统信任库，不加 --cacert）==="
$p1 = Start-Proxy 8445 $null
Start-Sleep -Seconds 3
curl.exe -s --max-time 20 -x "http://127.0.0.1:8445" -w "   api.github.com via tunnel: http=%{http_code} t=%{time_total}s`n" 'https://api.github.com/zen'
try { $p1.Kill() } catch {}
Start-Sleep -Seconds 1

Write-Output "`n=== B) Name Constraints 是否被强制校验（H1）==="
Write-Output "   让代理拦截 example.com（不在许可集内），预期客户端应拒绝"
$p2 = Start-Proxy 8446 'example.com'
Start-Sleep -Seconds 3
Write-Output "   B1) schannel/curl:"
curl.exe -sS --ssl-no-revoke --max-time 20 --cacert $ca -x "http://127.0.0.1:8446" -o NUL -w "        http=%{http_code} t=%{time_total}s`n" 'https://example.com/' 2>&1 | Select-Object -First 6 | ForEach-Object { "        $_" }
Write-Output "   B2) .NET / 系统存储（先把 CA 临时装入用户根存储）:"
$imported = Import-Certificate -FilePath $ca -CertStoreLocation Cert:\CurrentUser\Root
$thumb = $imported.Thumbprint
try {
    try {
        $r = Invoke-WebRequest -Uri 'https://example.com/' -Proxy 'http://127.0.0.1:8446' -TimeoutSec 20 -UseBasicParsing
        Write-Output "        !! 竟然成功: status=$($r.StatusCode) —— Name Constraints 未被强制"
    } catch {
        Write-Output "        被拒绝: $($_.Exception.Message)"
    }
    Write-Output "   B3) 对照：同一 CA 拦截 github.com（在许可集内）应被接受"
    try {
        $r2 = Invoke-WebRequest -Uri 'https://github.com/' -Proxy 'http://127.0.0.1:8446' -TimeoutSec 25 -UseBasicParsing
        Write-Output "        接受: status=$($r2.StatusCode)"
    } catch {
        Write-Output "        被拒绝（不符合预期）: $($_.Exception.Message)"
    }
}
finally {
    certutil -user -delstore Root $thumb | Out-Null
    $still = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb }
    Write-Output "   [cleanup] CA 已移除: $(-not [bool]$still)"
    try { $p2.Kill() } catch {}
}

Write-Output "`n=== 日志 ==="
foreach ($f in @("$dir\probe-8445.log","$dir\probe-8446.log")) {
    if (Test-Path $f) { Get-Content $f | Where-Object { $_ -notmatch 'CA thumbprint|PAC  =|ACCEL=|改写范围|LISTEN' } | Select-Object -Last 8 | ForEach-Object { "   $_" } }
}
foreach ($f in @("$dir\p-8445.err","$dir\p-8446.err")) { if ((Test-Path $f) -and (Get-Item $f).Length -gt 0) { Write-Output "--- $f ---"; Get-Content $f | Select-Object -Last 12 | ForEach-Object { "   $_" } } }
