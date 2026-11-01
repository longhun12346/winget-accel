$ErrorActionPreference = 'Continue'
$dir = 'D:\workspace\github\winget-accel\prototype'
$py = "$dir\.venv\Scripts\python.exe"
$log = "$dir\proxy.log"
$out = "$env:TEMP\proto-dl"
Remove-Item $log -ErrorAction SilentlyContinue
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out | Out-Null

$proc = Start-Process $py -ArgumentList @('wgaccel.py','--port','8443','--cert-dir','certs','--log','proxy.log') `
    -WorkingDirectory $dir -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$dir\proxy.stdout.txt" -RedirectStandardError "$dir\proxy.stderr.txt"
Start-Sleep -Seconds 3

try {
    Write-Output "=== 1) 健康检查 ==="
    curl.exe -s --max-time 5 "http://127.0.0.1:8443/health" ; Write-Output ""

    Write-Output "=== 2) PAC 内容 ==="
    curl.exe -s --max-time 5 "http://127.0.0.1:8443/proxy.pac"

    $url = 'https://github.com/sharkdp/fd/releases/download/v10.5.0/fd-v10.5.0-x86_64-pc-windows-msvc.zip'

    Write-Output "=== 3) 直连（对照，预期失败）==="
    curl.exe -s -o NUL --max-time 12 -w "   direct: http=%{http_code} size=%{size_download} t=%{time_total}s`n" $url

    Write-Output "=== 4) 经代理 + 信任原型 CA（白名单直改写）==="
    curl.exe -s --max-time 60 --ssl-no-revoke --cacert "$dir\certs\ca-cert.pem" -x "http://127.0.0.1:8443" `
        -o "$out\fd.zip" -w "   proxy : http=%{http_code} size=%{size_download} t=%{time_total}s speed=%{speed_download}B/s`n" $url

    Write-Output "=== 5) 非白名单 host（应原样隧道，不改写）==="
    curl.exe -s -o NUL --max-time 20 --ssl-no-revoke --cacert "$dir\certs\ca-cert.pem" -x "http://127.0.0.1:8443" `
        -w "   api.github: http=%{http_code} t=%{time_total}s`n" 'https://api.github.com/zen'

    Write-Output "=== 6) 文件校验 ==="
    if (Test-Path "$out\fd.zip") {
        $f = Get-Item "$out\fd.zip"
        "   大小: {0:N0} B ({1:N2} MB)" -f $f.Length, ($f.Length/1MB)
        "   SHA256: " + (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    }

    Write-Output "=== 7) 代理日志 ==="
    if (Test-Path $log) { Get-Content $log | Select-Object -Last 25 | ForEach-Object { "   $_" } }
}
finally {
    try { $proc.Kill() } catch {}
    Write-Output "[cleanup] 代理进程已停止"
}

