# 代理层架构验证（2026-11-01，第三次实测）

> 目的：验证"**不实现 REST 源，只在下载层做代理改写**"是否可行（即 `decisions.md` ADR-001 的替代方案）。
> 结论：**可行，且已端到端跑通**。本文只记录事实与证据；架构是否切换见下方"待确认"。

## 0. 一句话结论

用 mitmproxy 做本地代理，把白名单 host 的请求改写到 `gh-proxy.com`，
**winget 在默认设置下完成了下载并通过了官方哈希校验**——不需要清单、不需要同步、不需要 `source add`、不需要管理员。

## 1. 实验环境与安全声明

| 项 | 值 |
|---|---|
| 时间 | 2026-11-01 11:26–11:40（Asia/Shanghai） |
| 工具 | `mitmproxy`（经 `uv tool install` 安装，pypi 走清华镜像） |
| 测试包 | `sharkdp.fd`（此前**未**下载过，避免 DO 缓存污染） |
| 代理 | `127.0.0.1:8899`（mitmdump，含改写插件） |
| 代理配置 | `HKCU\...\Internet Settings`（**用户级，无需管理员**） |
| CA 部署 | `Cert:\CurrentUser\Root`（**用户级根存储，无需管理员**） |

**实验后已全部还原**：

- CA 已从 `CurrentUser\Root` 删除（`certutil -user -delstore Root`；`Remove-Item` 会因"用户根存储不允许 UI"失败，须用 certutil）
- `ProxyEnable` 已回 `0`，`ProxyServer` / `AutoConfigURL` 已清空
- `settings.json` 已还原为实验前内容（`network.downloader = "do"`）
- mitmdump 进程已终止，临时下载目录已删除

## 2. 结果

| 轮次 | 下载器 | 结果 |
|---|---|---|
| R1 | **默认（`do`）** | ✅ **成功**，34.6 s，退出码 0；下载 `fd_10.5.0_X64_portable_en-US.zip`(1.46 MB) + VC++ Redist(17.86 MB)；winget 报告**"已成功验证安装程序哈希"** |
| R2 | `wininet` | ⏱ 55 s 超时；卡在 `download.visualstudio.microsoft.com`（**非白名单，直通未改写**），与改写逻辑无关 |

### 2.1 关键日志证据

```
REWRITE https://github.com/sharkdp/fd/releases/download/v10.5.0/fd-v10.5.0-x86_64-pc-windows-msvc.zip
     -> https://gh-proxy.com/https://github.com/sharkdp/fd/releases/download/v10.5.0/fd-v10.5.0-x86_64-pc-windows-msvc.zip
RESP 206 ... len=486487
RESP 206 ... len=1048576
RESP 206 ... len=1048576
[winget] 已成功验证安装程序哈希
[winget] 已下载安装程序: ...\fd_10.5.0_X64_portable_en-US.zip
```

三点值得注意：

1. **`206` 且分成 486487 / 1048576 多段** —— winget 用的是 Range 分片请求，加速器（gh-proxy）正确返回 206 与 `Content-Range`，分片语义未被破坏
2. **`download.visualstudio.microsoft.com` 的 17.86 MB 直通下载成功** —— 非白名单 host 原样透传，未被误伤
3. **哈希校验通过** —— 字节经第三方加速器中转后，仍与官方清单的 `InstallerSha256` 一致。**完整性未因 MITM 下降**

## 3. 四个问题的答案

| 问题 | 结论 | 证据 |
|---|---|---|
| U1 下载流量是否走代理 | ✅ **走**（默认下载器即走，无需改设置） | R1 的 REWRITE + RESP 206 全链路 |
| U2 `CurrentUser\Root` 是否被接受 | ✅ **被接受**（无需管理员） | winget 完成 TLS 握手并成功下载，未报证书错误 |
| U3 DO 是否绕过代理 | ❌ **未绕过**（`downloader=do` 下仍走代理） | R1 在 `do` 配置下完成改写下载 |
| U4 是否需要清单/源 | ❌ **不需要** | 全程未注册任何源，manifest 仍来自官方 `winget` 源 |

### 3.1 一个反证：curl 穿代理返回 `000`

实验里 `curl -x http://127.0.0.1:8899 https://api.github.com` 返回 `000`。
原因不是代理坏了，而是 **curl 使用自带的 CA bundle，不读 Windows 证书存储**，
所以拒绝 mitmproxy 的证书。这恰好反证：**winget 走的是系统证书存储**，故 U2 成立于 winget 自身。

## 4. 与"本地 REST 源"方案的对比

| | A：REST 源（ADR-001） | **B：代理层改写（本文验证）** |
|---|---|---|
| 清单同步（1 GB） | 必需 | **不需要** |
| schema 投影 / 1.10.0 映射表 | 必需 | **不需要** |
| `manifestSearch` 语义（7×9 匹配） | 必需 | **不需要** |
| 协议端点 | 3 个 | **0 个** |
| 与官方源共存/重复 id 问题 | 存在 | **不存在**（不改源） |
| 覆盖范围 | 受同步范围限制 | **自动覆盖所有 GitHub 托管包** |
| 需要管理员 | `winget source add` 必需 | **不需要**（HKCU 代理 + 用户级 CA） |
| 需要信任证书 | localhost 证书 | 能签白名单 host 的 CA（**风险更高，需约束**） |
| 代码量估计 | 3000+ 行 | **300–500 行** |
| 失效时的表现 | winget 报源不可用 | **见 §5.1，这是 B 的最大弱点** |

## 5. B 方案的真实弱点（不粉饰）

### 5.1 代理是全局单点

`ProxyEnable` 一旦为 1 而代理进程没跑，**整台机器的 HTTP 流量都会失败**，不只是 winget。
这比"源不可用"严重得多。

缓解方向（未验证）：

- 用 **PAC**（`AutoConfigURL`，指向本地 PAC 服务）而非全局 `ProxyServer`：
  PAC 只对白名单 host 返回 `PROXY`，其余返回 `DIRECT`；PAC 取不到时浏览器/系统回落 `DIRECT`，
  **爆炸半径收缩到 github 一类 host**
- 代理随登录自启 + 崩溃自动重启（进程守护）

### 5.2 mitmproxy 的 CA 没有任何约束

mitmproxy 生成的 CA **可以签发任意域名**。这与 ADR-007 否决 MITM 的理由完全对应。
生产实现必须换成**自签的、带 Name Constraints 的 CA**，只允许签：

```
github.com
objects.githubusercontent.com
codeload.github.com
release-assets.githubusercontent.com
```

**未验证**：Windows 的 schannel / WinHTTP 是否强制校验 Name Constraints。
这决定了 §5.2 的缓解能否落地，是切换架构前必须解决的 H1。

### 5.3 本次用的是实验工具，不是交付形态

mitmproxy 是 Python + 一整套依赖，只适合验证。产品形态应是自己写的 Rust 代理
（ADR-009 的语言结论不受影响，ADR-012 的依赖预算仍然适用）。

## 6. 原型代码（实验用，约 40 行）

```python
WHITELIST = {"github.com", "objects.githubusercontent.com",
             "codeload.github.com", "release-assets.githubusercontent.com"}
ACCEL = "gh-proxy.com"

def request(flow):
    if flow.request.pretty_host in WHITELIST:
        original = f"https://{flow.request.pretty_host}{flow.request.path}"
        flow.request.host, flow.request.port, flow.request.scheme = ACCEL, 443, "https"
        flow.request.path = "/" + original          # gh-proxy 的路径前缀形式
        flow.request.headers["Host"] = ACCEL
```

其余 host 一律原样透传（实测 17.86 MB 的 Microsoft CDN 下载未受影响）。

## 7. 未验证项（切换架构前必须解决）

| # | 问题 | 影响 |
|---|---|---|
| H1 | Windows 是否强制校验 X.509 Name Constraints | 决定能否把 CA 风险收敛到 4 个域名 |
| H2 | `download.visualstudio.microsoft.com` 在 R2 超时的原因 | 若是代理引入的问题，说明直通路径有隐患 |
| H3 | 大文件（数十 MB）+ 断点续传 + 并发分片是否稳定 | 决定能否真正替代源方案 |
| H4 | 代理模式下多加速器健康检查怎么做（改写发生在代理请求时） | 影响 `doctor` 与回退设计 |
| H5 | winget 升级后是否仍使用系统代理 | 决定长期可靠性 |

## 8. 复现步骤

```powershell
uv tool install mitmproxy
# 1) 导入 CA（用户级，无需管理员）
Import-Certificate -FilePath "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer" `
  -CertStoreLocation Cert:\CurrentUser\Root
# 2) 启动带改写插件的代理
mitmdump --listen-port 8899 -q -s .\mitm-accel.py
# 3) 指向代理（用户级）
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value '127.0.0.1:8899'
# 4) 测试（用未缓存过的包）
winget download --id sharkdp.fd -d $env:TEMP\fdtest --accept-source-agreements
# 5) 清理（必须做）
certutil -user -delstore Root <thumbprint>
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
```

> 注意：`Remove-Item Cert:\CurrentUser\Root\<...>` 会因"用户根存储不允许 UI"失败，**必须用 `certutil -user -delstore`**。
