# 代理层架构验证（2026-11-01，第三次实测）

> 目的：验证"**不实现 REST 源，只在下载层做代理改写**"是否可行（即 `decisions.md` ADR-001 的替代方案）。
> 结论：**可行，且已端到端跑通**。2026-11-01 已据此切换架构（ADR-013）。
>
> 本文记录两次实验：§2–§8 是 mitmproxy 可行性验证，§9 是 `prototype/` 的 PAC 模式实测。

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
| 需要信任证书 | localhost 证书 | 能签白名单 host 的 CA（风险已被 §9.4 的 Name Constraints 收敛，见 ADR-014） |
| 代码量估计 | 3000+ 行 | **300–500 行** |
| 失效时的表现 | winget 报源不可用 | **见 §5.1，这是 B 的最大弱点** |

## 5. B 方案的真实弱点（不粉饰）

### 5.1 代理是全局单点

`ProxyEnable` 一旦为 1 而代理进程没跑，**整台机器的 HTTP 流量都会失败**，不只是 winget。
这比"源不可用"严重得多。

缓解（**§9.3 已验证**）：

- 用 **PAC**（`AutoConfigURL`，指向本地 PAC 服务）而非全局 `ProxyServer`：
  PAC 只对白名单 host 返回 `PROXY`，其余返回 `DIRECT`；PAC 取不到时系统回落 `DIRECT`，
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

**已由 §9.4 验证**：Windows 强制校验 Name Constraints——同一 CA 签发 `github.com` 被接受、
签发 `example.com` 被拒绝。因此"CA 风险更高"的判断可以下调为"风险被限定在 4 个 host 内"（ADR-014）。

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

## 7. 未验证项（截至 §2–§8）

| # | 问题 | 状态 / 影响 |
|---|---|---|
| H1 | Windows 是否强制校验 X.509 Name Constraints | ✅ 已验证：**强制校验**（§9.4），CA 风险可收敛到 4 个域名 |
| H2 | `download.visualstudio.microsoft.com` 在 R2 超时的原因 | ⬜ 未解决；后续 §9 的直通路径未复现该问题 |
| H3 | 大文件 + 并发 Range 分片 + 断点续传是否稳定 | 🟡 部分验证：18,314,725 B 单流下载 8.86 s ≈ **2.07 MB/s**，落盘完整无截断；**3 路并发 Range** 全 `206`，分片和恰为 1,535,063 B，拼接后 SHA256 与整包一致；加速器不可达时 0.12 s 返回 `502`（快速失败而非挂死）。**断点续传（中断后 `Range` 续传）仍未验证** |
| H4 | 代理模式下加速器健康检查与切换的设计 | 🟡 已设计（`design.md` §8），未实测 |
| H5 | winget 升级后是否仍使用系统代理/PAC | ⬜ 未验证，属长期风险 |

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

---

## 9. 原型实测结果（PAC 模式，2026-11-01 11:38）

§2 的 mitmproxy 实验证明了"能通"，但用的是无约束的 mitmproxy CA 与全局 `ProxyServer`。
本节改用 `prototype/`（PAC 服务 + CONNECT 分流 + MITM 改写 + 自签带约束 CA），
验证**交付形态真正依赖的那几条性质**是否成立。

环境：端口 `8443`，加速器 `gh-proxy.com`，CA 已装入 `CurrentUser\Root`，`AutoConfigURL` 指向 `http://127.0.0.1:8443/proxy.pac`。

### 9.1 速率与端到端

| 场景 | 结果 |
|---|---|
| `curl` 直连 release 资源 | **302 后卡住**（`objects.githubusercontent.com` 不可达） |
| `curl` 经原型 | **200，1,535,063 B / 2.39 s ≈ 634 KB/s** |
| `winget download --id junegunn.fzf` | **退出码 0，总 7.7 s，2,544,236 B，"已成功验证安装程序哈希"** |
| 非白名单 `api.github.com`（隧道） | **200 / 0.96 s，未被改写** |

`winget` 输出（`prototype/wg-pac.out.txt`）：

```
正在下载 https://github.com/junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip
已成功验证安装程序哈希
已下载安装程序: ...\fzf_0.74.5_X64_portable_en-US.zip
```

### 9.2 winget 的分片行为

日志（`prototype/proxy-pac.log`）：

```
11:38:24 REWRITE github.com/junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip -> 206 2B 1.12s
11:38:26 REWRITE github.com/junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip -> 206 447084B 1.59s
11:38:26 REWRITE github.com/junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip -> 206 1048576B 2.02s
11:38:26 REWRITE github.com/junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip -> 206 1048576B 1.91s
```

四次请求全部 `206`：先一次 2 B 探测，再三段 447,084 + 1,048,576 + 1,048,576 = **2,544,236 B**，
与 winget 报告的文件大小一致。结论：加速器必须支持 `Range` 与 `Content-Range`（gh-proxy 已验），
代理**不得**改动 `Range` 请求头与响应状态码。

### 9.3 PAC 被 WinINet 采纳

`PAC-SERVED ×9`（同一秒内取 9 次 PAC），随后 winget 的下载请求经代理被改写。
说明 `AutoConfigURL` 指向本地 PAC 被系统代理栈接受，且 `ProxyEnable=0` 不影响 PAC 生效。

### 9.4 Name Constraints 被强制校验（原 H1）

同一 CA（`path_length=0`，`permitted_subtrees` 仅 4 个 DNS）分别签发两本叶证书：

| 叶证书 host | 在许可集内 | 客户端结果 |
|---|---|---|
| `github.com` | ✅ | **接受**：下载完成，哈希校验通过 |
| `example.com` | ❌ | **拒绝**：`CLIENT-ERR [SSL: SSLV3_ALERT_CERTIFICATE_UNKNOWN]`（`prototype/probe-8446.log`） |

`example.com` 在 TLS 握手阶段即被拒。结论：Windows 的 TLS 栈会强制校验 Name Constraints，
**CA 私钥即使泄露，也无法用于劫持白名单之外的站点**。

### 9.5 结论

§5.1（代理单点）与 §5.2（CA 无约束）两个弱点，分别由 **PAC 定向**与 **Name Constraints** 收敛，
且两者都被实测支持。残余风险见 `decisions.md` ADR-014。

---

## 10. 根证书安装需交互确认

这是实测踩到的坑，会**改变安装器设计**，单列一节。

| 调用方式 | 无可见桌面时 |
|---|---|
| `Import-Certificate -CertStoreLocation Cert:\CurrentUser\Root` | **不报错，永久阻塞** |
| `[X509Store]('Root','CurrentUser').Add()` | 同上 |
| `certutil -user -addstore Root <file>` | 同上 |

原因：把自签 CA 装进根存储必须弹一次 Windows 安全警告，用户点"是"才继续；
看不到弹窗时调用方就一直等，且**不抛异常**。

原型 `prototype/setup.ps1` 的处理方式：

1. 把导入放进**子进程**，主进程 `WaitForExit(45s)`
2. 超时则杀掉子进程、打印可复制的手动命令（`certutil -user -addstore Root "certs\ca-cert.pem"`），`exit 1`
3. 按指纹判重，已装好则跳过，重跑安全

对交付形态的硬要求（已写入 `roadmap.md` 阶段 4）：

- 安装器必须假定这一步**可能无人值守**，任何情况下不得挂死
- 超时或用户取消 → 完整回滚（PAC、CA、进程），不留"装了一半"的状态
- 必须输出可直接复制的手动命令
- 移除 CA 用 `certutil -user -delstore Root <thumbprint>`：
  `Remove-Item Cert:\CurrentUser\Root\...` 会因"用户根存储不允许 UI"失败（§1 同因）
