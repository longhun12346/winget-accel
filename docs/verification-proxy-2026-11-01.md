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

环境：端口 `8443`，加速器 `gh-proxy.com`，CA 已装入 `CurrentUser\Root`，`AutoConfigURL` 指向 `http://127.0.0.1:8443/winget-accel.pac`。

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

## 11. 加速是否真的生效（2026-11-01 A/B 复测，Rust 二进制）

同一个资源（`fd v10.5.0` 的 x86_64-pc-windows-msvc.zip）、同一台机器、前后脚测。

| 路径 | 结果 | 速率 |
|---|---|---|
| 直连 `curl -L`（30 s 上限） | 30 s 只收到 **636,355 B**，未下完；302 指向 `release-assets.githubusercontent.com` | **21 KB/s** |
| 直连 `winget download` | **37 s 失败**：`WinHttpSendRequest: 12002`、`0x80072ee2`，0 字节落盘 | — |
| 经 Rust 代理 `curl` | 200，**1,535,063 B / 2.07 s** | **724 KB/s** |
| 经 Rust 代理 `winget download` | **13 s 成功**，2,544,236 B，"已成功验证安装程序哈希" | — |

**结论**：可测的路径上约 **35 倍**差距（21 KB/s → 724 KB/s）。
更要紧的是 `winget` 自己的判定：直连 37 秒超时失败，经代理 13 秒完成并通过官方哈希校验。

### 对早期结论的修正

早期文档写的是"直连 `000` / 20 s 超时"、"下载链路断了"。**这个说法不够准确**：

- `curl` 直连其实**能通，只是慢**（21 KB/s，30 秒只下 636 KB）
- 真正"断"的是 **WinHTTP 路径**：`winget` 用 WinHTTP，37 秒就因 `12002` 超时放弃

两条路径的表现不同，原因在客户端超时策略而不是网络完全不通。
对外表述应统一为"慢到不可用"，而不是"不通"——前者可复现、可量化，后者是当时的误判。

## 12. 加速器候选实测（2026-11-01 晚）

标准比"能访问"严：必须**支持 Range（206）**且**整包 SHA256 与官方一致**。

测试资源固定为 `fd v10.5.0`（1,535,063 B，`a227701b…d57cd7`）。

### 可用（3 个）

| 候选 | Range | 整包 | 速率 |
|---|---|---|---|
| `gh-proxy.com` | 206 | 哈希一致 | **765 KB/s** |
| `ghproxy.imciel.com` | 206 | 哈希一致 | 222 KB/s |
| `ghfast.top` | 206 | 哈希一致 | 190 KB/s |

### 不可用（11 个）

| 候选 | 现象 |
|---|---|
| `ghproxy.net` | 超时（curl 28） |
| `gh.llkk.cc` | 超时 |
| `github.moeyy.xyz` | 超时 |
| `ghproxy.cfd` | 连接超时 |
| `ghproxy.cc` / `ghp.ci` | TLS 连接被重置（35） |
| `gh-proxy.top` / `cf.gh-proxy.com` / `hub.gitmirror.com` / `gh-proxy.xyz` | DNS 解析失败（6） |
| `gh-proxy.net` | 可达但返回 200/302 的 HTML，不是文件（不支持 Range） |
| `ghps.cc` | 404 |
| `ghproxy.cn` | 200 但返回 6,990 B 的网页，不是文件 |
| `ghproxy.1888866.xyz` | 525（源站握手失败） |
| `gh.h233.eu.org` | 403 |
| `gh-proxy.cc` | 301 重定向，未跟随后非文件 |
| `gh.api.99988866.xyz` / `gh.xxooo.cf` | TLS 握手失败（`SEC_E_ILLEGAL_MESSAGE`） |

### 一个重要观察

`ghfast.top` 在**当天早些时候**测是 `000` / 12 s（记为"已失效"），晚上复测却完全可用。
说明这类公共服务存活状态**会在小时级别变化**。这有两个直接推论：

1. 健康探测不是锦上添花，是必需品——不探就会用到一个已经死掉的候选。
2. 配置里的候选必须定期复核，文档里的"可用/失效"都只是**某一时刻的快照**，要带日期读。

### 切换实测

配置 `[死端口(priority 1), ghfast.top(priority 2)]` 启动：

- 探测结果：`127.0.0.1 -> unhealthy`、`ghfast.top -> healthy`、`status = ok`
- 下载：200 / 1,535,063 B / 12.02 s，**哈希一致**
- 说明 `current()` 确实跳过了判死的候选，用的第二个

### 复测与速度稳定性（2026-11-01 19:12–19:20）

一小时后按同一标准复测全部 26 个候选：**可用仍是同样 3 个，没有发生状态翻转**
（上一轮记录的 `ghfast.top` "失效→可用" 是单次观察，不能据此推断小时级churn）。

速度有明显抖动，所以单次测量不足以定优先级。每候选连测 3 次：

| 候选 | 三次 | 中位 | 判断 |
|---|---|---|---|
| `gh-proxy.com` | 769 / 766 / 778 KB/s | **769** | 很稳，保持 priority 1 |
| `ghfast.top` | 357 / 339 / 219 KB/s | 339 | 中位高于 imciel → priority 2 |
| `ghproxy.imciel.com` | 375 / 159 / 238 KB/s | 238 | 抖动最大，priority 3 |

三次整包 SHA256 **全部一致**，三个候选的完整性都稳定。

配置已按中位数重排（ghfast 与 imciel 互换）。这也说明：**候选排序应该看多次中位数，
而不是一次快照**——否则会得到一个随机的顺序。

### 补充：从维护中的清单抓候选（2026-11-01 19:40）

先说明方法问题：前面 26 个候选是**凭记忆列的常见服务**，不是穷举。
改为从持续维护的清单里抓域名，再逐个实测，立刻多出可用候选。

来源（只取域名，不信任其推荐结论）：
- `hubporg/CF-GitHub-Proxy` 的 README
- `lightjunction/magicnet` 的 `docs/github-downloads.md`

新增 7 个候选的实测结果：

| 候选 | 结果 |
|---|---|
| `gh.geekertao.top` | ✅ Range 206，整包哈希一致，**692 / 715 KB/s** |
| `ghproxy.site` | ✅ Range 206，整包哈希一致，155 / 332 KB/s |
| `gh.ddlc.top` | ⚠️ **429**（限流，非死亡） |
| `ghfile.geekertao.top` | ⚠️ 429 |
| `github.dpik.top` | ⚠️ 429 |
| `gh.felicity.ac.cn` | ⚠️ 429 |
| `gh.jasonzeng.dev` | ❌ TLS 握手失败 |

**429 是一个需要单独记录的状态**：它既不是可用，也不该记为"已失效"——
服务是活的，只是当前拒绝本机请求。健康探测若把它判成 unhealthy 是合理的（当下确实不能用），
但把它从候选集里永久删掉就错了。将来复核时它们可能直接可用。

当前可用候选 5 个（按多次测量中位数排序）：

| priority | 候选 | 速率 |
|---|---|---|
| 1 | `gh-proxy.com` | 769 KB/s（最稳） |
| 2 | `gh.geekertao.top` | ~703 KB/s |
| 3 | `ghfast.top` | 339 KB/s |
| 4 | `ghproxy.site` | ~243 KB/s |
| 5 | `ghproxy.imciel.com` | 238 KB/s（抖动最大） |

**结论**：这个池子不是封闭的，也不可能穷举。可行的方法是"维护一个清单 + 定期用同一标准复测"，
而不是期望一次性找到全部。

## 13. 换机验证（192.0.2.10，2026-11-01 19:47）

把同一份二进制（SHA256 `706476a8…7771`）传到另一台 Windows（`TEST-PC-02`，10.0.26100.9711），
在那台机器的网络上验证。传输后两侧哈希一致。

### 结果

| 项 | 本机 | 目标机 |
|---|---|---|
| 二进制运行（`--version` / `--print-pac`） | ✅ | ✅ |
| `--doctor` 候选可达 | 5/5 | **5/5** |
| `gh-proxy.com` 探测延迟 | 666 ms | **46 ms** |
| 经代理下载 1.5 MB | 2.07 s ≈ 723 KB/s | 5.09 s ≈ **295 KB/s** |
| 整包 SHA256 | 一致 | **一致** |

**两点值得注意**：

1. **延迟低不等于吞吐高**。目标机到 `gh-proxy.com` 的探测延迟只有本机的 1/14（46 vs 666 ms），
   但实际下载速度只有本机的 40%（295 vs 723 KB/s）。说明这两台机器走的是不同链路，
   探测延迟只能作为"是否可用"的判断依据，**不能拿它推断下载速度**。
2. 之前在本机返回 **429** 的 `ghproxy.site`，在目标机上探测正常（720 ms）。
   再次印证"某地不可用 ≠ 全局不可用"，候选池不该按单点观测裁剪。

### 顺带发现的一个真实缺陷

目标机是中文 Windows，控制台代码页为 GBK，而程序输出 UTF-8 中文，
导致 `--doctor` 的表格与日志里的中文**全部乱码**（如 `检查项` 变成 `锟斤拷` 之类）。
英文部分（`OK`/`FAIL`/URL/数字）正常，所以不影响功能判断，但影响可读性。

**待修**：要么把输出改为 ASCII（放弃中文），要么在启动时把控制台代码页切到 UTF-8（`SetConsoleOutputCP(65001)`）。
倾向后者，但要注意：切代码页会影响同一控制台里其它程序的输出，需要权衡。

### 目标机上的遗留物

验证产生的文件都在 `%USERPROFILE%\wgaccel-test\`（二进制、config.json、certs、日志、下载样本）。
没有安装 CA 到根存储、没有改 PAC —— 因此**没有系统状态残留**。
我加到 `authorized_keys` 的公钥已清除（两个文件都归零）。

### 退出还原：之前的说法有误，已修正（2026-11-01 20:40）

**错误说法**：早期文档与对话里写"Ctrl+C 退出会自动还原 PAC"。

**事实**：Rust 默认把 Ctrl+C 当作进程终止信号，**不展开栈**，`Drop` 不会执行；
点窗口 X（`CTRL_CLOSE_EVENT`）同理。所以只靠 `EnvGuard::drop` 的话，
Ctrl+C 和关窗口**都**不会还原 PAC。

**修正**：新增 `install_exit_handler()`，用 `SetConsoleCtrlHandler` 注册控制台事件处理，
在进程消失前同步调用 `restore_now()`（把原 PAC 写回，或删除该值），
覆盖 Ctrl+C / 关闭窗口 / 注销 / 关机。原 PAC 值通过泄漏的静态缓冲区传递，
避免在事件线程里加锁。

**同时修正另一处**：此前说"PAC 指向死端口会让那 4 个域名全部失败"。
实际 WinINet 在 PAC 取不到时会**退化为直连**，所以残留 PAC 的后果是
"回到慢速直连"，不是"功能全挂"。这降低了该缺陷的严重性，但不改变"应该还原"的结论。

**验证状态**：
- `recover_stale`（下次启动清理残留）：已实测有效
- `install_exit_handler`：已编译通过，但**关闭事件路径尚未实测**——
  用 `taskkill`（不带 /F）测试无效，它不会给控制台程序发 `CTRL_CLOSE_EVENT`。
  需要真实按 Ctrl+C 或真实关窗口才能验证。

## 14. 速度问题取证（2026-11-01 22:41–22:44）

### 现象

用本工具跑 `winget download --id BurntSushi.ripgrep.MSVC`，只得到 **66 KB/s**（1.79 MB / 26.54 s）：

```
REWRITE ... -> 206 2B         0.77s
REWRITE ... -> 206 741,035B  10.08s   ← 74 KB/s
REWRITE ... -> 206 1,048,576B 21.00s  ← 50 KB/s
```

而此前 `fd` 资产实测 723 KB/s。差了 10 倍。

### 取证一：五个候选各自的速度（同一资产、1 MB Range）

| 候选 | 实测 | 我此前记录的"中位数" |
|---|---|---|
| `gh-proxy.com` | **521 KB/s** | 769 KB/s |
| `ghproxy.imciel.com` | 135 KB/s | 238 KB/s |
| `ghfast.top` | 131 KB/s | 339 KB/s |
| `ghproxy.site` | 128 KB/s | 243 KB/s |
| `gh.geekertao.top` | **104 KB/s** | 703 KB/s |

**`gh.geekertao.top` 从 703 掉到 104（6.8 倍）**，其余也普遍下降。
结论：**静态的"实测中位数"排序在几小时后就会失真**，写死优先级是不可靠的。

### 取证二：复现同一操作，确认是否选错了候选

给日志加上 `via=<加速器>` 后重跑同一命令：

```
REWRITE via=gh-proxy.com ... -> 206 2B        0.72s
REWRITE via=gh-proxy.com ... -> 206 741,035B  1.61s
REWRITE via=gh-proxy.com ... -> 206 1,048,576B 1.74s
winget: 1,789,611 B / 5.65s = 309 KB/s
```

**同一个候选、同一个资产：26.54 s → 5.65 s（快 4.7 倍）。**

### 结论

1. 那次 66 KB/s **不是选错了加速器**，而是当时服务侧/链路波动。
2. 更关键的发现：**当前的健康检查只判断"可达"，抓不住速度差异**。
   `gh-proxy.com` 从 769 → 521 → 309 → 66 KB/s，全程都是 "healthy"。
3. 因此"速度优选"必须**实测吞吐**，而不是靠：
   - 写死的优先级（会过期，本次已证）
   - 可达性探测（只回答"通不通"，不回答"快不快"）

### 顺带修掉的观测缺口

`REWRITE` 日志原先不记录实际使用的候选，导致无法回答"这次是谁在服务"。
现已改为 `REWRITE via=<host> ...`。
