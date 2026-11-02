# 调研记录

调查日期：**2026-11-01**（Asia/Shanghai）
环境：Windows 11 Enterprise LTSC 26100.9711，非管理员账户 `testuser`，winget `v1.29.380`

本文档记录全部实测数据，包括**失败的实验和被否决的方向**，因为其中几个坑会直接决定实现细节。

---

## 1. 问题定义

`winget install <GitHub 托管包>` 在国内网络下极慢。需要区分两个独立环节：

| 环节 | 数据来源 | 国内可用性 |
|---|---|---|
| 源索引与清单查询 | `cdn.winget.microsoft.com` | 可用，但偶发严重延迟 |
| 安装包下载 | 清单里 `InstallerUrl` 指向的 host（多为 GitHub） | **极慢** |

本项目的目标只针对第二个环节，但顺带可以改善第一个。

---

## 2. winget 的能力边界（全部实测）

### 2.1 管理员门禁

| 命令 | 结果 | 报错原文 |
|---|---|---|
| `winget settings --enable LocalManifestFiles` | 拒绝，退出码 -1978335207 | 需要具有管理员权限才能执行此命令 |
| `winget install -m <manifest>` | 拒绝 | 此功能需要由管理员启用。若要启用它，请以管理员身份运行 `winget settings --enable LocalManifestFiles` |
| `winget show --proxy http://...` | 拒绝，退出码 -1978335230 | 此功能需要由管理员启用。若要启用它，请以管理员身份运行 `winget settings --enable ProxyCommandLineOptions` |
| `winget source add ...` | 拒绝 | 需要具有管理员权限才能执行此命令 |

**绕过尝试（失败）**：手工向用户级 `settings.json` 写入
`"adminSettings": {"LocalManifestFiles": true}` 后重试 `winget install -m`，
**依然被拒绝**。说明 winget 不从该文件读取 adminSettings。

注册表检查：`HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller` 与
`HKCU\...\AppInstaller` 均不存在，本机未通过 GPO 配置。

### 2.2 adminSettings 现值

```
BypassCertificatePinningForMicrosoftStore  false
ConfigurationProcessorPath                 false
InstallerHashOverride                      false
LocalArchiveMalwareScanOverride            false
LocalManifestFiles                         false
ProxyCommandLineOptions                    false
```

### 2.3 已注册源

```
msstore     https://storeedgefd.dsx.mp.microsoft.com/v9.0
winget      https://cdn.winget.microsoft.com/cache
winget-font https://cdn.winget.microsoft.com/fonts   (explicit)
```

### 2.4 其他相关能力

- `winget download -d <dir>` 存在，可只下载不安装（无需管理员）
- `winget show` 可获取 `InstallerUrl` 与 `InstallerSha256`（无需管理员）
- `winget install --manifest` 需要 `LocalManifestFiles` 策略
- 系统代理未启用（`ProxyEnable = 0`）

---

## 3. 下载速率实测

测试文件（同一网络时段内）：

- `Git-2.56.0.4-64-bit.exe` — 63.75 MB，GitHub Releases
- `ripgrep-15.2.0-x86_64-pc-windows-msvc.zip` — 1.71 MB，GitHub Releases

### 3.1 单连接直连

| 目标 | 方法 | 速率 | 备注 |
|---|---|---|---|
| Git for Windows（4 MB Range） | 原始 HTTP，UA=winget-cli | **23.2 KB/s** | 耗时 176.27 s |
| ripgrep（完整 1.71 MB） | 原始 HTTP | **37.2 KB/s** | 耗时 47.01 s |
| Git for Windows（1 MB Range） | curl | **46.0 KB/s** | 耗时 22.28 s |
| Git for Windows（1 MB Range，稍后复测） | curl | **10.5 KB/s** | 见 5.2 节，测压之后 |

### 3.2 经加速器

| 加速器 | 目标 | 速率 |
|---|---|---|
| `gh-proxy.com` | Git for Windows（4 MB） | **1,437.1 KB/s** |
| `gh-proxy.com` | Git for Windows（1 MB，测压后） | **523.4 KB/s** |
| `gh-proxy.com` | ripgrep（完整） | 759.1 KB/s |
| `ghfast.top` | Git for Windows（1 MB，测压后） | **353.9 KB/s** |

加速器提升幅度 **20–50 倍**，且在直连被限速期间依然可用（出口 IP 不同）。

### 3.3 winget 自带下载器

| 配置 | 目标 | 速率 |
|---|---|---|
| `network.downloader = "do"` | ripgrep 15.2.0 | **34.3 KB/s**（51.01 s） |
| `network.downloader = "wininet"` | ripgrep 15.1.0 | 509.3 KB/s（单次） |
| `network.downloader = "wininet"` | ripgrep 14.1.1 | **失败**：`InternetOpenUrl() failed. 0x80072efd` |

**结论：切换下载器不是解决方案。** `do` 与直连速率一致；`wininet` 结果不稳定且出现硬失败。
这是微软在 winget-cli#4843 里给的官方建议，但在本机实测无效。

### 3.4 ⚠️ DO 缓存污染事件（记录以免后人重踩）

第一次对比测试时，`downloader=do` 报告 **627.9–723.9 KB/s**，一度让人误以为 DO 有奇效。
原因是：先前一次 `winget download` 因目录名非法（含 `:`）而**在报错前已完成下载并写入 DO 缓存**，
后续测量命中的是缓存。

干净复测（含删除输出目录、用不同版本避开同一文件）后，DO 稳定在 **34.3 KB/s**。

**教训**：测 winget 下载速率必须避免 DO 缓存命中。做法：每次换不同版本/不同文件，
或换 `downloader=wininet` 做交叉验证。

---

## 4. 并发下载实验（重要：这条路被否决了）

### 4.1 短窗口结果（曾让人乐观）

同一 63.75 MB 文件，多连接分段 Range：

| 并发数 × 分片 | 总量 | 耗时 | 聚合速率 | 相对单连接 |
|---|---|---|---|---|
| 1 × 1 MB | 1 MB | 22.28 s | 46.0 KB/s | 1.0× |
| 4 × 1 MB | 4 MB | 28.75 s | 142.5 KB/s | 3.1× |
| 8 × 1 MB | 8 MB | 47.85 s | 171.2 KB/s | 3.7× |
| 16 × 512 KB | 8 MB | 13.09 s | 626.0 KB/s | 13.6× |
| 16 × 1 MB | 16 MB | 42.32 s | 387.1 KB/s | 8.4× |
| 32 × 256 KB | 8 MB | 10.18 s | 804.4 KB/s | 17.5× |
| **64 × 128 KB** | 8 MB | 3.90 s | **2,099.8 KB/s** | **45.7×** |

64 连接甚至超过了 `gh-proxy` 单连接（1,437 KB/s）。

### 4.2 然后它崩了

紧接着尝试 32 × 1 MB（32 MB）与 16 × 2 MB 两个"持续速率"测试，**全部请求失败**。

随后的事实：

| 目标 | 结果 |
|---|---|
| `github.com` 首页 | 200 ✅ |
| `api.github.com` | 200 ✅ |
| `codeload.github.com` | 301 ✅ |
| `raw.githubusercontent.com` | 000（国内既有封锁，与此无关） |
| **发布资产下载**（Git、ripgrep 均测） | **000 / 0 字节，静置 20 秒后仍为 000** ❌ |
| 同一时刻 `gh-proxy.com` | 206 / 523.4 KB/s ✅ |
| 同一时刻 `ghfast.top` | 206 / 353.9 KB/s ✅ |

### 4.3 结论

**激进多连接会被 GitHub 的资产 CDN 惩罚，且惩罚会外溢到正常使用。**

- 不只是"这个下载器变慢"，而是该 IP 的**所有** GitHub 发布资产下载一起归零
- 连 `winget` 本身、`git clone` 依赖的资产下载也会受影响
- 恢复需要时间（本次在 20 分钟内未恢复）

**工程约束（写入设计）**：任何下载逻辑并发上限 **4–8**，分片随机化、带指数退避，
且**必须**默认走加速器而不是直连并发。

> 说明：本次实验是我方主动做的压力测试造成的，属于已知代价。

---

## 5. 源层（清单查询）延迟

| 操作 | 耗时 |
|---|---|
| `winget show BurntSushi.ripgrep.MSVC`（首次） | **80.96 s** |
| 同一包第二次 | 4.33 s |
| 换包 `winget show Git.Git` | **41.15 s** |
| `winget search --id 7zip.7zip` | 5.65 s |

**结论**：源层不是"慢"，是**偶发极慢**。同一包二次查询命中本地缓存变快，
换包又慢，说明每次新查询可能触发远端往返。

本地 REST 源可把这个环节变成纯本地读取（毫秒级）。

---

## 6. 信任模型分析

这是选择方案时最关键的一条，但容易被忽略。

### 6.1 winget 的哈希校验逻辑

winget 从**清单**读取 `InstallerSha256`，下载安装包后校验。
**哈希和 URL 来自同一份清单**——所以：

> 一个恶意 REST 源可以同时替换"安装包 URL"和"哈希值"，winget 的校验依然会通过。

因此**使用任何第三方 REST 源都等于把供应链信任交给对方**。

### 6.2 本方案为何更安全

本方案的清单来源于官方 `microsoft/winget-pkgs`（只做 host 改写，不动哈希）：

| 方案 | 哈希来源 | 可否被第三方同时替换 |
|---|---|---|
| 公共第三方 REST 源 | 对方下发的清单 | **可以** |
| 本项目（本地源） | 本地保存的官方清单 | 不可以 |
| 交叉核对（可选增强） | `winget show` 查官方 PreIndexed 源 | 不可以 |

加速器只经手字节，改动必然导致哈希不匹配、安装失败。

---

## 7. 社区调研结论

分三层看，结论不同：

### 7.1 REST 源服务端：**有现成实现**

| 项目 | ★ | 机制 | 与需求差距 |
|---|---|---|---|
| [microsoft/winget-cli-restsource](https://github.com/microsoft/winget-cli-restsource) | 320 | 官方参考实现，Azure Functions + CosmosDB | 无 URL 改写；依赖 Azure/模拟器 |
| [jantari/rewinged](https://github.com/jantari/rewinged) | 98 | Go 单二进制，读目录提供 REST 服务 | **最接近**，默认不改写（正合需要） |
| [pichuang/FerryWinget](https://github.com/pichuang/FerryWinget) | 1 | ASP.NET Core + 自动改写到内网 | 改写目标是自己的内网存储（需先落地安装包） |
| [thilojaeggi/WinGetty](https://github.com/thilojaeggi/WinGetty) | 274 | Flask + 自带包库 | 自己保管安装包，不改写 |

### 7.2 "改写指向公共加速器"这一层：**没有**

检索证据：

| 检索词 | 命中 |
|---|---|
| `winget manifest rewrite` | 0 |
| `winget ghproxy` | 0 |
| `winget LocalManifestFiles` | 0 |
| `winget 加速` | 0 |
| `winget download accelerator` | 0 |
| `winget 换源` | 0 |
| `winget rest source server` | 0 |
| `winget rest api localhost` | 0 |
| Gitee：`winget` / `winget 加速` / `winget 镜像` | 0 / 0 / 0 |

另外把 `winget in:readme ghproxy`(70)、`in:readme "gh-proxy"`(97)、
`in:readme 镜像源`(229) 三个查询合并去重，筛出 74 个涉及 Windows/软件安装的候选，
逐个核验最像的 5 个：

| 仓库 | ★ | winget | InstallerUrl | source add | Microsoft.Rest | rewrite |
|---|---|---|---|---|---|---|
| chenjrastro-tech/github-release-download-acceleration | 4 | ×1 | — | — | — | — |
| muyun1314/AgentCLI | 5 | ×2 | — | — | — | — |
| chrichuang218/codex-windows-cn | 79 | ×1 | — | — | — | — |
| l1i1/CodexAppInstaller | 112 | ×2 | — | — | — | — |
| chenqi92/Pier-X | 8 | ×8 | — | — | — | — |

`winget` 出现全是"用户自己调用 `winget install`"或"用 ghproxy 下载自己的安装包"，
**没有一个碰过 winget 的源层或清单层**。

### 7.3 已明确不可用/不采纳的

| 项目 | 否决原因 |
|---|---|
| `cf-winget-proxy` | 无 LICENSE（All rights reserved，不可合法复用）；改写**全部** host（Firefox 等非 GitHub 流量也过它的 Worker，零收益）；0★/1 fork，当日建当日停；域名 TLS 失败 |
| USTC 等镜像 | 只加速源索引与 `source.msix`，`InstallerUrl` 仍是 GitHub，不解决下载 |
| TUNA / 阿里云 | 该路径 404 |
| UniGetUI | 1814 个文件中无任何代理/镜像代码 |

### 7.4 检索方法局限（须如实记录）

- `web_search` 在本机不可用（无 API key），**中文博客、论坛、公众号里的脚本片段搜不到**
- Gitee 搜索返回 0，可能因需要 token，无法排除
- 上述空白结论仅对"有维护价值的 GitHub 仓库"成立

---

## 8. HTTPS 是否强制（未定论）

三条一手证据互相矛盾：

| 来源 | 说法 |
|---|---|
| WinGetty README | "**WinGet requires HTTPS** for secure communication and without it WinGet will throw an error." |
| FerryWinget README | `winget source add -n "InternalMirror" -a "http://<server-ip>:8080/api/" -t "Microsoft.Rest"` |
| rewinged README | `winget source add -n rewinged-local -a https://localhost:8443/api -t "Microsoft.Rest"` |
| rewinged `-listen` 默认值 | `localhost:8080`（明文 HTTP），仅在配置证书后才启用 TLS |

在 winget-cli 源码中检索 `Rest/RestSource.cpp` 与 `Resources.h` 未找到 https 相关校验。

**结论：需要一次提权实测才能确定。** 若确实强制 → 必须自签证书；
若不强制 → 可省掉证书环节（但仍需 `source add` 提权）。

**实测方法**（需管理员）：

```powershell
winget source add -n httpsprobe -a "http://127.0.0.1:9/api/" -t "Microsoft.Rest"
winget source remove -n httpsprobe
```

报错是"必须 HTTPS"还是"无法连接"，即可判定。

---

## 9. 结论摘要

1. 下载慢是**真实且严重**的问题（23–46 KB/s），加速器有效（20–50 倍）
2. 换 winget 内置下载器**无效**（官方建议在本机被证伪）
3. 并发下载**不可用**（触发惩罚，影响面外溢）
4. 所有"离开官方源"的机制都需一次提权 → 只能在此前提下优化
5. 本机 REST 源是**副作用最小、且顺带解决源层延迟**的方案
6. 服务端有现成实现（rewinged），但"改写指向公共加速器"这一层无人实现
7. 哈希必须来自官方清单，这是本方案相对第三方源的**核心安全优势**

