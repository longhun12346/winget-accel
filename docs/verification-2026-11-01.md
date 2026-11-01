# 复核记录（2026-11-01，第二次）

> 目的：对 `research.md` / `design.md` / `decisions.md` 的**前提**做一次独立复核，而不是重做调研。
> 本文只记录本次实测到的事实，以及因此需要订正的结论；既有数据不改写，冲突处在文中标明。

**环境**：Windows 11 Enterprise LTSC 26100.9711，非管理员账户 `testuser`，winget `v1.29.380`
**时段**：2026-11-01 10:43–11:05（Asia/Shanghai），与 `research.md` 同日、同一网络

## 0. 方法与边界

- **只用 64 KB–768 KB 的 Range 请求**做连通性与速率判断，避免重复 `research.md` §4 的压测事故（那次导致该 IP 的 GitHub 资产下载被惩罚）。
- **未执行任何需要管理员的命令**：本会话的审批被禁用，`winget source add` 探针（roadmap 0.3）仍未做。
- 规范与源码经 `gh-proxy` 获取（`raw.githubusercontent.com` 在本机直连不可用）。

## 1. 与 `research.md` 一致的部分

以下事实经复跑确认无误，原文档可以信任：

| 项 | 值 |
|---|---|
| winget 版本 | `v1.29.380` |
| 已注册源 | `msstore` / `winget` / `winget-font`（与前文完全一致） |
| adminSettings 六项 | 全部 `false` |

`winget settings export` 输出的用户设置文件路径为
`%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json`，
印证了 `research.md` §2.1 的结论：**手工向该文件写 `adminSettings` 无效**。

## 2. 与 `research.md` 不一致的部分

### 2.1 直连 GitHub 资产：已从"慢"恶化为"完全不可用"

| 探测 | `research.md` 记录 | 本次实测 |
|---|---|---|
| 发布资产（ripgrep 15.2.0，64 KB Range） | 37.2 KB/s（完整 1.71 MB） | **`http=000`，20.0 s 超时，0 字节** |
| `github.com` 首页 | 200 | 200，但 **8 s 只收到 262,144 字节（≈32 KB/s）后停止**，日志显示 schannel 反复重协商 |
| `api.github.com` | 200 | 200 / 0.78 s ✅ |
| `codeload.github.com` | 301 | 301 / 0.95 s ✅ |
| `objects.githubusercontent.com` | 未测 | 404 / 0.90 s（能建 TLS，仅路径无内容） |
| `release-assets.githubusercontent.com` | 未测 | 404 / 0.92 s（同上） |

**判断**：域名层可达，**资产下载路径被钳制**。`github.com` 不是"连不上"，而是"连上后传输被打断"——这比彻底不通更难处理，因为客户端会挂在自己的超时上。

> 结论：`research.md` §3.1 的 23–46 KB/s **不再代表当前状态**。当前直连资产 = 不可用。

### 2.2 加速器：实际只剩一个可用

| 加速器 | 结果 |
|---|---|
| `gh-proxy.com` | **206**，64 KB @ 54 KB/s；768 KB @ **468 KB/s**（单连接，TTFB 0.72 s） |
| `ghfast.top` | **`http=000`，12.0 s 超时**（DNS 可解析到 23.95.31.126） |

`config.example.json` 里的两个加速器**已死一个**，`priority` 回退链目前形同虚设。

**一个对设计至关重要的正面结论**：`gh-proxy` 对 Range 请求返回
`HTTP/1.1 206` + `Content-Range: bytes 0-1023/1789611`，**响应中没有 `Location` 头**。
即它**转发字节、不 302 重定向到真实资产地址**，且保留 Range 语义。

这一点是 `design.md` 方案成立的隐含前提：如果加速器改用 302 跳回
`release-assets.githubusercontent.com`，winget 会自己跟过去，加速效果归零。
**已证实 gh-proxy 不会这样**，但其它加速器未逐一验证——见 §6 待办。

同时注意：本次只证实了 gh-proxy 对 `github.com` 与 `raw.githubusercontent.com` 有效，
`objects.githubusercontent.com` / `release-assets.githubusercontent.com` **未经证实**。

## 3. 协议层：`design.md` §3.4 的未决项已基本解决

### 3.1 规范来源（可复现）

```
https://gh-proxy.com/https://raw.githubusercontent.com/microsoft/winget-cli-restsource/main/documentation/WinGet-1.1.0.yaml
```

| 项 | 值 |
|---|---|
| 大小 | 61,887 字节 / 1,906 行 |
| SHA-256 | `883120cf19ff88a3b0b7b59fc7f9554088d6d5d97860db6389761e422fa76fcc` |
| 标题 | `Open Windows Catalog API`，`info.version: 1.1.0` |

规范共 12 个 `paths`，其中**客户端只用到 3 个**：`/information`、`/manifestSearch`、`/packageManifests/{PackageIdentifier}`。
其余 `/packages...` 系列属于**发布端**（`winget-cli-restsource` 的 Azure Functions 实现用它写入仓库），本项目无需实现。

### 3.2 逐条回答原文档的未决项

| 原"未确认项" | 结论 |
|---|---|
| `ServerSupportedVersions` 格式 | `array<string>`，`minItems: 1`；元素 `minLength: 1` / `maxLength: 128` |
| `/information` 响应字段 | `SourceIdentifier` + `SourceAgreements` + `ServerSupportedVersions`（三者构成 `InformationSchema`） |
| `manifestSearch` 请求字段 | `MaximumResults`(int) / `FetchAllManifests`(bool) / `Query{KeyWord,MatchType}` / `Inclusions[]` / `Filters[]`（后两者元素为 `SearchRequestPackageMatchFilterSchema`） |
| `manifestSearch` 响应字段 | `Data[]` + `RequiredPackageMatchFields` + `UnsupportedPackageMatchFields` + `ContinuationToken` |
| 包不存在返回什么 | **404 + `array<Error>`**，`Error = {ErrorCode:int, ErrorMessage:string}`（**不是**空结果） |
| 三类文档怎么给 | **一个响应里嵌套**：`ManifestSchema = PackageSchema + Versions[]{ PackageVersion, Channel, Locales[], Installers[] }`；不需要三个请求 |
| ETag / 缓存头 | 规范未要求，可后置 |

`MatchType` 枚举（7 种）：`Exact`、`CaseInsensitive`、`StartsWith`、`Substring`、`Wildcard`、`Fuzzy`、`FuzzySubstring`。

`PackageMatchField` 枚举（9 种）：`PackageIdentifier`、`PackageName`、`Moniker`、`Command`、`Tag`、`PackageFamilyName`、`ProductCode`、`NormalizedPackageNameAndPublisher`、`Market`。

### 3.3 版本协商机制（修正 ADR-008 的关键）

`microsoft/winget-cli` 的 `src/AppInstallerRepositoryCore/Rest/RestClient.cpp` 中：

```cpp
std::set<Version> WingetSupportedContracts = {
    Version_1_0_0, Version_1_1_0, Version_1_4_0, Version_1_5_0, Version_1_6_0,
    Version_1_7_0, Version_1_9_0, Version_1_10_0, Version_1_12_0, Version_1_28_0,
};
```

协商函数 `RestClient::GetLatestCommonVersion(serverSupportedVersions, wingetSupportedVersions)`
对两侧取**交集后取最大值**。

因此：

1. **服务端只声明 `["1.10.0"]` 是安全的**——客户端会回落到 1.10.0，连接不会被拒。
2. 1.10.0 在客户端支持集内，`design.md`/`decisions.md` 里"C 方案风险高"的判断**可以下调**。
3. **风险**：若客户端版本过旧（不支持 1.10.0），只声明单版本会导致协商失败。缓解：`doctor` 检查 winget 版本并给明确报错。
4. 注意该清单取自 `master`，与 `v1.29.380` 的发布分支可能有细微差异；实现时用本机客户端抓一次 `/information` 请求即可最终确认。

### 3.4 一个新发现：版本维度是**双向**的

`decisions.md` ADR-008 只讨论了"**输出**哪个契约版本"，但 `microsoft/winget-pkgs` 里的 YAML 清单本身横跨多个 schema 版本。
输出 1.10.0，就必须**把任意旧版清单读进来、转成 1.10.0 形状**再吐出。

也就是说：`rewinged` 那 ~200 KB 模型里，有相当一部分是**读取侧**成本，而非输出侧。
ADR-008 的"代码量"估算低估了这件事，详见订正后的 ADR-008。

## 4. HTTPS 是否强制：仍未定论，但先验概率变了

在客户端源码中检索 scheme 校验，结果：

| 文件 | `https` 命中 |
|---|---|
| `Rest/RestClient.cpp` | 0 |
| `RepositorySource.cpp` | 0 |
| `Commands/SourceCommand.cpp` | 1（但只是 `https://aka.ms/winget-command-source` 帮助链接） |

**没有找到"必须 HTTPS"的校验**，这与 `research.md` §8 里 FerryWinget 用 `http://` 注册源的记载一致。

但这是**间接证据**，不能替代提权实测（roadmap 0.3）。**在结论确定前，不要提前做证书入信任库这一步**——否则可能白改一次机器信任库。

## 5. 工具链现状（订正 ADR-009 的前提）

| 工具 | 状态 |
|---|---|
| `git` | ✅ `C:\Program Files\Git\cmd\git.exe` |
| `pwsh` | ✅ 7.6.9 |
| **`uv`** | ✅ **已安装**：`%LOCALAPPDATA%\Microsoft\WinGet\Packages\astral-sh.uv_*\uv.exe`（由 winget 装的 `astral-sh.uv`） |
| `go` | ❌ 不在 PATH |
| `python` / `py` | ❌ 不在 PATH（但 `uv` 可按需拉取 CPython：`uv python install`） |
| `node` / `pnpm` | ❌ |
| `dotnet` | ❌ |

同级目录 `D:\workspace\github` 下的 `ashare-emotion-shortline` 与 `nvx` 都在用 `uv` + `.venv`。

> `decisions.md` ADR-009 写的"本机没有 Go、没有 .NET SDK、没有 Node，只有 git 与系统自带 PowerShell"**已不成立**：`uv` 提供了零摩擦的 Python 环境。

## 6. 本次复核引出的待办

### P0（阻塞或会导致返工）

| # | 事项 | 说明 |
|---|---|---|
| V1 | **健康检查改为按加速器各自探测** | 现 `probeUrl` 指向被封的 `github.com` 资产：直连都拿不到，测的就不是"加速器好坏"，而是"GitHub 是否活着"。全部加速器会因此被同时误判为不健康 |
| V2 | **`fallbackToOriginal` 语义要用超时兜住** | 直连是"握手成功、传到一半卡死"，不是"慢但可用"。当前配置会让安装表现为**长时间无响应**，比明确失败更糟 |
| V3 | **验证加速器对每个白名单 host 是否都可用** | 已证实 gh-proxy 支持 `github.com` / `raw.githubusercontent.com`；`objects.` / `release-assets.` 未证实。改写前应做 host × 加速器 的能力矩阵 |
| V4 | **核对本机客户端实际的 `ServerSupportedVersions` 交集** | 见 §3.3 第 4 点 |

### P1

| # | 事项 |
|---|---|
| V5 | `manifestSearch` 的匹配语义单独设计：7 种 `MatchType` × 9 种 `PackageMatchField` 如何降级、`Filters`/`Inclusions` 如何组合、排序与 `MaximumResults` 截断 |
| V6 | 建立协议测试 fixture：为三个端点各存"请求 → 期望响应"样本，否则回归只能靠人工 `winget show` |
| V7 | 探针 URL 不再硬编码具体资产版本（现为 ripgrep 15.2.0，会腐烂） |
| V8 | 若 HTTPS 强制，先试 `CurrentUser\Root`，再退到 `LocalMachine\Root`（后者是机器级变更） |

## 7. 复现命令

```powershell
# 直连 GitHub 资产（预期 000 / 超时）
curl.exe -s -o NUL --max-time 20 -r 0-65535 -w "http=%{http_code} time=%{time_total}s`n" `
  'https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip'

# 经加速器（预期 206 + Content-Range）
curl.exe -s -o NUL -D - --max-time 15 -r 0-1023 `
  'https://gh-proxy.com/https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip'

# 拉取 OpenAPI 规范
curl.exe -sL --max-time 60 -o WingetRest.yaml `
  'https://gh-proxy.com/https://raw.githubusercontent.com/microsoft/winget-cli-restsource/main/documentation/WinGet-1.1.0.yaml'
```

> 提醒：以上每条只取 ≤768 KB，不要在此基础上加并发——`research.md` §4 的教训仍然有效。
