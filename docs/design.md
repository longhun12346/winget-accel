# 设计说明

## 目标和边界

项目只解决一件事：让 Windows 上的 `winget` 下载 GitHub 安装包时能够使用公共 URL
前缀加速服务。它不替换 winget 源、不同步清单、不注册新的源，也不把自己做成通用 GitHub
代理。

下载内容仍由 winget 使用官方清单中的 `InstallerSha256` 校验。代理改写请求 URL，不改写
响应体。公共加速服务的运行期探测只确认可达和下载能力；维护候选清单的任务另行使用
字节校验筛除内容不一致的服务。

## 1. 请求路径

```text
winget ──查询清单──> cdn.winget.microsoft.com       DIRECT
  |
  └─下载 InstallerUrl──> GitHub 下载域名
                             |
                             └─PAC──> 127.0.0.1:8443
                                       ├─ TLS MITM + 路径改写
                                       ├─ TLS MITM + 原站转发
                                       └─ 非改写子域隧道
```

默认白名单由 `rewriteHosts` 给出：`github.com`、`objects.githubusercontent.com`、
`codeload.github.com`、`release-assets.githubusercontent.com`。白名单 host 由本机 CA
签发叶证书并终止 TLS；`*.github.com` 等 PAC 捕获到的子域可以只走隧道，不会自动进入
改写白名单。

代理绑定端口后才会开始证书初始化和系统环境接管。`listen` 固定要求
`127.0.0.1:<非零端口>`，因为 PAC 和 `AutoConfigURL` 都使用这个 IPv4 字面量。

## 2. PAC 为什么对 github.com 整域代理

PAC 由代理提供：`http://127.0.0.1:<port>/winget-accel.pac`。生成的核心逻辑是：

```javascript
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (url.substring(0, 6) == "https:" && (
      host == "github.com" || shExpMatch(host, "*.github.com") ||
      host == "objects.githubusercontent.com" ||
      host == "codeload.github.com" ||
      host == "release-assets.githubusercontent.com")) {
    return "PROXY 127.0.0.1:8443";
  }
  return "DIRECT";
}
```

WinINet 对 HTTPS 调用 PAC 时不会提供完整路径，路径规则在 winget 场景中无法可靠命中。
因此 `github.com` 必须整域交给本机；代理收到真实 HTTP 请求后，再由
`rewrite::needs_rewrite` 判断路径：

- `/releases/download/`
- `/releases/latest/download/`
- `/archive/`
- `/raw/`
- `/blob/`

命中这些路径才改写到加速器。普通页面和 Git clone 路径仍以原始 host 建立上游连接。
Git clone 需要发送 POST 请求体，而代理只处理响应体，所以明确不支持。

PAC 只接管 HTTPS。明文 HTTP 经过本地端点会得到 405，避免把可直连请求错误地送入 TLS
终止路径。PAC 不写全局 `ProxyServer`，Microsoft 域名和其它软件源保持 DIRECT。

## 3. TLS 和改写

对需要 MITM 的 host，代理向客户端签发带正确 SAN 的叶证书，CA 使用 Name Constraints
限制到配置白名单及其子域，`path_length=0` 防止继续签发下级 CA。CA 保存在 exe 目录的
`certs` 中，启动时复用现有 CA；白名单变化时会检查证书中的真实约束，避免只相信旁边的
meta 文件。

改写请求时：

1. 保留原始 HTTP 方法、Range、If-Range、If-None-Match 等端到端头；
2. 删除 `Connection` 指定的逐跳头、`Proxy-Authorization` 和 `Proxy-Authenticate`；
3. 生成加速器 URL，把原始完整 URL 放入服务要求的路径前缀；
4. 不修改响应状态、响应头或响应体；
5. 对 Range 请求拿到上游 200 整包时拒绝透传，避免客户端把整包当作分片。

代理不转发请求体。带 `Content-Length > 0` 或分块请求会快速返回 501，并记录
`REQ-BODY-UNSUPPORTED`。对 `Expect: 100-continue` 的客户端，会设置短读超时，避免等待
一个不会被代理转发的请求体。

## 4. 连接管理

代理是同步线程模型，每个连接一个处理线程，并设有总连接上限。隧道还有独立上限，避免
浏览器打开大量 GitHub 子域连接后占满所有名额，导致真正的下载无法建立。PAC 和 `/health`
在连接满时仍保留本地端点服务能力。

隧道只搬运字节，不解析 TLS；任一方向在空闲超时内没有数据就关闭。MITM 路径按 HTTP 响应
的 Content-Length、Transfer-Encoding 或连接关闭正确界定正文，并区分超时、提前 EOF 等
`RELAY-ERR` 类型。

## 5. 候选池和健康状态

候选来源按优先级排列：启动时尝试刷新公共候选清单，失败时使用缓存，再失败时使用编译期
内置清单。用户显式填写 `accelerators` 时，配置候选取代自动池。

候选必须先通过两步验证：

1. 访问候选自身根路径，确认网络可达；
2. 使用 `health.probeUrl` 指向的 HTTPS GitHub 资产发送 Range，要求返回 206 并取得足够正文。

未验证、验证失败、连续过慢的候选不会进入下载选择。例行巡检对已经通过验证且仍健康的
候选只检查根路径；其余候选必须重新进行资产验证，不能因为首页返回 200 就重新放行。
启动探测最多运行约 30 秒；没有候选通过时，服务仍可启动，但下载返回 502 并继续后台恢复。

真实下载成功会记录速度样本并更新候选权重。候选返回 429/5xx 或连接失败时按服务级别
处理；同一候选对同一 host 连续返回 403/404 时，运行期能力学习会临时跳过这个组合。
这些运行期状态只在内存中存在，不修改配置文件。

`health.enabled=false` 只关闭例行巡检；全部候选失效后的恢复探测仍运行，否则一次启动抖动
就可能永久保持 502。

## 6. 失败和重试

幂等下载请求可以在候选间切换。代理只在没有向客户端写出正文前重试，并受候选数量和总
时间预算限制。成功响应直接透传；候选耗尽时：

- 最后状态是明确的上游拒绝，保留该状态码供客户端和日志排查；
- 没有任何已验证候选或 Range 语义不安全时返回 502；
- 不向原始 GitHub 直连回退。

公共服务可能临时限流，运行期会记录 `ACCEL-COOLDOWN` 并换候选。下载文件的官方哈希
仍是最终内容完整性边界。

## 7. 系统环境接管

零参数模式会接管三项当前用户设置：

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL`
- 当前用户根证书存储中的本项目 CA
- winget 用户设置里的 `network.downloader=wininet`

`--no-env` 不接管这些设置，适合自动化和本地协议测试。

PAC 状态和用户级锁放在 `%LOCALAPPDATA%\winget-accel`：

```text
pac.lock
state.json
```

程序取得独占文件锁后才会恢复旧状态或写入新状态；锁文件本身不删除，句柄释放即解除锁。
`state.json` 使用版本 2，记录：

- 接管前的 PAC 值；
- 本次写入的 PAC 值；
- 会话标识；
- winget 设置原值、文件路径和是否由本次创建。

状态先原子写入并同步到磁盘，看门狗成功启动后才修改注册表。恢复时必须同时满足会话
匹配和当前设置仍属于本实例；用户在运行期间的新设置会保留。状态损坏或读取失败时保留
文件并停止自动接管，不把错误解释成“原来没有设置”。旧格式仍可迁移读取。

## 8. 退出和看门狗

正常 `Drop`、控制台事件、看门狗和下次启动恢复共享同一套归属检查。看门狗使用
`CREATE_NO_WINDOW` 启动，不继承父控制台；它等待父进程退出，取得同一把锁，再按会话恢复
PAC 和 winget 设置。旧看门狗发现状态属于新会话时跳过，不删除新状态。

日志会记录 `PAC-RESTORED`、`WINGET-RESTORED` 和实际结果。控制台事件路径会先尝试恢复，
但保留状态供看门狗再次核对，以覆盖事件处理和主线程最后一次写入交错的窗口。

## 9. winget 下载器设置

Delivery Optimization 不读取当前用户 PAC；如果保持默认下载器，winget 可能先直连 GitHub
并等待失败，再回退 WinINet。默认启动时把用户设置中的 `network.downloader` 设为 `wininet`，
只修改这个字段，JSON 中其它字段原样保留。非法 JSON 不覆盖，只记录警告；
`wingetDownloader=false` 时完全跳过这一步。

恢复时使用与 PAC 相同的状态文件和看门狗。若用户在运行期间修改了该设置，恢复逻辑会按
文件内容和归属规则保护用户的新值。

## 10. 诊断

`--doctor` 不改系统设置，主要检查：

- 配置和监听地址；
- CA 文件、实际 Name Constraints 和当前用户信任状态；
- PAC 是否存在、是否由正在运行的实例提供，以及是否与当前配置一致；
- 全局代理 `ProxyEnable`；
- 候选可达性、能力矩阵和测速资产；
- winget 当前下载器设置；
- 多张残留 CA。

`/health` 提供版本、运行时间、连接数、MITM/隧道计数、改写数、正文计数、错误、限流、
连接上限拒绝、绑定表饱和和运行期能力阻断等信息。`bytes` 只统计 MITM 正文，不统计隧道。

## 11. 测试和发布

Rust 单测覆盖解析、证书约束、PAC、健康状态、重试和恢复逻辑。Python 协议用例启动真实
Rust 二进制并使用本地假上游，覆盖 TLS、改写、Range、响应定界、并发、PAC 语义和多进程
看门狗。真实网络用例需要显式开启，因为公共服务的存活会变化。

发布前执行：

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
.\packaging\check-docs-sync.ps1
.\packaging\verify.ps1
.\packaging\make-release.ps1
.\packaging\verify-package.ps1
```

CI 还会强制关闭 Cargo ANSI 颜色、修改源文件到未来时间后确认确实重新编译，并比较两次
release 二进制 SHA256。这样可以避免“带颜色的 `Compiling` 文本匹配失败”和“Cargo 因 mtime
跳过重编却被误认为可复现”两类假通过。

## 12. 已知限制

- 公共加速服务可能下线、限流或改变行为；候选池不是可用性保证。
- 默认测速资产绑定一个具体 GitHub release；资产被删除时需要配置 `health.probeUrl`。
- 不支持 HTTP/2、CRL/OCSP 和请求体转发。
- 真实系统模式首次导入 CA 需要可见桌面确认；无交互环境只适合 `--no-env` 测试。
- `github.com` 普通浏览请求会多经过本机 TLS 终止和回源一跳；内容仍原样转发。
- 私钥以明文保存在本机证书目录，目录权限只能尽力收紧。
