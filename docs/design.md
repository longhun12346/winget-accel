# 设计说明

## 目标和边界

项目只解决一件事：让 Windows 上的 `winget` 下载 GitHub 安装包时能够使用公共 URL
前缀加速服务；直连足够快时由 PAC 放行，减少中转。它不替换 winget 源、不同步清单、不注册新的源，也不把自己做成通用 GitHub
代理。

下载内容仍由 winget 使用官方清单中的 `InstallerSha256` 校验。代理改写请求 URL，不改写
响应体。公共加速服务的运行期探测只确认可达和下载能力；维护候选清单的任务另行使用
字节校验筛除内容不一致的服务。

代理策略位于 `src/proxy.rs`，CONNECT、隧道与 TLS 接入位于 `src/proxy/network.rs`，
`src/proxy/probe.rs` 负责候选探测和测速，`src/proxy/local.rs` 提供 PAC 与 `/health`。
`src/http.rs` 统一封装 Hyper 客户端、正文大小限制与完成回调。
`src/routing.rs` 用有界真实资产采样决定精确域名是否可以 DIRECT。

网络使用共享的四线程 Tokio 运行时。Hyper 负责 HTTP/1.1 解析、消息边界、CONNECT 升级
和流式正文；`tokio-rustls` 复用现有 rustls 配置接入异步 TLS。启动、Windows 环境恢复
和后台探测调度保留同步入口，通过运行时桥接调用异步请求，下载任务直接使用异步接口。
安装包不整体缓存在内存中，客户端读取速度通过 Hyper 的正文接口向上游施加背压。

## 1. 请求路径

```text
winget ──查询清单──> cdn.winget.microsoft.com       DIRECT
  |
  └─下载 InstallerUrl──> GitHub 下载域名
                             |
                             └─PAC──┬─ 已验证精确域名 ──> GitHub，DIRECT
                                    └─ 其余 ──> 127.0.0.1:8443
                                       ├─ TLS MITM + 路径改写
                                       ├─ TLS MITM + 原站转发
                                       └─ 非改写子域隧道
```

默认白名单由 `rewriteHosts` 给出：`github.com`、`objects.githubusercontent.com`、
`codeload.github.com`、`release-assets.githubusercontent.com`。需要代理的白名单 host 由本机 CA
签发叶证书并终止 TLS；`*.github.com` 等 PAC 捕获到的子域可以只走隧道，不会自动进入
改写白名单。

代理绑定端口后才会开始证书初始化和系统环境接管。`listen` 固定要求
`127.0.0.1:<非零端口>`，因为 PAC 和 `AutoConfigURL` 都使用这个 IPv4 字面量。

## 2. PAC 为什么对 github.com 整域代理

PAC 由代理提供：`http://127.0.0.1:<port>/winget-accel.pac`。自动模式在以下代理规则之前
插入经过验证的精确 host DIRECT 条款，条款带毫秒级到期时间；没有有效证据时逻辑是：

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
因此需要加速的 `github.com` 整域交给本机；代理收到真实 HTTP 请求后，再由
`rewrite::needs_rewrite` 判断路径：

- `/releases/download/`
- `/releases/latest/download/`
- `/archive/`
- `/raw/`
- `/blob/`

命中这些路径才改写到加速器。普通页面和 Git clone 路径仍以原始 host 建立上游连接；它们无需健康候选，原站的拒绝状态和正文也不会触发候选冷却或能力学习。
经代理的 Git clone 需要发送 POST 请求体，而代理只处理响应体，所以明确不支持。

PAC 只接管 HTTPS。明文 HTTP 经过本地端点会得到 405，避免把可直连请求错误地送入 TLS
终止路径。PAC 不写全局 `ProxyServer`，Microsoft 域名和其它软件源保持 DIRECT。

### 自动直连判据

默认 `routing.mode=auto`。启动时及每 300 秒检查 Git for Windows release 安装包和
git/git 的 codeload 归档。每个资产连续采样两次，每次 256 KiB，较低速度必须达到
`routing.minDirectKbps`（默认 512 KiB/s）。每个资产两次采样共用 5 秒总期限，包含
DNS、TLS、重定向及正文；不同资产并行检查。配置最多 8 个自定义 HTTPS/443 资产。

只跟随白名单内最多 5 次绝对 HTTPS 重定向。206 要求精确 Range 和完整正文；忽略 Range
的 200 只取前 256 KiB 后取消。短正文、HTML、JSON、压缩编码或非法范围都不能作为证据。
只放行两次成功链中都出现的精确 host。一个域名有多份成功样本时取最低速度；该域名
自身的测速资产失败则不放行。未覆盖的 CDN 和 github.com 子域继续使用代理。

探测失败立即撤销内存中的直连选择，恢复直连需经过默认 300 秒冷却；结果不持久化。
DIRECT 条款有效期为复查间隔加探测期限再加 10 秒，过期证据不会由新 PAC 放行，
`/health.routing` 也会标记 `expired`。`routing.mode=accelerator` 跳过直连检查。
显式指定本机 HTTP 代理的客户端仍按加速器策略转发；直连选择由 PAC 生效。

更新时修改 PAC URL 的会话/版本查询参数，发送 WinINet 设置变更和刷新通知，并为
本地 PAC 返回 `Cache-Control: no-store, max-age=0`。旧脚本再次求值时自行拒绝过期证据，
但 Windows 也可能缓存代理决策，现有连接不会迁移，不保证所有客户端立即切换。

## 3. TLS 和改写

对需要 MITM 的 host，代理向客户端签发带正确 SAN 的叶证书，CA 使用 Name Constraints
限制到配置白名单及其子域，`path_length=0` 防止继续签发下级 CA。CA 保存在 exe 目录的
`certs` 中，启动时复用现有 CA；白名单变化时会检查证书中的真实约束，避免只相信旁边的
meta 文件。续期可以更新本地文件，但只有系统接管模式才修改受信任根；`--no-env` 不导入或删除系统根证书。

改写请求时：

1. 保留原始 HTTP 方法、Range、If-Range、If-None-Match 等端到端头；
2. 删除 `Connection` 指定的逐跳头、`Proxy-Authorization` 和 `Proxy-Authenticate`；
3. 生成加速器 URL，把原始完整 URL 放入服务要求的路径前缀；
4. 保留响应状态和端到端头，剥离逐跳头；正文内容保持一致，HTTP 分帧由 Hyper 重新生成；
5. 对 Range 请求拿到上游 200 整包，或 206 的显式 Content-Range 与请求、文件总长、Content-Length 不一致时，在下游响应头发出前拒绝并换候选。

范围一致性检查覆盖单段、开放尾部和后缀范围，允许文件末尾截短。部分公共服务缺少
Content-Range 时仍兼容透传；不解析 multipart 正文中的各段。最终文件完整性仍由 winget 校验。

代理不转发请求体。带 `Content-Length > 0` 或分块请求会快速返回 501，并记录
`REQ-BODY-UNSUPPORTED`。对 `Expect: 100-continue` 的客户端直接拒绝，不轮询正文，
避免为不支持的请求发送 100 Continue；其它正文只在 300 ms / 64 KiB 范围内尝试排空。

## 4. 连接管理

代理接受连接后立即占用名额，包含尚未发送请求的空闲连接；总上限为 64，隧道上限为 48。
名额跨 CONNECT 升级保留，直到 TLS 或隧道任务结束才释放。网络连接使用异步任务，不再
每连接创建线程。证书签发通过 Tokio 阻塞任务执行，避免占住网络工作线程。

达到上限后，最多再保留 16 个短期连接处理 PAC 与 `/health`，首个请求头期限为 200 ms；
其它请求返回 503，空闲超额连接也在约 200 ms 后得到 503。本地端点不会被下载连接占满。

隧道只搬运字节，不解析 TLS；任一方向在空闲超时内没有数据就关闭。MITM 路径按 HTTP 响应
的 Content-Length、Transfer-Encoding 或连接关闭正确界定正文，并区分超时、提前 EOF 等
`RELAY-ERR` 类型。

Hyper 解码上游分帧并按下游连接重新编码，不承诺保留原始块大小、块扩展、头部大小写
或不被客户端接受的 trailer。安装包字节、Range 和端到端响应头的语义必须保持一致。
收到完整终止块及 trailer 后立即收尾，不等待上游 EOF；缺少终止块或正文截断会使下游
响应失败，并清除文件绑定，不会在已发送响应头后拼接另一个候选的正文。

请求头按 32 KiB 预算限制，超限返回 431；Hyper 同时限制解析缓冲。首个请求头期限为
10 秒，连接、DNS、上游 TLS 握手与响应头受每次尝试的总期限限制，正文和隧道使用 60 秒
读写空闲超时。持续传输的大文件不会被固定总下载时长截断。

## 5. 候选池和健康状态

候选来源按优先级排列：启动时尝试刷新公共候选清单，失败时使用缓存，再失败时使用编译期
内置清单。网络源均成功时优先采用权威源，不能用条目更多的旧镜像覆盖删除结果。
用户清单、缓存中的有效空列表表示全部停用，不另加硬编码候选。用户显式填写 `accelerators` 时，配置候选取代自动池。

候选清单与下载转发共用 HTTP 响应分帧逻辑。清单正文限制为 1 MiB，分块响应读取到
终止块和 trailer 末尾即结束；截断、格式错误或超限响应不会作为有效清单缓存。

维护脚本将样本哈希不符的候选移入带 `quarantined` 标记的 watchlist，内置候选也不例外。
隔离不因临时故障、漏测或失败次数而消失，只有重新通过样本哈希校验才能解除。运行时
同样尊重隔离记录；内置候选只有普通网络故障时才保留离线兜底。

候选必须先通过两步验证：

1. 访问候选自身根路径，确认网络可达；
2. 使用 `health.probeUrl` 指向的 HTTPS GitHub 资产发送 Range，要求返回 206 并取得足够正文。

测速正文最多读取 64 KiB；超过上限的响应不作为有效样本。分块扩展与 trailer 不计入
下载量，分帧开销也有读取上限，避免把元数据误当成下载能力。
探测的 socket 读写共用时间预算，持续零星返回数据不会反复延长截止时间。

未验证、验证失败、连续过慢的候选不会进入下载选择。例行巡检对已经通过验证且仍健康的
候选只检查根路径；其余候选必须重新进行资产验证，不能因为首页返回 200 就重新放行。
启动探测最多运行约 30 秒；没有候选通过时，服务仍可启动，但下载返回 502 并继续后台恢复。

真实下载成功会记录速度样本并更新候选权重，同时保留 30 分钟的 host 支持证据，
避免后续两个文件 403/404 把已验证组合误排除。证据过期后，须重新累计两次不支持才能排除；
成功和失败记录共用 512 项上限。候选返回 429/5xx 或连接失败时按服务级别
处理；同一候选对同一 host 连续返回 403/404 时，运行期能力学习会临时跳过这个组合。
这些运行期状态只在内存中存在，不修改配置文件。

相对速度门槛只比较其它健康候选的近期样本；没有其它可用候选时，只应用绝对最低速度
限制。候选自己的启动测速峰值、已失效或过期候选的旧速度都不会成为淘汰它的依据。

`health.enabled=false` 只关闭例行巡检；全部候选失效后的恢复探测仍运行，否则一次启动抖动
就可能永久保持 502。

## 6. 失败和重试

幂等下载请求可以在候选间切换。代理只在没有向客户端发送响应头前重试，并受候选数量和总
时间预算限制。每次尝试的 DNS、连接、TLS 和响应头期限取单次上限与剩余总预算的较小值，
不会在切换候选后重新获得完整预算。成功响应直接透传；候选耗尽时：

- 最后状态是明确的上游拒绝，保留该状态码供客户端和日志排查；
- 没有任何已验证候选或 Range 语义不安全时返回 502；
- 代理内不向未经验证的原始 GitHub 直连回退；PAC 自动直连由独立的采样证据决定。

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
- 本次写入的 PAC 值，以及刷新中途的上一值；
- 会话标识；
- winget 设置原值、文件路径和是否由本次创建。

状态先原子写入并同步到磁盘，看门狗成功启动后才修改注册表。恢复时必须同时满足会话
匹配和当前设置仍属于本实例；用户在运行期间的新设置会保留。状态损坏或读取失败时保留
文件并停止自动接管，不把错误解释成“原来没有设置”。旧格式仍可迁移读取。

系统模式的 PAC URL 带本次 `session` 和 `route` 版本。刷新前原子记录新旧 URL，
写入注册表后再清理旧值；崩溃发生在任一侧都能恢复。刷新与退出恢复共用互斥锁，
不同会话或用户手工修改的 PAC 不会被覆盖。`--no-env` 不创建系统恢复上下文，
后台路由刷新仅更新内存和本地端点。

## 8. 退出和看门狗

正常 `Drop`、控制台事件、看门狗和下次启动恢复共享同一套归属检查。看门狗使用
`CREATE_NO_WINDOW` 启动，不继承父控制台；它等待父进程退出，取得同一把锁，再按会话恢复
PAC 和 winget 设置。旧看门狗发现状态属于新会话时跳过，不删除新状态。

`PAC-RESTORED` 日志记录整个环境恢复事务的实际结果。PAC 与 winget 均完成恢复或确认
已被用户修改后才删除状态文件；任一步失败均保留原始记录，可在解锁或下次启动时重试。控制台事件路径会先尝试恢复，
但保留状态供看门狗再次核对，以覆盖事件处理和主线程最后一次写入交错的窗口。

## 9. winget 下载器设置

Delivery Optimization 不读取当前用户 PAC；如果保持默认下载器，winget 可能先直连 GitHub
并等待失败，再回退 WinINet。默认启动时把用户设置中的 `network.downloader` 设为 `wininet`，
使其遵循 PAC 的 DIRECT / PROXY 选择。只修改这个字段，JSON 中其它字段原样保留。非法 JSON 不覆盖，只记录警告；
`wingetDownloader=false` 时完全跳过这一步。

恢复时使用与 PAC 相同的状态文件和看门狗。若用户在运行期间修改了该设置，恢复逻辑会按
文件内容和归属规则保护用户的新值：只有当前字段仍为 `wininet` 才恢复，字段或文件
已被用户删除时也不重建。

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
`routing` 提供路由模式、版本、每个 host 的直连选择、速度、最近检查时间、有效期和原因；
PAC DIRECT 流量绕过本机，不计入代理下载统计。

## 11. 测试和发布

Rust 单测覆盖解析、证书约束、PAC、健康状态、重试和恢复逻辑；Rust 协议集成测试启动
真实二进制并使用本地假上游，覆盖改写、Range、响应定界、并发、PAC 端点和连接边界。
客户端调用 Windows 自带的 `curl.exe` 验证 Schannel 与 CONNECT 行为。真实公共服务不作为
离线回归的固定依赖，因为服务的存活和限流会变化。
自动路由的离线测试覆盖双采样、期限、重定向范围、过期和冷却；Windows 自带的 WinHTTP
PAC 引擎验证 DIRECT 精确匹配、过期及 URL 版本切换。注册表测试使用独立临时键，
验证刷新前后崩溃恢复，不改真实 Internet Settings。

发布前执行：

```powershell
cargo fmt --all -- --check
cargo fetch --locked
cargo clippy --all-targets --offline -- -D warnings
cargo test --bin winget-accel --offline
cargo test --test protocol --offline -- --test-threads=1
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
- 默认测速资产绑定具体版本；资产删除时需配置 `health.probeUrl` 或 `routing.probeUrls`。
- 不支持 HTTP/2、CRL/OCSP 和请求体转发。
- 真实系统模式首次导入 CA 需要可见桌面确认；无交互环境只适合 `--no-env` 测试。
- 未验证为 DIRECT 的 `github.com` 普通浏览请求会多经过本机 TLS 终止和回源一跳。
- 直连速度来自短样本估计，不能保证所有安装包或网络变化后的实际表现。
- 私钥以明文保存在本机证书目录，目录权限只能尽力收紧。
