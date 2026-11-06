# winget-accel

`winget-accel` 是一个 Windows 本地代理，让 `winget` 下载 GitHub 安装包时使用公共
GitHub 加速服务。它不替换 winget 源、不修改清单，也不维护自己的软件包索引。

默认先检查真实下载资产的直连表现：连续两次达到速度门槛的精确域名由 PAC 返回
`DIRECT`，绕过本机代理和公共加速服务。其余域名交给本机，终止 TLS 后按请求路径
改写到公共加速服务，并流式转发正文。安装包完整性仍由 winget 根据官方清单中的
`InstallerSha256` 校验。

## 先看边界

- 只支持 Windows 10/11 x64，不需要管理员权限、VC++ 运行库或 .NET。
- 只使用公共 URL 前缀加速服务；候选池会在启动时刷新，也有本地缓存和内置兜底。
- 经本机代理的 `git clone` 等带请求体的 Git 操作会被拒绝；已验证为 DIRECT 的连接不经过本工具。
- 需要加速的 `github.com` 在 PAC 层按整域交给本机，因为 WinINet 的 HTTPS PAC 调用不提供路径。
  代理再按路径区分下载和普通页面；直连例外不自动放行未测试的子域。
- 代理内候选用尽仍返回 `502`，不盲目回退到未经验证的直连。

## 安装和运行

从 Releases 下载 `winget-accel-<版本>-win-x64.zip`，解压到有写权限的目录，例如：

```text
D:\Tools\winget-accel
%LOCALAPPDATA%\winget-accel
```

不要直接放进 `C:\Program Files\`。程序需要在 exe 目录写证书、日志和候选缓存；PAC
恢复记录和多实例锁则统一放在 `%LOCALAPPDATA%\winget-accel`。

双击 `winget-accel.exe`。默认模式会依次完成：

1. 预留监听端口，生成或复用本机 CA；
2. 检查真实资产的直连能力并验证公共加速候选；
3. 请求把 CA 加入“当前用户\受信任的根证书颁发机构”，供需要加速的连接使用；
4. 设置当前用户 PAC，把 winget 的 `network.downloader` 设为 `wininet`；
5. 报告“已就绪”，在 `127.0.0.1:8443` 提供服务并后台更新路由。

第一次安装 CA 时会出现 Windows 确认框，需要在可见桌面中点击“是”。确认完成后，在另一个
终端正常使用：

```powershell
winget install Git.Git
winget download --id junegunn.fzf --download-directory "$env:TEMP\winget-test"
```

按 `Ctrl+C` 停止。程序会恢复 PAC 和 winget 下载器设置。被强制结束时，看门狗会在父进程
退出后尝试恢复；如果用户在运行期间手动修改或删除 PAC，程序会保留用户的新设置。

## 代理链路

```text
winget 查询清单  ──>  官方 winget 源，DIRECT
       |
       └─ 下载 GitHub 资产 ── PAC ──┬─ 已验证够快的精确域名 ──> GitHub，DIRECT
                                   └─ 其余 ──> 127.0.0.1:8443
                                      ├ github.com 下载路径
                                      │  └ TLS MITM -> 公共加速器 -> GitHub
                                      ├ github.com 普通路径
                                      │  └ TLS MITM -> 原样转发 GitHub
                                      └ 其它 GitHub 子域
                                         └ 隧道转发
```

默认白名单是：

- `github.com`
- `objects.githubusercontent.com`
- `codeload.github.com`
- `release-assets.githubusercontent.com`

CA 使用 Name Constraints 限制签发范围为这四个域及其子域。代理只监听 `127.0.0.1`，
不写全局 `ProxyServer`，不修改 Microsoft 域名和其它软件源。

## 配置

复制 `config.example.json` 为 `config.json` 后按需修改：

```powershell
Copy-Item .\config.example.json .\config.json
winget-accel.exe --config .\config.json
```

常用字段：

| 字段 | 作用 |
|---|---|
| `listen` | 监听地址，只接受 `127.0.0.1:<固定端口>` |
| `rewriteHosts` | 终止 TLS 并允许 URL 改写的精确主机名 |
| `accelerators` | 自定义公共加速候选；非空时替代自动候选池 |
| `routing.mode` | `auto` 默认自动判断；`accelerator` 强制公共加速器 |
| `routing.minDirectKbps` | 直连门槛，默认 512 KiB/s |
| `routing.timeoutSeconds` | 每个资产两次采样的总期限，默认 5 秒 |
| `routing.intervalSeconds` / `routing.cooldownSeconds` | 复查间隔和恢复直连的冷却期，默认均为 300 秒 |
| `routing.probeUrls` | 可选的真实直连测速资产；默认检查 release 安装包和 codeload 归档 |
| `health.probeUrl` | 候选测速资产，必须是完整 HTTPS URL |
| `health.enabled` | 是否运行例行巡检；全挂后的恢复探测仍会运行 |
| `mitmExtra` | 额外终止 TLS 但不改写的主机，仅用于排障 |
| `wingetDownloader` | 是否接管 winget 的 `network.downloader`，默认 `true` |
| `certDir` / `logPath` | 覆盖证书目录和日志路径 |

`rewriteHosts` 只接受精确主机名，不接受通配符、协议、路径或端口。修改白名单后，若
已有 CA 的 Name Constraints 不再匹配，程序会提示删除证书目录并重新生成。

自动路由每个资产连续取两段 256 KiB，取较低速度，并将 DNS、TLS 和重定向时间计入。
默认两个资产并行检查，每个资产的总期限为 5 秒。未验证的域名保持代理；
`objects.githubusercontent.com` 等 CDN 只有在成功重定向链中连续两次出现，或显式配置
其测速资产后才可能直连。`/health` 中的 `routing` 给出每个域名的结果、速度和有效期。
这些是小样本估计；可调整门槛，或设 `routing.mode=accelerator` 固定使用加速器。

候选在本机最多四路并发验证，找到两个可用服务即可结束启动等待，候选验证总期限为 8 秒。
后台常规维护约 4 个常用、4 个备用，按需补位并低频探索其它候选，不必每次全量测速。
直连检测与候选验证并行；清单刷新、证书和系统接管的耗时另计。

速度优选只依据本机：64 KiB 短测给初值，第一份真实下载替换初值，后续按新样本 20%、
旧均值 80% 更新。正常下载在评分靠前的四个兼容候选间加权选择，失败自动补位，同文件固定候选。
CI 只验证可用性和样本内容；/health 的候选项提供 pool 和 selectionScore 方便检查本机选择。

路由变化时更新 PAC URL 并通知 Windows，退出后还原原始设置。DIRECT 规则自带有效期，
旧 PAC 再次求值时会拒绝过期的直连证据。Windows 还可能缓存代理决策，不能保证所有客户端
立即切换；现有连接不会被迁移，更新主要影响后续连接。

## 命令

```text
winget-accel [--config <路径>] [--doctor [--quick]] [--remove-ca]
             [--no-env] [--version] [--help]
```

- `--doctor`：只读体检，不修改系统设置，检查端口、证书、PAC、全局代理、候选链和测速资产。
- `--doctor --quick`：找到足够候选后提前结束，适合快速判断网络；完整结论仍用普通 `--doctor`。
- `--remove-ca`：删除当前用户证书存储中属于本工具的 CA。
- `--no-env`：只运行本地代理，不安装 CA、不设置 PAC、不修改 winget 设置，适合测试。
- `--version` / `--help`：显示版本或帮助。

## 安全与恢复

运行默认模式会做两类系统级用户设置：当前用户根证书和 Internet Settings 的 PAC；还会
按配置接管 winget 用户设置中的一个下载器字段。状态写入：

```text
%LOCALAPPDATA%\winget-accel\pac.lock
%LOCALAPPDATA%\winget-accel\state.json
```

`state.json` 记录原 PAC、程序写入的 PAC、会话标识，以及 winget 设置的原值。程序只在当前
PAC 仍等于本次写入值（包括 URL 更新中途记录的新旧值）时恢复它；损坏或无法读取状态时保留文件并停止自动接管，避免把用户
自己的 PAC 当成“原本没有”。winget 只有仍为本程序写入的 `wininet` 时才还原；用户
后续修改或删除的设置会保留。PAC 与 winget 全部处理完成才删除状态，恢复失败可重试。
同一用户的多个解压副本共用锁，旧看门狗不会处理新会话。

CA 私钥以明文保存在 `certs\ca-key.pem`。不要把包含 `certs` 的目录发给别人或放进云同步
目录。卸载时先停止代理，再执行：

```powershell
.\winget-accel.exe --remove-ca
```

最后删除 exe 目录；确认所有实例退出后，可以删除 `%LOCALAPPDATA%\winget-accel` 中的
状态和锁文件。

## 验证和开发

构建需要 Windows MSVC 工具链和 Rust 1.88 或更新版本。CI 同时检查最低版本的编译兼容性，
并在 stable 工具链上执行完整测试。

```powershell
cargo fmt --all -- --check
cargo fetch --locked
cargo clippy --all-targets --offline -- -D warnings
cargo test --bin winget-accel --offline
cargo test --test protocol --offline -- --test-threads=1
cargo build --release --offline

.\packaging\check-docs-sync.ps1
.\packaging\verify.ps1
.\packaging\make-release.ps1
.\packaging\verify-package.ps1
```

首次构建先用 `cargo fetch --locked` 下载锁文件中的依赖，之后测试和构建离线执行。
`verify.ps1` 默认先获取依赖；已有缓存且需要全程离线时，使用 `verify.ps1 -Offline`。

协议测试使用本地假上游，默认不访问外网：

```powershell
cargo test --test protocol --offline -- --test-threads=1
```

协议测试由 Rust 负责启动代理、假上游和临时目录，客户端调用 Windows 自带的
`curl.exe` 验证 Schannel、CONNECT、Range 和 HTTPS 下载行为。真实公共服务会变化，
不能作为离线回归的固定依赖。交付包中的 `SHA256.txt` 记录 exe 哈希；
构建使用 MSVC 静态 CRT 和 `/Brepro`，相同源码、工具链、Cargo 缓存和构建路径条件下可以
重复生成相同二进制。

需要验证真实公共服务时，可运行 `.\packaging\verify-no-env.ps1`。它要求两次 Range 请求
均通过代理取得完整的 64 KiB，并检查成功改写日志，以及运行前、运行中和退出后的
PAC、受信任根、恢复日志与锁的状态。
使用 `.\packaging\verify-no-env.ps1 -RoutingMode auto` 可同时运行真实直连探测，
打印路由结果；负载仍显式经过本机代理，以验证公共加速链和系统设置保护。

## 当前验证边界

已经自动验证：PAC 语义、TLS MITM、URL 改写、Range、分片重组、响应定界、候选切换、
PAC 生命周期、多进程锁、看门狗、公共服务字节保真和本地压测。

真实 `winget` 的系统 PAC + CA 首次确认需要可见桌面点击 Windows 信任对话框；无交互的 CI
不会代替用户点击，因此 CI 使用 `--no-env` 和显式 CA 的协议验证。真实服务和公共候选池
也可能临时限流或下线，运行期会验证候选并自动切换。

## 许可证

本项目使用 MIT 许可证。第三方组件许可见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
