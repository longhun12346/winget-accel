# winget-accel

在本机跑一个代理，用 PAC 只把 4 个 GitHub 下载域名指给它，再由它把请求改写到
GitHub 加速服务——让 `winget install` 在国内网络下也能下得动。

> 状态（2026-11-01）：**Rust 实现已完成并在两台机器上实测通过**。
> 单文件 1.6 MB、静态链接、无运行时依赖、不需要管理员。

## 快速开始

把 `winget-accel.exe` 放到任意文件夹，**双击它**（或直接运行，不带任何参数）：

```
winget-accel.exe
```

它会自动完成四步：生成 CA → 导入「受信任的根证书」（**弹窗点「是」**）→
设置系统 PAC → 开始监听 `127.0.0.1:8443`。窗口保持打开即生效。

然后正常用 winget：

```powershell
winget install Git.Git
```

**停止**：在那个窗口按 `Ctrl+C`，PAC 会被自动还原。

### 为什么不加命令行参数

"双击就能用"是刻意的设计。带参数启动的形态仍然保留，但只用于排障与测试，
不改变零参数的行为（见下方「命令行参数」）。

## 它解决的到底是什么问题

国内网络下 `winget` 的源索引与清单查询正常，**卡在安装包下载**。
同一资源、同一台机器、前后脚测：

| 通道 | 实测 |
|---|---|
| 直连，`curl -L` | **21 KB/s**（30 s 只收到 636,355 B，未下完） |
| 直连，`winget download`（WinHTTP） | **37 s 失败**：`WinHttpSendRequest: 12002`，0 字节落盘 |
| 经本代理，`curl` | **724 KB/s** |
| 经本代理，`winget download`（2.5 MB） | **13 s**，官方哈希校验通过 |
| 经本代理，`winget download`（63.75 MB） | **189 s / 344 KB/s**，哈希校验通过、无截断 |

可测路径上约 **35 倍**。注意两条路径表现不同：`curl` 直连**能通只是慢**，
而 `winget` 走 WinHTTP，37 秒就超时放弃——所以对外表述用"慢到不可用"，
不说"不通"（后者是早期误判，已修正，见 [verification §11](docs/verification-proxy-2026-11-01.md)）。

## 为什么必须是"代理层改写"

代理只能收到 `CONNECT github.com:443`，之后是端到端加密的字节流。只有两种可能：

1. 原样转发到 `github.com` —— 没有加速效果
2. 转发到加速器 —— TLS 握手失败（客户端 SNI 是 `github.com`，加速器证书不是它的）

要让第 2 种成立，必须自己终止 TLS。这是 MITM，必须让系统信任一张本程序生成的 CA。
没有第三条路。所以设计目标不是"避免 MITM"，而是**把 MITM 的代价收敛**：

| 约束 | 做法 | 验证 |
|---|---|---|
| CA 只能签 4 个域名 | `NameConstraints` + `path_length=0` | 签 `example.com` 被 Windows 拒绝 |
| 代理只被 4 个 host 使用 | PAC 只圈这 4 个，其余 `DIRECT` | 非白名单 host 隧道 200 |
| 内容被改会被发现 | winget 仍校验官方 `InstallerSha256` | 63.75 MB 包"已成功验证安装程序哈希" |

MITM 影响的只是"谁能看到你在下载什么"（都是公开安装包），
**不能影响"你下载到的是什么"**。详见 [ADR-014](docs/decisions.md)。

## 安全边界（请读完再决定是否使用）

- **会往「当前用户受信任根」装一张 CA**，有效期 **90 天**（`ca.rs` 的 `CA_VALIDITY_DAYS`）。
  这张 CA 的私钥以**明文**存放在 `certs\ca-key.pem`。
- 该 CA 带 Name Constraints，**只能签这 4 个域名**：`github.com`、
  `objects.githubusercontent.com`、`codeload.github.com`、`release-assets.githubusercontent.com`。
  签其他域名会被操作系统拒绝——所以最坏情况是"冒充这 4 个下载域名"，
  不能冒充银行、邮箱、内网。
- **不要**把含 `certs\` 的文件夹打包分发或放进云同步目录——那是把私钥散出去。
- 已知加固待办见 [roadmap T2](docs/roadmap.md)。

## 卸载（完整还原）

**先按 `Ctrl+C` 停掉**（PAC 会自动还原）。如果窗口是被强行关掉的，按下面手动清：

```powershell
# 1) 清 PAC
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
  -Name AutoConfigURL -ErrorAction SilentlyContinue

# 2) 删 CA —— 注意：certutil -delstore 在部分机器上返回 ERROR_NOT_SUPPORTED，
#    可靠做法是直接删注册表键
$t = (Get-PfxCertificate "$PWD\certs\ca-cert.pem").Thumbprint
Remove-Item "HKCU:\Software\Microsoft\Windows\SystemCertificates\Root\Certificates\$t" -Recurse -Force

# 3) 删文件夹
Remove-Item .\certs, .\state.json, .\proxy.log -Recurse -Force -ErrorAction SilentlyContinue
```

> **实测踩过的坑**：`certutil -user -delstore Root <指纹>` 与 .NET `X509Store.Remove()`
> 在某些机器上都会返回 `ERROR_NOT_SUPPORTED`（即使以管理员身份运行），
> 而删注册表键有效。卸载逻辑不要只依赖 certutil。

## PAC 与进程生命周期

PAC 指向 `http://127.0.0.1:8443/winget-accel.pac`。代理不在时，WinINet **取不到 PAC 会退化为直连**——
后果是"回到慢速直连"，不是"功能全挂"。即便如此，PAC 仍应被清理，因此做了三层保障：

| 结束方式 | PAC 是否还原 | 机制 |
|---|---|---|
| `Ctrl+C` / 关闭窗口 | ✅ | `SetConsoleCtrlHandler` |
| 任务管理器结束 / 崩溃 | ✅ | **看门狗子进程**（父进程一消失就还原） |
| 断电 / 蓝屏 | ❌ | 下次启动时 `recover_stale()` 清理残留 |

启动时会看到**两个** `winget-accel.exe` 进程——主进程与看门狗，属正常。

## 加速器候选

内置 5 个，按多次实测的中位数排序（可被 `--config` 覆盖）：

| 优先级 | 候选 | 实测速率 |
|---|---|---|
| 1 | `gh-proxy.com` | 723–769 KB/s |
| 2 | `gh.geekertao.top` | ~703 KB/s |
| 3 | `ghfast.top` | 339 KB/s |
| 4 | `ghproxy.site` | ~243 KB/s |
| 5 | `ghproxy.imciel.com` | 238 KB/s |

全部是**第三方免费公共服务**，存活状态会变（`ghfast.top` 一天之内经历过"失效→可用"）。
后台每 5 分钟探测一次各自 origin 的根路径，连续失败达阈值就切换。
**所有候选都不可用时直接返回 502**，不回退直连（ADR-016：直连对 winget 等于 37 秒超时失败）。

候选清单的自动获取是待办（[roadmap T1](docs/roadmap.md)）。

## 命令行参数（排障用，日常不需要）

```
--doctor               体检：端口 / CA / PAC / 5 个加速器可达性，不改任何系统设置
--print-pac            打印将要使用的 PAC 后退出
--port <端口>          默认 127.0.0.1:8443
--config <路径>        用配置文件（见 config.example.json）
--accel <基地址>       临时指定单个加速器，覆盖配置
--cert-dir <目录>      CA 存放目录，默认 exe 同目录下的 certs\
--log <路径>           日志文件，默认 exe 同目录下的 proxy.log
--log-level <级别>     error | warn | info | debug
--mitm-extra <host>    额外拦截某 host 但不改写（排障用，可重复）
--version / --help
```

带**任意参数**启动时是"纯代理"模式，**不会**修改 CA 与 PAC——
这是测试用例依赖的性质（测试不能污染系统状态）。

## 构建

```powershell
cargo build --release        # 产物 target\release\winget-accel.exe
cargo test                   # 67 个单元测试
cargo clippy --all-targets
```

首次构建需要联网拉依赖。`.cargo/config.toml` 已启用 `+crt-static`，
产物不依赖 VC++ 运行库。

## 测试

```powershell
# Rust 单测（纯逻辑与证书属性）
cargo test

# 协议用例：同一套 Python 用例直接驱动 Rust 二进制（不碰系统状态、无需外网）
cd prototype
.\.venv\Scripts\python.exe -m pytest tests --target-binary ..\target\release\winget-accel.exe

# 加上真实网络用例
.\.venv\Scripts\python.exe -m pytest tests --target-binary ..\target\release\winget-accel.exe --network
```

契约与判定标准见 [docs/test-plan.md](docs/test-plan.md)。

## 仓库结构

```
src/                  Rust 实现（唯一的交付物）
   main.rs            入口：零参数自动模式 / 参数模式
   autoenv.rs         装 CA、设 PAC、退出还原、看门狗
   proxy.rs           CONNECT 分流、隧道、MITM、健康探测
   rewrite.rs         改写决策（纯函数，可单测）
   ca.rs              CA 与叶证书（Name Constraints / path_length=0）
   http.rs            逐字节读头、三态定界转发
   health.rs          加速器健康状态机
   doctor.rs          --doctor 检查表
   console.rs         控制台代码页自适应
prototype/            Python 原型 + 协议测试用例（验证产物，不参与交付）
docs/
  design.md           架构设计
  decisions.md        16 条 ADR（含状态总表）
  roadmap.md          实现阶段 + T1/T2 待办
  test-plan.md        用例契约
  verification-proxy-2026-11-01.md   全部实测数据（含失败与被否决的方向）
  verification-2026-11-01.md         早期复核（REST 源时期）
  research.md         早期调研（REST 源时期，已被 ADR-013 取代）
  rewinged-reference.md / reference-log.md   历史记录
```

## 系统要求与兼容性

**实测环境**：Windows 10.0.26100（2 台机器，Win11 24H2/25H2）、winget v1.29.380、PowerShell 5.1、x64。

PE 头：机器类型 `x64`、子系统 `Windows CUI`、子系统版本 `6.00`（仅为链接器默认值，
不代表能在 Vista 上运行——实际下限由 Rust std 与依赖决定）。

### 支持情况

| 范围 | 状态 | 说明 |
|---|---|---|
| Windows 10 / 11 **x64 桌面版** | ✅ 支持 | 依赖仅 `kernel32`/`advapi32`/`ws2_32`/`bcrypt`/`ntdll`/`api-ms-win-core-synch-l1-2-0`，全部系统自带 |
| 不需要管理员 | ✅ | PAC 在 HKCU，CA 在 `CurrentUser\Root` |
| Windows 10 早期版本（1809–22H2） | 🟡 理论支持，未验证 | Rust 1.99 的 std 已不支持 Win7/8，Win10 是事实下限 |
| Windows Server 2019 / 2022 | 🟡 未验证 | Server Core 无 GUI，CA 确认弹窗无法交互 |
| ARM64 | ❌ 不支持 | 只有 x86_64 产物 |
| Windows 7 / 8 / 8.1 | ❌ 不支持 | Rust 1.99 已停止支持 |
| 非 Windows | ❌ 不支持 | 大量 Win32 FFI |

### 三个隐性依赖

| 依赖 | 用途 | 缺失后果 |
|---|---|---|
| `powershell.exe` | 用 `Get-PfxCertificate` 取 CA 指纹做信任比对 | 无法判断是否已信任 → 零参数模式失败（非降级） |
| `certutil.exe` | 导入 CA 到根存储 | 无法安装 CA |
| winget 的下载器行为 | 本方案假设 winget 走 WinINet 且尊重系统 PAC | **v1.29.380 实测有效**；若将来改为 WinHTTP 或忽略 PAC，加速会静默失效（roadmap H5） |

判断是否仍生效：看 `proxy.log` 里有没有 `REWRITE` 行。

## 已知限制

| 限制 | 说明 |
|---|---|
| 只支持 HTTP/1.1 | 不协商 ALPN；实测 winget 接受 |
| 无 CRL/OCSP | `curl`（schannel）需加 `--ssl-no-revoke`；winget 不受影响 |
| 中文显示依赖控制台代码页 | 已在需要时自动切 UTF-8 并还原，但在 GBK 控制台上的**实际显示效果未经用户确认** |
| 未验证断点续传 | 中断后续传未测；大文件完整下载已验（63.75 MB） |
| 单点 | 5 个候选全是公共加速器，全挂则功能不可用 |
| 无 CI / 无发布流程 | 阶段 5 未做 |

## 与 rewinged 的关系

**基本失效**（ADR-011）。[jantari/rewinged](https://github.com/jantari/rewinged) 是
**REST 源实现**，而本架构不实现任何协议端点。本项目与其没有代码关系，
也没有复制或翻译它的代码。

## 许可证

MIT
