# 实现计划

> 交接说明：开新会话时先读
> `README.md` → `docs/decisions.md`（为什么是代理架构，ADR-013/014/015）→
> `docs/verification-proxy-2026-11-01.md`（实测事实与未验证项）→
> `docs/design.md`（怎么实现）→ 本文档（做什么、按什么顺序）。
>
> 旧的"本地 REST 源"计划已作废，作废与映射关系见 [§阶段 0 的映射表](#旧编号映射)。

---

## 阶段 0：环境与验证（已完成）

| # | 事项 | 状态 | 说明 |
|---|---|---|---|
| 0.1 | 确定架构 | ✅ 已完成 | **PAC + 本机 MITM 改写代理**（ADR-013）；REST 源方案废弃 |
| 0.2 | 验证"绕开源"是否可行 | ✅ 已完成 | mitmproxy 实验：下载走代理、`CurrentUser\Root` 被接受、哈希校验仍生效（`verification-proxy` §2–§3） |
| 0.3 | Name Constraints 是否被强制校验（原 H1） | ✅ 已完成 | **强制**：签 `github.com` 接受，签 `example.com` 被拒（§9.4） |
| 0.4 | PAC 是否被 WinINet 采纳 | ✅ 已完成 | `PAC-SERVED ×9`，随后下载经代理改写（§9.3） |
| 0.5 | 端到端 `winget download` | ✅ 已完成 | `junegunn.fzf`：退出码 0 / 7.7 s / 2,544,236 B / 哈希校验通过（§9.1） |
| 0.6 | 根证书安装的实际行为 | ✅ 已完成 | 需**一次交互确认**；无 UI 会话下**阻塞而非报错**（§10） |
| 0.7 | 实现语言 | ✅ 已完成 | **Rust**（ADR-009 第四次修订）；Python 原型不进交付（ADR-015） |
| 0.8 | 安装 Rust 工具链并跑通一次构建 | ❌ 未完成 | `RUSTUP_DIST_SERVER=https://rsproxy.cn`（实测 0.58 s）+ `x86_64-pc-windows-msvc`；本机 MSVC 14.51 / SDK 10.0.26100 已就绪，无需装 VS 组件 |

**验收**：0.1–0.7 完成；0.8 需装工具链，是阶段 1 的唯一前置。

### 旧编号映射

REST 源时期的编号在此逐条交代去向，避免"文档里提到但没人知道它废了"。

| 旧编号 | 主题 | 处置 |
|---|---|---|
| 0.2 | 拿到 OpenAPI 规范 | **作废**（不实现协议） |
| 0.3 | 确认 HTTPS 是否强制 | **作废**（不注册源，无此问题） |
| 0.4 | 确认 winget 请求的 schema 版本 | **作废**（不实现协议） |
| 0.5 | 确认 GitHub 资产访问已恢复 | **作废**（不再依赖直连可用；加速器已覆盖） |
| 0.6 | 安装 Rust 工具链 | **保留** → 新 0.8 |
| V1 | 健康探测改为按加速器自身 origin | **保留** → 阶段 3 |
| V2 | `fallbackToOriginal` 配合直连可达性判定与超时 | **保留** → 阶段 3 |
| V3 | 建立 host × 加速器 能力矩阵 | **保留且更重要** → 阶段 3（现在有 4 个 host 要逐个验） |
| V4 | 实测 `/information` 的版本交集 | **作废**（不实现协议） |
| V5 | `manifestSearch` 匹配语义设计 | **作废**（无搜索） |
| V6 | 三个端点的协议 fixture | **作废**；替代品见阶段 2 的"改写与转发 fixture" |
| V7 | 去掉硬编码的探针资产版本 | **保留** → 阶段 3（探针指向 acceleratorOrigin） |
| V8 | 证书优先装 `CurrentUser\Root` | **已完成**（0.3 / 0.6 实测），阶段 4 落地 |

---

## 阶段 1：Rust 骨架（PAC + CONNECT 分流 + 隧道）

> 状态（2026-11-01）：**已完成**。编译通过，`cargo clippy` 无警告。
> 落在 `src/main.rs`、`src/proxy.rs`、`src/pac.rs`、`src/http.rs`、`src/config.rs`。

目标：先把"代理壳"跑起来，**不含 MITM**。此阶段完成后 winget 行为不变（仍慢），只验证分流正确。

- [ ] 配置加载：忽略 `$` 开头的键；校验 `listen` 只能是 `127.0.0.1:<port>`
- [ ] 监听：Windows 上必须 `SO_EXCLUSIVEADDRUSE`（`SO_REUSEADDR` 会允许抢占已占用端口）
- [ ] 端口占用 → 立即失败并打印占用进程，**不自动换端口**（PAC 里写死了端口）
- [ ] `GET /proxy.pac` → 返回 PAC（内容见 `design.md` §3，与 `rewriteHosts` 同源生成）
- [ ] `GET /health` → 返回连接/改写/隧道/字节/错误计数
- [ ] `CONNECT` 解析：逐字节读到 `\r\n\r\n`，**不得吞掉后面的 ClientHello**
- [ ] 非白名单 host → 纯隧道（双向泵字节，上游连接超时 15 s，失败回 `502` + `TUNNEL-FAIL`）
- [ ] 结构化日志：`PAC-SERVED` / `TUNNEL-FAIL` / `PLAIN-405` / `CLIENT-ERR`

**验收**：

- `curl -x http://127.0.0.1:8443 https://api.github.com` 返回 `200`（走隧道，未被改写）
- 设好 `AutoConfigURL` 后日志出现 `PAC-SERVED`
- 端口被占时启动失败且输出占用进程（用两个实例验证）
- 此阶段 `winget download` 仍然慢/断——**这是预期的**，只验分流

---

## 阶段 2：MITM 与改写（核心价值）

> 状态（2026-11-01）：**已完成并通过实测**。
> 落在 `src/rewrite.rs`（决策纯函数）、`src/ca.rs`（Name Constraints + 叶证书缓存）、
> `src/http.rs`（三态定界转发）。
> 实测：经 Rust 代理下载 `fd v10.5.0`，1,535,063 B / 2.13 s ≈ **704 KB/s**，SHA256 一致。
> rcgen 需要 `x509-parser` feature 才有 `Issuer::from_ca_cert_pem`（重启复用同一 CA 的前提）。

- [ ] **前置确认**：`rcgen` 能否写 `NameConstraints`；不能则改用 `x509-cert` 系 crate（**未验证**）
- [ ] CA 生成：ECDSA P-256（或 RSA-2048）、`BasicConstraints(ca, path_length=0)`、
      `NameConstraints` 限 4 个 DNS 且 `critical`、`KeyUsage` 含 `keyCertSign`、365 天
- [ ] 叶证书按需签发：SAN 只含该 host、`serverAuth`、30 天、**进程内缓存且不落盘**
- [ ] 对白名单 host 终止 TLS；握手失败记 `MITM-HANDSHAKE-FAIL` 并关闭，不重试
- [ ] 改写：路径 = 加速器模板前缀 + `https://<原 host><原 path+query>`；`Host` 改加速器
- [ ] 透传 `Range` / `If-Range` / `If-None-Match` / `User-Agent`；
      剥离 `Proxy-Connection` / `Connection` / `Keep-Alive` / `TE` / `Trailer` / `Upgrade`
- [ ] 响应体三态转发：`Content-Length` / `chunked` / 无长度读到 EOF；`206` 与 `Content-Range` 原样保留
- [ ] keep-alive（原型是一连接一请求；Rust 版应支持，减少重连）
- [ ] 并发上限（线程数封顶，杜绝无限建线程）
- [ ] **fixture**：改写规则的固定用例 + 三态转发的固定用例（替代作废的 V6）

**验收**：

- `curl --cacert <CA> -x http://127.0.0.1:8443` 取 release 资源返回 `200`，速率达数百 KB/s 量级
- `winget download --id junegunn.fzf` 退出码 0、`"已成功验证安装程序哈希"`，日志可见 4 段 `206`
      （对照基线：2 B 探测 + 447,084 + 1,048,576 + 1,048,576）
- 非白名单 host 隧道 `200` 且日志中无 `REWRITE`
- 篡改任一环（例如丢 `Range`）能被 fixture 捕获

---

## 阶段 3：加速器健康检查与切换

> 状态（2026-11-01）：**状态机已完成；探测与切换未实测**（当前只有 1 个可用候选，
> 探测线程在候选数 <2 时不启动，避免无意义请求）。
> 落在 `src/health.rs`（8 个单测覆盖选择与失败阈值）+ `src/proxy.rs`（探测线程、失败计数换取）。
> **未实现"回退直连"**：全挂时直接快速返回 502，而不是把请求打回原始 URL——
> 受限网络下直连 GitHub 本身等于卡死（见下方风险表）。

- [ ] 候选列表 + `priority`，取第一个健康的
- [ ] 探测目标：**加速器自身 origin 的根路径**（V1）；`HEAD` 失败退化 1 字节 `Range` GET
- [ ] 判定：收到任意 HTTP 响应（含 `404`）即可达；记录 TTFB；超时计失败
- [ ] 节奏：间隔 ≥300 s、并发 1、连续 `failuresBeforeUnhealthy` 次失败才标记不健康（ADR-006）
- [ ] **V3** host × 加速器 能力矩阵：4 个 host 逐个验证，不支持的组合不得改写（退化隧道）
- [ ] **V7** 探针不指向任何固定版本的资产（不硬编码 `ripgrep 15.2.0` 这类地址）
- [ ] **V2** `fallbackToOriginal`：全挂时回退直连，必须带超时 + 明确 `warn`，不得无限挂起

**验收**：

- 把主加速器改成不可达域名 → 下一个请求自动用次选（观察日志中的上游 host）
- 全部不可达且 `fallbackToOriginal=true` → 回退直连并输出 `warn`；
  `false` → `502` 明确失败
- 探测间隔与并发与配置一致（日志时间戳可验证）
- 矩阵中标记"不支持"的 host 不会被改写到该加速器

---

## 阶段 4：安装器 / 卸载器 / 自检

> 状态（2026-11-01）：**`--doctor` 已跑通**（实测：CA 缺失判 FAIL、加速器探测 660 ms 可达、
> 单候选告警）。`installer/setup.ps1`、`installer/teardown.ps1` 通过 PowerShell 语法解析，
> **但还没与二进制联调**——它们需要一次交互点击才能验证根证书导入。
> 已继承原型踩过的两个坑：装根证书必须放子进程 + 超时（无 UI 会话会永久阻塞）、
> 删根证书必须用 `certutil -user -delstore`（`Remove-Item` 会报"不允许使用 UI"）。

这一阶段的核心不是功能，是**不留半个状态**。根证书安装必须假定可能无人值守（§10）。

- [ ] `setup`：生成 CA → 装 `CurrentUser\Root`（**子进程 + 45 s 超时**，超时杀子进程、
      打印手动命令 `certutil -user -addstore Root <file>` 并 `exit 1`）
- [ ] `setup`：按指纹判重，已装则跳过；幂等重跑安全
- [ ] `setup`：记录原 `AutoConfigURL` → 写新值 → 启动代理（`ProxyEnable=0`）
- [ ] 任何一步失败/取消 → **完整回滚**（PAC、CA、进程），不留半装状态
- [ ] `teardown`：`certutil -user -delstore Root <thumbprint>` 删 CA
      （`Remove-Item Cert:\CurrentUser\Root\...` 会因"用户根存储不允许 UI"失败）、
      还原 `AutoConfigURL`、停进程
- [ ] `teardown` 自校验：`ProxyEnable` / `AutoConfigURL` / CA 残留 / 进程残留，有残留 `exit 1`
- [ ] `doctor`：端口与进程、`AutoConfigURL` 比对期望值、CA 指纹与有效期、加速器逐个探测、winget 版本
- [ ] 登录自启（HKCU `Run`，无窗口）
- [ ] 日志轮转

**验收**：

- `setup` 重跑跳过已装项；`teardown` 后 `ProxyEnable=0`、`AutoConfigURL` 还原、
  CA 计数 0、进程 0，且退出码 0
- 无人值守会话下 `setup` 在 45 s 内退出并给出可复制的手动命令（**不挂死**）
- `doctor` 能分别诊断：CA 未装 / 代理未运行 / PAC 未生效

---

## 阶段 5：打包与分发

- [ ] 单文件二进制：`x86_64-pc-windows-msvc` + `-C target-feature=+crt-static` + strip + LTO
- [ ] 体积目标 4–6 MB（无 VC++ 运行库依赖）
- [ ] 未签名 exe 的 SmartScreen 策略（签名 / 或在 README 显著位置给 SHA-256）
- [ ] 分发渠道（GitHub Releases 直连不通，需经加速器或其它渠道）
- [ ] 构建可复现说明（工具链版本、target、flags）

**验收**：干净机器上按 README 三步完成安装；`teardown` 后系统状态与安装前一致。

---

## 已知风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| **代理单点** | 代理挂了，被 PAC 圈入的 4 个 host 失败（其余正常） | 用 PAC 而非全局代理 + 登录自启 + `doctor` 诊断 |
| **CA 私钥泄露** | 可在 4 个 host 上冒充 | `NameConstraints` 限域（已实测强制）+ 私钥 ACL + 365 天有效期 + 卸载即删（ADR-014） |
| **加速器单点** | 当前只有 `gh-proxy.com` 可用（`ghfast.top` 已失效） | 配置多候选 + 健康检查；但事实上无回退链 |
| **回退直连等于卡死** | 全挂时安装长时间无响应 | V2：回退前判直连 + 超时 + `warn`；或 `fallbackToOriginal=false` |
| 大文件 / 并发分片 / 断点续传 | 数十 MB 包可能表现不同 | H3 部分验证（大文件与 3 路并发分片见 `prototype/README.md`），**断点续传未验**；阶段 2/3 用 Git for Windows（63.75 MB）补测 |
| 只支持 HTTP/1.1，不协商 ALPN | 若客户端强制 h2 则失败 | 原型实测 winget 接受；写入文档，不实现 |
| 无 CRL/OCSP | `curl`（schannel）需 `--ssl-no-revoke` | 不影响 winget/WinHTTP；写入文档 |
| winget 升级后不再走系统 PAC | 加速静默失效 | H5，`doctor` 无法直接测；靠日志观察 `PAC-SERVED` |
| 根证书安装需交互 | 无 UI 会话可能挂死 | 子进程 + 超时 + 手动命令 + 回滚（§10） |
| 依赖面膨胀 | 审计面扩大 | ADR-012 预算 + CI 计数卡阈值 |
| 未签名 exe 触发 SmartScreen | 用户不敢运行 | 代码签名，或 README 给 SHA-256 |

---

## 待定问题清单（需用户决策）

| # | 问题 | 状态 | 影响 |
|---|---|---|---|
| 1 | 实现语言 | ✅ **Rust**（ADR-009） | — |
| 2 | 分发形态 | ✅ **单文件二进制** | 决定打包与渠道 |
| 3 | 是否需要管理员 | ✅ **不需要**（HKCU + `CurrentUser\Root`） | — |
| 4 | 是否接受装一张受约束的 CA | ✅ **接受**（ADR-014 三重约束），但需一次交互确认 | 决定安装体验 |
| 5 | 加速器候选集：能接受依赖第三方公共加速器吗 | ⬜ 待定 | 当前仅 1 个可用，事实上无回退 |
| 6 | 未签名 exe 的 SmartScreen 策略 | ⬜ 待定 | 影响发布流程 |
| 7 | 分发渠道（Releases 直连不通） | ⬜ 待定 | 影响交付方式 |
| 8 | 是否需要 arm64 | ⬜ 可后置 | 多一条交叉编译 |
| 9 | 是否加响应缓存（同 URL 复用字节） | ⬜ 待定 | 影响重复安装耗时与磁盘占用 |
| 10 | 是否代理 `raw.githubusercontent.com` 等新增 host | ⬜ 待定 | 需先验加速器是否支持（V3） |

原清单中的"源共存/重复 id""清单覆盖范围""HTTPS 是否强制"随架构切换**整体作废**。
