# 方案决策记录（ADR）

每条记录：背景 → 决定 → 理由 → 代价。编号与调研阶段使用的 L1–L10 对应。

---

## ADR-001：采用 L3（本机 REST 源 + 服务时 URL 改写）

**决定**：在本机 `127.0.0.1` 上运行一个 winget REST 源，服务端把清单里的
`InstallerUrl` 动态改写为加速器地址。

**被否决的替代方案**：

| 方案 | 提权 | 安全基线影响 | 透明性 | winget 记账 | 否决理由 |
|---|---|---|---|---|---|
| **L1** 本地清单改写 + `winget install -m` | 1 次 | **明显下降** | 半透明 | ✅ | 需启用 `LocalManifestFiles`，等于让本机**任意程序**都能静默安装任意本地清单；且每次必须走包装器，`winget upgrade --all` 会绕过它 |
| **L2** 自己下载 + 自己装 | 无 | 不变 | 否 | ❌ | 丢失 `winget list` 记账与升级链；静默参数需自行维护 |
| **L4** MITM + `--proxy` | 1 次 + 根证书 | **最严重** | ✅ | ✅ | 根证书可签发任意域名；且 `--proxy` 也需 `ProxyCommandLineOptions` 提权 |
| **L5** hosts 劫持 + 伪冒证书 | 1 次 + 证书 | **最严重** | ✅ | ✅ | 破坏全机对相关 host 的访问，需覆盖多个域名 |
| **L7** 本机并发下载 | 无 | 不变 | 否 | ❌ | **实测触发 CDN 惩罚，导致该 IP 全部发布资产下载归零** |

**理由**：
1. 三种"必须提权"的方案里，L3 的副作用最小——只新增一张仅用于 `localhost` 的证书，
   不改动任何 winget 安全策略
2. 唯一**完全透明**的方案：`winget search/install/upgrade` 全部照常工作
3. 顺带解决源层偶发 4–81 秒的查询延迟
4. 哈希仍来自官方清单（见 ADR-004 与调研 6.2）

**代价**：需要常驻一个本地服务；需要一次性提权；依赖清单同步。

---

## ADR-002：不以 `cf-winget-proxy` 为基础

**决定**：不复用、不 fork。

**理由**（均为实测/核查结论）：
1. **无 LICENSE 文件** → 默认 All rights reserved，**法律上不可复用**
2. **改写全部 host**：连 Firefox 的 Mozilla CDN 也经它的 Worker，零收益、徒增风险
3. 健康度存疑：0★ / 1 fork，创建与最后推送同为 2026-05-27，无 README/issues/homepage
4. 第二个域名 `winget.cn.lihongjie.cn` TLS 失败
5. 架构上是公网 Worker，与"纯本机"目标相反

---

## ADR-003：自行实现，而非直接分发 rewinged

**决定**：自己写代码，参考 rewinged（MIT）的协议实现与模型组织。

**理由**：
1. rewinged 的目标是**企业内网/离线分发**，不是加速；它的 `autoInternalize`
   假设"服务端有好网络"，与我们的场景相反（见 `rewinged-reference.md`）
2. 我们只需要它最核心的一条行为（"读目录 → 原样经 REST 输出"），
   其余企业特性（Entra ID、trustedProxies）全部不需要
3. 它是 **pre-1.0**，作者明示配置与行为可变；自实现可控制演进
4. 我们的核心增量（host 白名单改写 + 加速器健康检查 + 失败回退）它没有

**代价**：承担协议实现的正确性责任。缓解：以 MIT 方式参考其代码并保留声明。

---

## ADR-004：只改写白名单内的 host

**决定**：配置提供"host → 加速器前缀"映射，**只有命中白名单的 URL 才改写**，
其余原样透传。

**默认白名单**（待实现时按真实数据补齐）：

```
github.com
objects.githubusercontent.com
codeload.github.com
release-assets.githubusercontent.com
```

**理由**：
1. 只有这些 host 在国内慢（实测数据）
2. `cf-winget-proxy` 的全量改写是明确的反面教材——把快流量也塞进代理
3. 白名单可配置，便于用户按自己的网络状况调整

**代价**：需覆盖 GitHub 未来的新资产域名；漏配时该包会退化到直连（慢但可用）。

---

## ADR-005：服务时改写，不落盘改写

**决定**：磁盘上的清单保持与上游完全一致；改写发生在 HTTP 响应生成时。

**理由**：
1. 换加速器、加/减 host 只需改配置，**无需重新同步清单**
2. 本地清单可随时与上游做 `diff` 校验完整性（若落盘改写则无法区分"我们的改动"和"上游的改动"）
3. 加速器失效时可立即回退到原始 URL，无需回滚文件

**代价**：每次响应都要做一次字符串/结构改写（成本可忽略）。

---

## ADR-006：内置下载逻辑并发上限 4–8，且必须走加速器

**决定**：项目中任何主动下载（清单同步骤除外）并发不超过 8，默认 4，
必须带指数退避与随机分片。

**理由**：实测 32–64 并发会导致 GitHub 资产 CDN 对本机 IP 施加惩罚，
且惩罚**外溢**到正常使用（详见 `research.md` 第 4 节）。

**代价**：放弃"靠并发免费提速"的幻想，依赖加速器。

---

## ADR-007：不启用 `LocalManifestFiles`、不装根证书、不改 hosts

**决定**：项目不要求用户做以上任何一项。

**理由**：这三项分别对应"任意本地清单可静默安装"、"任意域名可被伪造"、
"全机域名解析被改写"，都是**机器级安全基线下降**，
为一个下载加速需求付这种代价不成比例。

**代价**：功能上限受限（见 ADR-001 的取舍）。

---

## ADR-008：清单版本支持范围

**状态**：原为"待定"；2026-11-01 复核后**已确定**（依据见 `verification-2026-11-01.md` §3.3–3.4）。

**背景**：rewinged 同时支持清单 schema **1.1.0 – 1.10.0**，其 `models/` 目录
为此有 8 个版本的模型文件，合计约 **200 KB**（占其代码 342.8 KB 的六成）。

**原选项**：

| 选项 | 代码量 | 原判断风险 |
|---|---|---|
| A. 全版本（照 rewinged） | ~200 KB 模型 | 低（兼容性好），维护重 |
| B. 仅当前 winget 使用版本（1.10.0）+ 1.9.0 兜底 | ~50 KB | 中（winget 升级后可能失效） |
| C. 只做 1.10.0 | ~26 KB | 高 |

**原倾向**：先做 **B**，把版本处理抽象成可插拔，后续按需补。

**复核结论**：

1. 协商机制已查明。客户端 `RestClient::GetLatestCommonVersion()` 对
   "服务端 `ServerSupportedVersions`"与"客户端支持集"取**交集再取最大值**；
   客户端支持集为 `1.0.0 / 1.1.0 / 1.4.0 / 1.5.0 / 1.6.0 / 1.7.0 / 1.9.0 / 1.10.0 / 1.12.0 / 1.28.0`。
   **服务端只声明 `["1.10.0"]` 时，客户端必然回落到 1.10.0，不会拒绝连接。**
2. 因此原表对 C 的"风险高"**下调为中低**：残余风险只剩下"客户端版本过旧、不支持 1.10.0
   导致协商失败"，由 `doctor` 检查 winget 版本并给明确报错即可兜住。
3. **但原表低估了工作量**：版本维度是**双向**的。输出只做 1.10.0，仍然必须把
   `winget-pkgs` 里横跨多个 schema 版本的 YAML **读进来**，再转换成 1.10.0 形状。
   那 ~200 KB 模型中有相当一部分是**读取侧**成本，不是输出侧。

**决定（修订）**：采用 **C′ —— 输出契约只做 1.10.0，且读侧不按版本建 struct**。

- 读侧：YAML → 通用树（`map` / `any`），不对应任何 schema 版本
- 转换：一张"跨 schema 字段改名/新增映射表"
- 输出：投影成 1.10.0 JSON，由单一 `ManifestCodec` 负责

**理由**：

1. 契约只需一个版本，协商安全性已证明（上面第 1 点）
2. 通用树把"8 份模型 ≈ 200 KB"压成"一张映射表 + 一个投影函数"，
   且**天然支持任意新版本清单**——上游加字段只需补映射，不需要新代码
3. 与 ADR-003 一致：借鉴 rewinged 的**字段语义**，不搬它的模型体系

**代价与风险**：

- 需一次性穷举跨版本改名/新增字段（`AppsAndFeaturesEntries`、`Markets`、
  `InstallerSha256` 一系等）；**漏掉的字段会被静默丢弃**，这是本方案最危险的地方
  → 必须配 fixture 测试（`verification-2026-11-01.md` V6），不能靠人工 `winget show`
- 1.10.0 中不存在的字段会被截断，这是"最小集"的固有代价
- 若将来 winget 的必需字段只在新契约中提供，需重新评估

**回退路径**：若映射表维护成本超出预期，退回 A（照搬 rewinged 的多版本模型），
接口不变（`ManifestCodec`），改动局限在实现层。

---

## ADR-009：实现语言

**状态**：**已定：Rust**（2026-11-01 第三次修订）。

**变更史**（真正重要的是最后一列的"判据"，不是结论）：

| # | 语言 | 触发条件 | 失效原因 |
|---|---|---|---|
| 1 | Go（初稿） | 与参考对象同语言，"移植成本最低" | ADR-008 改为 C′ 后不再移植模型，理由消失 |
| 2 | Python + uv（复核后） | 本机已有 `uv`、零安装、性能不敏感 | 隐含前提"只自己用"被推翻 |
| 3 | **Rust（现在）** | **明确要产出单文件二进制对外分发** | — |

**判据**（环境一变就重评，不凭偏好）：

1. **谁长期维护**（交接成本）→ 自己维护，故不构成 Go/C# 的加分项
2. **依赖预算**能否压到可审计范围（ADR-012）
3. **Windows 系统集成**在关键路径上的权重 → 证书库是 `cert` / `setup` 的必经路径

三条全指向 Rust。

**为什么是 Rust**：

1. **`windows-rs` 正好压在本项目唯一的系统集成层上**：证书存储
   （`CertOpenStore` / `CertAddEncodedCertificateToStore`）、注册表（HKCU Run）、提权检测。
   Go 的 `x/sys/windows` 是裸 syscall，需自封一层或转调 PowerShell。
2. **类型系统能把"只改 `InstallerUrl`"变成编译期不变量**：newtype 区分
   `OriginalUrl` / `RewrittenUrl`、字段私有、只留一个转换函数。本项目的核心卖点是
   哈希信任链不变，Go 只能靠测试断言加人工评审。
3. **产物 4–6 MB**，`+crt-static` 后零依赖（不需要 VC++ 运行库）；Go 约 11–13 MB。
   用户恰在慢速网络上，体积是真实成本。
4. **T2 边界更安全**（ADR-011）：跨语言重写天然不会滑向"搬运"；
   同语言 + 同 workload 则极易趋同。
5. **不需要异步**：本地单用户、并发 1–2，同步代码足够，`async` 与 borrow 纠缠的场景基本不出现。

**实测支撑**（工具链可达性，2026-11-01）：

| 源 | 结果 |
|---|---|
| `rsproxy.cn`（dist） | **200 / 0.58 s** |
| `mirrors.ustc.edu.cn/rust-static` | 200 / 1.47 s |
| `static.rust-lang.org`（官方） | 200 / 12.0 s |
| `index.crates.io` / `static.crates.io` | 200 / 3.57 s、1.60 s |
| 本机 MSVC | ✅ 14.51.36231 + Windows SDK 10.0.26100.0（VS Enterprise 2026） |

官方源慢，但国内镜像比 Go 官方源（`dl.google.com` 3.0 s）**还快** ⇒ 工具链不构成阻碍。
（初稿曾以"工具链慢"排除 Rust，那是没测镜像就下的判断，已作废。）

**为什么不选其它**：

| 语言 | 否决点（针对本项目） |
|---|---|
| Go | 系统集成层要自封 syscall；与参考同语言，T2 边界易破；体积 11–13 MB |
| Python | **PyInstaller 产物杀软误报率高**——一个"要帮用户装软件"的工具被 Defender 拦下，信任直接归零；产物运行时解包到 temp、启动 1–3 s |
| C# | NativeAOT 与 YamlDotNet 的反射冲突；非 AOT 自包含约 70 MB，对慢网用户不友好；本机无 .NET SDK |

**硬约束**（违反即重议）：

- 依赖预算见 **ADR-012**
- TLS 用 `rustls`（纯 Rust、静态链接友好），**不用** `native-tls`
- 同步子命令用 `std::process::Command` 调系统 `git.exe`，**不用** `git2`（libgit2 会引入 C 工具链）
- YAML 用 `serde_yaml_ng`（`serde_yaml` 已归档停维护）
- 发布 `x86_64-pc-windows-msvc` + `-C target-feature=+crt-static` + strip + LTO

**代价**：编译比 Go 慢（首次含依赖 1–2 min，增量 5–20 s）；第三方读者读 Go 更容易；
`serde_yaml` 生态分裂需显式锁定。

**何时重审**：若需交给不熟 Rust 的人维护，或依赖面失控到 >40 个 crate。

---

## ADR-010：不实现 rewinged 的企业特性

**决定**：不实现 Entra ID 认证、`trustedProxies`、`autoInternalize`。

**理由**：本地单用户场景无意义；`autoInternalize` 与"不落地安装包"的目标直接冲突。

**代价**：不能用于多用户共享的内网源——但那不是本项目目标。

---

## ADR-011：与 rewinged 的关系定为 T2（只参考设计与事实，不搬代码）

**决定**：把"参考"分三档，本项目**只做 T2 与 T3，不做 T1**。

| 档 | 含义 | 法律性质 | 义务 |
|---|---|---|---|
| T1 | 逐行翻译 / 改写其代码 | 衍生作品 | 逐文件保留版权头 + 注明来源路径 |
| **T2** | 参考设计思路，用自己语言与结构重写 | 非衍生作品 | 台账注明出处 |
| **T3** | 只取事实（字段名、JSON tag、协议字段、错误格式） | 事实性信息，不受版权保护 | 注明出处 |

**理由**：

1. 语言已改为 Rust（ADR-009），逐行翻译 Go 代码本就别扭——它的接口与反射体系在 Rust 无对应物
2. 它的检索实现靠反射遍历 struct（`findField`），正是 ADR-008 C′ 要摆脱的东西
3. 我们真正需要它的只有"哪些形态要处理、哪个字段会缺"，属 T2/T3 范畴
4. 义务从"逐文件申报"降到"注明参考了哪个设计"，合规成本大幅下降

**实测清单修正**（详见 `rewinged-reference.md` §2）：

| 项 | 原记录（体积推断） | 实测（GitHub API） |
|---|---|---|
| Go 文件数 | 27 | **25** |
| 总代码量 | 342.8 KB | 340.3 KB |
| `models/` 占比 | "约 200 KB / 六成" | **286 KB / 84%** |
| 文档漏列 | — | `controllers/information.go`、`models/api_common.go`、`models/manifests_common.go`、`settings/settings.go` |
| 上游测试 | 树里未见 `*_test.go` | ✅ 属实 |

**参考范围（4 个文件）**：`manifests.go`（摄取形态）、`models/manifests_1_10_0.go`（字段语义）、
`models/internal.go`（索引形状，**不含检索**）、`controllers/packages.go`（端点组织）。

**明确不参考**：`models/` 多版本体系、检索的反射实现、`autoInternalize`、
Entra ID、`trustedProxies`、Docker / goreleaser。

**顺序约束**：**先按 OpenAPI 规范写完三个端点骨架，再读参考文件**。顺序反过来，
T2 边界守不住——"结构趋同"不等于"参考"，同 workload 下极易滑向搬运。

**台账**：每读一个文件，在 `reference-log.md` 记一条（文件、看了什么、产出什么）。

---

## ADR-012：依赖预算与技术选型约束

**决定**：直接依赖 ≤ 8 个，传递依赖 ≤ 30 个。超阈值须在提交说明里写明理由。

统计方式：`cargo tree -e normal --prefix none | sort -u | wc -l`

**理由**：本工具要求用户**信任**它改写安装源。一个自身带 80 个第三方 crate 的工具，
逻辑上自相矛盾；且依赖越多，`cargo audit` 噪音越大、构建越慢、攻击面越广——
对"能改写安装源的工具"来说，供应链攻击的收益极高，这是必须主动收敛的风险。

**禁止清单**：

| 依赖 | 原因 | 替代 |
|---|---|---|
| `tokio` / `axum` / `actix-web` / `hyper` | 本地单用户、并发 1–2，异步是过度设计 | `std::net::TcpListener` + 最小 HTTP/1.1 |
| `git2` / `libgit2-sys` | 引入 C 工具链与 cmake 依赖 | `std::process::Command` 调系统 `git.exe` |
| `native-tls` / `openssl` | 系统依赖、静态链接困难 | `rustls` + `rustls-pemfile` |
| `serde_yaml` | **上游已归档停维护** | `serde_yaml_ng` |
| `reqwest`（默认特性） | 拖入 tokio 与整套 TLS 栈 | 健康探测用 `TcpStream` + `rustls`，或最小 HTTP 客户端 |

**允许的直接依赖**（预估，以实测为准）：`serde`、`serde_json`、`serde_yaml_ng`、
`rustls`、`rustls-pemfile`、`windows`（限 feature）、`anyhow` 或 `thiserror`（二选一）。

**手写最小 HTTP 的边界**：

- 必须按 `Content-Length` 读请求体（`POST /manifestSearch` 带 JSON）
- 支持 `Connection: keep-alive`；错误体为固定 JSON（404 / 500）
- **不实现 chunked 请求体**——但必须先确认 winget 客户端不发 chunked（发则改为支持）
- 不实现 HTTP/2、压缩、multipart

**`windows` crate 的 feature 白名单**：`Win32_Security_Cryptography`、
`Win32_System_Registry`、`Win32_Foundation`、`Win32_System_Threading`（提权检测）。
不得为省事开启 `windows` 全量 feature。

**检查方式**：CI 统计 `cargo tree` 数量，超阈值失败。
