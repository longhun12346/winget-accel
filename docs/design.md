# 设计

## 1. 架构总览

```
                    ┌──────────────────────────────────────────┐
                    │           本机（127.0.0.1）              │
                    │                                          │
  winget CLI ──────▶│  winget-accel  (HTTPS :8443)             │
   (REST client)    │    ├── /information                      │
                    │    ├── /manifestSearch                   │
                    │    └── /packageManifests/{id}            │
                    │              │                           │
                    │              │ 读取 + 改写               │
                    │              ▼                           │
                    │    data/manifests/  ◀── sync ──┐         │
                    │    (官方 winget-pkgs 副本)      │         │
                    └────────────────────────────────┼─────────┘
                                                     │
                                     git sparse-checkout（低频）
                                                     │
                                            microsoft/winget-pkgs

  winget 拿到改写后的 InstallerUrl 后，自己直接去下载：
  winget ──▶ https://<加速器>/https://github.com/... ──▶ GitHub
              （字节不经过本项目）
```

**关键点：本项目不转发字节。** 它只在清单层面把 URL 换成加速器地址，
真正的安装包下载由 winget 自己完成。

---

## 2. 组件

| 组件 | 职责 | 是否常驻 |
|---|---|---|
| `serve` | HTTPS REST 服务，响应 winget 的三种请求 | ✅ |
| `sync` | 稀疏检出/增量更新 `winget-pkgs` 清单 | ❌ 定时或手动 |
| `health` | 加速器可用性与延迟探测，结果供改写引擎选择 | 内嵌于 serve |
| `cert` | 生成 localhost 自签证书、导出/安装到信任库 | ❌ 一次性 |
| `setup` | 注册/移除 winget 源（需管理员） | ❌ 一次性 |

CLI 形态建议（子命令）：

```
winget-accel serve   --config config.json
winget-accel sync    --config config.json [--full]
winget-accel cert    --out ./certs [--install]
winget-accel setup   [--remove]        # 内部调用 winget source add/remove
winget-accel doctor                    # 自检：证书、端口、源、清单、加速器
```

---

## 3. REST 协议

**权威依据**：`microsoft/winget-cli-restsource` 仓库中的 OpenAPI 文档
`documentation/WinGet-1.1.0.yaml`（实现阶段必须先拉下来逐字段核对）。

已知的三个端点：

### 3.1 `GET {base}/information`

返回源元信息：源标识、支持的清单 schema 版本、协议版本等。
winget 在 `source add` 之后会调用它做校验。

### 3.2 `POST {base}/manifestSearch`

请求体包含查询条件（`Query`、`Inclusions`、`Filters`、`MaximumResults` 等）。
响应为匹配的包列表，含 `PackageIdentifier`、`PackageName`、`Publisher`、
`Versions` 等。

**注意**：`search` 只需要包标识级信息，**不需要** `InstallerUrl`——
所以搜索路径不涉及改写。

### 3.3 `GET {base}/packageManifests/{id}`

返回该包的完整清单组合（version / installer / locale 三类文档）。
**`InstallerUrl` 就在这里，改写发生在这个端点。**

响应需按 winget 请求的 schema 版本输出（见 `decisions.md` ADR-008）。

### 3.4 已核实项（原"未确认项"，2026-11-01 复核后关闭）

依据：`documentation/WinGet-1.1.0.yaml`（61,887 字节，SHA-256 `883120cf…76fcc`）
与 `winget-cli` 源码，详见 `verification-2026-11-01.md` §3。

- [x] `ServerSupportedVersions`：`array<string>`，`minItems: 1`，`maxLength: 128`
- [x] 版本协商：客户端对"自己支持的契约集"与"服务端声明集"取**交集再取最大值**；
      服务端声明 `["1.10.0"]` 即锁定 1.10.0（ADR-008）
- [x] `manifestSearch` 字段：请求 `MaximumResults` / `FetchAllManifests` / `Query` / `Inclusions` / `Filters`；
      响应 `Data[]` + `RequiredPackageMatchFields` + `UnsupportedPackageMatchFields` + `ContinuationToken`
- [x] 错误响应：包不存在返回 **404 + `array<Error{ErrorCode,ErrorMessage}>`**，不是空结果
- [x] 三类文档形态：**单个响应内嵌套**（`Versions[]{ Locales[], Installers[] }`），不是三个请求
- [ ] ETag / 缓存头：规范未要求，**可后置**，不阻塞开工

**仍未确定**：HTTPS 是否强制（需一次提权实测，见 §6.2 与 `research.md` §8）。

---

## 4. 清单流水线

### 4.1 获取

`microsoft/winget-pkgs` 全量约 1 GB 级别（数万包 × 多版本）。
使用 **git sparse-checkout** 只取 `manifests/` 目录，并按首字母分批：

```bash
git clone --filter=blob:none --sparse https://github.com/microsoft/winget-pkgs.git
cd winget-pkgs
git sparse-checkout set manifests/g manifests/m manifests/7
```

> 若 GitHub 直连受限，`clone` 这一步同样需要经加速器（或在能联网的环境下同步后拷贝）。
> 这是本项目**唯一**依赖大流量同步的环节，必须提供"离线导入"路径。

### 4.2 存放

```
data/
  manifests/            # 与上游一致的目录结构，禁止就地改写（ADR-005）
  index.json            # 启动时构建的内存索引的持久化快照（可选）
  state.json            # 上次同步的 commit id、时间
```

### 4.3 增量更新

- 记录上次同步的 commit
- 每次 `sync` 做 `git fetch` + `git sparse-checkout reapply`
- 只重建受影响包的索引项（按 `git diff --name-only` 判断）
- **完整性校验**：可选地抽样比对若干包的 `InstallerSha256` 与官方源

### 4.4 索引

启动时扫描 `manifests/` 构建内存索引：
`PackageIdentifier → { 最新版本, 全部版本, 各版本清单文件路径 }`。
数万包的文件扫描应在几秒内完成；若过慢则读 `index.json` 快照。

---

## 5. 改写引擎

### 5.1 配置

**字段形状的权威定义是 [`config.example.json`](../config.example.json)**；本节只解释语义，
不再复制整份配置——此前 `design.md` 与 `config.example.json` 各存一份，已经出现过字段不一致
（`failuresBeforeUnhealthy`、`stateFile`、`logLevel`）。

| 字段 | 语义 |
|---|---|
| `listen` | 监听地址，**只能**是 `127.0.0.1:<port>`（§9） |
| `certFile` / `keyFile` | PEM 证书与私钥（§6） |
| `manifestDir` | 本地清单根目录，结构须与上游一致（ADR-005） |
| `stateFile` | 上次同步的 commit 与时间（§4.3） |
| `rewriteHosts` | 改写白名单，按 host 精确匹配（ADR-004） |
| `accelerators[]` | `name` / `template`（`{url}` 占位）/ `priority` / 可选 `probeUrl` |
| `health.*` | 见 §5.3，`probeUrl` 默认 `{acceleratorOrigin}/` |
| `fallbackToOriginal` | 全挂时是否回退原始 URL，见 §5.3 的风险说明 |
| `logLevel` | `debug` / `info` / `warn` / `error` |

实现约定：以 `$` 开头的键（`$comment` 等）是注释，解析时必须忽略。

### 5.2 改写规则

输入 `https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip`

输出（priority=1 的加速器健康时）：

```
https://gh-proxy.com/https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip
```

判断逻辑：

1. 解析 `InstallerUrl`，取 host
2. host 不在 `rewriteHosts` → **原样返回**
3. 按 priority 找第一个 `healthy == true` 的加速器 → 套模板
4. 全部不健康 → 若 `fallbackToOriginal` 则返回原 URL，并记 warning 日志

> 第 4 步有前提：**必须先确认直连可用**。受限网络下直连 `github.com` 是
> "握手成功、传输中断"，回退等于让安装长时间无响应（§5.3 末尾、V2）。

### 5.3 健康检查

**探测目标：每个加速器探测它自己的入口**（默认 `{acceleratorOrigin}/`），
不再共用一个 GitHub 资产 URL。

> 原因（`verification-2026-11-01.md` V1）：受限网络下 **GitHub 资产本身就不通**，
> 用资产 URL 当探针，测出来的是"GitHub 是否活着"，不是"加速器是否好"，
> 结果是所有加速器被同时误判为不健康。

- 发 `HEAD`，不支持则退化为 1 字节 `Range` GET
- **判定：收到任意 HTTP 响应（含 404）即视为可达**，不要求 2xx/3xx；同时记录 TTFB
- 探测必须带超时（`timeoutSeconds`），超时计入失败
- 探测频率不得高于 5 分钟一次，并发上限 1，避免重蹈压测覆辙（ADR-006）
- 连续 `failuresBeforeUnhealthy` 次（默认 2）失败才标记不健康，避免抖动

**直连可达性要单独判定**：`fallbackToOriginal` 只在"加速器全挂"时生效，
而受限网络下直连往往同样不可用。回退前应做一次低成本直连探测并记录结论，
否则安装会表现为**长时间无响应**，比明确失败更难排查（V2）。

### 5.4 绝不改动的字段

`InstallerSha256`、`InstallerType`、`InstallerSwitches`、依赖声明、区域设置文档——
**只改 `InstallerUrl`**。这是安全模型的根基（调研 6.2）。

---

## 6. 证书

### 6.1 生成

- 自签，密钥算法 RSA 2048 或 ECDSA P-256
- **SAN 必须同时包含**：`DNS:localhost`、`IP:127.0.0.1`
- 有效期建议 1 年（过长不便轮换，过短频繁维护）
- 私钥权限收紧到当前用户

### 6.2 信任

winget 要求 REST 源使用 HTTPS（待实测确认，见 `research.md` 第 8 节）。
证书需加入**本机**信任库：

```powershell
Import-Certificate -FilePath .\certs\localhost.crt -CertStoreLocation Cert:\LocalMachine\Root
```

**这是本项目唯一的机器级安全变更**，必须在安装时明确告知用户：
它使本机信任一张我们生成的证书，但该证书仅对 `localhost` 有效。

### 6.3 轮换与卸载

- 提供 `cert --remove` 从信任库删除
- 证书到期前 `doctor` 应告警

---

## 7. 一次性安装步骤

```powershell
# 1. 生成并信任证书（管理员）
winget-accel cert --install

# 2. 注册源（管理员，内部执行 winget source add）
winget-accel setup

# 3. 同步清单（可普通权限）
winget-accel sync

# 4. 启动服务（可普通权限，建议做成登录自启）
winget-accel serve
```

卸载：

```powershell
winget-accel setup --remove
winget-accel cert --remove
```

---

## 8. 失败模式与处理

| 场景 | 表现 | 处理 |
|---|---|---|
| 服务未启动 | winget 报源不可用 | `doctor` 明确提示；建议登录自启 |
| 端口被占用 | 启动失败 | 立即失败并打印占用进程 |
| 证书过期/未信任 | TLS 握手失败 | `doctor` 检查有效期与信任链 |
| 加速器全挂 | 退化为直连（慢但可用） | 日志 warning，`doctor` 显示各加速器状态 |
| 清单缺包 | 该包搜不到 | `sync` 未覆盖；`doctor` 提示覆盖范围 |
| 清单过期 | 装到旧版本 | `sync` 定期化，`doctor` 显示上次同步时间 |
| schema 版本不匹配 | winget 解析失败 | 按 ADR-008 处理，日志记录实际请求版本 |

---

## 9. 安全注意事项（实现时必须遵守）

1. **只绑定 `127.0.0.1`**，不得绑定 `0.0.0.0`
2. **不提供任何文件下载端点**（我们不是镜像，不转发字节）
3. 路径参数必须校验，防目录穿越（`{id}` 只允许 `[A-Za-z0-9._-]`）
4. 不记录可能含敏感信息的完整请求体
5. 配置里的加速器地址来自用户，不应在日志里输出带凭据的 URL

---

## 10. 明确不做的事

- 不实现 `autoInternalize`（不落地安装包）
- 不实现 Entra ID / 多用户鉴权
- 不做 MITM、不改 hosts、不装根证书
- 不启用 `LocalManifestFiles`
- 不做激进并发下载
