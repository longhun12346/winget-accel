# 设计

## 1. 架构总览

```
                    ┌──────────────────────────────────────────┐
                    │           本机（127.0.0.1）              │
                    │                                          │
  winget CLI ──────▶│  winget-local-source  (HTTPS :8443)      │
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
winget-local-source serve   --config config.json
winget-local-source sync    --config config.json [--full]
winget-local-source cert    --out ./certs [--install]
winget-local-source setup   [--remove]        # 内部调用 winget source add/remove
winget-local-source doctor                    # 自检：证书、端口、源、清单、加速器
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

### 3.4 未确认项（实现前必须解决）

- [ ] `ServerSupportedVersions` 的准确格式与取值
- [ ] winget 1.29.380 实际请求的 schema 版本
- [ ] `manifestSearch` 请求/响应的完整字段集
- [ ] 错误响应格式（包不存在时返回 404 还是空结果？）
- [ ] 是否需要 ETag / 缓存头

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

```jsonc
{
  "listen": "127.0.0.1:8443",
  "certFile": "./certs/localhost.crt",
  "keyFile":  "./certs/localhost.key",
  "manifestDir": "./data/manifests",

  // 只有 host 命中这里的 URL 才会被改写（ADR-004）
  "rewriteHosts": [
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com"
  ],

  // 按 priority 升序尝试；{url} 会被替换为原始完整 URL
  "accelerators": [
    { "name": "gh-proxy", "template": "https://gh-proxy.com/{url}", "priority": 1 },
    { "name": "ghfast",   "template": "https://ghfast.top/{url}",   "priority": 2 }
  ],

  "health": {
    "enabled": true,
    "intervalSeconds": 300,
    "timeoutSeconds": 8,
    "probeUrl": "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip"
  },

  "fallbackToOriginal": true
}
```

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

### 5.3 健康检查

- 周期性对 `probeUrl` 发 `HEAD`（不支持则退化为 1 字节 `Range` 请求）
- 记录：可达性、TTFB、是否返回 2xx/3xx
- **副作用约束**：探测频率不得高于 5 分钟一次，且必须并发上限 1，避免重蹈压测覆辙（ADR-006）
- 探测失败**连续 2 次**才标记不健康（避免抖动）

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
winget-local-source cert --install

# 2. 注册源（管理员，内部执行 winget source add）
winget-local-source setup

# 3. 同步清单（可普通权限）
winget-local-source sync

# 4. 启动服务（可普通权限，建议做成登录自启）
winget-local-source serve
```

卸载：

```powershell
winget-local-source setup --remove
winget-local-source cert --remove
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
