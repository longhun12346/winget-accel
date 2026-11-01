# 设计

> 架构已于 2026-11-01 从"本地 REST 源"切换为"PAC + 本机 MITM 改写代理"（ADR-013）。
> 事实依据：[docs/verification-proxy-2026-11-01.md](verification-proxy-2026-11-01.md)；
> 安全边界：[docs/decisions.md](decisions.md) ADR-014。

## 1. 架构总览

```
winget ──①查清单──▶ cdn.winget.microsoft.com        官方源，DIRECT，不经过本项目
   │
   └──②下载 InstallerUrl──▶ github.com:443
                              │
                    PAC 只把这 4 个 host 指给本机代理
                              ▼
                     127.0.0.1:8443（本项目常驻）
                       ├ 命中白名单 → 终止 TLS（CA 签叶证书）
                       │              → 请求改写为 https://<加速器>/<原始完整 URL>
                       │              → 响应体原样转发
                       └ 其余 host  → 纯隧道，字节不解析
                              │
                              ▼
                        gh-proxy.com ──▶ GitHub
```

**不实现 REST 源、不建索引、不注册源、不需要管理员。**
winget 的清单仍来自官方源，`InstallerSha256` 也来自官方清单——被篡改就装不上，
所以**完整性不因 MITM 下降**（实测：`"已成功验证安装程序哈希"`）。

## 2. 组件

| 组件 | 职责 | 是否常驻 |
|---|---|---|
| `proxy` | 监听端口、PAC 端点、CONNECT 分流、MITM 与改写、隧道、健康探测 | ✅ |
| `setup` | 生成 CA、装 `CurrentUser\Root`、记录原 PAC、设 `AutoConfigURL` | ❌ 一次性 |
| `teardown` | 删 CA、还原 `AutoConfigURL`、停进程、自校验无残留 | ❌ 一次性 |
| `doctor` | 自检：CA 在库、PAC 生效、端口占用、加速器健康 | ❌ 按需 |

Rust 交付形态的子命令：

```
winget-accel proxy      --config config.json
winget-accel setup      [--config config.json]   # 会弹一次根证书确认
winget-accel teardown
winget-accel doctor
```

## 3. PAC 生成与语义

PAC 由**代理进程自己提供**，地址固定为 `http://127.0.0.1:<port>/winget-accel.pac`。
端口与 PAC 内容在同一进程内生成，不会出现"配置改了但 PAC 没改"的不一致。

内容（与原型一致）：

```javascript
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host == "github.com" || host == "objects.githubusercontent.com"
   || host == "codeload.github.com" || host == "release-assets.githubusercontent.com"
   || shExpMatch(host, "*.github.com")) {
    return "PROXY 127.0.0.1:8443";
  }
  return "DIRECT";
}
```

| 设计点 | 理由 |
|---|---|
| 只列 4 个 host + `*.github.com` | 爆炸半径最小化；`cf-winget-proxy` 全量改写是反面教材（ADR-002） |
| 其余一律 `DIRECT` | Microsoft 域、商店域、其它软件源完全不受影响 |
| 用 PAC 而非全局 `ProxyServer` | 代理进程挂掉时，只有这 4 个 host 失败；其余网络照常 |
| `ProxyEnable=0` | 避免与 `ProxyServer` 语义叠加；PAC 单独生效（§9.3 实测） |

> `*.github.com` 在 PAC 里只是转到代理，**不会**被终止 TLS：MITM 只发生在那 4 个
> 精确匹配的 host 上，其余 `github.com` 子域走纯隧道（`design.md` §4）。
> PAC 范围比 MITM 范围宽，是为了避免子域流量被系统直连卡住。

系统侧只改一个值：

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL
  = http://127.0.0.1:8443/winget-accel.pac
```

`setup` 在改动前把**原有 `AutoConfigURL`** 记进状态文件，`teardown` 原样写回。

> PAC 取不到时，WinINet 会退化为直连。这是有意接受的行为：
> 表现为"没有加速"，而不是"没有网络"。

## 4. CONNECT 分流

代理收到的第一条报文决定走哪条路：

| 首行 | 处理 |
|---|---|
| `CONNECT <host>:<port>`，host 在 `rewriteHosts` 内 | **MITM**（§5），终止 TLS 并改写 |
| `CONNECT <host>:<port>`，host 不在白名单 | **隧道**：连接上游后双向泵字节，不解析 |
| `GET /winget-accel.pac` | 返回 PAC 文本（`PAC-SERVED`） |
| `GET /health` 或 `/status` | 返回 JSON 计数 |
| 其它明文请求 | `405`，记 `PLAIN-405` |

实现约束：

1. **只绑定 `127.0.0.1`**，不得绑 `0.0.0.0`
2. Windows 上必须用 `SO_EXCLUSIVEADDRUSE`。原型最初用 `SO_REUSEADDR`，
   实测在 Windows 上会允许**抢占已被占用的端口**，出现两个实例同时绑定、命中随机
3. 读 `CONNECT` 头时**逐字节读到 `\r\n\r\n`**，不得多读——头后面紧跟 ClientHello，
   多读会把 TLS 记录切碎（原型 `read_until_atomic` 即为此）
4. 隧道上游连接超时 15 s，失败返回 `502` 并记 `TUNNEL-FAIL`
5. 端口被占用时**立即失败并打印占用进程**，不静默换端口——PAC 里写死了端口，
   换了端口就等于指向空气

## 5. MITM 与叶证书

### 5.1 CA 参数（已实测）

| 项 | 值 | 说明 |
|---|---|---|
| 算法 | ECDSA P-256 | 原型选择；Rust 版可改 RSA-2048 规避边缘兼容问题 |
| `BasicConstraints` | `ca=true, path_length=0` | 只能签终端证书，不能签下级 CA |
| `NameConstraints` | `permitted_subtrees` = 4 个 DNS，`critical` | **核心约束**：Windows 强制校验（§9.4） |
| `KeyUsage` | `keyCertSign` + `crlSign` + `digitalSignature` | |
| 有效期 | 90 天 | 过长不便轮换，过短频繁打扰用户 |

### 5.2 叶证书

| 项 | 值 |
|---|---|
| SAN | **只含该 host 一个** `DNSName` |
| `BasicConstraints` | `ca=false`，`critical` |
| `ExtendedKeyUsage` | `serverAuth` |
| 有效期 | 30 天 |
| 生成时机 | 首次遇到该 host 时生成并缓存（进程内） |

> 原型的叶证书会落盘到 `certs/leaves/`。Rust 版应**在内存生成并缓存**，
> 不落盘（ADR-015）。

### 5.3 握手失败的处理

握手失败只记 `MITM-HANDSHAKE-FAIL <host> <err>` 并关闭连接，**不重试、不改道**。
最常见原因是客户端不信任 CA（未 `setup` 或 CA 被删）。

## 6. URL 改写规则

输入（`CONNECT github.com:443` 之后的请求行）：

```
GET /junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip HTTP/1.1
```

改写为：

```
GET /https://github.com/junegunn/fzf/releases/download/v0.74.5/fzf-0.74.5-windows_amd64.zip HTTP/1.1
Host: gh-proxy.com
```

规则：

1. 目标 = 加速器模板 `https://<加速器>/{url}`，代入
   `url = https://<原 host><原 path+query>`。实际报文是把
   `/https://<原 host><原 path+query>` 作为请求路径、`Host` 设为加速器域名，
   等价于 `https://gh-proxy.com/https://github.com/...`
2. `Host` 头改成加速器域名
3. **必须原样透传**：`Range`、`If-Range`、`If-None-Match`、`User-Agent`
4. **必须剥离**逐跳头：`Proxy-Connection`、`Connection`、`Keep-Alive`、`TE`、`Trailer`、`Upgrade`
5. 不改请求方法、不改查询串、不重新编码路径（`%2F` 之类保持原样）
6. **只改 URL，不碰响应体**——这是完整性论证的前提（ADR-014 约束 3）

> `Range` 透传是硬要求：实测 winget 用 4 段 Range 取同一个文件（§9.2），
> 丢掉 `Range` 会退化为整包重传，或者拼出坏文件。

## 7. 响应转发

| 上游响应形态 | 处理 |
|---|---|
| 有 `Content-Length` | 按长度读满再转发 |
| `Transfer-Encoding: chunked` | 按块解码转发（含 0 块后的 trailer） |
| 两者都没有 | 读到 EOF |
| 上游连接失败 | 回 `502`，记 `UPSTREAM-FAIL` |

状态码、`Content-Range`、`Content-Type` 等响应头**原样转发**，不重写。
请求侧统一加 `Connection: close`（原型为一连接一请求）；Rust 版支持 keep-alive 后
这一条要相应调整，届时需重新验证「多请求复用一条隧道」下 `206` 仍正确。

## 8. 加速器健康检查与切换

### 8.1 配置形状

**字段形状的权威定义是 [`config.example.json`](../config.example.json)**；本节只解释语义，
不再复制整份配置——此前 `design.md` 与 `config.example.json` 各存一份，出现过字段不一致
（`failuresBeforeUnhealthy`、`stateFile`、`logLevel`）。

| 字段 | 语义 |
|---|---|
| `listen` | 监听地址，**只能**是 `127.0.0.1:<port>`；该端口同时写进 PAC |
| `rewriteHosts` | 改写白名单，按 host 精确匹配；PAC 与 CONNECT 分流共用这一份（ADR-004 / ADR-014 约束 2） |
| `accelerators[]` | `name` / `template`（`{url}` 占位）/ `priority` |
| `health.*` | 见 §8.2 |
| ~~`fallbackToOriginal`~~ | **已删除**：全挂时快速 502，不回退直连（ADR-016） |
| `logLevel` | `debug` / `info` / `warn` / `error` |

实现约定：以 `$` 开头的键（`$comment` 等）是注释，解析时必须忽略。

`accelerators[]` 按 `priority` 升序，取第一个健康的：

```json
{ "name": "gh-proxy", "template": "https://gh-proxy.com/{url}", "priority": 1 }
```

### 8.2 探测

| 项 | 值 | 依据 |
|---|---|---|
| 探测目标 | 加速器**自身 origin** 根路径 | 用 GitHub 资产当探针会把"GitHub 不通"误判为"加速器不健康"（`verification-2026-11-01.md` V1） |
| 判定 | **收到任意 HTTP 响应（含 404）即可达** | 不要求 2xx/3xx；同时记录 TTFB |
| 方法 | `HEAD`，不支持则退化为 1 字节 `Range` GET | |
| 超时 | `health.timeoutSeconds`（默认 8） | 超时计一次失败 |
| 间隔 | `health.intervalSeconds`（默认 300），不得更快 | 避免重蹈压测惩罚（ADR-006） |
| 并发 | 1 | 同上 |
| 判定阈值 | 连续 `failuresBeforeUnhealthy`（默认 2）次失败才标记不健康 | 抗抖动 |

### 8.3 切换

改写发生在**每个请求**上，所以切换是即时的：健康状态一变，下一个请求就用新加速器。
不需要重建任何缓存。

> 未验证（H4）：并发下载中途加速器失效时，已建立的连接不会自动迁移。
> 当前设计接受这一点——该连接会失败，winget 重试时才会命中新加速器。

### 8.4 host × 加速器 能力矩阵

不同加速器对 host 的支持不一致。改写前必须查矩阵，不支持的组合**不得**改写
（退化到直接隧道，慢但可用）。

当前已证实的组合只有：`gh-proxy` 支持 `github.com`。
`objects.githubusercontent.com` / `codeload.github.com` / `release-assets.githubusercontent.com`
是否被支持**未验证**（原型实测的都是 `github.com` 直链）。

### 8.5 当前候选

| 加速器 | 状态（2026-11-01） |
|---|---|
| `gh-proxy.com` | ✅ 可用，支持 `Range` / `206`（§9.2） |
| `ghproxy.imciel.com` | ✅ 可用（222 KB/s） |

2026-11-01 复测后有 3 个可用候选（765 / 222 / 190 KB/s），回退链成立（verification-proxy §12）。

## 9. 失败回退：不回退（ADR-016）

所有加速器都**不健康**时，直接返回 `502` + 日志 `NO-HEALTHY-ACCEL`，**不回退直连**。

早期设计有 `fallbackToOriginal` 开关，2026-11-01 实测后删除：

| 路径 | 实测 |
|---|---|
| 直连 `curl -L` | 21 KB/s，30 秒只收到 636,355 B |
| 直连 `winget download`（WinHTTP） | **37 秒失败**（`12002`），0 字节落盘 |
| 经代理 `winget download` | **13 秒成功**，哈希校验通过 |

差别不在可达性，而在客户端超时策略：`curl` 会慢慢收，`winget` 37 秒就放弃。
所以回退对 `winget` 不是"变慢"，是"多等 37 秒后仍然失败"。明确失败优于假死。

代价：加速器全挂时用户直接看到失败。公共加速器存活状态会变（`ghfast.top` 当天就经历了"失效→可用"），
只能靠"多找候选"缓解（`doctor` 的 `chain` 项会对此告警）。

### 全挂时"报错"的具体形态

"报错"不是退出进程（那会让 PAC 指向一个死端口，反而更难排查），而是四件事：

| 位置 | 表现 |
|---|---|
| 日志 | **一条 ERROR**：`ALL-ACCEL-DOWN 所有加速器均不可用（host=unhealthy, ...）：请求会立即返回 502，后台继续重试`。只在状态**翻转**时打，避免每请求刷屏 |
| 请求 | 立即 `502`（实测 0.1 s），并打一条 `NO-HEALTHY-ACCEL` warn |
| `/health` | `"status":"down"`，可直接被脚本消费 |
| `--doctor` | `chain` 项 **FAIL**：`N 个候选全部不可达：下载会立即失败` |

恢复时打一条 `ALL-ACCEL-RECOVERED`。全挂期间探测间隔从 300 s 缩短到 **30 s**，
让恢复更快被发现；**单候选也照常探测**——否则一旦被判死就永久 502，没有任何恢复路径。

## 10. 失败模式与诊断

| 场景 | 用户看到 | 诊断依据 |
|---|---|---|
| 代理未启动 | 这 4 个 host 的下载失败（其余网络正常） | `AutoConfigURL` 指向的端口无响应；`doctor` 报"代理未运行" |
| CA 未安装 / 被删 | TLS 握手失败，`MITM-HANDSHAKE-FAIL` | `doctor` 查 `CurrentUser\Root` 指纹 |
| CA 过期 | 同上 | `doctor` 查有效期 |
| 端口被占用 | 启动即失败 | 打印占用进程（`SO_EXCLUSIVEADDRUSE` 保证不会静默抢占） |
| 加速器全挂 | 回退直连（很慢）或 `502` | 日志 + `/health` 的加速器状态 |
| PAC 未生效 | 完全没有加速，但一切正常 | `doctor` 读 `AutoConfigURL` 并与期望值比对 |
| winget 改为不走系统 PAC | 同上 | 只能靠日志观察（H5） |

### 10.1 日志

| 行 | 含义 |
|---|---|
| `PAC-SERVED` | 有人来取 PAC（说明 PAC 生效） |
| `REWRITE <host><path> -> <status> <bytes>B <time>s` | 白名单请求已改写并转发 |
| `PASS ...` | 进入 MITM 但未改写（非白名单，理论上不该出现） |
| `TUNNEL-FAIL` / `UPSTREAM-FAIL` | 上游不可达 |
| `MITM-HANDSHAKE-FAIL` | 客户端不信任 CA |
| `RELAY-ERR` | 转发中断 |
| `CLIENT-ERR` | 客户端侧异常（含 Name Constraints 拒绝） |

`GET /health` 返回计数：`connects / mitm / tunnel / rewrites / bytes / errors`。

### 10.2 `doctor` 检查项

1. 代理进程与端口（`127.0.0.1:8443` 是否可连）
2. PAC：`AutoConfigURL` 是否等于期望值
3. CA：是否在 `CurrentUser\Root`、指纹是否匹配、是否临近过期
4. 加速器：逐个探测 origin，输出状态与 TTFB
5. winget 版本（记录用，不进判定）

## 11. 安全边界

| 边界 | 实现 |
|---|---|
| CA 不能签别的域名 | `NameConstraints` 限定 4 个 DNS + `path_length=0`，Windows 强制校验（§9.4） |
| 代理挂了不会全机断网 | PAC 而非全局 `ProxyServer`，只圈 4 个 host |
| 下载内容不会被篡改 | winget 校验官方清单的 `InstallerSha256`；本项目不碰响应体 |
| 只监听本机 | 绑定 `127.0.0.1` |
| 不记录敏感内容 | **不记录请求/响应体**，只记 host、path 前缀、状态码、字节数 |
| 私钥保护 | CA 私钥仅当前用户可读，`*.pem` / `*.key` 已被 `.gitignore` 排除 |
| 可完整卸载 | `teardown` 删 CA + 还原 PAC + 停进程，并自校验 |

## 12. 明确不做的事

- 不实现 REST 源、不建索引、不同步清单、不注册源（ADR-013）
- 不做 hosts 劫持、不改 DNS、不启用 `LocalManifestFiles`
- 不代理 `microsoft.com` / 商店域 / 其它软件源
- 不实现 HTTP/2——不协商 ALPN，强制 HTTP/1.1（原型即如此，实测 winget 接受）
- 不做 CRL/OCSP（自签 CA 无吊销信息；`curl` schannel 需 `--ssl-no-revoke`，winget 不受影响）
- 不做激进并发：健康探测并发 1、间隔 ≥5 分钟
- 不缓存响应体（同一 URL 重复下载仍走加速器；是否加缓存待实测后再定）
