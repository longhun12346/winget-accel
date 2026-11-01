# 测试用例（行为契约）

> 状态：**可执行**。`prototype/tests/` 下 52 个用例，2026-11-01 在本机全绿。
> 本文是这些用例的索引与判定标准，也是 Rust 版必须对齐的契约。
> 运行方式见 §6。

## 0. 为什么要先写用例

不是流程要求，是三个已被抓到的缺陷：

| 用例暴露的问题 | 后果 | 状态 |
|---|---|---|
| `Host` 头丢了非默认端口 | 指向非 443 的加速器会收到错误的 Host | 已修（`host_header()`） |
| 响应结束不发 `close_notify` | 客户端报 `(56) missing close_notify`，**字节完整却被当下载失败** | 已修（`shutdown_tls()`） |
| 叶证书"生成 + 加载"非原子 | 并发首连同 host 时读到半截 PEM，TLS 连接被重置 | 已修（`_leaf_lock` + 双重检查） |

第三条只在 3 路并发 Range 下才复现，手工测过一次没抓到。

## 1. 分层

| 层 | 前缀 | 依赖 | 默认 | 目的 |
|---|---|---|---|---|
| 单元 | `CFG` `PAC` `REW` `CA` | 无 | 跑 | 纯逻辑与证书属性 |
| 协议 | `FWD` `ERR` `TUN` `LCL` | 本地假上游 | 跑 | 改写、保真、错误、隧道 |
| 网络 | `NET` | 外网 + 可用加速器 | **跳过** | 钉住加速器真实行为 |
| 系统 | `SYS` | 交互确认 + 真实 winget | **手工** | 安装/卸载/端到端 |

关键设计：**协议层不碰系统状态**。CA 通过 `curl --cacert` 显式信任，不装进
`CurrentUser\Root`；PAC 不被写入注册表。因此这一层能在无网、无管理员、无交互的
环境里跑，也不留残留。

## 2. 单元用例

### 配置解析 `CFG`

| ID | 断言 | 实现 |
|---|---|---|
| CFG-01 | 接受 `host` / `host:port` / `scheme://host:port`，默认 scheme 为 https、默认端口随 scheme | `test_parse_accel_accepts_supported_forms`（7 组） |
| CFG-02 | 拒绝 `ftp://`、空主机、只有端口、非数字端口 | `test_parse_accel_rejects_bad_input`（4 组） |

### PAC 文本 `PAC`

PAC 是 JScript，这里不做 JS 求值，只锁定生成文本的结构；真实路由行为由
`FWD-01..03` 与线上实测（`verification-proxy-2026-11-01.md` §9）覆盖。

| ID | 断言 | 实现 |
|---|---|---|
| PAC-01 | 存在 `FindProxyForURL(url, host)` 入口 | `test_pac_declares_entry_function` |
| PAC-02 | 4 个白名单 host 逐一出现在条件里 | `test_pac_covers_all_whitelist_hosts` |
| PAC-03 | `*.github.com` 是**唯一**通配，且不存在 `*.com` 这类过宽模式 | `test_pac_routes_github_subdomains_but_not_other_wildcards` |
| PAC-04 | 端口嵌入正确，兜底为 `DIRECT` | `test_pac_uses_given_port_and_defaults_to_direct` |
| PAC-05 | host 先 `toLowerCase()` 再比较 | `test_pac_lowercases_host` |

### 改写决策 `REW`

`plan_upstream()` 是纯函数：决定上游地址、请求行、转发的头，不碰 socket。

| ID | 断言 | 实现 |
|---|---|---|
| REW-01 | 路径改写为 `/https://<host><原 target>` | `test_rewrite_path_prefixes_original_url` |
| REW-02 | 查询串原样保留，已百分号编码的字符不二次编码 | `test_rewrite_keeps_query_string_untouched` |
| REW-03 | 改写时上游 = 加速器，`Host` 换为加速器（含非默认端口） | `test_plan_rewrite_targets_accel_and_replaces_host_header` |
| REW-04 | 剥离 6 个逐跳头、保留 `Range`/`Accept`、追加 `Connection: close` | `test_plan_rewrite_drops_hop_by_hop_headers_and_keeps_range` |
| REW-05 | 非白名单：上游与原路径不变、保留客户端原 `Host` | `test_plan_passthrough_keeps_host_and_path` |
| REW-06 | 透传保留非默认端口 | `test_plan_passthrough_keeps_nonstandard_port` |
| REW-07 | 4 个白名单 host 全部命中改写分支 | `test_plan_rewrite_applies_to_every_whitelisted_host` |
| REW-08 | `api.github.com`、`cdn.winget.microsoft.com` 等**不**被改写 | `test_plan_non_whitelisted_host_is_not_rewritten` |

### 证书 `CA`

| ID | 断言 | 实现 |
|---|---|---|
| CA-01 | CA 含 critical `NameConstraints`，permitted 恰为 4 个 DNS，无 excluded | `test_ca_has_name_constraints_limited_to_whitelist` |
| CA-02 | `BasicConstraints.ca=True` 且 `path_length=0`（不能签下级 CA） | `test_ca_cannot_sign_subordinate_ca` |
| CA-03 | `KeyUsage.key_cert_sign=True` | `test_ca_key_usage_allows_cert_signing` |
| CA-04 | 同一 cert-dir 复用同一 CA（否则每次重启都要重新信任） | `test_ca_is_stable_across_restarts` |
| CA-05 | 叶证书 SAN 恰为目标 host、`ca=False`、EKU=serverAuth、issuer=CA、签名可验 | `test_leaf_certificate_is_valid_for_host` |
| CA-06 | 同 host 复用同一 SSLContext | `test_leaf_is_cached_per_host` |
| CA-07 | 不同 host 的叶证书不同 | `test_leaf_certificates_are_distinct_per_host` |
| CA-08 | 16 线程并发首建只产出**一份可解析**的叶证书 | `test_concurrent_first_use_builds_one_valid_leaf` |
| CA-09 | 约束外的 `example.com` 被客户端拒绝（集成级，见 §3） | `test_name_constraints_reject_host_outside_whitelist` |

## 3. 协议用例

假上游是本地明文 HTTP 服务（记录请求、按路径返回不同形态），因此**不需要外网**，
也不需要 443 端口或管理员权限。

### 转发保真 `FWD`

| ID | 断言 | 实现 |
|---|---|---|
| FWD-01 | 上游收到 `/https://github.com/ok` 且 `Host` 为加速器 | `test_rewrite_forwards_prefixed_url_and_accel_host` |
| FWD-02 | 上游收到 `Connection: close`、无 `Proxy-Connection`、自定义头保留 | `test_rewrite_drops_hop_by_hop_and_forces_close` |
| FWD-03 | 4 个白名单 host 逐个端到端走通 | `test_every_whitelisted_host_gets_rewritten` |
| FWD-04 | `Range: bytes=10-109` 被转发，返回 206 且恰 100 字节 | `test_range_is_forwarded_and_status_206_preserved` |
| FWD-05 | 响应头 `Content-Range: bytes 0-9/1024` 原样透出 | `test_content_range_header_survives_rewrite` |
| FWD-06 | chunked 响应正确转发（`abc`+`defg`+`h` = 8 字节） | `test_chunked_response_is_relayed` |
| FWD-07 | 无 `Content-Length` 的关闭定界响应完整转发**且不报 close_notify** | `test_response_without_content_length_is_relayed` |
| FWD-08 | 8 MiB 响应逐字节一致（SHA256 比对） | `test_large_response_is_byte_exact` |
| FWD-09 | 5 个并发首连全部成功，无连接被重置 | `test_concurrent_first_connections_all_succeed` |

### 错误路径 `ERR`

| ID | 断言 | 实现 |
|---|---|---|
| ERR-01 | 上游 502 原样透传，不改写状态码 | `test_upstream_error_status_is_passed_through` |
| ERR-02 | 加速器不可达时**快速**返回 502（不挂到超时），`errors` 计数 +1 | `test_unreachable_accel_returns_502_quickly` |
| ERR-03 | 同端口第二个实例启动即失败（防 `SO_REUSEADDR` 静默抢占） | `test_second_instance_on_same_port_fails_fast` |

### 隧道 `TUN`

| ID | 断言 | 实现 |
|---|---|---|
| TUN-01 | 非白名单 host 走隧道：客户端验证的是**目标站自己的证书**，路径未被加前缀 | `test_non_whitelisted_host_is_tunneled_not_rewritten` |

### 本地端点 `LCL`

| ID | 断言 | 实现 |
|---|---|---|
| LCL-01 | `/proxy.pac` 返回 `application/x-ns-proxy-autoconfig`，内容含本实例端口 | `test_pac_is_served_on_own_port` |
| LCL-02 | `/health` 的 `rewrites` / `bytes` / `mitm` 随请求增长 | `test_health_reports_counters` |
| LCL-03 | 其他明文请求返回 405 | `test_unknown_plain_request_gets_405` |

## 4. 网络用例 `NET`（`--network`）

固定 `sharkdp/fd v10.5.0`，避免上游发版导致漂移。

| ID | 断言 | 已知值 |
|---|---|---|
| NET-01 | 完整下载字节数与 SHA256 一致 | 1,535,063 B / `a227701b…d57cd7` |
| NET-02 | 加速器支持 Range：`-r 0-1023` 返回 **206** 且 1024 字节 | — |
| NET-03 | 3 路并发 Range 拼接后 SHA256 与整包一致 | — |

NET-02 直接决定 `fallbackToOriginal` 是否可用：加速器不支持 Range 时，
winget 的多段下载会退化为整段重下。

## 5. 未自动化的用例

| ID | 用例 | 为什么手工 | 判定标准 |
|---|---|---|---|
| SYS-01 | `setup.ps1` 装 CA + 设 PAC | 装根证书**必须交互确认**，无 UI 会话会阻塞（§10） | 弹一次确认；`ProxyEnable/ AutoConfigURL` 写入；`state.json` 记录原值 |
| SYS-02 | `winget download` 端到端 | 需真实 winget + 真实网络 | 退出码 0，输出"已成功验证安装程序哈希" |
| SYS-03 | `teardown.ps1` 还原 | 同上 | `AutoConfigURL` 恢复原值、CA 不在、进程不在，自检 exit 0 |
| SYS-04 | 重复 setup 幂等 | 同上 | 第二次不重复装 CA，不叠加 PAC |
| SYS-05 | 无 UI 会话下 setup 行为 | 需构造无桌面会话 | **不能无限挂**：45 s 内提示手动命令并 `exit 1` |
| SYS-06 | `winget install` 真实安装 | 受本机策略/已有版本影响 | 能下到包并进入安装阶段 |

SYS-01/03 已在本机手工跑通（结果见 `verification-proxy-2026-11-01.md` §9–§10），
但**不适合放进自动回归**：会让测试机留下受信任根证书。

## 6. 运行

```powershell
cd prototype
.\.venv\Scripts\python.exe -m pytest              # 49 个，无网无副作用
.\.venv\Scripts\python.exe -m pytest --network    # 加 3 个真实链路
```

前置：`uv pip install --python .venv\Scripts\python.exe pytest`（已装）。

## 7. Rust 版怎么对齐

| 层 | 做法 | 理由 |
|---|---|---|
| 单元（`CFG` `PAC` `REW` `CA`） | 在 Rust 内用 `#[test]` 重写，逐条对应 | 纯逻辑，同语言测最直接 |
| 协议（`FWD` `ERR` `TUN` `LCL`） | **保留 Python 侧，只把启动命令换成 Rust 二进制** | 黑盒测协议，与实现语言无关；省掉重写假上游 |
| 网络（`NET`） | 同上 | 同理 |
| 系统（`SYS`） | 仍是手工 | 交互确认无法自动化 |

为支持第 2 行，`conftest.py` 已实现 `--target-binary` 选项（默认走 `wgaccel.py`）：

```powershell
.\.venv\Scripts\python.exe -m pytest --target-binary ..\target\release\winget-accel.exe
```

该模式下 `test_units.py` 自动跳过（它测的是 Python 内部实现，Rust 侧有自己的单测）。
Rust 二进制刻意沿用同一套 CLI 参数（`--port` / `--cert-dir` / `--log` / `--accel` / `--mitm-extra`），
所以协议层的 17 个用例可以原样复用。这是刻意设计：**行为契约不随语言迁移而重写**。

## 8. 已知未覆盖

| 项 | 风险 | 计划 |
|---|---|---|
| 断点续传（中断后 `Range` 续传） | 大包安装中断后能否接着下 | 阶段 2/3 用 Git for Windows（63.75 MB）手工验证 |
| HTTP/2 / ALPN | 若客户端强制 h2 则失败 | 原型只支持 1.1；实测 winget 接受，写入限制不实现 |
| 高并发（>16 连接） | winget 默认并发数未知 | 阶段 3 压测 |
| CRL/OCSP | `curl` 需 `--ssl-no-revoke` | 不影响 WinHTTP；写入手册 |
| `download.visualstudio.microsoft.com` 超时（H2） | 个别 host 行为不同 | 未复现，暂不覆盖 |
