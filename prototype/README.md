# 原型：PAC + 白名单改写代理（Python）

> 这是**验证用原型**，不是交付代码。目的：证明"不实现 REST 源、只在下载层改写"的架构成立，
> 并把风险点（CA 约束、PAC 范围、哈希校验）逐个实测掉。交付形态是 Rust 单文件二进制。

## 它做什么

```
winget ──①查清单──> 官方 winget 源（DIRECT，完全不经过我们）
   │
   └──②下载 InstallerUrl──> github.com:443
                              │
                        PAC 只把这 4 个 host 指给本机代理
                              ↓
                        本机代理 127.0.0.1:8443
                          · 用自签 CA 签发该 host 的叶证书，终止 TLS
                          · 把请求改写成 https://gh-proxy.com/<原始完整 URL>
                          · 回程字节原样转发
                              ↓
                          gh-proxy.com ──> GitHub
```

**不改清单、不建索引、不注册源、不需要管理员。**
winget 仍用官方清单里的 `InstallerSha256` 校验字节，被篡改就装不上——**完整性不因 MITM 下降**。

## 依赖与安装

```powershell
cd prototype
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe cryptography
```

## 运行

```powershell
.\setup.ps1              # 装 CA 到 CurrentUser\Root + 设置 PAC + 启动代理
winget download --id sharkdp.fd -d $env:TEMP\fdtest --accept-source-agreements
Get-Content proxy.log -Tail 20
.\teardown.ps1           # 移除 CA + 还原 PAC + 停进程
```

只做只读自检（不动系统状态）：

```powershell
.\selftest.ps1           # 用 curl --cacert 显式信任原型 CA，走代理下载
```

`setup.ps1` / `teardown.ps1` 都是幂等的，`teardown.ps1` 结束时会自校验
`ProxyEnable`、`AutoConfigURL`、CA 残留、进程残留，有残留则 `exit 1`。

### 安装根证书需要点一次「是」

把 CA 装进 `CurrentUser\Root` 会弹出 Windows 安全警告，**必须手动确认**。
在没有可见桌面的会话里，`Import-Certificate`、`X509Store.Add`、`certutil -addstore`
都不会报错，而是**永久阻塞**——这是实测踩到的坑。

`setup.ps1` 因此用子进程 + 超时（默认 45 s）来调用，超时会明确提示并在可见终端里执行：

```powershell
certutil -user -addstore Root "$PWD\certs\ca-cert.pem"
```

装好后再跑一次 `.\setup.ps1` 会自动跳过（按指纹判重）。

## 实测结果（2026-11-01，本机）

| 场景 | 结果 |
|---|---|
| `curl` 直连 release 资源 | 302，随后卡住（`objects.` 被墙） |
| `curl` 经原型 | **200，1,535,063 B / 2.39 s ≈ 634 KB/s** |
| `curl` 经原型下载 18.3 MB 大文件 | **200，18,314,725 B / 8.86 s ≈ 2.07 MB/s**，落盘完整、无截断 |
| `winget download --id junegunn.fzf`（PAC 模式） | **退出码 0，7.7 s，2,544,236 B，"已成功验证安装程序哈希"** |
| 非白名单 host（`api.github.com`） | 原样隧道，200 / 0.96 s，未被改写 |
| Name Constraints 强制校验 | **生效**：签 `github.com` 被接受，签 `example.com` 被客户端拒绝 |

细节与日志见 [../docs/verification-proxy-2026-11-01.md](../docs/verification-proxy-2026-11-01.md)。

## 安全边界

| 边界 | 实现方式 |
|---|---|
| CA 不能签别的域名 | `NameConstraints` 只允许 4 个 host + `path_length=0`（已实测被 Windows 强制） |
| 代理挂了不会全机断网 | 用 **PAC** 而非全局 `ProxyServer`：只有 4 个 host 走代理，其余 `DIRECT` |
| 下载内容不会被篡改 | winget 仍校验官方清单的 `InstallerSha256`（实测通过） |
| 可完整卸载 | `teardown.ps1` 移 CA + 还原 PAC + 停进程，并自校验 |
| 不碰 Microsoft 域名 | PAC 不把任何 `microsoft.com` host 指给代理，清单查询完全直连 |

## 已知限制（原型刻意不做）

这些是**写 Rust 版时要解决**的，不是 bug：

1. **单加速器硬编码**：`--accel` 只有一个候选，没有健康检查与切换（对应 roadmap V2）
2. **每连接一次请求**：响应后即关闭，不支持 keep-alive；winget 会重连，功能正常但不最优
3. **无线程池**：一连接一线程，未限并发
4. **无磁盘缓存**：同一 URL 重复下载仍走加速器
5. **不处理 HTTP/2**：不协商 ALPN，强制 HTTP/1.1（材料见 `docs/decisions.md` ADR-014）
6. **撤销检查**：自签 CA 无 CRL/OCSP，`curl`（schannel）需 `--ssl-no-revoke`；winget/WinHTTP 不受影响
7. **ECDSA 叶证书**：本机验证通过；Rust 版可改 RSA-2048 以规避边缘兼容问题
8. **证书落盘**：叶证书写到 `certs/leaves/`，Rust 版应内存生成
9. **安装 CA 需交互**：见上一节；Rust 版安装器必须显式设计这一步（弹窗 + 取消即回滚）

## 文件说明

| 文件 | 作用 |
|---|---|
| `wgaccel.py` | PAC 服务 + CONNECT 分流 + MITM 改写 + 隧道路径 |
| `ca.py` | 自签 CA（带 Name Constraints）与叶证书生成 |
| `setup.ps1` / `teardown.ps1` | 安装 / 卸载（幂等，带回滚与自校验） |
| `selftest.ps1` | 不改系统状态的端到端自检 |
| `probe-constraints.ps1` | H1 实验：隧道 + Name Constraints 是否强制 |
| `probe-winget-pac.ps1` | winget + PAC 全链路实验（自带清理） |

> `certs/` 里含私钥，已在 `.gitignore` 中排除，**永不入库**。
