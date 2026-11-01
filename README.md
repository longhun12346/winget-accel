# winget-accel

在本机运行一个**代理**，用 PAC 只把 4 个 GitHub 下载域名指给它，
再由它把请求改写到 GitHub 加速服务——让 `winget install` 在国内网络下也能下得动。

> 状态：**原型已实测通过（2026-11-01），尚未开始 Rust 交付实现**。
>
> 架构在同一天从"本地 REST 源"切换为"PAC + 本机 MITM 改写代理"。
> 切换依据：[docs/verification-proxy-2026-11-01.md](docs/verification-proxy-2026-11-01.md)；
> 决策记录：[docs/decisions.md](docs/decisions.md) ADR-013 / ADR-014 / ADR-015。

## 要解决的问题

国内网络下 `winget` 的主流程可以正常工作（源索引、清单查询），但**安装包下载极慢，且已经恶化到不可用**：

| 通道 | 实测 | 备注 |
|---|---|---|
| 直连 GitHub 发布资产 | **`000` / 20 s 超时** | 2026-11-01 复测：`curl` 拿到 `302` 后卡住，`objects.githubusercontent.com` 不可达 |
| 经 `gh-proxy.com` | 634 KB/s（1,535,063 B / 2.39 s） | 同一资源，经原型代理 |
| 经原型代理，`winget download` | 2,544,236 B / 7.7 s | 退出码 0，哈希校验通过 |

也就是说：问题不在"慢"，而在**下载链路断了**。回退到原始 URL 的代价不是"等"，是"卡死"。

## 方案定位（为什么是"代理层改写"）

### 先看 winget 把什么做成了管理员门禁

| 机制 | 状态 | 报错原文 |
|---|---|---|
| `winget source add` | 需管理员 | 需要具有管理员权限才能执行此命令 |
| `winget install -m`（本地清单） | 需管理员 | 请以管理员身份运行 `winget settings --enable LocalManifestFiles` |
| `--proxy`（命令行代理） | 需管理员 | 请以管理员身份运行 `winget settings --enable ProxyCommandLineOptions` |

本机 `winget settings export` 显示六项 adminSettings 全为 `false`。

早期的结论是"既然必须提权，就选副作用最小的 REST 源"（ADR-001）。
这个结论在 2026-11-01 被推翻：**还有一种不需要管理员的路——系统 PAC 与用户级根存储都不需要提权。**

### 为什么不能"只做纯代理"

代理只收到 `CONNECT github.com:443`，之后是端到端加密的字节流。只有两种可能：

1. 原样转发到 `github.com` —— 没有任何加速效果
2. 转发到加速器 —— TLS 握手失败（客户端 SNI 是 `github.com`，加速器的证书不是它的）

要让第 2 种成立，必须自己终止 TLS。这是 MITM，必须让系统信任一张我们生成的 CA。
没有第三条路。

### 所以：终止 TLS，但把代价收敛到三重约束

| 约束 | 做法 | 实测 |
|---|---|---|
| CA 只能签 4 个域名 | `NameConstraints` + `path_length=0` | 签 `example.com` 被客户端拒绝 |
| 代理只被 4 个 host 使用 | PAC 只圈这 4 个 host，其余 `DIRECT` | `PAC-SERVED ×9`，非白名单 host 隧道 200 |
| 内容被改会被发现 | winget 仍校验官方 `InstallerSha256`，我们只改请求 URL | `"已成功验证安装程序哈希"` |

MITM 在这里影响的只是"谁能看到你在下载什么"（全是公开安装包），
**不能影响"你下载到的是什么"**。详见 [docs/decisions.md](docs/decisions.md) ADR-014。

## 设计要点

1. **不改清单、不建索引、不注册源**：winget 的清单查询仍走官方源，完全直连。
2. **只圈 4 个 host**：`github.com`、`objects.githubusercontent.com`、
   `codeload.github.com`、`release-assets.githubusercontent.com`。其余一律直通。
3. **用 PAC 而不是全局代理**：代理进程挂掉时，只有这 4 个 host 失败，其余网络不受影响。
4. **只改 URL，不碰字节**：响应体原样转发；`Range` / `206` 必须原样透传
   （实测 winget 用 4 段 Range 取同一个文件）。
5. **不需要管理员**：`AutoConfigURL` 在 HKCU，CA 装进 `CurrentUser\Root`。

详见 [docs/design.md](docs/design.md)。

## 实测结果

| 场景 | 结果 |
|---|---|
| `curl` 直连 release 资源 | 302 后卡住 |
| `curl` 经原型 | 200，1,535,063 B / 2.39 s ≈ 634 KB/s |
| `winget download --id junegunn.fzf`（PAC 模式） | 退出码 0，7.7 s，2,544,236 B，哈希校验通过 |
| 非白名单 host（`api.github.com`） | 原样隧道，200 / 0.96 s |
| Name Constraints 是否强制 | 强制：签 `github.com` 接受，签 `example.com` 拒绝 |

完整日志与未验证项：[docs/verification-proxy-2026-11-01.md](docs/verification-proxy-2026-11-01.md)。

## 实现形态

**Python 原型已跑通**（[`prototype/`](prototype/)，验证用，不进交付）；
交付形态是 **Rust 单文件二进制**（`x86_64-pc-windows-msvc` + `crt-static`），无运行时依赖。

语言与依赖约束见 ADR-009 / ADR-012 / ADR-015。

## 安装与卸载

一次性，**不需要管理员**——但装根证书会弹一次 Windows 安全警告，需要点"是"：

```powershell
winget-accel setup      # 生成 CA → 装入 CurrentUser\Root → 设 AutoConfigURL → 启动代理
winget-accel doctor     # 自检：CA / PAC / 端口 / 加速器
winget-accel teardown   # 删 CA → 还原 AutoConfigURL → 停进程 → 自校验无残留
```

`setup` 必须能在**无人值守**场景下不挂死：把根证书导入放到子进程 + 超时，
超时则打印可复制的手动命令（`certutil -user -addstore Root ...`）并完整回滚。
这个坑是实测踩到的，见 [docs/verification-proxy-2026-11-01.md](docs/verification-proxy-2026-11-01.md) §10。

## 仓库结构

```
prototype/          Python 原型（PAC + CONNECT 分流 + MITM 改写），验证产物，不进交付
docs/
  research.md      调研过程与全部实测数据（含失败与被否决的方向）
  verification-2026-11-01.md        第二次复核：网络现状与协议事实（REST 源时期）
  verification-proxy-2026-11-01.md  代理架构验证：mitmproxy 实验 + 原型实测
  design.md        代理架构设计：PAC、CONNECT 分流、MITM、改写、健康检查、失败回退
  decisions.md     方案取舍记录（ADR-001–015，含状态总表）
  roadmap.md       实现计划与验收标准
  rewinged-reference.md  历史记录：REST 源时期的参考边界（现已基本失效）
  reference-log.md       历史记录：参考台账
```

## 与 rewinged 的关系

**基本失效**（ADR-011）。[jantari/rewinged](https://github.com/jantari/rewinged) 是一个
**REST 源实现**，而新架构不实现任何协议端点，当初想参考的东西（端点组织、清单摄取、
跨版本字段语义）几乎都用不上了。

`docs/rewinged-reference.md` 与 `docs/reference-log.md` 作为历史记录保留，不再追加。
本项目与其没有代码关系，也没有复制或翻译它的代码。

## 许可证

MIT
