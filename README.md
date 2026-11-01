# winget-accel

在本机运行一个 **winget REST 源**，把清单里的 `InstallerUrl` 动态改写到 GitHub 加速服务，
让 `winget install / search / upgrade` 在国内网络下也能正常工作。

> 状态：**调研完成，尚未开始编码**。本文档集是交给下一次会话的完整交接材料。
>
> **2026-11-01 复核**：直连 GitHub 资产已从"慢"恶化为"不可用"，两个加速器只剩一个可用；
> 协议层的 5 个未决项已全部关闭。详见 [docs/verification-2026-11-01.md](docs/verification-2026-11-01.md)。

## 要解决的问题

国内网络下 `winget` 的主流程可以正常工作（源索引、清单查询），但**安装包下载极慢**：

| 通道 | 实测速率 | 备注 |
|---|---|---|
| 直连 GitHub 单连接 | 23–46 KB/s | 63.75 MB 的 Git for Windows 需约 30 分钟 |
| 经 `gh-proxy.com` | 523–1,437 KB/s | 20–50 倍提升 |
| winget 自带 Delivery Optimization | 34 KB/s | 与直连同源，无改善 |

> 复核补记（2026-11-01）：上表是调研当日数据。复测时直连已是 **`000` / 20 秒超时，完全不可用**，
> `ghfast.top` 亦不可达。也就是说"慢"已恶化为"断"，回退到原始 URL 的代价从"等"变成"卡死"。

同时 `winget show` 的源层查询存在偶发严重延迟（实测 4.33 / 41.15 / 80.96 秒），
本地源可一并消除这个问题。

## 方案定位（为什么是"本地 REST 源"）

winget 把**所有能绕开官方源的机制都做成了管理员门禁**，实测确认：

| 机制 | 状态 | 报错原文 |
|---|---|---|
| `winget source add` | 需管理员 | 需要具有管理员权限才能执行此命令 |
| `winget install -m`（本地清单） | 需管理员 | 请以管理员身份运行 `winget settings --enable LocalManifestFiles` |
| `--proxy`（命令行代理） | 需管理员 | 请以管理员身份运行 `winget settings --enable ProxyCommandLineOptions` |

本机 `winget settings export` 显示六项 adminSettings 全为 `false`。

因此在"必须提权一次"的前提下，选择**副作用最小**的那条路：

- **本机 127.0.0.1 上的 REST 源** + 一张仅用于 `localhost` 的自签证书
- 不启用 `LocalManifestFiles`（那会让本机任意程序可静默安装任意本地清单）
- 不装根证书、不做 MITM、不改 hosts

详见 [docs/decisions.md](docs/decisions.md)。

## 设计要点

1. **只改写白名单内的 host**（`github.com`、`objects.githubusercontent.com` 等），
   其余 URL 原样透传。不做全量改写。
2. **服务时改写，不落盘改写**：本地保存的清单保持与上游完全一致，
   改写规则由配置驱动，换加速器无需重新同步。
3. **哈希信任链不变**：`InstallerSha256` 来自官方 `microsoft/winget-pkgs`，
   加速器只经手字节，改了就装不上。
4. **禁止激进并发下载**：实测 32–64 连接会触发 CDN 侧惩罚，导致该 IP 的
   GitHub 发布资产下载**整体归零**。任何内置下载逻辑并发上限 4–8，且必须有退避。

详见 [docs/design.md](docs/design.md)。

## 实现形态

**Rust 单文件二进制**（`x86_64-pc-windows-msvc` + `crt-static`，约 4–6 MB），无运行时依赖，
解压即用、便于分发给他人。语言选择与依赖约束见
[docs/decisions.md](docs/decisions.md) 的 ADR-009 / ADR-012（依赖预算：直接依赖 ≤8、传递 ≤30）。

## 前置条件（一次性，需管理员）

```powershell
# 1) 生成仅用于 localhost 的自签证书并加入本机信任库
# 2) 注册源（HTTPS 端口，具体端口见配置）
winget source add -n winget-accel -a https://localhost:8443/api -t "Microsoft.Rest"
```

卸载/回滚：

```powershell
winget source remove -n winget-accel
```

## 仓库结构

```
docs/
  research.md    调研过程与全部实测数据（含失败与被否决的方向）
  verification-2026-11-01.md  第二次复核：网络现状、已核实的协议事实、待办 V1–V8
  design.md      架构、REST 协议、清单流水线、证书、信任模型
  decisions.md   方案取舍记录（ADR-001–012 逐条判定）
  rewinged-reference.md  参考 jantari/rewinged 的边界、范围与阅读顺序
  reference-log.md  参考台账：每次阅读的来源、范围与产出
  roadmap.md     实现计划与验收标准
```

## 与 rewinged 的关系

本项目**自行实现**。与 [jantari/rewinged](https://github.com/jantari/rewinged)（MIT）的关系是
**只参考设计与事实、不搬代码**（T2/T3，见 [docs/decisions.md](docs/decisions.md) ADR-011）：
只借鉴"要处理哪些清单形态、1.10.0 有哪些字段"，不沿用它的模型体系与检索实现。
逐次阅读记录见 [docs/reference-log.md](docs/reference-log.md)。

## 许可证

MIT
