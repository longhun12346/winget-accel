# winget-accel

在本机运行一个 **winget REST 源**，把清单里的 `InstallerUrl` 动态改写到 GitHub 加速服务，
让 `winget install / search / upgrade` 在国内网络下也能正常工作。

> 状态：**调研完成，尚未开始编码**。本文档集是交给下一次会话的完整交接材料。

## 要解决的问题

国内网络下 `winget` 的主流程可以正常工作（源索引、清单查询），但**安装包下载极慢**：

| 通道 | 实测速率 | 备注 |
|---|---|---|
| 直连 GitHub 单连接 | 23–46 KB/s | 63.75 MB 的 Git for Windows 需约 30 分钟 |
| 经 `gh-proxy.com` | 523–1,437 KB/s | 20–50 倍提升 |
| winget 自带 Delivery Optimization | 34 KB/s | 与直连同源，无改善 |

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
  design.md      架构、REST 协议、清单流水线、证书、信任模型
  decisions.md   方案取舍记录（L1–L10 逐条判定）
  rewinged-reference.md  参考 jantari/rewinged 的具体部分与边界
  roadmap.md     实现计划与验收标准
```

## 与 rewinged 的关系

本项目**自行实现**，但参考 [jantari/rewinged](https://github.com/jantari/rewinged)（MIT）的
REST 协议实现与清单模型组织方式。凡参考其代码，保留原始版权声明，见
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

## 许可证

MIT
