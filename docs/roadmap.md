# 实现计划

> 交接说明：本文档面向**下一个会话**。开新会话时先读
> `README.md` → `docs/research.md`（结论）→ `docs/verification-2026-11-01.md`（最新复核，含协议事实）→
> `docs/decisions.md`（为什么这样做）→ 本文档（做什么）。

---

## 阶段 0：环境与前提确认

| # | 事项 | 状态 | 说明 |
|---|---|---|---|
| 0.1 | 决定实现语言 | ✅ 已完成 | **Python + uv**（ADR-009 已修订）。`uv` 本机已装，零安装成本 |
| 0.2 | 拿到 OpenAPI 规范 | ✅ 已完成 | 61,887 B / 1,906 行，SHA-256 见 `verification-2026-11-01.md` §3.1；经 gh-proxy 获取 |
| 0.3 | 确认 HTTPS 是否强制 | ❌ 未完成 | 需**管理员**执行一次 `source add http://...` 探针（`research.md` §8）。客户端源码中未见 scheme 校验，先验偏向"不强制" |
| 0.4 | 确认 winget 请求的 schema 版本 | ✅ 已完成 | 协商取"交集最大值"；服务端声明 `["1.10.0"]` 即锁定 1.10.0（ADR-008） |
| 0.5 | 确认 GitHub 资产访问已恢复 | ❌ **未达成** | 2026-11-01 复核：直连仍 `000` / 20 s 超时，`github.com` 传输中途断流。**阶段 4 的验收目前无法进行**，但阶段 1–3 不受影响 |

**验收**：0.1 / 0.2 / 0.4 已完成；0.3 需提权、0.5 受外部网络制约，二者都不阻塞阶段 1–3。

### 复核引入的额外任务

来源：`docs/verification-2026-11-01.md` §6。

| # | 事项 | 落在哪个阶段 |
|---|---|---|
| V1 | 健康探测改为**按加速器各自 origin** 探测（勿用 GitHub 资产 URL） | 阶段 3 |
| V2 | `fallbackToOriginal` 需配合直连可达性判定与超时，避免"长时间无响应" | 阶段 3 |
| V3 | 建立 host × 加速器 能力矩阵（目前仅证实 gh-proxy 支持 `github.com` / `raw.githubusercontent.com`） | 阶段 3 |
| V4 | 用本机客户端实测一次 `/information` 的版本交集（确认 1.10.0 在支持集内） | 阶段 1 |
| V5 | `manifestSearch` 匹配语义单独设计（7 种 MatchType × 9 种 PackageMatchField） | 阶段 1 之前 |
| V6 | 三个端点的协议 fixture（请求 → 期望响应），否则回归只能靠人工 | 阶段 1 |
| V7 | 去掉硬编码的探针资产版本（原 `probeUrl` 指向 ripgrep 15.2.0，会腐烂） | 阶段 3 |
| V8 | 若 HTTPS 强制，先试 `CurrentUser\Root`，再退 `LocalMachine\Root` | 阶段 2 |

---

## 阶段 1：最小可用 REST 服务（骨架）

不含改写，先把协议跑通。

- [ ] 加载本地清单目录，构建内存索引
- [ ] `GET /information`：返回 `SourceIdentifier` + `SourceAgreements` + `ServerSupportedVersions`
- [ ] `POST /manifestSearch`：支持按 id 精确查询与关键词查询
- [ ] `GET /packageManifests/{id}`：**单个响应**内嵌套 `Versions[]{ Locales[], Installers[] }`
- [ ] 包不存在返回 `404` + `array<Error{ErrorCode,ErrorMessage}>`（不是空结果）
- [ ] 结构化日志
- [ ] 解析配置时忽略以 `$` 开头的键
- [ ] **V4**：抓一次本机客户端发来的 `/information` 与协商结果，确认 1.10.0 在交集内
- [ ] **V6**：三个端点各存"请求 → 期望响应" fixture，作为回归基线

**验收**：
- `curl -k https://localhost:8443/api/information` 返回合法 JSON
- 通过 `winget source add` 注册后，`winget search -s <源名> ripgrep` 能搜到结果
- `winget show -s <源名> BurntSushi.ripgrep.MSVC` 能显示版本与安装器信息

（此阶段 `InstallerUrl` 仍指向 GitHub，安装会很慢甚至卡死——**这是预期的**，只验证协议。）

> **前置设计任务（V5）**：`manifestSearch` 的匹配语义比原计划复杂得多——
> 7 种 `MatchType` × 9 种 `PackageMatchField`、`Inclusions`/`Filters` 组合、排序、
> `MaximumResults` 截断。建议先出一页纸的设计再编码，否则会出现"能搜到但搜不准"。

---

## 阶段 2：证书与一次性安装

> **先等 0.3 的结论**：若证实不强制 HTTPS，本阶段整体可跳过，安装步骤直接减半。

- [ ] `cert` 子命令：生成含 `DNS:localhost` + `IP:127.0.0.1` 的证书
- [ ] `cert --install`：**优先尝试 `CurrentUser\Root`**（V8），失败再退 `LocalMachine\Root`
- [ ] `setup` 子命令：调用 `winget source add`（检测到非管理员时给出明确提示）
- [ ] `setup --remove` / `cert --remove` 完整回滚

**验收**：
- `winget source list` 能看到新源，且**无 TLS 警告**
- `setup --remove` 后源消失、`cert --remove` 后信任库干净

---

## 阶段 3：改写引擎（核心价值）

- [ ] 配置化 host 白名单 + 加速器模板 + 优先级
- [ ] 只改 `InstallerUrl`，其余字段原样（写测试断言）
- [ ] **V1** 健康检查：每加速器探测自身 origin，收到任意 HTTP 响应即视为可达；
      连续 2 次失败才标记不健康、并发上限 1、带超时
- [ ] **V2** 全挂时先判定直连是否可用，再决定回退；回退必须记 warning 且不得让请求无限挂起
- [ ] **V3** host × 加速器 能力矩阵：不支持的 host 不得改写到该加速器
- [ ] 响应缓存：同一 (id, version) 的改写结果可复用，健康状态变化时失效

**验收**：
- `winget show -s <源名> BurntSushi.ripgrep.MSVC` 输出的 URL 已带加速器前缀
- 非 GitHub host 的包，URL **未被改写**（用 msstore 或其它 host 的包验证）
- 把加速器地址改成不可达，观察自动切换到第二优先级，再全部不可达时**快速失败**而非挂起

---

## 阶段 4：端到端安装验证（决定性）

> ⚠️ **前置**：0.5 未达成时本阶段无法有效进行（直连与部分加速器均不可用，
> 测出的速率没有参考意义）。可先用小包走通流程，速率结论待网络恢复后补。

- [ ] 用本地源装一个小包（ripgrep，1.71 MB）
- [ ] 用本地源装一个大包（Git for Windows，63.75 MB）并记录速率
- [ ] **确认哈希校验生效**：手工篡改本地清单的 `InstallerSha256`，
      验证 winget 拒绝安装
- [ ] 确认 `winget list` 能看到装上的包（记账未丢失）
- [ ] 对比：同一包走官方源 vs 走本地源的耗时

**验收**：
- 大包下载速率达到加速器水平（数百 KB/s 以上），非 23–46 KB/s
- 篡改哈希后安装失败，且报错明确指向哈希不匹配
- `winget list` 正常

---

## 阶段 5：清单同步

- [ ] `sync` 子命令：稀疏检出 + 增量更新
- [ ] `state.json` 记录 commit 与时间
- [ ] `--full` 全量重建
- [ ] `clone` / `fetch` 本身走加速器（直连 `github.com` 传输中断，不能依赖）
- [ ] **离线导入路径**：允许从另一台机器拷贝 `data/manifests`
      （因为首次 clone 本身可能很慢，这是现实约束）

**验收**：
- 首次同步完成后能搜到大量包（不只是手工放的几个）
- 二次 `sync` 在无变更时快速返回
- `doctor` 能显示上次同步时间与覆盖的包数量

---

## 阶段 6：运维友好性

- [ ] `doctor` 自检：证书有效期、端口占用、源注册状态、清单覆盖、加速器健康、**直连可达性**
- [ ] 登录自启（HKCU `Run`，无窗口、无 VBS）
- [ ] 日志轮转

**验收**：新机器上按 README 五步走完可用；`doctor` 能诊断三类典型故障
（证书未信任 / 服务未启动 / 清单为空）。

> 注：原文档此处引用"本项目前身 AutoLock 的 HKCU Run 方案"，但本仓库内
> **没有 AutoLock 的任何记录**，该引用不可追溯。实现时请直接按 HKCU `Run`
> 常规做法做，或补一份来源。

---

## 已知风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| winget 升级后 schema 版本变化 | 源不可用 | 只声明 1.10.0 + `doctor` 版本检查（ADR-008） |
| **加速器单点**（复核时仅 1/2 可用） | 无可用加速器 | 候选补足到 ≥3 + 健康检查 + 可配置 |
| **直连被钳制导致回退卡死** | 安装长时间无响应 | V2：回退前判定直连 + 超时 |
| 首次同步清单很慢/受阻 | 无法开工 | 离线导入路径 + 走加速器 |
| 映射表漏字段（ADR-008 C′） | 字段被静默丢弃 | V6 fixture 测试 |
| `manifestSearch` 语义实现偏差 | 搜不到/搜不准 | V5 单独设计 + fixture |
| rewinged 参考代码的 MIT 归属遗漏 | 许可证问题 | `THIRD-PARTY-NOTICES.md` + 文件头声明 |
| 自签证书被用户误解为"降级安全" | 抵触 | 说明仅对 localhost 有效、优先用用户级根存储、提供一键移除 |

---

## 待定问题清单（需用户决策）

1. ~~实现语言~~ → **已定 Python + uv**（ADR-009）。仅当确定要分发单文件二进制时才考虑 Go
2. **是否接受一次性提权**：证书入信任库 + `source add`，两者都需要管理员
   （若 0.3 证实不强制 HTTPS，则只剩 `source add` 一项）
3. **清单覆盖范围**：全量（1 GB 级，同步慢）还是先只覆盖常用包（几十个，手写清单）？
4. **是否需要给他人分发**：若只是自用，可省掉打包与安装器
5. ~~HTTPS 实测~~ → 仍需管理员执行，见 0.3
