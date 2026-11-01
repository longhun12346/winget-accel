# 实现计划

> 交接说明：本文档面向**下一个会话**。开新会话时先读
> `README.md` → `docs/research.md`（结论）→ `docs/decisions.md`（为什么这样做）→ 本文档（做什么）。

---

## 阶段 0：环境与前提确认

**必须先解决**，否则后续无法开工：

| # | 事项 | 说明 |
|---|---|---|
| 0.1 | **决定实现语言** | ADR-009 倾向 Go，但本机**没有 Go/.NET/Node**，只有 git 和 PowerShell。装 Go 从 `go.dev/dl` 下载（非 GitHub，不受当前封锁影响） |
| 0.2 | 拿到 OpenAPI 规范 | `microsoft/winget-cli-restsource` 的 `documentation/WinGet-1.1.0.yaml`（需经加速器获取） |
| 0.3 | 确认 HTTPS 是否强制 | 需管理员执行一次 `source add http://...` 探针（`research.md` 第 8 节） |
| 0.4 | 确认 winget 请求的 schema 版本 | 影响 ADR-008 的版本裁剪决策 |
| 0.5 | 确认 GitHub 资产访问已恢复 | 我方压测导致的封锁需已解除（否则一切下载相关验证都无法进行） |

**验收**：能列出"语言已定、OpenAPI 已读、HTTPS 结论已定、目标 schema 版本已定"。

---

## 阶段 1：最小可用 REST 服务（骨架）

不含改写，先把协议跑通。

- [ ] 加载本地清单目录，构建内存索引
- [ ] `GET /information`：返回源标识与支持版本
- [ ] `POST /manifestSearch`：支持按 id 精确查询与关键词查询
- [ ] `GET /packageManifests/{id}`：返回三类文档组合
- [ ] 结构化日志

**验收**：
- `curl -k https://localhost:8443/api/information` 返回合法 JSON
- 通过 `winget source add` 注册后，`winget search -s <源名> ripgrep` 能搜到结果
- `winget show -s <源名> BurntSushi.ripgrep.MSVC` 能显示版本与安装器信息

（此阶段 `InstallerUrl` 仍指向 GitHub，安装会很慢——**这是预期的**，只验证协议。）

---

## 阶段 2：证书与一次性安装

- [ ] `cert` 子命令：生成含 `DNS:localhost` + `IP:127.0.0.1` 的证书
- [ ] `cert --install`：导入 `Cert:\LocalMachine\Root`
- [ ] `setup` 子命令：调用 `winget source add`（检测到非管理员时给出明确提示）
- [ ] `setup --remove` / `cert --remove` 完整回滚

**验收**：
- `winget source list` 能看到新源，且**无 TLS 警告**
- `setup --remove` 后源消失、`cert --remove` 后信任库干净

---

## 阶段 3：改写引擎（核心价值）

- [ ] 配置化 host 白名单 + 加速器模板 + 优先级
- [ ] 只改 `InstallerUrl`，其余字段原样（写测试断言）
- [ ] 健康检查：周期探测、连续 2 次失败才标记不健康、并发上限 1
- [ ] 全挂时回退原始 URL 并记 warning
- [ ] 响应缓存：同一 (id, version) 的改写结果可复用，健康状态变化时失效

**验收**：
- `winget show -s <源名> BurntSushi.ripgrep.MSVC` 输出的 URL 已带加速器前缀
- 非 GitHub host 的包，URL **未被改写**（用 msstore 或其它 host 的包验证）
- 把加速器地址改成不可达，观察自动切换到第二优先级，再全部不可达时回退原始 URL

---

## 阶段 4：端到端安装验证（决定性）

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
- [ ] **离线导入路径**：允许从另一台机器拷贝 `data/manifests`
      （因为首次 clone 本身可能很慢，这是现实约束）

**验收**：
- 首次同步完成后能搜到大量包（不只是手工放的几个）
- 二次 `sync` 在无变更时快速返回
- `doctor` 能显示上次同步时间与覆盖的包数量

---

## 阶段 6：运维友好性

- [ ] `doctor` 自检：证书有效期、端口占用、源注册状态、清单覆盖、加速器健康
- [ ] 登录自启（参考本项目前身 AutoLock 的 HKCU Run 方案，无窗口、无 VBS）
- [ ] 日志轮转

**验收**：新机器上按 README 五步走完可用；`doctor` 能诊断三类典型故障
（证书未信任 / 服务未启动 / 清单为空）。

---

## 已知风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| winget 升级后 schema 版本变化 | 源不可用 | Codec 抽象（ADR-008）+ `doctor` 明确报错 |
| 加速器失效或跑路 | 下载回退到慢速 | 多加速器 + 健康检查 + 可配置 |
| 首次同步清单很慢/受阻 | 无法开工 | 提供离线导入路径 |
| rewinged 参考代码的 MIT 归属遗漏 | 许可证问题 | `THIRD-PARTY-NOTICES.md` + 文件头声明 |
| 自签证书被用户误解为"降级安全" | 抵触 | 明确说明仅对 localhost 有效，且提供一键移除 |

---

## 待定问题清单（需用户决策）

1. **实现语言**：Go（需安装工具链）/ Python（免安装）/ 其它？
2. **是否接受一次性提权**：证书入信任库 + `source add`，两者都需要管理员
3. **清单覆盖范围**：全量（1 GB 级，同步慢）还是先只覆盖常用包（几十个，手写清单）？
4. **是否需要给他人分发**：若只是自用，可省掉打包与安装器；若要分发，需考虑
   Go 单文件二进制 + 一个安装脚本
5. **HTTPS 实测**：若证实不强制，可去掉证书环节，安装步骤减少一半
