# 参考 rewinged 的边界与要点

上游：[jantari/rewinged](https://github.com/jantari/rewinged) · **MIT License** · Copyright (c) 2022 jantari

我们**自行实现**，但要"参考部分代码"（用户决策）。本文档界定：参考什么、放弃什么、
以及法律义务。

---

## 1. 许可证义务（必须遵守）

MIT 允许修改、商用、再分发，条件是：

> 在软件的所有副本或实质性部分中，必须包含上述版权声明和本许可声明。

因此：

- 凡从 rewinged **复制或改写**的代码文件，**文件头保留其原始版权声明**
- 仓库根目录提供 `THIRD-PARTY-NOTICES.md`，内含完整 MIT 文本与出处
- 若某文件的逻辑基本照搬，在该文件顶部注明来源与原始文件路径

不要做"改几个变量名就算原创"这种事。

---

## 2. 代码结构分析

27 个 Go 文件，合计 **342.8 KB**。按体积分布可以看出它的复杂度集中在哪里：

| 文件 | 体积 | 作用（据命名与体积推断） |
|---|---|---|
| `manifests.go` | 27.7 KB | 清单加载/解析/索引 |
| `models/manifests_1_10_0.go` | 25.9 KB | 清单 schema 1.10.0 的模型 |
| `models/manifests_1_9_0.go` | 25.6 KB | 同上 1.9.0 |
| `models/manifests_1_7_0.go` | 25.0 KB | 同上 1.7.0 |
| `models/manifests_1_6_0.go` | 24.7 KB | 同上 1.6.0 |
| `models/manifests_1_5_0.go` | 24.3 KB | 同上 1.5.0 |
| `models/manifests_1_4_0.go` | 23.5 KB | 同上 1.4.0 |
| `models/manifests_1_2_0.go` | 19.6 KB | 同上 1.2.0 |
| `models/manifests_1_1_0.go` | 18.7 KB | 同上 1.1.0 |
| `models/internal.go` | 14.1 KB | 版本无关的内部模型 |
| `models/api_1_*.go` | 10.7–13.3 KB × 7 | 各版本的 API 请求/响应模型 |
| `main.go` | 11.3 KB | 参数/环境变量/配置文件解析、启动 |
| `controllers/packages.go` | 9.1 KB | 三个 REST 端点的处理逻辑 |
| `logging/logging.go` | 2.8 KB | 日志 |
| `controllers/auth.go` | 2.3 KB | Entra ID 认证（我们不需要） |
| `go.sum` | 2.2 KB | 依赖锁定 |

**关键观察**：`models/` 下按清单 schema 版本各有一份模型，合计约 **200 KB**，
占全部代码六成。这才是"支持 1.1.0–1.10.0 全版本"的真实成本。

> 注：上表依据文件体积与命名推断，未逐一阅读源码。实现阶段应逐个打开确认。

---

## 3. 值得参考的部分

| 关注点 | 参考文件 | 参考什么 |
|---|---|---|
| REST 端点实现 | `controllers/packages.go` | 三个端点的路由、请求解析、响应组装方式 |
| 清单加载与索引 | `manifests.go` | 目录遍历、三类文档（version/installer/locale）的关联、按 id/version 索引 |
| 启动与配置 | `main.go` | 配置优先级（CLI > env > 文件 > 默认），可借鉴其结构 |
| 版本无关模型 | `models/internal.go` | 如何在多 schema 版本间做抽象 |
| 精确 schema 定义 | `models/manifests_1_10_0.go` | **字段名/JSON tag 的权威参考**，比读 OpenAPI 更直观 |
| 日志 | `logging/logging.go` | 简单可用的日志分级 |

其中**最有价值的是 `models/manifests_1_10_0.go` 与 `models/api_1_10_0.go`**：
winget 的 schema 字段多且命名不一致，这两个文件能省掉大量试错。

---

## 4. 不需要的部分

| 特性 | 放弃原因 |
|---|---|
| Entra ID 认证（`controllers/auth.go`） | 本地单用户场景无意义 |
| `-sourceAuthType` / `-sourceAuthEntraIDAuthorityURL` / `-sourceAuthEntraIDResource` | 同上 |
| `-trustedProxies` | 不做反向代理部署 |
| `autoInternalize` 系列（下载并托管安装包） | 与"不落地字节"的核心设计直接冲突 |
| Docker 相关 | 本机运行，无需容器 |

---

## 5. 我们的增量（rewinged 没有的）

这才是本项目的价值所在，也是不能直接用它二进制的根本原因：

1. **host 白名单改写**：它默认**不改写**（`autoInternalize=false`），
   若开启改写则指向**它自己**；我们需要"改写指向第三方加速器"
2. **多加速器 + 健康检查 + 优先级回退**
3. **改写规则配置化**，改完即生效，无需重新同步清单
4. **`doctor` 自检**：证书、端口、源注册、清单覆盖、加速器状态
5. **并发上限与退避**（ADR-006，来自一次真实事故）

---

## 6. 版本模型裁剪策略（已由 ADR-008 修订）

> 本节原计划"只保留 1.10.0 + 1.9.0 的模型文件"。复核后 ADR-008 改为 **C′**：
> 输出契约只做 1.10.0，**读侧不按版本建 struct**，因此**不移植** `models/` 那套体系。

具体做法：

1. **读侧**：YAML → 通用树（`dict` / `Any`），不绑定任何 schema 版本
2. **转换**：维护一张"跨 schema 版本字段改名/新增映射表"
3. **输出**：投影成 1.10.0 JSON，由单一投影函数负责

```python
# 伪代码（语言无关，按 ADR-009 用 Python 形态书写）
class ManifestCodec(Protocol):
    contract_version: str                      # 固定 "1.10.0"
    def load(self, yaml_bytes: bytes) -> dict: ...
    def dump(self, tree: dict) -> bytes: ...
```

4. 上游新增清单版本时，通常**只需补映射表条目**，不改代码
5. 若映射表失控，回退到"照搬 rewinged 多版本模型"（ADR-008 的回退路径）

**从 rewinged 仍值得借鉴的**：`models/manifests_1_10_0.go` 与 `models/api_1_10_0.go`
里的**字段名与 JSON tag**——它们是"1.10.0 契约到底有哪些字段"的最直观参考。
借鉴的是字段语义，不是代码结构。

---

## 7. 实现前应做的核对

- [ ] 拉取 `documentation/WinGet-1.1.0.yaml`（来自 microsoft/winget-cli-restsource），
      与 `models/` 里的字段逐一对照
- [ ] 确认 `controllers/packages.go` 里 `manifestSearch` 的过滤/排序语义
- [ ] 确认 `/information` 的 `ServerSupportedVersions` 具体格式
- [ ] 确认错误响应（包不存在）的实际返回形态
- [ ] 检查 rewinged 是否有测试用例可参考（树里未见 `*_test.go`，
      说明**上游缺少测试**——我们不能照抄其测试覆盖度）
