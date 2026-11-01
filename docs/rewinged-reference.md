# 参考 rewinged 的边界与要点

上游：[jantari/rewinged](https://github.com/jantari/rewinged) · **MIT License** · Copyright (c) 2022 jantari

**参考强度：T2 / T3 —— 只参考设计与事实，不搬代码**（见 `decisions.md` ADR-011）。

本文档界定：参考什么、不参考什么、以及由此产生的合规义务。

---

## 1. 合规义务（T2 档）

本项目**不复制、不逐行翻译** rewinged 的代码，因此 MIT 的"副本须附带版权声明"义务**未被触发**。
但仍保留两件事：

- `THIRD-PARTY-NOTICES.md` 记录出处与完整 MIT 文本（诚实披露，也为将来可能的变化留好位置）
- 本文档与 `reference-log.md` 记录"读了哪个文件、借鉴了什么、产出了什么"

> 若日后因故需要 T1（复制或改写代码），义务立刻生效：**逐文件保留版权头并注明来源路径**。
> 在此之前，不要做"改几个变量名就算原创"这种事——T2 的正确做法是**只看设计，自己写**。

---

## 2. 代码结构（2026-11-01 实测，非推断）

用 GitHub API 拉取 `main` 分支完整树：**25 个 Go 文件 / 348,417 字节**。

| 文件 | 体积 | 作用 |
|---|---|---|
| `manifests.go` | 27.1 KB | 清单遍历、形态识别、解析、摄取 |
| `models/manifests_1_10_0.go` | 25.3 KB | 清单 schema 1.10.0 模型 |
| `models/manifests_1_9_0.go` | 25.0 KB | 同上 1.9.0 |
| `models/manifests_1_7_0.go` | 24.4 KB | 同上 1.7.0 |
| `models/manifests_1_6_0.go` | 24.1 KB | 同上 1.6.0 |
| `models/manifests_1_5_0.go` | 23.8 KB | 同上 1.5.0 |
| `models/manifests_1_4_0.go` | 23.0 KB | 同上 1.4.0 |
| `models/manifests_1_2_0.go` | 19.1 KB | 同上 1.2.0 |
| `models/manifests_1_1_0.go` | 18.2 KB | 同上 1.1.0 |
| `models/internal.go` | 13.8 KB | 索引与检索（`ManifestsStore`） |
| `models/api_1_*.go`（7 份） | 10.5–13.0 KB | 各契约版本的 API 模型 |
| `models/api_common.go` | 2.1 KB | API 公共类型 |
| `models/manifests_common.go` | 2.1 KB | 清单公共类型 |
| `main.go` | 11.0 KB | 参数 / 环境变量 / 配置解析、启动 |
| `controllers/packages.go` | 8.9 KB | 包列表、单包、搜索 |
| `controllers/information.go` | 1.8 KB | `/information` |
| `controllers/auth.go` | 2.3 KB | Entra ID 认证（不需要） |
| `logging/logging.go` | 2.7 KB | 日志 |
| `settings/settings.go` | 0.2 KB | 设置 |

**关键观察**：`models/` 合计约 **286 KB，占全部代码 84%**。
原文档记的"约 200 KB / 占六成"只统计了 `manifests_*`（183 KB），**低估了整个模型层**。
这正是 ADR-008 选 C′（不搬模型体系）的核心依据。

另：仓库 `packages/` 下有单文件清单样例（`bottom.yml`、`minimal-example.yml`），
说明它同时支持"多文件三段式"与"单文件 singleton"两种清单形态。

树中**没有 `*_test.go`** —— 上游缺乏测试，其测试覆盖度不可照抄。

---

## 3. 值得参考的 4 个文件（T2）

| 文件 | 看什么 | 不看什么 |
|---|---|---|
| `manifests.go` | 目录遍历与清单识别：如何区分 version / installer / locale / defaultLocale 四类文件、如何解析版本号、多文件与单文件如何统一；12 个函数的职责切分 | 按版本 `unmarshalXXX` 的多态实现（我们不建多版本 struct） |
| `models/manifests_1_10_0.go` | **字段名与 JSON tag**——"1.10.0 契约到底有哪些字段"的最直观清单，比 OpenAPI 更细 | 其 struct 组织与接口体系 |
| `models/internal.go` | `ManifestsStore` 的**索引形状**：`id → versions → manifest`、`GetAllPackageIdentifiers`、`GetManifestCount` | **检索实现**（见 §4） |
| `controllers/packages.go` | 三个 handler 的职责切分、请求解析与响应组装 | 具体代码 |

`controllers/information.go` 可顺手一看，但 `/information` 的字段已由 OpenAPI 权威定义
（`verification-2026-11-01.md` §3.2），参考价值低。

---

## 4. 明确不参考

| 项 | 原因 |
|---|---|
| `models/` 多版本模型体系（18 个文件） | 与 ADR-008 C′ 冲突；占其代码 84% |
| **检索实现**（`GetByKeyword` / `GetByMatchFilter` / 反射 `findField`） | 靠反射遍历 struct 字段，只够做"包含关键字"，**撑不起 7 种 `MatchType` × 9 种 `PackageMatchField`** 的规范语义；且正是我们 C′ 要摆脱的东西 |
| `autoInternalize` 系列（下载并托管安装包） | 与"不落地字节"直接冲突（ADR-010） |
| Entra ID 认证、`trustedProxies` | 本地单用户无意义（ADR-010） |
| Docker / goreleaser | 与本项目交付形态无关 |

> 关于检索：即便想照搬也搬不出正确结果——它的语义不完整，且会被 struct 体系绑死。
> 这块必须按规范自己实现（`roadmap.md` V5）。

---

## 5. 我们的增量（不受参考边界影响）

这才是本项目的价值所在，也是不能直接分发它二进制的根本原因：

1. **host 白名单改写**：它默认**不改写**（`autoInternalize=false`），开启改写也只指向**它自己**；
   我们需要"改写指向第三方加速器"
2. **多加速器 + 健康检查 + 优先级回退**（含 V1/V2 的探测与回退语义修正）
3. **改写规则配置化**，改完即生效，无需重新同步清单（ADR-005）
4. **`doctor` 自检**：证书、端口、源注册、清单覆盖、加速器状态、直连可达性
5. **并发上限与退避**（ADR-006，来自一次真实事故）

---

## 6. 版本与清单处理策略

按 ADR-008 的 **C′**：

1. **读侧**：YAML → 通用值树（`serde_yaml_ng::Value`），不绑定任何 schema 版本
2. **转换**：一张"跨 schema 版本字段改名/新增映射表"
3. **输出**：投影成 1.10.0 JSON，由单一投影函数负责

```rust
// 伪代码
trait ManifestCodec {
    const CONTRACT: &'static str = "1.10.0";
    fn load(&self, yaml: &[u8]) -> Result<Value>;
    fn project(&self, tree: &Value) -> Result<Vec<u8>>;
}
```

上游新增清单版本时通常**只需补映射表条目**，不改代码。
从 rewinged 借鉴的只有**字段名与 JSON tag**（T3），不是它的模型结构。

---

## 7. 阅读顺序（重要）

**先按 OpenAPI 规范把三个端点骨架写完，再读参考文件。** 顺序反过来，T2 边界守不住。

1. 写 `/information`、`/manifestSearch`、`/packageManifests/{id}` 骨架（依据 `verification-2026-11-01.md` §3）
2. 读 `manifests.go` —— 只为知道"要处理哪些形态、哪个字段会缺"
3. 读 `models/manifests_1_10_0.go` —— 只为建映射表
4. 读 `models/internal.go` —— 只看索引形状
5. 每步在 `reference-log.md` 记一行

### 已完成的核对（原 §7 清单）

- [x] 拉取 OpenAPI 规范并与字段对照 —— 见 `verification-2026-11-01.md` §3.1
- [x] `/information` 的 `ServerSupportedVersions` 格式 —— `array<string>`，`minItems: 1`
- [x] 包不存在的返回形态 —— `404` + `array<Error>`
- [x] 上游是否有测试可参考 —— 确认无 `*_test.go`
- [ ] `manifestSearch` 的过滤/排序语义 —— **不参考其实现**，按规范自行设计（V5）
