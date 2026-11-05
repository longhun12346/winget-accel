# Third-Party Notices

`winget-accel.exe` 是静态链接的单文件二进制，其中包含下列第三方 Rust crate 的代码。
本文件按许可证分组列出它们，并说明每类许可证的原文位置。

> 上一版本文件只列了 rewinged / winget-pkgs / winget-cli-restsource ——
> 后两项属于**已废弃的 REST 源架构**（ADR-013），而且漏掉了真正被打进二进制的
> Rust 依赖（含 ISC / BSD-3-Clause / CDLA-Permissive-2.0）。2026-11-03 已按
> `cargo metadata` 的实际依赖重写。

依赖清单可用以下命令复现（同一份 `Cargo.lock` 结果一致）：

```powershell
cargo metadata --format-version 1 | ConvertFrom-Json |
  Select-Object -ExpandProperty packages |
  Select-Object name, version, license, repository |
  Sort-Object name
```

---

## 1. 随二进制分发的 Rust crate

按许可证表达式分组（名称去重；同一 crate 可能有多个版本，例如 `windows-sys 0.52/0.60`）：

| 许可证 | crate |
|---|---|
| `MIT OR Apache-2.0` | anyhow, asn1-rs, base64, cc, cfg-if, der-parser, deranged, displaydoc, getrandom, httparse, itoa, lazy_static, libc, log, num-bigint, num-conv, num-integer, num-traits, oid-registry, once_cell, powerfmt, proc-macro2, quote, rcgen, rustls-pki-types, serde, serde_json, shlex, syn, thiserror, time, windows-sys, windows-targets, windows-link, x509-parser, yasna 等 |
| `Apache-2.0 OR MIT` | autocfg, bit-vec, fastrand, zeroize |
| `Apache-2.0 OR ISC OR MIT` | rustls, rustls-pemfile |
| `Apache-2.0 AND ISC` | ring |
| `ISC` | rustls-webpki, untrusted |
| `BSD-3-Clause` | subtle |
| `CDLA-Permissive-2.0` | webpki-roots |
| `MIT` | data-encoding, nom, pem, synstructure, zmij |
| `MIT OR Apache-2.0 AND Unicode-3.0` | unicode-ident |
| `Unlicense OR MIT` | memchr |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | wasi |

关键直接依赖及其作用（便于审计"为什么它在里面"）：

| crate | 版本 | 用途 |
|---|---|---|
| `rustls` / `rustls-pemfile` | 0.23 / 2 | 终止/发起 TLS，读 PEM |
| `rcgen` | 0.14 | 生成 CA 与叶证书（含 `NameConstraints`） |
| `webpki-roots` | 1 | 校验加速器证书的根证书集合 |
| `ring` | 0.17 | `rustls`/`rcgen` 的加密后端（`aws-lc-rs` 被刻意排除，见 ADR-012） |
| `x509-parser` / `asn1-rs` / `der-parser` / `yasna` | — | 解析证书有效期、读取 Name Constraints（测试与诊断） |
| `windows-sys` | 0.60 | Win32 证书存储 API、本地时间 |
| `serde` / `serde_json` | 1 | 配置与 `/health` 输出 |
| `httparse` | 1 | HTTP/1.1 头部解析 |
| `anyhow` | 1 | 错误上下文 |
| `fastrand` | 2 | 加权随机选候选 |
| `time` | 0.3 | 证书有效期计算 |

### 许可证原文位置

- **Apache-2.0**：完整文本随发布包附带（`LICENSE-APACHE.txt`），
  也可在 <https://www.apache.org/licenses/LICENSE-2.0.txt> 获取。
- **MIT / ISC / BSD-3-Clause / Unicode-3.0 / Unlicense / CDLA-Permissive-2.0 / LLVM-exception**：
  原文在各自 crate 内（`crates.io` 的 `.crate` 包、或 `~/.cargo/registry/src/`）。
  本项目不逐份复制这些文本，但在此明确：**这些 crate 以其各自许可证分发**，
  版权归各自作者所有；`cargo vendor` 可一次取得全部原文。
- `CDLA-Permissive-2.0`（`webpki-roots`）：数据来源于 Mozilla 的根证书库，
  按 CDLA-Permissive-2.0 分发，见 <https://cdla.dev/permissive-2-0/>。

> 这是个刻意的取舍：逐份复制 60+ 个 crate 的 LICENSE 文本会让发布包膨胀且容易过期。
> 如果你需要一份"离线可读的完整许可证包"，运行 `cargo vendor` 并把 `vendor/` 一起分发。

---

## 2. 仅参考设计与事实、**不包含代码**

### jantari/rewinged

- 上游：<https://github.com/jantari/rewinged>
- 许可证：MIT
- 使用方式：**仅参考其设计与事实性信息，不复制、不逐行翻译其代码**（见 `docs/decisions.md` §6）。
  新架构（ADR-013）不实现任何 REST 协议端点，与该项目已无代码关系。

```
MIT License

Copyright (c) 2022 jantari

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### microsoft/winget-cli-restsource

- 上游：<https://github.com/microsoft/winget-cli-restsource>
- 许可证：MIT
- 使用方式：**已作废**。REST 源架构（ADR-001）在 2026-11-01 被 PAC + MITM 代理取代（ADR-013），
  当前代码不实现任何协议端点，也不再参考其 OpenAPI 规范。保留此条只为交代历史。

### microsoft/winget-pkgs

- 不适用：本项目**不同步、不分发**清单数据。winget 自己从官方源取清单，
  本工具只改写下载请求的 URL（见 ADR-013）。

---

## 3. 第三方服务（非代码）

本工具会把下载请求改写并转发给用户配置的公共 GitHub 加速服务（候选清单见
`candidates.json`）。这些服务由第三方运营，**不在本项目的许可证范围内**，
可用性、日志与隐私政策由各自运营方决定。项目不向其发送任何本地文件内容，
只发送原本要发给 GitHub 的 HTTP 请求。
