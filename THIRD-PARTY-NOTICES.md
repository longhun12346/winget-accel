# Third-Party Notices

本项目包含或参考了以下第三方代码。按其许可证要求保留声明。

---

## jantari/rewinged

- 上游：https://github.com/jantari/rewinged
- 许可证：MIT
- 使用方式：参考其 winget REST 源协议实现、清单模型组织方式与端点处理逻辑。
  凡直接复制或改写其代码的文件，均在文件头保留原始版权声明并注明来源路径。

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

---

## microsoft/winget-pkgs

- 上游：https://github.com/microsoft/winget-pkgs
- 许可证：MIT
- 使用方式：**运行时数据依赖**。本项目同步其 `manifests/` 目录作为清单来源，
  不修改其中的 `InstallerSha256` 等字段，仅在响应时改写 `InstallerUrl` 的 host。
  代码仓库本身不分发该数据集。

---

## microsoft/winget-cli-restsource

- 上游：https://github.com/microsoft/winget-cli-restsource
- 许可证：MIT
- 使用方式：仅参考其公开的 OpenAPI 规范（`documentation/WinGet-1.1.0.yaml`）
  作为协议实现的依据，不包含其代码。
