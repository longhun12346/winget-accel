# Python 协议测试夹具

`prototype/` 不是发布代码。它提供本地假上游、临时 CA、请求脚本和 pytest 用例，作用是
驱动真正的 Rust 二进制验证协议行为。

测试默认不安装根证书、不修改 PAC、不访问外网。`--target-binary` 模式下，Python 原型的
模块级单测会跳过，由 Rust 单测覆盖；协议用例会启动 `target\release\winget-accel.exe`，
并把加速器指向本地 HTTP 假上游。

## 安装环境

```powershell
cd prototype
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe pytest cryptography
```

## 本地协议测试

```powershell
.\.venv\Scripts\python.exe -m pytest tests `
  --target-binary ..\target\release\winget-accel.exe
```

测试覆盖 TLS 终止、公共 URL 前缀改写、普通 github.com 路径原样转发、PAC 整域语义、
Range、响应定界、候选切换、连接上限、并发首连、PAC 生命周期和看门狗。

需要真实公共服务时显式开启：

```powershell
.\.venv\Scripts\python.exe -m pytest tests --network `
  --target-binary ..\target\release\winget-accel.exe
```

网络用例依赖公共服务，失败可能来自服务下线或限流。不要把它们当作离线回归的唯一依据。
