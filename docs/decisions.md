# 方案决策

本文只记录当前仍有效的设计约束。实现细节见 [design.md](design.md)，使用说明见
[README.md](../README.md)。

## ADR-012：依赖和供应链

项目使用 Rust 标准库加少量有明确理由的直接依赖。代理采用同步线程模型，不引入
`tokio`、`axum`、`hyper`、`actix-web` 或 `reqwest`；不引入 `openssl`、`native-tls` 和
`git2`，避免额外系统依赖、C 工具链和更大的审计面。证书、TLS、JSON、HTTP 头解析、
Windows API 和随机选择各自使用专门依赖，理由写在 `Cargo.toml`。

## ADR-013：PAC + 本机 TLS MITM

目标是加速安装包下载，而不是替换 winget 源。PAC 只圈定 GitHub 下载相关域名，本机
终止 TLS 并在请求侧改写，响应字节原样转发。清单仍来自官方源，程序不需要管理员权限，
只使用当前用户 PAC 和当前用户根证书。

代价是需要用户信任一张本机 CA、依赖公共加速服务，并且代理成为下载链路中的单点。若
系统不允许当前用户安装根证书，应使用其它架构，而不是放宽白名单。

## ADR-014：TLS 安全边界

三条约束必须同时成立：

1. CA 的 Name Constraints 只允许 `rewriteHosts` 中的域及其子域，并设置 `path_length=0`；
2. PAC 只把这些域交给本机，不写全局代理；
3. 代理不改响应体，winget 继续用官方 `InstallerSha256` 校验安装包。

私钥明文保存在本机证书目录，只能尽力收紧 ACL。程序不把 CA 私钥放进发布包，也不建议
把证书目录放进云同步目录。

## ADR-015：交付形态

交付物是 x64 Windows 单文件 Rust 二进制，启用静态 CRT 和 MSVC `/Brepro`。Python
原型只用于协议验证，不进入发布包，也不作为用户运行时依赖。发布 zip 必须包含 exe、
QUICKSTART、许可证文件、第三方声明和 `SHA256.txt`，并通过解压后的独立运行检查。

## ADR-016：候选全挂时快速失败

当所有候选都未通过验证时返回 502，不回退到原始 GitHub。直连在目标网络中可能慢到
超过 winget 的超时，回退只会增加等待时间并隐藏真正的故障。候选通过启动测速、运行期
巡检和真实下载样本持续筛选。

## ADR-017：把 winget 下载器固定为 WinINet

Delivery Optimization 不读取当前用户 PAC。默认启动时把用户设置中的
`network.downloader` 设为 `wininet`，只修改这个字段，退出时按状态文件恢复；用户可用
`wingetDownloader=false` 关闭。程序不修改 DO 的系统级设置、不改 WinHTTP 全局代理、
不安装机器级 CA。

非法设置 JSON 不覆盖。PAC 和 winget 设置共用状态文件、会话标识、锁和看门狗，避免只
恢复一半。

## ADR-018：PAC 对 github.com 整域代理

WinINet 的 HTTPS PAC 调用不提供完整路径，因此对 `github.com` 写路径条件不会在 winget
下载中可靠命中。PAC 现在对 `github.com` 及其子域整域返回本机代理；代理收到真实请求
后再按路径决定是否改写。

普通页面原样回源 GitHub，下载路径改写到公共加速服务。Git clone 仍不支持，因为本机
代理不转发请求体。若未来 WinINet 提供完整 URL，或项目改用不依赖 PAC 的下载接管方式，
可以重新评估这项决策。
