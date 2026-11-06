# HTTP 代理节点的 Kerberos 认证

HTTP 节点可使用运行 mihomo 的系统身份，通过 `Proxy-Authorization: Negotiate` 完成 Kerberos 认证。节点无需配置用户名、密码或票据缓存路径。

```yaml
proxies:
  - name: corporate-proxy
    type: http
    server: proxy.example.com
    port: 8080
    kerberos: true
    # kerberos-spn: HTTP/proxy.example.com
    # kerberos-mutual-auth: true
    # tls: true
```

`kerberos` 默认为 `false`。启用后不能同时配置 `username`、`password` 或自定义 `Proxy-Authorization` 请求头。认证失败会返回错误，不回退到 Basic 或 NTLM。

`kerberos-spn` 为可选的服务主体名称（SPN），默认为 `HTTP/<server>`。默认值不包含代理端口，且不受目标网站地址或 `sni` 影响。使用代理的完整域名；如果通过 IP 地址或别名连接，需将 SPN 指向代理实际注册的主体。需要指定 realm 时可使用 `HTTP/proxy.example.com@EXAMPLE.COM`。

`kerberos-mutual-auth` 默认为 `false`，兼容在 CONNECT 成功响应中省略最终认证令牌的代理。缺少最终令牌时，客户端无法验证代理的 Kerberos 身份。设为 `true` 可要求完成双向认证，否则拒绝连接；此选项要求启用 `kerberos`。

## 系统身份

| 系统 | 认证接口 | 前提 |
| --- | --- | --- |
| Windows | SSPI / Negotiate，仅允许 Kerberos | 运行账户具有可用的域身份和 Kerberos 凭据 |
| macOS（amd64、arm64） | 系统 GSS.framework | 当前账户已通过系统登录、企业 SSO 或 `kinit` 获取 Kerberos 凭据 |
| Linux（amd64、arm64） | 系统 GSS-API | 使用 `with_gssapi` 构建，安装 GSS-API 运行库，并准备好当前账户的 Kerberos 凭据 |

默认使用 mihomo 进程可访问的系统凭据。Windows 服务、Linux 后台守护进程或容器不会自动使用桌面登录用户的身份。macOS 的 root 服务在缺少凭据时，可通过独立认证助手使用前台登录用户的身份，具体条件见下节。系统认证库负责访问默认凭据存储，因此可使用系统支持的 FILE、KCM、KEYRING 等缓存，而不局限于 ccache 文件。

在 macOS 或 Linux 上，可在运行 mihomo 的账户下执行 `kinit user@EXAMPLE.COM`，并通过 `klist` 检查票据。`KRB5_CONFIG`、`KRB5CCNAME` 等环境变量由系统 Kerberos 实现解释；如需使用这些变量，应在启动 mihomo 前设置。mihomo 将票据获取和缓存管理交给系统认证库，不直接执行 `kinit` 或管理续期任务。

Kerberos 的 DNS 查询、KDC 连接和凭据选择由操作系统处理，不经过节点的 `dialer-proxy`。系统须能访问 KDC，且本机时间须与域保持同步。

## macOS 系统服务

macOS 的 GSSCred 默认按审计会话隔离凭据。通过 launchd 启动的 root 服务可能无法访问桌面用户已经取得的票据，即使同一核心在桌面会话中运行时能够认证。

mihomo 仍先尝试当前进程的系统凭据。仅当 root 进程获取凭据时返回 `GSS_S_NO_CRED`，且未显式设置 `KRB5CCNAME` 或 `KRB5_CLIENT_KTNAME`，才尝试前台登录用户。HTTP 节点仍只需配置 `kerberos: true`，无需修改 Sparkle。

此时 mihomo 调用系统 `/bin/launchctl asuser`，在前台用户的认证会话中启动自身的 `kerberos-helper` 子进程。助手确认用户未发生切换后，降权到该用户，再调用系统 GSS.framework。核心继续以原有权限处理网络连接；助手仅通过继承的匿名管道交换认证令牌，不导出票据缓存、不开放监听端口，也不修改系统 GSSCred 设置。

每次握手重新选择前台用户并创建独立助手。助手在握手结束、连接取消或最多 30 秒后退出。没有前台登录用户、用户没有可用票据或会话切换失败时，连接返回错误；不会选择其他后台登录用户。快速用户切换后，新连接使用新的前台用户，已经建立的隧道不重新认证。

该机制依赖 mihomo 可执行文件内置的助手入口。将 mihomo 作为库嵌入其他程序时，宿主需在启动时将 `kerberos-helper` 参数交给 `kerberos.RunHelper`，才能使用此功能。

## Linux 构建

```sh
CGO_ENABLED=0 go build -tags with_gssapi -o mihomo .
```

GSS-API 支持通过运行时动态加载实现，不需要 C 编译器，但会引入 libc 动态依赖。Linux 默认构建保持原有静态链接方式，不包含系统 Kerberos 支持；Windows 和 macOS 不需要此标签。其他操作系统或架构会在启用 `kerberos` 时返回不支持错误。

Linux 运行环境需提供 `libgssapi_krb5.so.2`、`libgssapi.so.3` 或 `libgssapi.so`。例如，Debian/Ubuntu 可安装 `libgssapi-krb5-2`。需按目标系统的 libc 配置构建和部署；不要直接将依赖 glibc 的二进制放入现有 Alpine 镜像。

## 认证行为

每个 CONNECT 连接独立创建认证上下文，并发送系统生成的 SPNEGO 令牌。代理返回 `407` 和后续 Negotiate 令牌时，在同一连接上继续认证，最多执行 8 轮。客户端始终向系统认证库请求双向认证。

代理返回 `200` 且包含 Negotiate 令牌时，无论 `kerberos-mutual-auth` 如何配置，客户端都必须验证令牌并确认认证完成，才会开放隧道。代理未返回令牌时，默认允许建立隧道；启用 `kerberos-mutual-auth` 后，认证尚未完成则返回 `proxy did not complete mutual authentication`。

代理必须支持 Kerberos/Negotiate，并在需要继续认证时保持连接。缺少系统凭据、SPN 不匹配、票据过期、最终令牌无效或代理拒绝身份，均会导致连接失败。系统认证调用阻塞时，连接的取消或超时仍会返回；该系统调用返回后释放其认证上下文。

实现依据：[Microsoft SSPI](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--kerberos)、[MIT GSS-API](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html)。
