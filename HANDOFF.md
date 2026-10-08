# Server transport builder 重构方案

## 1. 任务和用户已确认的决定

实现 `hickory-server` 的协议 builder 和统一注册接口，支持已经绑定的自定义 UDP socket、TCP listener 以及自定义 `RuntimeProvider`。UDP、TCP、TLS、HTTPS、QUIC、H3 全部迁移。

用户在 2026-10-06 已明确确认：

- **删除旧注册 API，不考虑兼容性。** 不保留 `register_socket`、`register_listener`、各类 `register_*_listener` 或其 TLS config 变体作为转发入口。迁移仓库里的全部调用点。
- **这次只实现 builder 和自定义 socket/provider。** 保留现有 Tokio 任务管理、计时器和 Quinn runtime，不在这个任务中完成全部 runtime 中立化。
- **使用简单的手写 builder，不引入 bon。** 用户后续指出 bon 在切换泛型参数时不方便，普通 setter 用 `Self { field, ..self }` 即可；无需宏、生成代码或公共 typestate。
- 使用 `server.register(transport)`，不增加 `transport.register(&mut server)` 这套反向注册语法。
- 用户会自行 reset 当前分支中不再需要的提交。执行实现任务的 agent 应先检查 reset 后的状态，不能假定当前所有改动还在，也不要自行 reset 用户分支。
- 本文件是给后续 agent 的实施说明。编写本文件时没有开始修改生产代码。

目标是把协议配置和任务构造从 `Server` 中提取出去，让新增协议或配置项无需继续增加 `Server` 方法。单纯在旧方法外面包一层 builder 不算完成。

相关讨论：

- [PR #3986，djc 对模块化注册 API 的建议](https://github.com/hickory-dns/hickory-dns/pull/3986#issuecomment-6015827475)
- [issue #3982，运行时抽象及 Fuchsia 的使用](https://github.com/hickory-dns/hickory-dns/issues/3982#issuecomment-5805011099)

djc 提出了方向，没有批准本文中的具体 trait 签名；本文件记录的是本次讨论形成的实施方案。Fuchsia 已使用客户端相关 runtime 抽象，不能声称它已经需要或使用这里的 server builder。

## 2. 目标用户 API

公开模块为 `hickory_server::server::transport`，包含 `Transport` trait 和 `Udp`、`Tcp`、`Tls`、`Https`、`Quic`、`H3`。同时从 `server` 模块重导出 `Transport`；具体协议类型集中放在 `transport` 命名空间，避免与 net 中的 stream/server 类型混淆。

```rust
use std::time::Duration;
use hickory_server::{
    Server,
    server::transport::{Udp, Tcp, Https},
};

let mut server = Server::new(handler);

server.register(
    Udp::new(udp_socket)
        .with_provider(provider.clone()),
)?;

server.register(
    Tcp::new(tcp_listener)
        .with_provider(provider.clone())
        .stream_timeout(Some(Duration::from_secs(30)))
        .response_buffer_size(32),
)?;

server.register(
    Https::new(https_listener, tls_config)
        .with_provider(provider)
        .handshake_timeout(Some(Duration::from_secs(10)))
        .idle_timeout(Some(Duration::from_secs(30)))
        .request_timeout(Some(Duration::from_secs(10)))
        .dns_hostname("dns.example.com")
        .http_endpoint("/dns-query"),
)?;
```

默认 Tokio 调用不需要指定 provider：

```rust
server.register(Udp::new(tokio_udp_socket))?;
server.register(Tcp::new(tokio_tcp_listener))?;
```

约定：

- socket/listener 必须已经绑定；构造函数消费这个资源，不负责绑定或连接。
- `new()` 创建的对象本身就是可配置、可注册的 transport，不要求用户再调用 `.build()`。
- timeout setter 接受 `Option<Duration>`，名字不带 `maybe_`。省略或传 `None` 表示不启用该项超时。
- 普通配置 setter 消费 `self` 并返回 `Self`；重复设置覆盖原值。
- `.with_provider()` 消费对象并**改变 provider 泛型类型**，保留 socket/listener、TLS 来源和已设置的所有配置。
- `.with_provider()` 可以出现在普通配置 setter 前后；两种顺序都应成立。
- `dns_hostname(impl Into<String>)` 设置 `Some`；同时提供 `maybe_dns_hostname(Option<String>)`，方便迁移已有可选配置。默认 `None`。
- `http_endpoint(impl Into<String>)` 只用于 HTTPS，默认使用 `hickory_net::http::DEFAULT_DNS_QUERY_PATH`。
- 不引入 socket 或 TLS config 缺失的运行时状态。必需资源在构造函数中传入。

## 3. 架构和职责

```text
用户已绑定的资源 + provider + builder 配置
                    |
            Transport::into_future()
       同步构造 TLS/QUIC 等必要资源，可失败
                    |
              Send + 'static future
                    |
              Server::register()
                    |
              Tokio JoinSet 管理
                    |
         协议任务 / 连接任务 / 请求任务
                    |
         ServerContext::handle_request()
       源地址检查、DNS 校验、ACL、统计、handler
```

`Server<H>` 管理 handler、访问控制、关闭信号和顶层任务。不持有 provider，不把所有资源类型统一限制到某个全局 provider 上。每个 transport 自己拥有 provider；一个 `Server` 可以注册来自不同 provider 的 transport。

`RuntimeProvider` 仍是已有的 I/O 抽象。新 `Transport` trait 表达“如何构造一个协议任务”，它不再定义一套 socket/stream 抽象。

`DnsTcpListener` 表达接受连接的操作。它是需要的新 I/O 能力，但 listener **不必**成为 provider 的关联类型；在 transport 实现上约束 `L: DnsTcpListener<P::Tcp>` 即可。

因此最终删除 `ServerRuntimeProvider`、相关 impl、`Server` 的第二个泛型参数、`Server::with_provider()` 和 `with_access_and_provider()`。保留 `Server::new()`、`with_access()`、`shutdown_token()`、`shutdown_gracefully()`、`block_until_done()`。

## 4. 核心 trait 和注册方法

推荐签名：

```rust
pub trait Transport: Send + 'static {
    /// Runtime provider used by this transport.
    type Provider: RuntimeProvider;

    /// Initialize the transport and return its long-running task.
    fn into_future<H: RequestHandler>(
        self,
        context: Arc<ServerContext<H>>,
    ) -> Result<
        impl Future<Output = Result<(), NetError>> + Send + 'static,
        NetError,
    >;
}

pub struct Server<H: RequestHandler> {
    context: Arc<ServerContext<H>>,
    join_set: JoinSet<Result<(), NetError>>,
}

impl<H: RequestHandler> Server<H> {
    pub fn register(&mut self, transport: impl Transport) -> Result<(), NetError> {
        let task = transport.into_future(self.context.clone())?;
        self.join_set.spawn(task);
        Ok(())
    }
}
```

实施要求：

- trait 是公开、可在下游 crate 实现的，不 sealed。
- 当前 Rust MSRV 为 1.88，支持 trait 中的返回位置 `impl Trait`，不需要为此引入 async-trait 或每次注册都 boxing。
- 明确声明返回 future 的 `Send + 'static`；不能捕获 `&mut Server`、短生命周期 `&P` 或借用 builder 的内容。
- `into_future()` 本身是同步方法。证书默认配置构造、socket wrapping、Quinn endpoint 初始化要在返回 future 前进行，错误经 `register()` 立即返回。
- 初始化失败不把任务加入 JoinSet，不丢弃错误，不 `unwrap()`，也不先 spawn 再把初始化错误推迟到 `block_until_done()`。
- 协议任务运行时的错误仍由 `block_until_done()` 处理。沿用现有顶层任务错误和关闭语义。
- trait 不需要支持 `dyn Transport`；现有静态分发足够。不要再引入 transport enum 来枚举所有协议。
- 内建 transport 的 `type Provider = P`；只有 provider 的关联类型匹配资源类型时才实现 `Transport`。

## 5. Builder 类型和类型推导

以 UDP 为例：

```rust
pub struct Udp<S, P = TokioRuntimeProvider> {
    socket: S,
    provider: P,
}

impl<S> Udp<S, TokioRuntimeProvider> {
    pub fn new(socket: S) -> Self {
        Self { socket, provider: TokioRuntimeProvider::default() }
    }
}

impl<S, P> Udp<S, P> {
    pub fn with_provider<Q: RuntimeProvider>(self, provider: Q) -> Udp<S, Q> {
        Udp { socket: self.socket, provider }
    }
}

impl<S, P> Transport for Udp<S, P>
where
    P: RuntimeProvider<Udp = S>,
    S: DnsUdpSocket + 'static,
{
    type Provider = P;
    // into_future() 调用 handle_udp::<P>(...)。
}
```

TCP、TLS、HTTPS 保存实际 listener 类型 `L`：

```rust
pub struct Tcp<L, P = TokioRuntimeProvider> {
    listener: L,
    provider: P,
    stream_timeout: Option<Duration>,
    response_buffer_size: usize,
}

impl<L, P> Tcp<L, P> {
    pub fn stream_timeout(self, stream_timeout: Option<Duration>) -> Self {
        Self { stream_timeout, ..self }
    }

    pub fn response_buffer_size(self, response_buffer_size: usize) -> Self {
        Self { response_buffer_size, ..self }
    }

    pub fn with_provider<Q: RuntimeProvider>(self, provider: Q) -> Tcp<L, Q> {
        Tcp {
            listener: self.listener,
            provider,
            stream_timeout: self.stream_timeout,
            response_buffer_size: self.response_buffer_size,
        }
    }
}

impl<L, P> Transport for Tcp<L, P>
where
    P: RuntimeProvider,
    L: DnsTcpListener<P::Tcp>,
{
    type Provider = P;
    // ...
}
```

TLS/HTTPS 的实现采用相同 listener 约束。QUIC/H3 的原始 UDP socket 路径采用 UDP 的 `P: RuntimeProvider<Udp = S>` 约束。

重要陷阱：

- 构造器使用 `new(socket: S)`，不是 `new(socket: P::Udp)`；后者容易产生关联类型反推 provider 的推导问题。
- 不要在 `Udp<S, P>` / `Tcp<L, P>` 的结构体定义、默认构造器或普通 setter 上就要求 socket 与 provider 匹配。`new(custom_socket)` 暂时带有默认 Tokio provider，随后 `.with_provider(custom_provider)` 才形成可注册对象；提前约束会使这条调用链无法编译。
- 类型匹配放在 `Transport` impl 上。遗漏 `.with_provider()` 或使用不匹配 provider 应在注册阶段产生编译错误。
- `with_provider<Q>()` 真正返回带 `Q` 的新类型；不能是 `fn with_provider(self, provider: P) -> Self`。
- 普通 setter 直接使用 `Self { field, ..self }`；`with_provider()` 改变了实例类型，需明确移动其余字段，不能照搬同类型的 struct update 语法来移动 provider 字段。
- 重建新类型时移动全部配置，不能重置 timeout、路径、TLS 来源或 buffer size。
- 无需要求 `P: Debug`。保留 socket/stream/listener 的日志可观察性。当前分支已为 `DnsUdpSocket` / `DnsTcpStream` 加了 Debug；若 reset 后保留这些提交就直接沿用，若移除了则复用相应 Debug 改动及 mock 实现，不删除现有 `?socket` / `?listener` 日志。
- UDP 的 `'static` 需求放在可注册 transport/任务的约束上，不额外扩大已有基础 trait 的生命周期要求。

## 6. 各协议配置和默认值

每个协议类型直接保存配置字段，实现简单手写 setter；不增加公开 `FooConfig`、`FooBuilder` 或字段状态类型。处理函数可以接收整个协议对象和上下文；需要传入已初始化的 TLS acceptor/QUIC server 时，也可把剩余选项打包成小型私有配置对象，避免再次出现长参数列表。不要仅为了 setter 引入额外配置层。

| 类型 | 必需构造参数 | 可选配置及默认值 | feature |
| --- | --- | --- | --- |
| `Udp<S, P>` | 已绑定 `S` | provider 默认为 Tokio | 总是可用 |
| `Tcp<L, P>` | 已绑定 `L` | `stream_timeout = None`，`response_buffer_size = 32` | 总是可用 |
| `Tls<L, P>` | `L`、`Arc<rustls::ServerConfig>` | handshake/stream timeout 都为 `None` | `__tls` |
| `Https<L, P>` | `L`、`Arc<rustls::ServerConfig>` | handshake/idle/request timeout 都为 `None`；hostname `None`；HTTP endpoint 为已有默认路径 | `__https` |
| `Quic<S, P>` | `S`、`Arc<rustls::ServerConfig>` | handshake/idle/request timeout 都为 `None` | `__quic` |
| `H3<S, P>` | `S`、`Arc<rustls::ServerConfig>` | handshake/idle/request timeout 都为 `None`；hostname `None` | `__h3` |

说明：

- `response_buffer_size` 是可排队的 DNS 响应消息数量，不是字节数。32 对应现有 `BufDnsStreamHandle` 默认容量。CLI 继续明确传入它已有的配置值。
- TCP/TLS 的 `stream_timeout` 仍是当前 `TimeoutStream` 的超时，不能替换成独立 idle/request timeout 或改变重置时机。
- CLI 的 `stream_timeout()` 仍保留现有算法：idle 和 request 都为 Some 时相加，否则返回 None。
- HTTP/QUIC 的 handshake、idle、request timeout 继续作用在当前阶段，不因为配置重排改变作用范围。
- 不增加 H3 的 HTTP endpoint 或 hostname 校验功能。当前 H3 内部 `_dns_hostname` 没有用于校验；本次保留已有行为，不把这个参数宣称为已实现的 hostname 验证。
- 不在此重构新增无关的 buffer 范围、TLS ALPN 或路径验证规则；沿用已有规则，并准确文档化自定义 TLS config 的前提。

### 证书 resolver 入口

保留原有两种 TLS 配置来源，但放在协议类型的构造器上：

```rust
Tls::new(listener, tls_config)
Tls::from_cert_resolver(listener, cert_resolver)

Https::new(listener, tls_config)
Https::from_cert_resolver(listener, cert_resolver)

Quic::new(socket, tls_config)
Quic::from_cert_resolver(socket, cert_resolver)

H3::new(socket, tls_config)
H3::from_cert_resolver(socket, cert_resolver)
```

这些构造器都返回 transport 本身，在 `into_future()` 中处理可能失败的 TLS 配置构造。使用一个内部 `TlsSource` enum 区分 `Config(Arc<ServerConfig>)` 和 `CertResolver(Arc<dyn ResolvesServerCert>)` 即可，不暴露公共 typestate。

TLS/HTTPS 默认配置复用现有 `default_tls_server_config()` 和协议对应 ALPN。QUIC/H3 的 resolver 路径复用现有 net server 构造逻辑，保留 TLS 1.3、ALPN 和 transport config。自定义 `Arc<ServerConfig>` 不得被隐式替换、修改或丢失 key logging 等配置。

## 7. DnsTcpListener 和运行时边界

保留或重建以下 trait；删除旧的 `ServerRuntimeProvider`：

```rust
pub trait DnsTcpListener<S: DnsTcpStream>: Debug + Send + Unpin + 'static {
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(S, SocketAddr)>>;
}
```

契约需要明确：Pending 时注册 waker；取消和重试不丢失尚未接受的连接；永久关闭返回 `ErrorKind::NotConnected`。当前 server 只将 NotConnected 视为不可恢复错误，其他错误重试。这是现有策略，不改成 Tokio 未提供的错误分类机制。

Tokio listener 实现该 trait，返回 `AsyncIoTokioAsStd<tokio::net::TcpStream>`，与 `TokioRuntimeProvider::Tcp` 一致。不要误调用 trait 自身导致递归，应明确调用 Tokio 原生 `TcpListener::poll_accept()`。

处理函数的类型关系示意：

```rust
async fn handle_tcp<P, L, H>(
    transport: Tcp<L, P>,
    context: Arc<ServerContext<H>>,
) -> Result<(), NetError>
where
    P: RuntimeProvider,
    L: DnsTcpListener<P::Tcp>,
    H: RequestHandler,
```

函数起始处解构 transport，得到 listener 和配置。TLS、HTTPS 同样直接使用 `P::Tcp`。原来的 accept、连接及请求任务逻辑复用即可。

TLS/HTTPS 继续通过 `AsyncIoStdAsTokio` 接入 tokio-rustls；DoT 握手完成后继续用 `AsyncIoTokioAsStd` 接回 Hickory 的 futures I/O。

本次不要求 `P::Timer` 与 `P::Tcp::Time` / `P::Udp::Time` 相等，也不改公共 Time trait。本次 `ServerContext` 调用 RequestHandler 时继续使用已有 `TokioTime`；`TimeoutStream` 和 `timeout` 继续使用 Tokio。

## 8. QUIC/H3 socket 适配

继续通过 `RuntimeProvider` 的可选 wrapper 能力适配输入 UDP socket，保留 binder 和 wrapper 的独立性：

```rust
fn quic_wrapper(&self) -> Option<&dyn QuicSocketWrapper<Self::Udp>> {
    None
}
```

`QuicSocketWrapper<Udp>` 在 `__quic` 下有必需的 `wrap_udp()` 方法，返回 `io::Result<Arc<dyn AsyncUdpSocket>>`；未启用 `__quic` 时保留同名、同泛型的空 trait。wrapper 的默认缺失不增加普通 provider 的实现负担。

实施顺序：

1. 解构 transport，拿到拥有所有权的 socket、provider、TLS 来源及 timeout 配置。
2. 获取 wrapper；None 时立即返回明确 NetError。
3. 同步调用 `wrap_udp(socket)`，传播错误。
4. 同步构造 `QuicServer` / `H3Server`，传播 TLS/endpoint 错误。
5. 返回调用现有 QUIC/H3 handler 的拥有所有权 future。

不把 `&dyn QuicSocketWrapper` 带入 spawned future；它只在同步初始化阶段借用 provider，因此不需要为此给 wrapper 添加 Send/Sync 约束。

Tokio wrapper 使用 `socket.into_std()?` 再调用 `quinn::TokioRuntime.wrap_udp_socket()`。下游自定义实现可以返回自定义 Quinn AsyncUdpSocket。

保持 Quinn 依赖局部化：普通 `RuntimeProvider` 的声明不直接出现 Quinn 类型；实际 Quinn 类型出现在 feature gated 的 wrapper/QUIC 模块中。不要在 UDP/TCP 普通模块加入无条件 Quinn import，也不要让 QUIC-only 代码依赖 `h3_quinn`。

若 reset 恢复了 net server 的 Tokio-only socket 构造器，需要重新提供接受 `Arc<dyn AsyncUdpSocket>` 的构造路径。当前分支已经把 `QuicServer::with_socket()` / `H3Server::with_socket()` 改成该签名，可以复用；用户不要求兼容旧签名。H3 的 TLS 转换同样用 `?`，不能 `unwrap()`。

`QuicSocketBinder` 的客户端调用和行为不因本次 builder 改造改变。只有 binder、没有 wrapper 的 provider 不应被要求实现 wrapping；尝试注册原始 UDP QUIC transport 时按上述路径报错。

本轮不额外设计一套可替换 QUIC backend trait，或增加所有可能的已构造 server 入口。公开 Transport 和请求上下文使以后可以独立添加此类入口，不需要再扩展 Server。

## 9. 公开请求处理上下文

公开 `ServerContext<H>` 并从 `server` 模块重导出，字段、构造函数保持私有。Server 通过 Arc 向 transport 传递上下文。

建议公开最小接口：

```rust
impl<H: RequestHandler> ServerContext<H> {
    pub fn shutdown_token(&self) -> &CancellationToken;

    pub async fn handle_request(
        &self,
        message_bytes: Bytes,
        src_addr: SocketAddr,
        protocol: Protocol,
        response_handler: impl ResponseHandler,
    );
}
```

`handle_raw_request(SerialMessage, Protocol, BufDnsStreamHandle)` 可保持 `pub(crate)`，作为内建 UDP/TCP/TLS 的便利入口。

`handle_request()` 复用目前 ServerContext 中的完整实现：DNS header/message 解析、拒绝响应消息、错误响应、ACL、日志、ReportingResponseHandler、metrics、RequestHandler 调用。保留其无返回值的处理契约；不要让外部 transport 自行绕过这些步骤调用裸 handler。

把源地址安全检查也放在公开入口的起始位置，确保第三方 transport 使用这个入口时经过已有检查。内建协议在 accept/recv 阶段可以继续提前拒绝非法源地址，行为保持一致。

公开 shutdown token，用于外部 transport 的 accept/read 循环响应关闭。不要暴露内部 JoinSet、AccessControl 可变访问、原始 handler 或随意替换 server 上下文的接口。

扩展 transport 仍应实现协议对应的 ResponseHandler。沿用 UDP/TCP/TLS response handle，以及 HTTPS/QUIC/H3 各自的编码、HTTP response、DoQ ID 归零等行为。

新 Transport 能减少新增 Server 方法，不意味着现有 Protocol enum 能表达任意未知 wire protocol；真正新增协议仍可能需要扩展协议相关类型。

## 10. 文件布局和代码迁移

推荐布局，允许合并过小的内部模块，但不让协议处理函数继续集中堆在 `Server` impl：

```text
crates/server/src/server/
  mod.rs                  Server 构造、register、关闭及顶层任务管理
  context.rs              ServerContext、请求校验/处理及 reporting helper
  transport/
    mod.rs                Transport trait、按 feature 重导出协议类型
    udp.rs                Udp 类型、配置/初始化及 UDP 接收任务
    tcp.rs                Tcp 类型、配置及 TCP 接收/连接任务
    tls.rs                Tls 类型、配置及 TLS 接收/握手任务
    https.rs              Https 类型、配置及 H2 handler/response handle
    quic.rs               Quic 类型、配置及 DoQ handler/response handle
    h3.rs                 H3 类型、配置及 H3 handler/response handle
    tls_source.rs         私有 TLS 来源转换；仅需要时拆出
  request_handler.rs      现有 RequestHandler 等类型
  response_handler.rs     现有 ResponseHandler 等类型
  timeout_stream.rs       保留现有 timeout 语义
```

现有 h2_handler.rs / quic_handler.rs / h3_handler.rs 可以迁入各协议模块，或暂时作为协议模块的私有子模块；不要再暴露长参数调用的 Server 注册入口。处理函数接收协议对象，或资源加小型私有配置对象，避免仅转移 `too_many_arguments` 问题。

保持 feature 条件：TLS `__tls`，HTTPS `__https`，QUIC `__quic`，H3 `__h3`。路径、导入、测试和文档例子也要正确 gated。必须独立检查默认、TLS-only、HTTPS-only、QUIC-only、H3 配置。

## 11. 当前分支及 reset 后的恢复指南

编写时分支为 `server/generic-register-dev`，HEAD 为 `343de5aed`，源码工作区干净。本文件新增后 HEAD 可能被用户 reset；以下 SHA 只作参考，不是要求全部 cherry-pick。

| 当前提交 | 可复用内容 / 新方案中的处理 |
| --- | --- |
| `bc98df689` | AsyncIoStdAsTokio ReadBuf 修复，是独立 bugfix；先检查用户保留的基线或主线是否已包含 |
| `f15556adc` | 复用 DnsTcpListener、Tokio listener impl、可选 QuicSocketWrapper；**去掉 ServerRuntimeProvider** |
| `186705fc9` | Debug 约束及相关 placeholder 实现，可复用以保留日志 |
| `5f6167558` | mocks 的 Debug 实现，与 Debug 约束一起处理 |
| `eff5342d7` | 复用 TCP/TLS generic I/O 适配、listener 关闭测试；不保留泛型 Server 或旧注册接口 |
| `f6d834390` | 复用 HTTPS generic listener 和 AsyncIoStdAsTokio 接入 |
| `d177a3c41` | 复用 QUIC abstract socket 构造和 handler 接受 QuicServer 的边界 |
| `343de5aed` | 复用 H3 abstract socket 构造和 handler 接受 H3Server 的边界 |

不要盲目重新引入已经放弃的 ServerRuntimeProvider 设计。本文的公开接口、约束和迁移清单足以从主线重新实现，不依赖这些 commit 仍可达。

I/O adapter 前置问题：TLS/HTTPS 双向适配依赖 `AsyncIoStdAsTokio::poll_read()` 使用 `buf.initialize_unfilled()`，不是 `initialized_mut()`。后者会覆盖已有数据，且在完全未初始化缓冲区上返回空切片。若 reset 丢失此修复且主线未包含，应先把它作为独立 bugfix/前置提交处理，不能把读失败误诊为 builder 问题。真正未初始化缓冲区的回归测试应使用 `MaybeUninit` 和 `ReadBuf::uninit()`。

临时类型原型位于 `/tmp/hickory-transport-proposal/src/lib.rs`，使用真实 RuntimeProvider、DnsTcpListener、RequestHandler 验证过默认/自定义 provider 的类型关系。**它没有协议收发实现，不是可直接移植的生产代码，也不是验收依据。** 后续 agent 不必依赖该临时文件。

## 12. 调用点迁移

先全仓库搜索：

```sh
rg -n 'register_(socket|listener|tls_listener|https_listener|quic_listener|h3_listener)|ServerRuntimeProvider|with_access_and_provider' --glob '*.rs' --glob '*.md' --glob '!target/**'
```

已知位置：

- `bin/src/lib.rs` 的 ServerSetup，UDP/TCP/TLS/HTTPS/QUIC 注册。
- `crates/server/src/server/mod.rs` 的生命周期及自定义 listener 测试。
- `tests/integration-tests/src/lib.rs`。
- `tests/integration-tests/tests/integration/server_future_tests.rs`。
- integration 下的 truncation、rfc4592、validating_forwarder 测试。
- 文档、示例、conformance/util 等也需要搜索确认，不只修改上面列出的文件。

所有调用改成构造协议对象并传给 `server.register()`。UDP/TCP 现在也返回 Result，按调用点上下文使用 `?`、测试中的 `.unwrap()` 或 CLI 的现有 `map_err` 风格；不能忽略 Result。

CLI 保留 socket binding、多 socket 配置、端口及地址日志、TLS key logging 配置和已有错误上下文。已有默认配置构造器可以继续用于 CLI：先完成 CLI 特定 key logging 等设置，再传 Arc<ServerConfig> 给 builder。

闭合 listener 测试可以直接 `Server::new(Catalog::new())` 后注册 `Tcp::new(ClosedListener)`：它产生 TokioRuntimeProvider::Tcp，因此不再需要为它专门创建一个 ServerRuntimeProvider。

所有公开新类型、方法、关联类型补充英文 rustdoc。示例展示默认 Tokio 和自定义 provider 两条路径，并说明 server 本次仍需要 Tokio。

## 13. 手写 builder 的实现要求

不引入 bon 或其他 builder 宏，保留普通 Rust 字段和方法。采用第 5 节中的 setter 模式：普通配置返回 Self，provider 切换返回带新泛型参数的协议类型。

构造器设置所有默认值；必需资源由 new()/from_cert_resolver() 提供。协议对象本身就是 builder，不额外生成 `.build()` 终点，也不增加公共 typestate。

沿用第 2 节的公开方法名称，例如 `.stream_timeout(...)`、`.response_buffer_size(...)`；用户所举 `with_xxx(self, xxx) -> Self` 是实现模式，不要求把示例里的所有 setter 都改名。唯一改变类型的 `.with_provider()` 必须有专门的泛型方法。

配置方法可重复调用，后一次值覆盖前一次。为每个方法补充配置含义的 rustdoc，避免复制宏产生的大量状态 helper 或无关生成注解。最终依赖和 Cargo.lock 不应因为 builder 引入 bon。

## 14. 测试和验收重点

优先新增能证明新能力的测试，不为每个简单 setter 单独堆大量同构测试。

### 类型及 API

- 默认 Tokio socket/listener 可以直接注册。
- 使用与 Tokio 类型不同的自定义 UDP newtype、TCP stream newtype、listener 与 custom RuntimeProvider 完成真实本地请求收发。仅用 alias 或一个关联类型全部等于 Tokio 的 provider 不足以验证泛型能力。
- 同一个 Server 注册不同 provider 的 transport。
- `with_provider()` 在配置前后调用都保留已设置参数。
- 一个 provider 使用不同 listener 类型，只要它们产生 P::Tcp 就能注册；没有任何 TcpListener 关联类型或 ServerRuntimeProvider impl。
- 不匹配的 socket/provider 和 listener/stream 组合不能注册，可使用少量 compile_fail doctest。
- 下游 crate 能实现 Transport，获得 shutdown token，并通过公开 ServerContext 处理请求。应放在 integration test 或 doctest，避免仅在同模块测试误用私有字段。

### 行为和错误

- 迁移现有 server 生命周期、关闭、任务回收和源地址安全检查测试。
- listener 永久关闭返回 NotConnected 后任务退出，并保留当前 unexpected-close 错误语义；不忙循环。
- QUIC/H3 wrapper 缺失、wrapper 失败、TLS/endpoint 构造失败经 register() 同步返回，失败注册不留下后台任务。
- wrapper 被调用且收到预期自定义 socket；客户端 binder 不应被 server 初始化误调用。测试 provider 可以让 binder 返回错误或计数，以证明二者独立。
- TLS/HTTPS 对自定义 stream 的适配完成实际握手和 DNS 请求，避免只测试注册和关闭。
- QUIC/H3 至少完成本地端到端注册及请求收发；使用仓库已有 TestCertificates/rcgen 工具。不要依赖公共 DNS 服务进行测试。
- 从公开 context 进入的请求同样经过 DNS/ACL/源地址检查；测试其一两条关键路径，复用已有解析测试。
- 确认 CLI、所有 feature 下的调用点都迁移，默认值及实际 timeout/buffer 参数没有被丢弃。

### 建议检查命令

以下按实施阶段执行；最后以 reset 后实际 package/features 为准。新增测试的具体 target/filter 由实现者补充。

```sh
cargo fmt --all -- --check
cargo check -p hickory-server --all-targets
cargo check -p hickory-server --all-targets --features tls-ring
cargo check -p hickory-server --all-targets --features https-ring
cargo check -p hickory-server --all-targets --features quic-ring
cargo check -p hickory-server --all-targets --features h3-ring
cargo check -p hickory-net --no-default-features
cargo check -p hickory-dns --all-targets --features https-ring,quic-ring
cargo check -p hickory-integration --all-targets --features tls-ring
cargo clippy -p hickory-server -p hickory-net --all-targets --features hickory-server/https-ring,hickory-server/h3-ring,hickory-server/metrics -- -D warnings
cargo test -p hickory-server --lib
cargo test -p hickory-server --lib --features https-ring,h3-ring
cargo test -p hickory-server --doc --features https-ring,h3-ring
cargo test -p hickory-integration --features tls-ring --test integration server_future_tests
cargo test -p hickory-net --lib --features quic-ring quic::tests::test_quic_stream
```

至少编译一次 aws-lc 对应安全协议组合，例如 server 的 https-aws-lc-rs,h3-aws-lc-rs，确保 cfg/crypto provider 不被 ring 写死。若本地工具链/依赖条件不满足，明确记录未完成检查及原因。

最后进行 workspace 调用点编译检查；不要因只检查 server crate 而遗漏 bin 和 integration。测试本地 socket 被沙箱拒绝时按环境审批流程在沙箱外重跑，不能将 PermissionDenied 当成代码故障。当前 integration TLS 测试使用生成的 TestCertificates，不需要假定旧证书文件路径。

检查残留：

```sh
rg -n 'ServerRuntimeProvider|register_(socket|listener|tls_listener|https_listener|quic_listener|h3_listener)|with_access_and_provider' crates bin tests conformance util --glob '*.rs' --glob '*.md'
rg -n '\bbon\b|bon_macros|bon-macros' Cargo.toml Cargo.lock crates --glob '*.toml' --glob '*.rs' --glob Cargo.lock
```

生产代码和调用点不得残留旧注册方法或旧 provider 扩展 trait；本 HANDOFF 中的历史引用不算残留。bon 检查结果需结合锁文件的依赖关系确认，但 hickory-server 不得保留 bon 的任何直接或间接构建要求。

## 15. 实施顺序和完成标准

1. 确认用户 reset 后的基线、工作区和 I/O adapter 修复状态。
2. 恢复必要 net I/O 基础能力；若 reset 后仍保留泛型 Server，先清理它对 ServerRuntimeProvider 的依赖。最终去掉该 trait，不重新套用旧设计。
3. 建立公开 ServerContext、Transport trait 和唯一 register()，保留任务生命周期语义。
4. 实现 UDP builder/handler，迁移 UDP 调用和最小自定义 UDP 收发测试。
5. 实现 TCP builder/handler，迁移 TCP 调用和自定义 listener/stream 测试。
6. 实现 TLS、HTTPS，各自一份协议配置，保留 I/O 适配和证书配置路径。
7. 实现 QUIC、H3，同步初始化 wrapper 和 net server，补齐错误路径与本地收发测试。
8. 删除全部旧注册 API 和旧 Server provider 构造器，迁移剩余文档/CLI/test 调用点。
9. 检查简单手写 setter、类型切换和默认值；确认没有引入 builder 宏依赖。
10. 执行完整检查，审阅 diff 以确认配置、ACL、关闭、协议响应编码都没有意外变化。

提交组织遵循 djc 先前“每个 transport 一份 commit”的偏好：核心共享结构和 net 能力单独提交，随后 UDP/TCP/TLS/HTTPS/QUIC/H3 分别提交；每个提交尽量迁移相应调用点并保持可编译。分阶段提交中，尚未迁移协议的原有方法可以暂留，迁移一个协议就删除对应旧方法；这只是实施顺序，最终交付不保留兼容层。若 reset 后的泛型 Server 影响中间提交编译，应先恢复 Server<H> 和尚未迁移协议的原有具体类型入口。I/O adapter bugfix 单独处理。不要把所有协议堆在一个提交里。

完成必须同时满足：目标调用语法成立；六种协议都接入统一注册；自定义资源类型的测试证明泛型适配有效；旧 API 删除且全仓库调用迁移；下游能够实现 Transport；初始化失败可立即观测；最终无 bon；必要测试通过。对外说明仍为“支持自定义 socket/provider 的模块化 server API”，不能声称已摆脱 Tokio runtime。
