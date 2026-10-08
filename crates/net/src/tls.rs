// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

use std::{future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::future::BoxFuture;
#[cfg(not(feature = "rustls-platform-verifier"))]
use rustls::RootCertStore;
use rustls::{
    ClientConfig, ServerConfig,
    crypto::{self, CryptoProvider},
    pki_types::ServerName,
    server::ResolvesServerCert,
};
#[cfg(feature = "rustls-platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::{
    error::NetError,
    runtime::{
        DnsTcpStream, RuntimeProvider, Spawn,
        iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd},
    },
    tcp::{TcpClientStream, TcpStream},
    xfer::{BufDnsStreamHandle, CONNECT_TIMEOUT, DnsExchange, DnsMultiplexer, StreamReceiver},
};

/// Type of TlsClientStream used with Rustls
pub type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>>>;

/// Create a new [`DnsExchange`] wrapped around a multiplexed [`TlsClientStream`],
/// optionally binding the underlying TCP socket to a local address.
///
/// # Arguments
///
/// * `remote_addr` - Address of the remote nameserver
/// * `bind_addr` - Local address to bind the outgoing TCP socket to. When `None`, the OS picks.
/// * `server_name` - TLS server name for certificate validation
/// * `config` - TLS client configuration
/// * `timeout` - Timeout for requests
/// * `connect_timeout` - Timeout for the TCP connect step
/// * `max_active_requests` - Optional limit on concurrent in-flight requests.
///   If `None`, uses the default (32).
/// * `provider` - Runtime provider for spawning background tasks
#[allow(clippy::too_many_arguments)]
pub async fn tls_exchange<P: RuntimeProvider<Tcp = S>, S: DnsTcpStream>(
    remote_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    mut config: ClientConfig,
    timeout: Duration,
    connect_timeout: Duration,
    max_active_requests: Option<usize>,
    provider: P,
) -> Result<DnsExchange<P>, NetError> {
    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    config.enable_sni = false;

    let stream = provider
        .connect_tcp(remote_addr, bind_addr, Some(connect_timeout))
        .await?;
    let (future, sender) = tls_client_connect_with_future(
        stream,
        remote_addr,
        server_name.to_owned(),
        Arc::new(config),
    );

    let mut multiplexer = DnsMultiplexer::new(future.await?, sender).with_timeout(timeout);
    if let Some(max) = max_active_requests {
        multiplexer = multiplexer.with_max_active_requests(max);
    }
    let (exchange, bg) = DnsExchange::<P>::from_stream(multiplexer);
    provider.create_handle().spawn_bg(bg);
    Ok(exchange)
}

/// Creates a new TlsStream to the specified name_server
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect<P: RuntimeProvider>(
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tcp>, NetError>>,
    BufDnsStreamHandle,
) {
    tls_client_connect_with_bind_addr(name_server, None, server_name, client_config, provider)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect_with_bind_addr<P: RuntimeProvider>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tcp>, NetError>>,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);
    let early_data_enabled = client_config.enable_early_data;
    let tls_connector = TlsConnector::from(client_config).early_data(early_data_enabled);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = async move {
        let tcp = provider.connect_tcp(name_server, bind_addr, None).await?;
        connect_tls_stream(
            tls_connector,
            tcp,
            name_server,
            server_name,
            outbound_messages,
        )
        .await
    };

    let new_future = Box::pin(async { Ok(TcpClientStream::from_stream(stream.await?)) });

    (new_future, message_sender)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `future` - A future producing DnsTcpStream
/// * `dns_name` - The DNS name associated with a certificate
fn tls_client_connect_with_future<S: DnsTcpStream>(
    stream: S,
    socket_addr: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
) -> (
    impl Future<Output = Result<TlsClientStream<S>, NetError>> + Send + 'static,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(socket_addr);
    let early_data_enabled = client_config.enable_early_data;
    let tls_connector = TlsConnector::from(client_config).early_data(early_data_enabled);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = async move {
        connect_tls_stream(
            tls_connector,
            stream,
            socket_addr,
            server_name,
            outbound_messages,
        )
        .await
    };

    (
        async move { Ok(TcpClientStream::from_stream(stream.await?)) },
        message_sender,
    )
}

pub(super) async fn connect_tls_stream<S: DnsTcpStream>(
    tls_connector: TlsConnector,
    stream: S,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    outbound_messages: StreamReceiver,
) -> Result<TcpStream<AsyncIoTokioAsStd<TokioTlsClientStream<S>>>, NetError> {
    let stream = AsyncIoStdAsTokio(stream);
    let s = match timeout(CONNECT_TIMEOUT, tls_connector.connect(server_name, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(NetError::from(e)),
        Err(_) => {
            debug!(%name_server, "TLS connect timeout");
            return Err(NetError::Timeout);
        }
    };

    Ok(TcpStream::from_stream_with_receiver(
        AsyncIoTokioAsStd(s),
        name_server,
        outbound_messages,
    ))
}

/// Make a new [`ClientConfig`] with the default settings
pub fn client_config() -> Result<ClientConfig, rustls::Error> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap();

    #[cfg(feature = "rustls-platform-verifier")]
    let builder = builder.with_platform_verifier()?;
    #[cfg(not(feature = "rustls-platform-verifier"))]
    let builder = builder.with_root_certificates({
        #[cfg_attr(not(feature = "webpki-roots"), allow(unused_mut))]
        let mut root_store = RootCertStore::empty();
        #[cfg(feature = "webpki-roots")]
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    });

    Ok(builder.with_no_client_auth())
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub fn default_provider() -> CryptoProvider {
    crypto::aws_lc_rs::default_provider()
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(feature = "tls-ring")]
pub fn default_provider() -> CryptoProvider {
    crypto::ring::default_provider()
}

/// Predefined type for abstracting the TlsClientStream with TokioTls
pub type TokioTlsClientStream<S> = tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>;

/// Construct a default [`ServerConfig`] for TLS over TCP, such as DoT or HTTP/2.
///
/// The returned configuration uses the safe default protocol versions and does not request client
/// certificates. `alpn` selects the ALPN, such as `b"dot"` or `b"h2"`.
/// QUIC needs a TLS 1.3 configuration; use `default_quic_server_config` for those protocols.
pub fn default_tls_server_config(
    alpn: &[u8],
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// Construct a default TLS [`ServerConfig`] for QUIC-based protocols, such as DoQ or HTTP/3.
///
/// The returned configuration only enables TLS 1.3, as required by QUIC, uses the given ALPN
/// protocol and does not request client certificates. `alpn` selects the ALPN, such as
/// `b"doq"` or `b"h3"`.
#[cfg(feature = "__quic")]
pub fn default_quic_server_config(
    alpn: &[u8],
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3 not supported") // The ring default provider is guaranteed to support TLS 1.3
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

mod tls_listener {
    use std::{fmt, io, sync::Arc, time::Duration};

    use rustls::ServerConfig;
    use tokio::task::JoinSet;
    use tokio_rustls::TlsAcceptor;
    use tracing::{debug, warn};

    use crate::{
        runtime::{
            Accepted, DnsTcpListener,
            iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd},
        },
        tcp::TcpListener,
        utils,
    };

    /// An established server-side TLS stream over a DNS TCP stream.
    pub type TlsServerStream<S> =
        AsyncIoTokioAsStd<tokio_rustls::server::TlsStream<AsyncIoStdAsTokio<S>>>;

    /// Accepts TCP connections and performs concurrent TLS handshakes.
    ///
    /// Unfinished handshakes are aborted when the listener is dropped.
    pub struct TlsListener<L: DnsTcpListener> {
        listener: TcpListener<L>,
        tls_acceptor: TlsAcceptor,
        handshakes: JoinSet<Option<Accepted<TlsServerStream<L::Stream>>>>,
    }

    impl<L: DnsTcpListener> fmt::Debug for TlsListener<L> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TlsListener")
                .field("listener", &self.listener)
                .field("handshakes", &self.handshakes)
                .finish_non_exhaustive()
        }
    }

    impl<L: DnsTcpListener> TlsListener<L> {
        /// Wraps an already-bound TCP listener with the supplied TLS configuration.
        pub fn new(listener: L, tls_config: Arc<ServerConfig>) -> Self {
            Self {
                listener: TcpListener::new(listener),
                tls_acceptor: TlsAcceptor::from(tls_config),
                handshakes: JoinSet::new(),
            }
        }

        async fn handshake(
            accepted: Accepted<L::Stream>,
            tls_acceptor: TlsAcceptor,
            timeout: Option<Duration>,
        ) -> Option<Accepted<TlsServerStream<L::Stream>>> {
            let src_addr = accepted.src_addr;
            debug!(%src_addr, "starting TLS request");

            let tls_stream = utils::optional_timeout(
                timeout,
                tls_acceptor.accept(AsyncIoStdAsTokio(accepted.connection)),
            )
            .await
            .inspect_err(|_| warn!("tls timeout expired during handshake"))
            .ok()?
            .inspect_err(|error| debug!(%src_addr, %error, "tls handshake error"))
            .ok()?;

            debug!(%src_addr, "accepted TLS request");
            Some(Accepted {
                connection: AsyncIoTokioAsStd(tls_stream),
                src_addr,
            })
        }

        /// Accepts an established TLS stream together with its recorded connection metadata.
        ///
        /// The optional timeout applies to each TLS handshake. Failed handshakes are ignored;
        /// errors from the underlying TCP listener are returned to the caller.
        /// Cancelling this future does not cancel handshakes that have already started;
        /// dropping the listener aborts them.
        pub async fn accept(
            &mut self,
            timeout: Option<Duration>,
        ) -> io::Result<Accepted<TlsServerStream<L::Stream>>> {
            loop {
                tokio::select! {
                    result = self.listener.accept() => {
                        self.handshakes.spawn(Self::handshake(
                            result?,
                            self.tls_acceptor.clone(),
                            timeout,
                        ));
                    }
                    Some(result) = self.handshakes.join_next() => {
                        if let Ok(Some(connection)) = result {
                            return Ok(connection);
                        };
                    }
                }
            }
        }
    }
}

pub use tls_listener::{TlsListener, TlsServerStream};
