// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::net::SocketAddr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::{IntoQuicSocket, quic_config, quic_stream::QuicStream};
use crate::tls as tls_config;
use crate::{error::NetError, runtime::Accepted};
use quinn::{Connecting, Connection};
use rustls::server::ResolvesServerCert;
use rustls::server::ServerConfig as TlsServerConfig;
use tokio::net::UdpSocket;

/// A listener for established DNS-over-QUIC connections.
#[derive(Debug)]
pub struct QuicServer {
    endpoint: QuicEndpoint<QuicStreams>,
}

impl QuicServer {
    /// Binds a UDP socket and constructs a listener with a default TLS configuration.
    pub async fn new(
        name_server: SocketAddr,
        cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        Self::with_socket(UdpSocket::bind(name_server).await?, cert_resolver)
    }

    /// Constructs a listener with an existing socket and a default TLS configuration.
    pub fn with_socket(
        socket: impl IntoQuicSocket,
        cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        let config = tls_config::default_quic_server_config(b"doq", cert_resolver);
        Self::with_socket_and_tls_config(socket, Arc::new(config))
    }

    /// Constructs a listener with an existing socket and a custom TLS configuration.
    ///
    /// The caller must ensure the `TlsServerConfig` has the appropriate DoQ ALPN protocol enabled.
    pub fn with_socket_and_tls_config(
        socket: impl IntoQuicSocket,
        tls_config: Arc<TlsServerConfig>,
    ) -> Result<Self, NetError> {
        let endpoint = QuicEndpoint::new(
            socket,
            tls_config,
            quic_config::endpoint(),
            quic_config::transport(),
        )?;

        Ok(Self { endpoint })
    }

    /// Accept the next connection and its recorded metadata after completing its QUIC handshake.
    ///
    /// Handshakes run concurrently. The timeout applies to each individual handshake.
    /// Handshake failures are logged and skipped; synchronous accept errors are returned.
    /// Dropping the listener aborts pending handshakes without waiting for them to finish.
    ///
    /// Cancelling this future leaves already-started handshakes owned by the listener.
    /// A subsequent call can receive their completed connections.
    pub async fn next(
        &mut self,
        timeout: Option<Duration>,
    ) -> Option<Result<Accepted<QuicStreams>, NetError>> {
        self.endpoint.accept(timeout).await
    }

    /// Returns the address this listener is listening on.
    ///
    /// This can be useful in tests, where a random port can be associated with the server by binding on `127.0.0.1:0` and then getting the
    ///   associated port address with this function.
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.endpoint.local_addr()
    }
}

use self::endpoint::{QuicEndpoint, QuicHandshake};

pub(crate) mod endpoint {
    use std::{fmt, future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

    use quinn::crypto::rustls::QuicServerConfig;
    use quinn::{
        Connecting, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig,
    };
    use rustls::ServerConfig as TlsServerConfig;
    use tokio::task::JoinSet;
    use tracing::{debug, warn};

    use super::IntoQuicSocket;
    use crate::{error::NetError, runtime::Accepted, utils, utils::sanitize_src_address};

    /// QUIC and HTTP/3 share acceptance and task ownership but initialize different protocols.
    pub(crate) trait QuicHandshake: Sized + Send + 'static {
        /// Returns a Send future that completes protocol initialization.
        fn handshake(connecting: Connecting)
        -> impl Future<Output = Result<Self, NetError>> + Send;
    }

    /// Keeping handshake tasks here preserves them across cancelled accept calls and cancels
    /// them when the listener is dropped.
    pub(crate) struct QuicEndpoint<H> {
        endpoint: Endpoint,
        handshakes: JoinSet<Option<Accepted<H>>>,
    }

    impl<H> fmt::Debug for QuicEndpoint<H> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("QuicEndpoint")
                .field("endpoint", &self.endpoint)
                .field("handshakes", &self.handshakes)
                .finish()
        }
    }

    impl<H: QuicHandshake> QuicEndpoint<H> {
        pub(crate) fn new(
            socket: impl IntoQuicSocket,
            tls_config: Arc<TlsServerConfig>,
            endpoint_config: EndpointConfig,
            transport_config: TransportConfig,
        ) -> Result<Self, NetError> {
            let mut server_config =
                ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
            server_config.transport = Arc::new(transport_config);

            let socket = socket.into_quic_socket()?;
            let endpoint = Endpoint::new_with_abstract_socket(
                endpoint_config,
                Some(server_config),
                socket,
                Arc::new(TokioRuntime),
            )?;

            Ok(Self {
                endpoint,
                handshakes: JoinSet::new(),
            })
        }

        async fn handshake(
            connecting: Connecting,
            timeout: Option<Duration>,
        ) -> Option<Accepted<H>> {
            let src_addr = connecting.remote_address();
            debug!(%src_addr, "starting QUIC request");

            let connection = utils::optional_timeout(timeout, H::handshake(connecting))
                .await
                .inspect_err(|_| warn!("timeout expired during handshake"))
                .ok()?
                .inspect_err(|error| debug!(%error, "error completing incoming quic connection"))
                .ok()?;

            debug!(%src_addr, "accepted QUIC request");
            Some(Accepted {
                connection,
                src_addr,
            })
        }

        pub(crate) async fn accept(
            &mut self,
            timeout: Option<Duration>,
        ) -> Option<Result<Accepted<H>, NetError>> {
            loop {
                tokio::select! {
                    incoming = self.endpoint.accept() => {
                        let incoming = incoming?;
                        let src_addr = incoming.remote_address();
                        // Require address validation before allocating connection state for a spoofable peer.
                        if !incoming.remote_address_validated() {
                            if let Err(error) = incoming.retry() {
                                warn!(%error, "could not send retry packet");
                            }
                            continue;
                        }
                        if let Err(error) = sanitize_src_address(src_addr) {
                            warn!(%error, %src_addr, "address can not be responded to");
                            continue;
                        }
                        let connecting = match incoming.accept() {
                            Ok(connecting) => connecting,
                            Err(error) => return Some(Err(error.into())),
                        };
                        self.handshakes.spawn(Self::handshake(connecting, timeout));
                    }
                    Some(result) = self.handshakes.join_next() => {
                        if let Ok(Some(connection)) = result {
                            return Some(Ok(connection));
                        };
                    }
                }
            }
        }

        pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
            self.endpoint.local_addr()
        }
    }
}

/// An established QUIC connection that accepts bidirectional streams.
pub struct QuicStreams {
    connection: Connection,
}

impl QuicStreams {
    /// Get the next bidirectional stream from the client
    pub async fn next(&mut self) -> Result<QuicStream, NetError> {
        match self.connection.accept_bi().await {
            Ok((send, receive)) => Ok(QuicStream::new(send, receive)),
            Err(e) => Err(NetError::from(e)),
        }
    }
}

impl QuicHandshake for QuicStreams {
    async fn handshake(connecting: Connecting) -> Result<Self, NetError> {
        Ok(Self {
            connection: connecting.await?,
        })
    }
}
