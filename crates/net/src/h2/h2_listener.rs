// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::fmt::{self, Debug};
use core::str::FromStr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    error::NetError,
    http::{Version, fetch_body},
};
use bytes::{Bytes, BytesMut};
use futures_util::stream::Stream;
use http::{Method, Request, header::CONTENT_LENGTH};
use rustls::ServerConfig;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::runtime::{Accepted, DnsTcpListener};
use crate::tcp::TcpListener;
use crate::utils;

/// An established server-side HTTP/2 connection over a DNS TCP stream.
pub type HttpsConnection<S> =
    h2::server::Connection<tokio_rustls::server::TlsStream<AsyncIoStdAsTokio<S>>, Bytes>;

/// Accepts TCP connections and performs concurrent TLS and HTTP/2 handshakes.
///
/// Unfinished handshakes are aborted when the listener is dropped.
pub struct HttpsListener<L: DnsTcpListener> {
    listener: TcpListener<L>,
    tls_acceptor: TlsAcceptor,
    handshakes: JoinSet<Option<Accepted<HttpsConnection<L::Stream>>>>,
}

impl<L: DnsTcpListener> Debug for HttpsListener<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsListener")
            .field("listener", &self.listener)
            .field("handshakes", &self.handshakes)
            .finish_non_exhaustive()
    }
}

impl<L: DnsTcpListener> HttpsListener<L> {
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
    ) -> Option<Accepted<HttpsConnection<L::Stream>>> {
        let src_addr = accepted.src_addr;
        debug!("starting HTTPS request from: {src_addr}");

        let tls_stream = utils::optional_timeout(
            timeout,
            tls_acceptor.accept(AsyncIoStdAsTokio(accepted.connection)),
        )
        .await
        .inspect_err(|_| warn!("https timeout expired during handshake"))
        .ok()?
        .inspect_err(|error| debug!("https handshake src: {src_addr} error: {error}"))
        .ok()?;

        debug!("accepted HTTPS request from: {src_addr}");

        let connection = h2::server::handshake(tls_stream)
            .await
            .inspect_err(|error| warn!(%src_addr, %error, "handshake error"))
            .ok()?;

        Some(Accepted {
            connection,
            src_addr,
        })
    }

    /// Accepts an established HTTP/2 connection together with its recorded metadata.
    ///
    /// The optional timeout applies only to the TLS handshake. Failed TLS or HTTP/2
    /// handshakes are ignored; errors from the underlying TCP listener are returned.
    /// Cancelling this future does not cancel handshakes that have already started;
    /// dropping the listener aborts them.
    pub async fn accept(
        &mut self,
        handshake_timeout: Option<Duration>,
    ) -> io::Result<Accepted<HttpsConnection<L::Stream>>> {
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    self.handshakes.spawn(Self::handshake(
                        result?,
                        self.tls_acceptor.clone(),
                        handshake_timeout,
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

/// Given an HTTP request, return a future that will result in the next sequence of bytes.
///
/// To allow downstream clients to do something interesting with the lifetime of the bytes, this doesn't
///   perform a conversion to a Message, only collects all the bytes.
pub async fn message_from<R>(
    this_server_name: Option<Arc<str>>,
    this_server_endpoint: Arc<str>,
    request: Request<R>,
) -> Result<BytesMut, NetError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{
    debug!("Received request: {:#?}", request);

    let this_server_name = this_server_name.as_deref();
    match crate::http::verify(
        Version::Http2,
        this_server_name,
        &this_server_endpoint,
        &request,
    ) {
        Ok(_) => (),
        Err(err) => return Err(err),
    }

    // attempt to get the content length
    let mut content_length = None;
    if let Some(length) = request.headers().get(CONTENT_LENGTH) {
        let length = usize::from_str(length.to_str()?)?;
        debug!("got message length: {}", length);
        content_length = Some(length);
    }

    match *request.method() {
        Method::GET => Err(format!("GET unimplemented: {}", request.method()).into()),
        Method::POST => fetch_body(request.into_body(), content_length).await,
        _ => Err(format!("bad method: {}", request.method()).into()),
    }
}
