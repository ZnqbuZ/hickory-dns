//! Transport protocol abstractions and builders for server registration.

use std::{future::Future, sync::Arc};

use crate::net::NetError;
use crate::server::{ServerContext, request_handler::RequestHandler};

pub(super) trait Transport: Send + 'static {
    /// Runs a transport whose listener was initialized by its constructor.
    fn run<H: RequestHandler>(
        self,
        cx: Arc<ServerContext<H>>,
    ) -> impl Future<Output = Result<(), NetError>> + Send + 'static;
}

mod udp;
pub use udp::Udp;

mod tcp;
pub use tcp::Tcp;

#[cfg(feature = "__tls")]
mod tls;
#[cfg(feature = "__tls")]
pub use tls::Tls;

#[cfg(feature = "__https")]
mod h2;
#[cfg(feature = "__https")]
pub use h2::H2;

#[cfg(feature = "__quic")]
mod quic;
#[cfg(feature = "__quic")]
pub use quic::Quic;

#[cfg(feature = "__h3")]
mod h3;
#[cfg(feature = "__h3")]
pub use h3::H3;
