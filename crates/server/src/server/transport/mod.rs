//! Transport protocol abstractions and builders for server registration.

use std::{future::Future, sync::Arc};

use crate::{
    net::NetError,
    server::{ServerContext, request_handler::RequestHandler},
};

/// Common interface for server transports.
///
/// A `Transport` encapsulates a bound network resource (such as a UDP socket or
/// a TCP listener) together with protocol-specific configurations.
/// Calling [`into_future`](Transport::into_future) initializes any required state synchronously
/// and returns a long-running future that processes inbound requests.
///
/// # Task ownership
///
/// The returned future owns the listening resource:
///
/// * The cancellation signal is obtained from the [`ServerContext`] it is given.
/// * Built-in transports own UDP requests or accepted connections in a local
///   `JoinSet`, which cancels those tasks when the returned future is dropped.
/// * Protocols may spawn requests independently of the connection task. The transport
///   chooses how to finish accepted work when it stops.
/// * The server waits for the registered transport futures. It does not separately
///   wait for child tasks to finish cancellation or discover third party tasks.
pub trait Transport: Send + 'static {
    /// Initialize the transport and return its long-running task.
    ///
    /// Socket adaptation and endpoint setup can fail before the server spawns a task,
    /// so a failed registration leaves no listening task behind.
    fn into_future<H: RequestHandler>(
        self,
        context: Arc<ServerContext<H>>,
    ) -> Result<impl Future<Output = Result<(), NetError>> + Send + 'static, NetError>;
}

#[cfg(feature = "__https")]
mod h2_handler;
#[cfg(feature = "__h3")]
mod h3_handler;
#[cfg(feature = "__quic")]
mod quic_handler;
mod tcp_transport;
#[cfg(feature = "__tls")]
mod tls_transport;
mod udp_transport;

pub use self::udp_transport::Udp;

pub use self::tcp_transport::Tcp;

#[cfg(feature = "__tls")]
pub use self::tls_transport::Tls;

#[cfg(feature = "__https")]
pub use self::h2_handler::Https;

#[cfg(feature = "__quic")]
pub use self::quic_handler::Quic;

#[cfg(feature = "__h3")]
pub use self::h3_handler::H3;
