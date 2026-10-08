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
