//! TLS protocol related components for DNS over TLS

mod tls_client_stream;
/// Default TLS configurations and cryptographic provider selection.
pub mod tls_config;
mod tls_listener;
pub use tls_client_stream::{
    TlsClientStream, TokioTlsClientStream, tls_client_connect, tls_client_connect_with_bind_addr,
    tls_exchange,
};
#[cfg(feature = "__quic")]
pub use tls_config::default_quic_server_config;
pub use tls_config::{client_config, default_provider, default_tls_server_config};
pub use tls_listener::{TlsListener, TlsServerStream};
