//! TLS protocol related components for DNS over TLS

mod tls_client_stream;
/// Default TLS configurations and cryptographic provider selection.
pub mod tls_config;
mod tls_listener;

pub use self::tls_client_stream::{
    TlsClientStream, TokioTlsClientStream, tls_client_connect, tls_client_connect_with_bind_addr,
    tls_exchange,
};
pub use self::tls_listener::{TlsListener, TlsServerStream};
#[cfg(feature = "__quic")]
pub use tls_config::default_quic_server_config;
pub use tls_config::{client_config, default_provider, default_tls_server_config};

/// TLS protocol IDs used by the DNS transport configuration factories.
#[allow(missing_docs)]
pub mod alpn {
    pub const ALPN_H2: &[u8] = b"h2";
    pub const ALPN_H3: &[u8] = b"h3";
    pub const DOT_ALPN: &[u8] = b"dot";
    pub const DOQ_ALPN: &[u8] = b"doq";
}
