//! TLS protocol related components for DNS over HTTPS (DoH)

mod h2_client_stream;
mod h2_listener;
#[cfg(test)]
mod tests;
pub use h2_client_stream::{HttpsClientStream, HttpsClientStreamBuilder, connect};
pub use h2_listener::{HttpsConnection, HttpsListener, message_from};
const ALPN_H2: &[u8] = b"h2";
