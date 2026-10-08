//! Networking library for Hickory DNS

#![warn(clippy::dbg_macro, clippy::print_stdout, missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use hickory_proto as proto;

pub mod client;

#[cfg(feature = "__dnssec")]
pub mod dnssec;

mod error;
pub use error::{DnsError, ForwardNSData, NetError, NoRecords};

#[cfg(feature = "__https")]
pub mod h2;
#[cfg(feature = "__h3")]
pub mod h3;
#[cfg(any(feature = "__https", feature = "__h3"))]
pub mod http;
#[cfg(feature = "mdns")]
pub mod multicast;
#[cfg(all(feature = "__quic", feature = "tokio"))]
pub mod quic;
pub mod runtime;
pub mod tcp;
#[cfg(feature = "__tls")]
pub mod tls;
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::BufDnsStreamHandle;
#[doc(hidden)]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;

mod utils {
    use std::net::{IpAddr, SocketAddr};
    #[cfg(feature = "__tls")]
    use std::{future::Future, time::Duration};

    /// Checks if the IP address is safe for returning messages.
    ///
    /// Examples of unsafe addresses are any with a port of `0`.
    ///
    /// # Returns
    ///
    /// Error if the address should not be used for returned requests.
    pub(crate) fn sanitize_src_address(src_addr: SocketAddr) -> Result<(), String> {
        if src_addr.port() == 0 {
            return Err(format!("cannot respond to src on port 0: {src_addr}"));
        }

        match src_addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => {
                Err(format!("cannot respond to unspecified v4 addr: {ip}"))
            }
            IpAddr::V4(ip) if ip.is_broadcast() => {
                Err(format!("cannot respond to broadcast v4 addr: {ip}"))
            }
            IpAddr::V6(ip) if ip.is_unspecified() => {
                Err(format!("cannot respond to unspecified v6 addr: {ip}"))
            }
            _ => Ok(()),
        }
    }

    /// Optionally applies a timeout to a future.
    #[cfg(feature = "__tls")]
    pub(crate) async fn optional_timeout<T>(
        timeout: Option<Duration>,
        future: impl Future<Output = T>,
    ) -> Result<T, tokio::time::error::Elapsed> {
        match timeout {
            Some(duration) => tokio::time::timeout(duration, future).await,
            None => Ok(future.await),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::net::SocketAddr;

        use super::sanitize_src_address;

        #[test]
        fn test_sanitize_src_address() {
            // ipv4 tests
            assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 4_096))).is_ok());
            assert!(sanitize_src_address(SocketAddr::from(([127, 0, 0, 1], 53))).is_ok());

            assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 0))).is_err());
            assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 0))).is_err());
            assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 4_096))).is_err());
            assert!(sanitize_src_address(SocketAddr::from(([255, 255, 255, 255], 4_096))).is_err());

            // ipv6 tests
            assert!(
                sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 4_096)))
                    .is_ok()
            );
            assert!(
                sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 4_096))).is_ok()
            );

            assert!(
                sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 4_096))).is_err()
            );
            assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))).is_err());
            assert!(
                sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 0))).is_err()
            );
        }
    }
}
