/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! UDP protocol related components for DNS

#[cfg(test)]
#[allow(clippy::print_stdout)]
mod tests;
mod udp_client_stream;
mod udp_stream;

pub use self::udp_client_stream::{UdpClientStream, UdpClientStreamBuilder};
pub use self::udp_stream::{UdpSocket, UdpStream};

/// Max size for the UDP receive buffer as recommended by
/// [RFC6891](https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5).
pub const MAX_RECEIVE_BUFFER_SIZE: usize = 4_096;

mod udp_listener {
    use core::future::poll_fn;
    use core::pin::Pin;
    use core::task::Poll;
    use std::fmt;
    use std::io;

    use futures_util::{Stream, ready};
    use tracing::{debug, warn};

    use crate::{
        proto::op::SerialMessage, runtime::DnsUdpSocket, udp::UdpStream,
        utils::sanitize_src_address,
    };

    /// Receives UDP messages whose source addresses are safe for responses.
    pub struct UdpListener<S: DnsUdpSocket> {
        stream: UdpStream<S>,
    }

    impl<S: DnsUdpSocket> fmt::Debug for UdpListener<S> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("UdpListener").finish_non_exhaustive()
        }
    }

    impl<S: DnsUdpSocket> UdpListener<S> {
        /// Wraps an existing UDP stream.
        pub fn new(stream: UdpStream<S>) -> Self {
            Self { stream }
        }

        /// Receives a UDP message whose source address is safe for responses.
        ///
        /// Each poll checks at most one candidate message. Messages from unsafe source addresses
        /// are dropped, and the task is woken to poll again. Receiving continues to drive the
        /// stream's outgoing message queue, and socket errors are returned without retrying.
        ///
        /// The source must have a nonzero port and an IP address that is neither unspecified nor
        /// an IPv4 broadcast address.
        pub async fn receive(&mut self) -> Option<io::Result<SerialMessage>> {
            poll_fn(|cx| {
                let message = match ready!(Pin::new(&mut self.stream).poll_next(cx)) {
                    Some(Ok(message)) => message,
                    result => return Poll::Ready(result),
                };
                let src_addr = message.addr();
                debug!("received udp request from: {}", src_addr);
                if let Err(e) = sanitize_src_address(src_addr) {
                    warn!("address can not be responded to {src_addr}: {e}");
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(message)))
            })
            .await
        }
    }
}

pub use udp_listener::UdpListener;
