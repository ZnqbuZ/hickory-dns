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

//! TCP protocol related components for DNS
mod tcp_client_stream;
mod tcp_stream;
#[cfg(test)]
#[allow(clippy::print_stdout)]
mod tests;

pub use self::tcp_client_stream::TcpClientStream;
pub use self::tcp_stream::TcpStream;

mod tcp_listener {
    use std::{future::poll_fn, io, task::Poll};

    use tracing::warn;

    use crate::{
        runtime::{Accepted, DnsTcpListener},
        utils::sanitize_src_address,
    };

    /// Accepts TCP connections whose peer addresses are safe for responses.
    #[derive(Debug)]
    pub struct TcpListener<L: DnsTcpListener> {
        listener: L,
    }

    impl<L: DnsTcpListener> TcpListener<L> {
        /// Wraps an already-bound TCP listener.
        pub fn new(listener: L) -> Self {
            Self { listener }
        }

        /// Accepts a connection whose peer address is safe for responses.
        ///
        /// Each poll checks at most one candidate connection. Connections from unsafe source
        /// addresses are dropped, and the task is woken to poll again.
        /// Listener errors are returned without retrying.
        ///
        /// The peer must have a nonzero port and an IP address that is neither unspecified nor
        /// an IPv4 broadcast address.
        /// Cancelling this future preserves the cancellation guarantees of
        /// [`DnsTcpListener::poll_accept`].
        pub async fn accept(&mut self) -> io::Result<Accepted<L::Stream>> {
            poll_fn(|cx| {
                let accepted = core::task::ready!(self.listener.poll_accept(cx))?;
                let src_addr = accepted.src_addr;
                if let Err(error) = sanitize_src_address(src_addr) {
                    warn!(%src_addr, %error, "address can not be responded to (TCP)");
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Ok(accepted))
            })
            .await
        }
    }
}

pub use tcp_listener::TcpListener;
