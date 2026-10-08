// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{future::Future, sync::Arc};

use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Transport;
use crate::{
    net::{
        NetError,
        runtime::DnsUdpSocket,
        udp::{UdpListener, UdpStream},
        xfer::Protocol,
    },
    server::{
        ServerContext,
        request_handler::RequestHandler,
        utils::{is_unrecoverable_socket_error, reap_tasks},
    },
};

/// Builder and transport implementation for UDP.
///
/// Wraps an already-bound UDP socket and handles incoming DNS datagrams.
pub struct Udp<S> {
    socket: S,
}

impl<S> Udp<S> {
    /// Constructs a new UDP transport.
    ///
    /// The `socket` must be already bound to the desired local address.
    pub fn new(socket: S) -> Self {
        Self { socket }
    }
}

impl<S> Transport for Udp<S>
where
    S: DnsUdpSocket + 'static,
{
    fn into_future<H: RequestHandler>(
        self,
        cx: Arc<ServerContext<H>>,
    ) -> Result<impl Future<Output = Result<(), NetError>> + Send + 'static, NetError> {
        Ok(async move {
            debug!("registering udp: {:?}", self.socket);

            // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
            //   the address used is acquired from the inbound queries
            let (stream, stream_handle) =
                UdpStream::with_bound(self.socket, ([127, 255, 255, 254], 0).into());
            let mut listener = UdpListener::new(stream);

            let mut inner_join_set = JoinSet::new();
            loop {
                let Some(option) = cx
                    .shutdown_token()
                    .run_until_cancelled(listener.receive())
                    .await
                else {
                    // Graceful shutdown
                    break;
                };
                let Some(message_res) = option else {
                    // End of stream
                    break;
                };

                let message = match message_res {
                    Err(error) => {
                        warn!(%error, "error receiving message on udp_socket");
                        if is_unrecoverable_socket_error(&error) {
                            break;
                        }
                        continue;
                    }
                    Ok(message) => message,
                };

                let src_addr = message.addr();
                let cx = cx.clone();
                let stream_handle = stream_handle.with_remote_addr(src_addr);
                inner_join_set.spawn(async move {
                    cx.handle_raw_request(message, Protocol::Udp, stream_handle)
                        .await;
                });

                reap_tasks(&mut inner_join_set);
            }

            if cx.shutdown_token().is_cancelled() {
                Ok(())
            } else {
                // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
                Err(NetError::from("unexpected close of UDP socket"))
            }
        })
    }
}
