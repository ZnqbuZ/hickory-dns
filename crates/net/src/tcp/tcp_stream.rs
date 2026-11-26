// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module contains all the TCP structures for demuxing TCP into streams of DNS packets.

use core::mem;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;

use futures_io::IoSlice;
use futures_util::future::Future;
use futures_util::stream::Stream;
use tracing::{debug, trace};

use crate::proto::op::SerialMessage;
use crate::runtime::{DnsTcpStream, Time};
use crate::xfer::{BufDnsStreamHandle, StreamReceiver};

/// Current state while writing to the remote of the TCP connection
enum WriteTcpState {
    /// Currently writing the length of bytes to of the buffer.
    LenBytes {
        /// Current position in the length buffer being written
        pos: usize,
        /// Length of the buffer
        length: [u8; 2],
        /// Buffer to write after the length
        bytes: Vec<u8>,
    },
    /// Currently writing the buffer to the remote
    Bytes {
        /// Current position in the buffer written
        pos: usize,
        /// Buffer to write to the remote
        bytes: Vec<u8>,
    },
    /// Currently flushing the bytes to the remote
    Flushing,
}

/// Current state of a TCP stream as it's being read.
pub(crate) enum ReadTcpState {
    /// Currently reading the length of the TCP packet
    LenBytes {
        /// Current position in the buffer
        pos: usize,
        /// Buffer of the length to read
        bytes: [u8; 2],
    },
    /// Currently reading the bytes of the DNS packet
    Bytes {
        /// Current position while reading the buffer
        pos: usize,
        /// buffer being read into
        bytes: Vec<u8>,
    },
}

/// A Stream used for sending data to and from a remote DNS endpoint (client or server).
#[must_use = "futures do nothing unless polled"]
pub struct TcpStream<S: DnsTcpStream> {
    socket: S,
    outbound_messages: StreamReceiver,
    send_state: Option<WriteTcpState>,
    read_state: ReadTcpState,
    peer_addr: SocketAddr,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    read_timeout: Option<ReadTimeout>,
}

impl<S: DnsTcpStream> TcpStream<S> {
    /// Returns the address of the peer connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Initializes a TcpStream with an established connection.
    ///
    /// Uses the default buffer size (32) for the outbound message queue.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - address of the remote peer
    pub fn from_stream(stream: S, peer_addr: SocketAddr) -> (Self, BufDnsStreamHandle) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);
        (stream, message_sender)
    }

    /// Initializes a TcpStream with an established connection and explicit buffer size.
    ///
    /// Use this when you need a larger buffer to handle high message rates without
    /// dropping messages due to backpressure.
    ///
    /// # Arguments
    ///
    /// * `stream` - the established IO stream for communication
    /// * `peer_addr` - address of the remote peer
    /// * `buffer_size` - maximum number of messages that can be queued for sending
    pub fn from_stream_with_buffer_size(
        stream: S,
        peer_addr: SocketAddr,
        buffer_size: usize,
    ) -> (Self, BufDnsStreamHandle) {
        let (message_sender, outbound_messages) =
            BufDnsStreamHandle::with_buffer_size(peer_addr, buffer_size);
        let stream = Self::from_stream_with_receiver(stream, peer_addr, outbound_messages);
        (stream, message_sender)
    }

    /// Wraps a stream where a sender and receiver have already been established
    pub fn from_stream_with_receiver(
        socket: S,
        peer_addr: SocketAddr,
        outbound_messages: StreamReceiver,
    ) -> Self {
        Self {
            socket,
            outbound_messages,
            send_state: None,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0u8; 2],
            },
            peer_addr,
            idle_timeout: None,
            request_timeout: None,
            read_timeout: None,
        }
    }

    /// Creates a new future of the eventually establish a IO stream connection or fail trying
    ///
    /// # Arguments
    ///
    /// * `future` - underlying stream future which this tcp stream relies on
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_future<F: Future<Output = Result<S, io::Error>> + Send + 'static>(
        future: F,
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (
        impl Future<Output = Result<Self, io::Error>> + Send,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);
        let stream_fut = Self::connect_with_future(future, name_server, timeout, outbound_messages);

        (stream_fut, message_sender)
    }

    /// Sets the timeout before closing an idle connection while waiting for the next message.
    ///
    /// Pass `None` to disable the idle timeout.
    pub fn with_idle_timeout(self, idle_timeout: Option<Duration>) -> Self {
        Self {
            idle_timeout,
            read_timeout: None,
            ..self
        }
    }

    /// Sets the timeout for receiving a complete message once reading has started.
    ///
    /// Pass `None` to disable the request timeout.
    pub fn with_request_timeout(self, request_timeout: Option<Duration>) -> Self {
        Self {
            request_timeout,
            read_timeout: None,
            ..self
        }
    }

    async fn connect_with_future<F: Future<Output = Result<S, io::Error>> + Send + 'static>(
        future: F,
        name_server: SocketAddr,
        timeout: Duration,
        outbound_messages: StreamReceiver,
    ) -> Result<Self, io::Error> {
        let socket = S::Time::timeout(timeout, future).await??;
        debug!("TCP connection established to: {}", name_server);
        Ok(Self {
            socket,
            outbound_messages,
            send_state: None,
            read_state: ReadTcpState::LenBytes {
                pos: 0,
                bytes: [0u8; 2],
            },
            peer_addr: name_server,
            idle_timeout: None,
            request_timeout: None,
            read_timeout: None,
        })
    }
}

impl<S: DnsTcpStream> Stream for TcpStream<S> {
    type Item = io::Result<SerialMessage>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            socket,
            outbound_messages,
            send_state,
            read_state,
            peer_addr,
            idle_timeout,
            request_timeout,
            read_timeout,
        } = self.get_mut();
        let peer = *peer_addr;
        let mut socket = Pin::new(socket);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        // TODO: it might be interesting to try and split the sending and receiving futures.
        loop {
            // in the case we are sending, send it all?
            if send_state.is_some() {
                // sending...
                match send_state {
                    Some(WriteTcpState::LenBytes { pos, length, bytes }) => {
                        let Poll::Ready(result) = socket.as_mut().poll_write_vectored(
                            cx,
                            &[IoSlice::new(&length[*pos..]), IoSlice::new(bytes)],
                        ) else {
                            return poll_existing_timeout(read_timeout, cx);
                        };
                        *pos += result?;
                    }
                    Some(WriteTcpState::Bytes { pos, bytes }) => {
                        let Poll::Ready(result) = socket.as_mut().poll_write(cx, &bytes[*pos..])
                        else {
                            return poll_existing_timeout(read_timeout, cx);
                        };
                        *pos += result?;
                    }
                    Some(WriteTcpState::Flushing) => {
                        let Poll::Ready(result) = socket.as_mut().poll_flush(cx) else {
                            return poll_existing_timeout(read_timeout, cx);
                        };
                        result?;
                    }
                    _ => (),
                }

                // get current state
                let current_state = send_state.take();

                // switch states
                match current_state {
                    Some(WriteTcpState::LenBytes { pos, length, bytes }) => {
                        if pos < length.len() {
                            *send_state = Some(WriteTcpState::LenBytes { pos, length, bytes });
                        } else if pos < length.len() + bytes.len() {
                            *send_state = Some(WriteTcpState::Bytes {
                                pos: pos - length.len(),
                                bytes,
                            });
                        } else {
                            *send_state = Some(WriteTcpState::Flushing);
                        }
                    }
                    Some(WriteTcpState::Bytes { pos, bytes }) => {
                        if pos < bytes.len() {
                            *send_state = Some(WriteTcpState::Bytes { pos, bytes });
                        } else {
                            // At this point we successfully delivered the entire message.
                            //  flush
                            *send_state = Some(WriteTcpState::Flushing);
                        }
                    }
                    Some(WriteTcpState::Flushing) => {
                        // At this point we successfully delivered the entire message.
                        send_state.take();
                    }
                    None => (),
                };
            } else {
                // then see if there is more to send
                match outbound_messages.as_mut().poll_next(cx)
                    // .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
                {
                    // already handled above, here to make sure the poll() pops the next message
                    Poll::Ready(Some(message)) => {
                        // if there is no peer, this connection should die...
                        let (buffer, dst) = message.into();

                        // This is an error if the destination is not our peer (this is TCP after all)
                        //  This will kill the connection...
                        if peer != dst {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("mismatched peer: {peer} and dst: {dst}"),
                            ))));
                        }

                        // will return if the socket will block
                        // the length is 16 bits
                        let Ok(len) = u16::try_from(buffer.len()) else {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "message of {} bytes does not fit the 16-bit TCP length prefix",
                                    buffer.len()
                                ),
                            ))));
                        };
                        let len = len.to_be_bytes();

                        debug!("sending message len: {} to: {}", buffer.len(), dst);
                        *send_state = Some(WriteTcpState::LenBytes {
                            pos: 0,
                            length: len,
                            bytes: buffer,
                        });
                    }
                    // now we get to drop through to the receives...
                    // TODO: should we also return None if there are no more messages to send?
                    Poll::Pending => break,
                    Poll::Ready(None) => {
                        debug!("no messages to send");
                        break;
                    }
                }
            }
        }

        let mut ret_buf = None;

        // this will loop while there is data to read, or the data has been read, or an IO
        //  event would block
        while ret_buf.is_none() {
            // Evaluates the next state. If None is the result, then no state change occurs,
            //  if Some(_) is returned, then that will be used as the next state.
            let new_state: Option<ReadTcpState> = match read_state {
                ReadTcpState::LenBytes { pos, bytes } => {
                    // debug!("reading length {}", bytes.len());
                    let Poll::Ready(result) = socket.as_mut().poll_read(cx, &mut bytes[*pos..])
                    else {
                        break;
                    };
                    let read = match result {
                        Ok(read) => read,
                        Err(err) => {
                            *read_timeout = None;
                            return Poll::Ready(Some(Err(err)));
                        }
                    };
                    if read == 0 {
                        // the Stream was closed!
                        debug!("zero bytes read, stream closed?");
                        *read_timeout = None;

                        if *pos == 0 {
                            // Since this is the start of the next message, we have a clean end
                            return Poll::Ready(None);
                        } else {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "closed while reading length",
                            ))));
                        }
                    }
                    trace!("in ReadTcpState::LenBytes: {}", pos);
                    *pos += read;

                    if *pos < bytes.len() {
                        trace!("remain ReadTcpState::LenBytes: {}", pos);
                        None
                    } else {
                        let length = u16::from_be_bytes(*bytes);
                        trace!("got length: {}", length);
                        let mut bytes = vec![0; length as usize];
                        bytes.resize(length as usize, 0);

                        trace!("move ReadTcpState::Bytes: {}", bytes.len());
                        Some(ReadTcpState::Bytes { pos: 0, bytes })
                    }
                }
                ReadTcpState::Bytes { pos, bytes } => {
                    let Poll::Ready(result) = socket.as_mut().poll_read(cx, &mut bytes[*pos..])
                    else {
                        break;
                    };
                    let read = match result {
                        Ok(read) => read,
                        Err(err) => {
                            *read_timeout = None;
                            return Poll::Ready(Some(Err(err)));
                        }
                    };
                    if read == 0 {
                        // the Stream was closed!
                        trace!("zero bytes read for message, stream closed?");
                        *read_timeout = None;

                        // Since this is the start of the next message, we have a clean end
                        // try!(self.socket.shutdown(Shutdown::Both));  // TODO: add generic shutdown function
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "closed while reading message",
                        ))));
                    }

                    trace!("in ReadTcpState::Bytes: {}", bytes.len());
                    *pos += read;

                    if *pos < bytes.len() {
                        trace!("remain ReadTcpState::Bytes: {}", bytes.len());
                        None
                    } else {
                        trace!("reset ReadTcpState::LenBytes: {}", 0);
                        Some(ReadTcpState::LenBytes {
                            pos: 0,
                            bytes: [0u8; 2],
                        })
                    }
                }
            };

            // this will move to the next state,
            //  if it was a completed receipt of bytes, then it will move out the bytes
            if let Some(state) = new_state {
                if let ReadTcpState::Bytes { pos, bytes } = mem::replace(read_state, state) {
                    assert_eq!(pos, bytes.len());
                    ret_buf = Some(bytes);
                }
            }
        }

        // if the buffer is ready, return it, if not we're Pending
        if let Some(buffer) = ret_buf {
            *read_timeout = None;
            Poll::Ready(Some(Ok(SerialMessage::new(buffer, peer))))
        } else {
            debug!("bottomed out");
            let phase = read_state.phase();
            if read_timeout
                .as_ref()
                .is_none_or(|active| active.phase != phase)
            {
                let duration = match phase {
                    ReadPhase::Idle => *idle_timeout,
                    ReadPhase::Request => *request_timeout,
                };
                *read_timeout = duration.map(|duration| ReadTimeout {
                    phase,
                    duration,
                    timer: S::Time::delay_for(duration),
                });
            }

            poll_existing_timeout(read_timeout, cx)
        }
    }
}

fn poll_existing_timeout(
    read_timeout: &mut Option<ReadTimeout>,
    cx: &mut Context<'_>,
) -> Poll<Option<io::Result<SerialMessage>>> {
    let Some(active) = read_timeout.as_mut() else {
        return Poll::Pending;
    };

    match active.timer.as_mut().poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(()) => {
            let phase = active.phase;
            let duration = active.duration;
            *read_timeout = None;
            debug!(?phase, ?duration, "timeout on TCP stream");
            Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{phase:?} timeout elapsed after {duration:?}"),
            ))))
        }
    }
}

struct ReadTimeout {
    phase: ReadPhase,
    duration: Duration,
    timer: Pin<Box<dyn Future<Output = ()> + Send>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadPhase {
    Idle,
    Request,
}

impl ReadTcpState {
    fn phase(&self) -> ReadPhase {
        match self {
            Self::LenBytes { pos: 0, .. } => ReadPhase::Idle,
            Self::LenBytes { .. } | Self::Bytes { .. } => ReadPhase::Request,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use core::time::Duration;
    use std::io;
    use std::sync::Arc;

    use futures_util::StreamExt;
    use test_support::subscribe;
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio::sync::Barrier;
    use tokio::time::sleep;

    use super::TcpStream;
    use crate::proto::op::SerialMessage;
    use crate::runtime::iocompat::AsyncIoTokioAsStd;
    use crate::runtime::{RuntimeProvider, TokioRuntimeProvider};
    use crate::tcp::tests::tcp_stream_test;
    use crate::xfer::dns_handle::DnsStreamHandle;

    #[tokio::test]
    async fn test_tcp_stream_ipv4() {
        subscribe();
        tcp_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), TokioRuntimeProvider::new()).await;
    }

    #[tokio::test]
    async fn test_tcp_stream_ipv6() {
        subscribe();
        tcp_stream_test(IpAddr::V6(Ipv6Addr::LOCALHOST), TokioRuntimeProvider::new()).await;
    }

    #[tokio::test]
    async fn test_tcp_stream_rejects_oversized_message() {
        subscribe();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = listener.local_addr().unwrap();

        let tcp = TokioRuntimeProvider::new()
            .connect_tcp(server_addr, None, None)
            .await
            .unwrap();
        let (_server, _) = listener.accept().unwrap();
        let (mut stream, mut sender) = TcpStream::from_stream(tcp, server_addr);

        // 65536 bytes would wrap to a length prefix of 0
        let oversized = vec![0; usize::from(u16::MAX) + 1];
        sender
            .send(SerialMessage::new(oversized, server_addr))
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("oversized message was written instead of rejected");
        let Some(Err(error)) = result else {
            panic!("expected an error for the oversized message");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test(start_paused = true)]
    async fn test_tcp_stream_no_timeout() {
        subscribe();

        for timeout in [Some(Duration::from_secs(360)), None] {
            let (mut client, server) = duplex(64);
            let (stream, _sender) =
                TcpStream::from_stream(AsyncIoTokioAsStd(server), test_peer_addr());
            let mut stream = stream
                .with_idle_timeout(timeout)
                .with_request_timeout(timeout);

            client.write_all(&[0, 2, 0xaa, 0xbb]).await.unwrap();
            client.write_all(&[0, 1, 0xcc]).await.unwrap();
            drop(client);

            let first = stream.next().await.unwrap().unwrap();
            assert_eq!(first.bytes(), &[0xaa, 0xbb]);

            let second = stream.next().await.unwrap().unwrap();
            assert_eq!(second.bytes(), &[0xcc]);

            assert!(stream.next().await.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_tcp_stream_idle_timeout() {
        subscribe();

        let (_client, server) = duplex(64);
        let (stream, _sender) = TcpStream::from_stream(AsyncIoTokioAsStd(server), test_peer_addr());
        let mut stream = stream
            .with_idle_timeout(Some(Duration::from_secs(1)))
            .with_request_timeout(Some(Duration::from_secs(5)));

        let Some(Err(err)) = stream.next().await else {
            panic!("expected timeout error");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn test_tcp_stream_request_timeout_after_idle() {
        subscribe();

        let (mut client, server) = duplex(64);
        let (stream, _sender) = TcpStream::from_stream(AsyncIoTokioAsStd(server), test_peer_addr());
        let mut stream = stream
            .with_idle_timeout(Some(Duration::from_secs(1)))
            .with_request_timeout(Some(Duration::from_secs(1)));

        let send_task = tokio::spawn(async move {
            // Wait 800ms while idle (< 1s idle_timeout), then begin the frame.
            sleep(Duration::from_millis(800)).await;
            client.write_all(&[0, 4]).await.unwrap();

            // Finish the frame 500ms later (total 1.3s > idle_timeout, but 500ms < request_timeout).
            sleep(Duration::from_millis(500)).await;
            client.write_all(&[1, 2, 3, 4]).await.unwrap();

            // Start a second frame and stall past request_timeout.
            sleep(Duration::from_millis(200)).await;
            client.write_all(&[0]).await.unwrap();
            sleep(Duration::from_secs(2)).await;
            client
        });

        let msg = stream.next().await.unwrap().unwrap();
        assert_eq!(msg.bytes(), &[1, 2, 3, 4]);

        let Some(Err(err)) = stream.next().await else {
            panic!("expected timeout error");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        send_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn test_tcp_stream_slowloris_drip() {
        subscribe();

        let (mut client, server) = duplex(64);
        let (stream, _sender) = TcpStream::from_stream(AsyncIoTokioAsStd(server), test_peer_addr());
        let mut stream = stream
            .with_idle_timeout(None)
            .with_request_timeout(Some(Duration::from_secs(1)));

        let send_task = tokio::spawn(async move {
            // Drip-feed 1 byte every 400ms; total 6 bytes would take 2.0s > 1s request_timeout.
            for byte in [0, 4, 1, 2, 3, 4] {
                client.write_all(&[byte]).await.unwrap();
                sleep(Duration::from_millis(400)).await;
            }
        });

        let Some(Err(err)) = stream.next().await else {
            panic!("expected timeout error");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        send_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn test_tcp_stream_delay_between_polls() {
        subscribe();

        let (mut client, server) = duplex(64);
        let (stream, _sender) = TcpStream::from_stream(AsyncIoTokioAsStd(server), test_peer_addr());
        let mut stream = stream
            .with_idle_timeout(Some(Duration::from_secs(1)))
            .with_request_timeout(Some(Duration::from_secs(1)));

        let barrier = Arc::new(Barrier::new(2));
        let send_task = tokio::spawn({
            let barrier = barrier.clone();
            async move {
                for byte in [1u8, 2] {
                    sleep(Duration::from_millis(500)).await;
                    client.write_all(&[0, 1, byte]).await.unwrap();
                    barrier.wait().await;
                }
            }
        });

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.bytes(), &[1]);

        // Simulate slow request handling before polling for the next message.
        sleep(Duration::from_secs(2)).await;
        barrier.wait().await;

        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.bytes(), &[2]);

        barrier.wait().await;
        send_task.await.unwrap();
    }

    fn test_peer_addr() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53))
    }
}
