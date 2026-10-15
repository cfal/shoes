//! QUIC Transport traits
//!
//! This module includes traits and types meant to allow being generic over any
//! QUIC implementation.

use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::task::{self, Poll};

use bytes::Buf;

use crate::error::Code;
pub use crate::proto::stream::{InvalidStreamId, StreamId};
pub use crate::stream::WriteBuf;

/// Error type to communicate that the quic connection was closed
///
/// This is used by to implement the quic abstraction traits
#[derive(Clone)]
pub enum ConnectionErrorIncoming {
    /// Error from the http3 layer
    ApplicationClose {
        /// http3 error code
        error_code: u64,
    },
    /// Quic connection timeout
    Timeout,
    /// This variant can be used to signal, that an internal error occurred within the trait implementations
    /// h3 will close the connection with H3_INTERNAL_ERROR
    InternalError(String),
    /// A unknown error occurred (not relevant to h3)
    ///
    /// For example when the quic implementation errors because of a protocol violation
    Undefined(Arc<dyn std::error::Error + Send + Sync>),
}

// Manual Debug implementation to display the right h3 error string for the error code like H3_NO_ERROR instead of a number
impl Debug for ConnectionErrorIncoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApplicationClose { error_code } => {
                let error_code = Code::from(*error_code);
                write!(f, "ApplicationClose({})", error_code)
            }
            Self::Timeout => write!(f, "Timeout"),
            Self::InternalError(arg0) => f.debug_tuple("InternalError").field(arg0).finish(),
            Self::Undefined(arg0) => f.debug_tuple("Undefined").field(arg0).finish(),
        }
    }
}

/// Error type to communicate that the stream was closed
///
/// This is used by to implement the quic abstraction traits
/// When an error within the quic trait implementation occurs, use ConnectionErrorIncoming variant with InternalError
#[derive(Debug)]
pub enum StreamErrorIncoming {
    /// Stream is closed because the whole connection is closed
    ConnectionErrorIncoming {
        /// Connection error
        connection_error: ConnectionErrorIncoming,
    },
    /// Stream side was closed by the peer
    ///
    /// This can mean a reset for peers sending side or a stop_sending for peers receiving side
    StreamTerminated {
        /// Error code sent by the peer
        error_code: u64,
    },
    /// A unknown error occurred (not relevant to h3)
    ///
    /// H3 will handle this exactly like a StreamTerminated
    /// like closing the connection with an error if http3 forbids a stream end for example with the control stream
    Unknown(Box<dyn std::error::Error + Send + Sync>),
}

impl std::error::Error for StreamErrorIncoming {}

impl Display for StreamErrorIncoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // display enum with fields
        match self {
            StreamErrorIncoming::ConnectionErrorIncoming { connection_error } => {
                write!(f, "ConnectionError: {}", connection_error)
            }
            StreamErrorIncoming::StreamTerminated { error_code } => {
                let error_code = Code::from(*error_code);
                write!(f, "StreamClosed: {}", error_code)
            }
            StreamErrorIncoming::Unknown(error) => write!(f, "Error undefined by h3: {}", error),
        }
    }
}

impl Display for ConnectionErrorIncoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // display enum with fields
        match self {
            ConnectionErrorIncoming::ApplicationClose { error_code } => {
                let error_code = Code::from(*error_code);
                write!(f, "ApplicationClose: {}", error_code)
            }
            ConnectionErrorIncoming::Timeout => write!(f, "Timeout"),
            ConnectionErrorIncoming::InternalError(error) => {
                write!(
                    f,
                    "InternalError in the quic trait implementation: {}",
                    error
                )
            }
            ConnectionErrorIncoming::Undefined(error) => {
                write!(f, "Error undefined by h3: {}", error)
            }
        }
    }
}

impl std::error::Error for ConnectionErrorIncoming {}

/// Trait representing a QUIC connection.
pub trait Connection<B: Buf>: OpenStreams<B> {
    /// The type produced by `poll_accept_recv()`
    type RecvStream: RecvStream;
    /// A producer of outgoing Unidirectional and Bidirectional streams.
    type OpenStreams: OpenStreams<B, SendStream = Self::SendStream, BidiStream = Self::BidiStream>;

    /// Accept an incoming unidirectional stream
    ///
    /// Returning `None` implies the connection is closing or closed.
    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>>;

    /// Accept an incoming bidirectional stream
    ///
    /// Returning `None` implies the connection is closing or closed.
    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>>;

    /// Get an object to open outgoing streams.
    fn opener(&self) -> Self::OpenStreams;
}

/// Trait for opening outgoing streams
pub trait OpenStreams<B: Buf> {
    /// The type produced by `poll_open_bidi()`
    type BidiStream: SendStream<B> + RecvStream;
    /// The type produced by `poll_open_send()`
    type SendStream: SendStream<B>;

    /// Poll the connection to create a new bidirectional stream.
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>>;

    /// Poll the connection to create a new unidirectional stream.
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>>;

    /// Close the connection immediately
    fn close(&mut self, code: crate::error::Code, reason: &[u8]);
}

/// A trait describing the "send" actions of a QUIC stream.
pub trait SendStream<B: Buf> {
    /// Polls if the stream can send more data.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>>;

    /// Send more data on the stream.
    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming>;

    /// Poll to finish the sending side of the stream.
    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>>;

    /// Send a QUIC reset code.
    fn reset(&mut self, reset_code: u64);

    /// Get QUIC send stream id
    fn send_id(&self) -> StreamId;
}

/// Allows sending unframed pure bytes to a stream. Similar to [`AsyncWrite`](https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html)
pub trait SendStreamUnframed<B: Buf>: SendStream<B> {
    /// Attempts to write data into the stream.
    ///
    /// Returns the number of bytes written.
    ///
    /// `buf` is advanced by the number of bytes written.
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>>;
}

/// A trait describing the "receive" actions of a QUIC stream.
pub trait RecvStream {
    /// The type of `Buf` for data received on this stream.
    type Buf: Buf;

    /// Poll the stream for more data.
    ///
    /// When the receiving side will no longer receive more data (such as because
    /// the peer closed their sending side), this should return `None`.
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>>;

    /// Send a `STOP_SENDING` QUIC code.
    fn stop_sending(&mut self, error_code: u64);

    /// Get QUIC send stream id
    fn recv_id(&self) -> StreamId;
}

/// Optional trait to allow "splitting" a bidirectional stream into two sides.
pub trait BidiStream<B: Buf>: SendStream<B> + RecvStream {
    /// The type for the send half.
    type SendStream: SendStream<B>;
    /// The type for the receive half.
    type RecvStream: RecvStream;

    /// Split this stream into two halves.
    fn split(self) -> (Self::SendStream, Self::RecvStream);
}
