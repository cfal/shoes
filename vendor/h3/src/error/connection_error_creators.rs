//! functions to create the error structs

use std::task::Poll;

use bytes::Buf;

use crate::{
    connection::ConnectionInner,
    frame::FrameStreamError,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming},
    shared_state::ConnectionState,
};

use super::{
    codes::Code,
    internal_error::{ErrorOrigin, InternalConnectionError},
    ConnectionError, LocalError, StreamError,
};

/// This trait is implemented for all types which can close the connection
impl<C, B> ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Handle errors on the connection, closes the connection if needed
    ///
    /// This can be a [`ConnectionErrorIncoming`] or a [`InternalConnectionError`]
    pub fn handle_connection_error<T: Into<ErrorOrigin>>(&mut self, error: T) -> ConnectionError {
        if let Some(ref error) = self.handled_connection_error {
            return error.clone();
        }

        let err = self.set_conn_error(error.into());
        let err = self.close_if_needed(err);
        // err might be a different error so match again
        self.convert_to_connection_error(err)
    }

    /// Closes the connection if needed
    /// Check self.handled_connection_error before calling this function
    fn close_if_needed(&mut self, error: ErrorOrigin) -> ErrorOrigin {
        match error {
            ErrorOrigin::Internal(ref internal_error) => {
                self.close_connection(internal_error.code, internal_error.message.clone())
            }
            ErrorOrigin::Quic(ConnectionErrorIncoming::InternalError(ref reason)) => {
                self.close_connection(Code::H3_INTERNAL_ERROR, reason.clone())
            }

            // All other path do not need to close the connection
            _ => (),
        }
        error
    }

    /// Converts a [`ErrorOrigin`] into a [`ConnectionError`] and sets self.handled_connection_error
    ///
    /// Check close the connection if needed before calling this function
    fn convert_to_connection_error(&mut self, error: ErrorOrigin) -> ConnectionError {
        let error = convert_to_connection_error(error);
        self.handled_connection_error = Some(error.clone());
        error
    }

    /// Polls for the connection error
    ///
    /// Returns an Result to allow using ? in the calling function
    pub fn poll_connection_error(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), ConnectionError>> {
        if let Some(ref error) = self.handled_connection_error {
            return Poll::Ready(Err(error.clone()));
        };

        // Check if the connection is in error state
        if let Some(err) = self.get_conn_error() {
            let err = self.close_if_needed(err);
            // err might be a different error so match again
            return Poll::Ready(Err(self.convert_to_connection_error(err)));
        }
        self.waker().register(cx.waker());
        Poll::Pending
    }

    /// Close the connection
    pub fn close_connection(&mut self, code: Code, reason: String) -> () {
        self.conn.close(code, reason.as_bytes())
    }
}

/// Converts a [`ErrorOrigin`] into a [`ConnectionError`] and sets self.handled_connection_error
fn convert_to_connection_error(error: ErrorOrigin) -> ConnectionError {
    match error {
        ErrorOrigin::Internal(internal_error) => ConnectionError::Local {
            error: LocalError::Application {
                code: internal_error.code,
                reason: internal_error.message,
            },
        },
        ErrorOrigin::Quic(ConnectionErrorIncoming::Timeout) => ConnectionError::Timeout,
        ErrorOrigin::Quic(connection_error) => ConnectionError::Remote(connection_error),
    }
}

/// This trait is implemented for all types which can close a stream
pub trait CloseStream: ConnectionState {
    /// Handles a connection error on a stream
    fn handle_connection_error_on_stream(
        &mut self,
        internal_error: InternalConnectionError,
    ) -> StreamError {
        let err = self.set_conn_error_and_wake(internal_error);
        StreamError::ConnectionError(convert_to_connection_error(err))
    }

    /// Handles a incoming stream error from the quic layer
    fn handle_quic_stream_error(&self, error: StreamErrorIncoming) -> StreamError {
        match error {
            StreamErrorIncoming::ConnectionErrorIncoming { connection_error } => {
                let err = self.set_conn_error_and_wake(connection_error);
                StreamError::ConnectionError(convert_to_connection_error(err))
            }
            StreamErrorIncoming::StreamTerminated { error_code } => StreamError::RemoteTerminate {
                code: Code::from(error_code),
            },
            StreamErrorIncoming::Unknown(custom_quic_impl_error) => {
                StreamError::Undefined(custom_quic_impl_error)
            }
        }
    }

    /// Checks if the peer connection is closing an if it is allowed to send a request / server push
    fn check_peer_connection_closing(&self) -> Option<StreamError> {
        if self.is_closing() {
            return Some(StreamError::RemoteClosing);
        };
        None
    }
}

pub(crate) trait CloseRawQuicConnection<B: Buf>: quic::Connection<B> {
    // Should only be used when there is no h3 connection created
    fn handle_quic_error_raw(&mut self, error: ConnectionErrorIncoming) -> ConnectionError {
        match error {
            ConnectionErrorIncoming::Timeout => ConnectionError::Timeout,
            ConnectionErrorIncoming::InternalError(reason) => {
                let local_error = LocalError::Application {
                    code: Code::H3_INTERNAL_ERROR,
                    reason: reason.to_string(),
                };
                self.close(Code::H3_INTERNAL_ERROR, reason.as_bytes());
                let conn_error = ConnectionError::Local { error: local_error };
                conn_error
            }
            _ => ConnectionError::Remote(error),
        }
    }

    // Should only be used when there is no h3 connection created
    fn close_raw_connection_with_h3_error(
        &mut self,
        internal_error: InternalConnectionError,
    ) -> ConnectionError {
        let error = ConnectionError::Local {
            error: internal_error.clone().into(),
        };
        self.close(internal_error.code, internal_error.message.as_bytes());
        error
    }
}

impl<T, B> CloseRawQuicConnection<B> for T
where
    T: quic::Connection<B>,
    B: Buf,
{
}

pub(crate) trait HandleFrameStreamErrorOnRequestStream {
    fn handle_frame_stream_error_on_request_stream(
        &mut self,
        error: FrameStreamError,
    ) -> StreamError;
}

impl<T> HandleFrameStreamErrorOnRequestStream for T
where
    T: CloseStream,
{
    fn handle_frame_stream_error_on_request_stream(
        &mut self,
        error: FrameStreamError,
    ) -> StreamError {
        match error {
            FrameStreamError::Quic(error) => self.handle_quic_stream_error(error),
            FrameStreamError::Proto(frame_error) => self.handle_connection_error_on_stream(
                InternalConnectionError::got_frame_error(frame_error).into(),
            ),
            FrameStreamError::UnexpectedEnd => {
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_FRAME_ERROR,
                    "received incomplete frame".to_string(),
                ))
            }
        }
    }
}
