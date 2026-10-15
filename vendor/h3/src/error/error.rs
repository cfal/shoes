//! This is the public facing error types for the h3 crate
use crate::quic::ConnectionErrorIncoming;

use super::{codes::Code, internal_error::InternalConnectionError};

/// This enum represents the closure of a connection because of an a closed quic connection
/// This can be either from this endpoint because of a violation of the protocol or from the remote endpoint
///
/// When the code [`Code::H3_NO_ERROR`] is used bei this peer or the remote peer, the connection is closed without an error
/// according to the [h3 spec](https://www.rfc-editor.org/rfc/rfc9114.html#name-http-3-error-codes)
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The error occurred on the local side of the connection
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    Local {
        /// The error
        error: LocalError,
    },
    /// Error returned by the quic layer
    /// I might be an quic error or the remote h3 connection closed the connection with an error
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    Remote(ConnectionErrorIncoming),
    /// Timeout occurred
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    Timeout,
}

impl ConnectionError {
    /// Returns if the error is H3_NO_ERROR local or remote
    pub fn is_h3_no_error(&self) -> bool {
        match self {
            ConnectionError::Local {
                error:
                    LocalError::Application {
                        code: Code::H3_NO_ERROR,
                        ..
                    },
            } => true,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code })
                if *error_code == Code::H3_NO_ERROR.value() =>
            {
                true
            }
            _ => false,
        }
    }
}

/// This enum represents a local error
#[derive(Debug, Clone, Hash)]
#[non_exhaustive]
pub enum LocalError {
    #[non_exhaustive]
    /// The application closed the connection
    Application {
        /// The error code
        code: Code,
        /// The error reason
        reason: String,
    },
    #[non_exhaustive]
    /// Graceful closing of the connection initiated by the local peer
    Closing,
}

/// This enum represents a stream error
#[derive(Debug)]
#[non_exhaustive]
pub enum StreamError {
    /// The error occurred on the stream
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    StreamError {
        /// The error code
        code: Code,
        /// The error reason
        reason: String,
    },
    /// The remote peer terminated the corresponding stream side
    ///
    /// Either Reset on peers sending side or StopSending on peers receiving side
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    RemoteTerminate {
        /// Reset code received from the peer
        code: Code,
    },
    /// The error occurred on the connection
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    ConnectionError(ConnectionError),
    /// Error is used when violating the MAX_FIELD_SECTION_SIZE
    ///
    /// This can mean different things depending on the context
    /// When sending a request, this means, that the request cannot be sent because the header is larger then permitted by the server
    /// When receiving a request, this means, that the server sent a
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    HeaderTooBig {
        /// The actual size of the header block
        actual_size: u64,
        /// The maximum size of the header block
        max_size: u64,
    },
    /// Received a GoAway frame from the remote
    ///
    /// Stream operations cannot be performed
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    RemoteClosing,
    /// Undefined error propagated by the quic layer
    #[cfg_attr(
        not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"),
        non_exhaustive
    )]
    Undefined(Box<dyn std::error::Error + Send + Sync>),
}

impl StreamError {
    /// Returns if the error is H3_NO_ERROR
    pub fn is_h3_no_error(&self) -> bool {
        match self {
            StreamError::StreamError {
                code: Code::H3_NO_ERROR,
                ..
            } => true,
            StreamError::ConnectionError(conn_error) => conn_error.is_h3_no_error(),
            _ => false,
        }
    }
}

impl From<InternalConnectionError> for LocalError {
    fn from(err: InternalConnectionError) -> Self {
        LocalError::Application {
            code: err.code,
            reason: err.message,
        }
    }
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Local { error } => write!(f, "Local error: {:?}", error),
            ConnectionError::Remote(err) => write!(f, "Remote error: {}", err),
            ConnectionError::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::StreamError { code, reason } => {
                write!(f, "Stream error: {:?} - {}", code, reason)
            }
            StreamError::ConnectionError(err) => write!(f, "Connection error: {}", err),
            StreamError::RemoteTerminate { code } => write!(f, "Remote reset: {}", code),
            StreamError::HeaderTooBig {
                actual_size,
                max_size,
            } => write!(
                f,
                "Header too big: actual size: {}, max size: {}",
                actual_size, max_size
            ),
            StreamError::Undefined(err) => write!(f, "Undefined error: {}", err),
            StreamError::RemoteClosing => write!(f, "Remote is closing the connection"),
        }
    }
}

impl std::error::Error for StreamError {}
