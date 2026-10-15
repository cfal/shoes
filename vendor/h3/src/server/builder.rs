//! Builder of HTTP/3 server connections.
//!
//! Use this struct to create a new [`Connection`].
//! Settings for the [`Connection`] can be provided here.
//!
//! # Example
//!
//! ```rust
//! fn doc<C,B>(conn: C)
//! where
//! C: h3::quic::Connection<B>,
//! B: bytes::Buf,
//! {
//!     let mut server_builder = h3::server::builder();
//!     // Set the maximum header size
//!     server_builder.max_field_section_size(1000);
//!     // do not send grease types
//!     server_builder.send_grease(false);
//!     // Build the Connection
//!     let mut h3_conn = server_builder.build(conn);
//! }
//! ```

use std::{collections::HashSet, result::Result, sync::Arc};

use bytes::Buf;

use tokio::sync::mpsc;

use crate::{
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    quic::{self},
    shared_state::SharedState,
};

use super::connection::Connection;

/// Create a builder of HTTP/3 server connections
///
/// This function creates a [`Builder`] that carries settings that can
/// be shared between server connections.
pub fn builder() -> Builder {
    Builder::new()
}

/// Builder of HTTP/3 server connections.
pub struct Builder {
    pub(crate) config: Config,
}

impl Builder {
    /// Creates a new [`Builder`] with default settings.
    pub(super) fn new() -> Self {
        Builder {
            config: Default::default(),
        }
    }

    // Not public API, just used in unit tests
    #[doc(hidden)]
    #[cfg(test)]
    pub fn send_settings(&mut self, value: bool) -> &mut Self {
        self.config.send_settings = value;
        self
    }

    /// Set the maximum header size this client is willing to accept
    ///
    /// See [header size constraints] section of the specification for details.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_field_section_size = value;
        self
    }

    /// Send grease values to the Client.
    /// See [setting](https://www.rfc-editor.org/rfc/rfc9114.html#settings-parameters), [frame](https://www.rfc-editor.org/rfc/rfc9114.html#frame-reserved) and [stream](https://www.rfc-editor.org/rfc/rfc9114.html#stream-grease) for more information.
    #[inline]
    pub fn send_grease(&mut self, value: bool) -> &mut Self {
        self.config.send_grease = value;
        self
    }

    /// Indicates to the peer that WebTransport is supported.
    ///
    /// See: [establishing a webtransport session](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1)
    ///
    ///
    /// **Server**:
    /// Supporting for webtransport also requires setting `enable_extended_connect` `enable_datagram`
    /// and `max_webtransport_sessions`.
    #[inline]
    pub fn enable_webtransport(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_webtransport = value;
        self
    }

    /// Enables the extended CONNECT protocol required for various HTTP/3 extensions.
    pub fn enable_extended_connect(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_extended_connect = value;
        self
    }

    /// Limits the maximum number of WebTransport sessions
    pub fn max_webtransport_sessions(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_webtransport_sessions = value;
        self
    }

    /// Indicates that the client or server supports HTTP/3 datagrams
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1>
    pub fn enable_datagram(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_datagram = value;
        self
    }
}

impl Builder {
    /// Build an HTTP/3 connection from a QUIC connection
    ///
    /// This method creates a [`Connection`] instance with the settings in the [`Builder`].
    pub async fn build<C, B>(&self, conn: C) -> Result<Connection<C, B>, ConnectionError>
    where
        C: quic::Connection<B>,
        B: Buf,
    {
        let (sender, receiver) = mpsc::unbounded_channel();
        let shared = SharedState::default();

        Ok(Connection {
            inner: ConnectionInner::new(conn, Arc::new(shared), self.config).await?,
            max_field_section_size: self.config.settings.max_field_section_size,
            request_end_send: sender,
            request_end_recv: receiver,
            ongoing_streams: HashSet::new(),
            sent_closing: None,
            recv_closing: None,
            last_accepted_stream: None,
        })
    }
}
