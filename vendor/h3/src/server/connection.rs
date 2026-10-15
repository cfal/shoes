//! HTTP/3 server connection
//!
//! The [`Connection`] struct manages a connection from the side of the HTTP/3 server

use std::{
    collections::HashSet,
    future::poll_fn,
    option::Option,
    result::Result,
    task::{ready, Context, Poll},
};

use bytes::Buf;
use quic::RecvStream;
use quic::StreamId;
use tokio::sync::mpsc;

use crate::{
    connection::ConnectionInner,
    error::{internal_error::InternalConnectionError, Code, ConnectionError},
    frame::FrameStream,
    proto::{
        frame::{Frame, PayloadLen},
        push::PushId,
    },
    quic::{self, SendStream as _},
    shared_state::{ConnectionState, SharedState},
    stream::BufRecvStream,
};

#[cfg(feature = "tracing")]
use tracing::{instrument, trace, warn};

use super::request::RequestResolver;

/// Server connection driver
///
/// The [`Connection`] struct manages a connection from the side of the HTTP/3 server
///
/// Create a new Instance with [`Connection::new()`].
/// Accept incoming requests with [`Connection::accept()`].
/// And shutdown a connection with [`Connection::shutdown()`].
pub struct Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// TODO: temporarily break encapsulation for `WebTransportSession`
    pub inner: ConnectionInner<C, B>,
    pub(super) max_field_section_size: u64,
    // List of all incoming streams that are currently running.
    pub(super) ongoing_streams: HashSet<StreamId>,
    // Let the streams tell us when they are no longer running.
    pub(super) request_end_recv: mpsc::UnboundedReceiver<StreamId>,
    pub(super) request_end_send: mpsc::UnboundedSender<StreamId>,
    // Has a GOAWAY frame been sent? If so, this StreamId is the last we are willing to accept.
    pub(super) sent_closing: Option<StreamId>,
    // Has a GOAWAY frame been received? If so, this is PushId the last the remote will accept.
    pub(super) recv_closing: Option<PushId>,
    // The id of the last stream received by this connection.
    pub(super) last_accepted_stream: Option<StreamId>,
}

impl<C, B> ConnectionState for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.inner.shared
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Create a new HTTP/3 server connection with default settings
    ///
    /// Use a custom [`super::builder::Builder`] with [`super::builder::builder()`] to create a connection
    /// with different settings.
    /// Provide a Connection which implements [`quic::Connection`].
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn new(conn: C) -> Result<Self, ConnectionError> {
        super::builder::builder().build(conn).await
    }
}

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
/// Impls for extension implementation which are not stable
impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
    /// Create a [`RequestResolver`] to handle an incoming request.
    pub fn create_resolver(&self, stream: FrameStream<C::BidiStream, B>) -> RequestResolver<C, B> {
        self.create_resolver_internal(stream)
    }

    /// Polls the Connection and accepts an incoming request_streams
    #[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
    pub fn poll_accept_request_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<C::BidiStream>, ConnectionError>> {
        self.poll_accept_request_stream_internal(cx)
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Accept an incoming request.
    ///
    /// This method returns a [`RequestResolver`] which can be used to read the request and send the response.
    /// This method will return `None` when the connection receives a GOAWAY frame and all requests have been completed.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn accept(&mut self) -> Result<Option<RequestResolver<C, B>>, ConnectionError> {
        // Accept the incoming stream
        let stream = match poll_fn(|cx| self.poll_accept_request_stream_internal(cx)).await? {
            Some(s) => FrameStream::new(BufRecvStream::new(s)),
            None => {
                // We always send a last GoAway frame to the client, so it knows which was the last
                // non-rejected request.
                self.shutdown(0).await?;
                return Ok(None);
            }
        };

        let resolver = self.create_resolver_internal(stream);

        // send the grease frame only once
        self.inner.send_grease_frame = false;

        Ok(Some(resolver))
    }

    fn create_resolver_internal(
        &self,
        stream: FrameStream<C::BidiStream, B>,
    ) -> RequestResolver<C, B> {
        RequestResolver {
            frame_stream: stream,
            request_end_send: self.request_end_send.clone(),
            send_grease_frame: self.inner.send_grease_frame,
            max_field_section_size: self.max_field_section_size,
            shared: self.inner.shared.clone(),
        }
    }

    /// Initiate a graceful shutdown, accepting `max_request` potentially still in-flight
    ///
    /// See [connection shutdown](https://www.rfc-editor.org/rfc/rfc9114.html#connection-shutdown) for more information.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown(&mut self, max_requests: usize) -> Result<(), ConnectionError> {
        let max_id = self
            .last_accepted_stream
            .map(|id| id + max_requests)
            .unwrap_or(StreamId::FIRST_REQUEST);

        self.inner.shutdown(&mut self.sent_closing, max_id).await
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// This could be either a *Request* or a *WebTransportBiStream*, the first frame's type
    /// decides.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_accept_request_stream_internal(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<C::BidiStream>, ConnectionError>> {
        let _ = self.poll_control(cx)?;
        let _ = self.poll_requests_completion(cx);
        loop {
            let conn = self.inner.poll_accept_bi(cx)?;
            return match conn {
                Poll::Pending => {
                    let done = if conn.is_pending() {
                        self.recv_closing.is_some() && self.poll_requests_completion(cx).is_ready()
                    } else {
                        self.poll_requests_completion(cx).is_ready()
                    };

                    if done {
                        Poll::Ready(Ok(None))
                    } else {
                        // Wait for all the requests to be finished, request_end_recv will wake
                        // us on each request completion.
                        Poll::Pending
                    }
                }
                Poll::Ready(mut s) => {
                    // When the connection is in a graceful shutdown procedure, reject all
                    // incoming requests not belonging to the grace interval. It's possible that
                    // some acceptable request streams arrive after rejected requests.
                    if let Some(max_id) = self.sent_closing {
                        if s.send_id() > max_id {
                            s.stop_sending(Code::H3_REQUEST_REJECTED.value());
                            s.reset(Code::H3_REQUEST_REJECTED.value());
                            if self.poll_requests_completion(cx).is_ready() {
                                break Poll::Ready(Ok(None));
                            }
                            continue;
                        }
                    }
                    self.last_accepted_stream = Some(s.send_id());
                    self.ongoing_streams.insert(s.send_id());
                    Poll::Ready(Ok(Some(s)))
                }
            };
        }
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>> {
        while (self.poll_next_control(cx)?).is_ready() {}
        Poll::Pending
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn poll_next_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Frame<PayloadLen>, ConnectionError>> {
        let frame = ready!(self.inner.poll_control(cx))?;

        match &frame {
            Frame::Settings(_setting) => {
                #[cfg(feature = "tracing")]
                trace!("Got settings > {:?}", _setting);
                ()
            }
            &Frame::Goaway(id) => self.inner.process_goaway(&mut self.recv_closing, id)?,
            _frame @ Frame::MaxPushId(_) | _frame @ Frame::CancelPush(_) => {
                #[cfg(feature = "tracing")]
                warn!("Control frame ignored {:?}", _frame);

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                //= type=TODO
                //# If a server receives a CANCEL_PUSH frame for a push
                //# ID that has not yet been mentioned by a PUSH_PROMISE frame, this MUST
                //# be treated as a connection error of type H3_ID_ERROR.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                //= type=TODO
                //# A MAX_PUSH_ID frame cannot reduce the maximum push
                //# ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than
                //# previously received MUST be treated as a connection error of type
                //# H3_ID_ERROR.
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A server MUST treat the
            //# receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            frame => {
                return Poll::Ready(Err(self.inner.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        format!("on server control stream: {:?}", frame),
                    ),
                )));
            }
        }
        Poll::Ready(Ok(frame))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_requests_completion(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            match self.request_end_recv.poll_recv(cx) {
                // The channel is closed
                Poll::Ready(None) => return Poll::Ready(()),
                // A request has completed
                Poll::Ready(Some(id)) => {
                    self.ongoing_streams.remove(&id);
                }
                Poll::Pending => {
                    if self.ongoing_streams.is_empty() {
                        // Tell the caller there is not more ongoing requests.
                        // Still, the completion of future requests will wake us.
                        return Poll::Ready(());
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

impl<C, B> Drop for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn drop(&mut self) {
        self.inner.close_connection(
            Code::H3_NO_ERROR,
            "Connection was closed by the server".to_string(),
        );
    }
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//= type=TODO
//# In order to
//# permit these streams to open, an HTTP/3 server SHOULD configure non-
//# zero minimum values for the number of permitted streams and the
//# initial stream flow-control window.

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//= type=TODO
//# So as to not unnecessarily limit
//# parallelism, at least 100 request streams SHOULD be permitted at a
//# time.

pub(super) struct RequestEnd {
    pub(super) request_end: mpsc::UnboundedSender<StreamId>,
    pub(super) stream_id: StreamId,
}
