use std::{
    convert::TryFrom,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::{future, ready};
use http::HeaderMap;
use stream::WriteBuf;

#[cfg(feature = "tracing")]
use tracing::{instrument, warn};

use crate::{
    config::Config,
    error::{
        connection_error_creators::{
            CloseRawQuicConnection, CloseStream, HandleFrameStreamErrorOnRequestStream,
        },
        internal_error::InternalConnectionError,
        Code, ConnectionError, StreamError,
    },
    frame::{FrameStream, FrameStreamError},
    proto::{
        frame::{self, Frame, PayloadLen},
        headers::Header,
        stream::StreamType,
        varint::VarInt,
    },
    qpack,
    quic::{self, RecvStream, SendStream, StreamErrorIncoming},
    shared_state::{ConnectionState, SharedState},
    stream::{self, AcceptRecvStream, AcceptedRecvStream, BufRecvStream, UniStreamHeader},
    webtransport::SessionId,
};

#[allow(missing_docs)]
pub struct AcceptedStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[allow(missing_docs)]
    pub wt_uni_streams: Vec<(SessionId, BufRecvStream<C::RecvStream, B>)>,
}

impl<B, C> Default for AcceptedStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn default() -> Self {
        Self {
            wt_uni_streams: Default::default(),
        }
    }
}

struct QpackStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    decoder_send: Option<C::SendStream>,
    decoder_recv: Option<AcceptedRecvStream<C::RecvStream, B>>,
    encoder_send: Option<C::SendStream>,
    encoder_recv: Option<AcceptedRecvStream<C::RecvStream, B>>,
}

#[allow(missing_docs)]
pub struct ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    pub shared: Arc<SharedState>,
    /// TODO: breaking encapsulation just to see if we can get this to work, will fix before merging
    pub conn: C,
    control_send: C::SendStream,
    control_recv: Option<FrameStream<C::RecvStream, B>>,
    qpack_streams: QpackStreams<C, B>,
    /// Buffers incoming uni/recv streams which have yet to be claimed.
    ///
    /// This is opposed to discarding them by returning in `poll_accept_recv`, which may cause them to be missed by something else polling.
    ///
    /// See: <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-4.5>
    ///
    /// In WebTransport over HTTP/3, the client MAY send its SETTINGS frame, as well as
    /// multiple WebTransport CONNECT requests, WebTransport data streams and WebTransport
    /// datagrams, all within a single flight. As those can arrive out of order, a WebTransport
    /// server could be put into a situation where it receives a stream or a datagram without a
    /// corresponding session. Similarly, a client may receive a server-initiated stream or a
    /// datagram before receiving the CONNECT response headers from the server.To handle this
    /// case, WebTransport endpoints SHOULD buffer streams and datagrams until those can be
    /// associated with an established session. To avoid resource exhaustion, the endpoints
    /// MUST limit the number of buffered streams and datagrams. When the number of buffered
    /// streams is exceeded, a stream SHALL be closed by sending a RESET_STREAM and/or
    /// STOP_SENDING with the H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED error code. When the
    /// number of buffered datagrams is exceeded, a datagram SHALL be dropped. It is up to an
    /// implementation to choose what stream or datagram to discard.
    accepted_streams: AcceptedStreams<C, B>,
    pending_recv_streams: Vec<Option<AcceptRecvStream<C::RecvStream, B>>>,
    got_peer_settings: bool,
    pub(crate) handled_connection_error: Option<ConnectionError>,
    pub send_grease_frame: bool,
    // tells if the grease steam should be sent
    send_grease_stream_flag: bool,
    // step of the grease sending poll fn
    grease_step: GreaseStatus<C::SendStream, B>,
    pub config: Config,
}

impl<B, C> ConnectionState for ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

enum GreaseStatus<S, B>
where
    S: SendStream<B>,
    B: Buf,
{
    /// Grease stream is not started
    NotStarted(PhantomData<B>),
    /// Grease steam is started without data
    Started(Option<S>),
    /// Grease stream is started with data
    DataPrepared(Option<S>),
    /// Data is sent on grease stream
    DataSent(S),
    /// Grease stream is finished
    Finished,
}

impl<B, C> ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Sends the settings and initializes the control streams
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_control_stream_headers(&mut self) -> Result<(), ConnectionError> {
        #[cfg(test)]
        if !self.config.send_settings {
            return Ok(());
        }

        let settings = frame::Settings::try_from(self.config).map_err(|_err| {
            // TODO: converting a config to settings should never fail
            //       it should be impossible to construct a config which cannot be represented as settings
            self.handle_connection_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "error when creating settings frame".to_string(),
            ))
        })?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Sending server settings: {:#x?}", settings);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
        //# After the QUIC connection is
        //# established, a SETTINGS frame MUST be sent by each endpoint as the
        //# initial frame of their respective HTTP control stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Each side MUST initiate a single control stream at the beginning of
        //# the connection and send its SETTINGS frame as the first frame on this
        //# stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //# A SETTINGS frame MUST be sent as the first frame of
        //# each control stream (see Section 6.2.1) by each peer, and it MUST NOT
        //# be sent subsequently.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //= type=implication
        //# SETTINGS frames MUST NOT be sent on any stream other than the control
        //# stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //= type=implication
        //# Endpoints MUST NOT require any data to be received from
        //# the peer prior to sending the SETTINGS frame; settings MUST be sent
        //# as soon as the transport is ready to send data.

        let mut decoder_send = Option::take(&mut self.qpack_streams.decoder_send);
        let mut encoder_send = Option::take(&mut self.qpack_streams.encoder_send);

        let (control, ..) = future::join3(
            stream::write(
                &mut self.control_send,
                WriteBuf::from(UniStreamHeader::Control(settings)),
            ),
            async {
                if let Some(stream) = &mut decoder_send {
                    let _ = stream::write(stream, WriteBuf::from(UniStreamHeader::Decoder)).await;
                }
            },
            async {
                if let Some(stream) = &mut encoder_send {
                    let _ = stream::write(stream, WriteBuf::from(UniStreamHeader::Encoder)).await;
                }
            },
        )
        .await;

        self.qpack_streams.decoder_send = decoder_send;
        self.qpack_streams.encoder_send = encoder_send;

        match control {
            Ok(control) => Ok(control),
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                Err(self.handle_connection_error(connection_error))
            }
            Err(StreamErrorIncoming::StreamTerminated { error_code: err }) => Err(self
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If either control
                //# stream is closed at any point, this MUST be treated as a connection
                //# error of type H3_CLOSED_CRITICAL_STREAM.
                .handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!(
                        "control stream was requested to stop sending with error code {}",
                        err
                    ),
                ))),
            Err(StreamErrorIncoming::Unknown(error)) => {
                Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("an error occurred on the control stream {}", error),
                )))
            }
        }
    }

    /// Initiates the connection and opens a control stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn new(
        mut conn: C,
        shared: Arc<SharedState>,
        config: Config,
    ) -> Result<Self, ConnectionError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# Endpoints SHOULD create the HTTP control stream as well as the
        //# unidirectional streams required by mandatory extensions (such as the
        //# QPACK encoder and decoder streams) first, and then create additional

        // start streams
        let (control_send, qpack_encoder, qpack_decoder) = (
            future::poll_fn(|cx| conn.poll_open_send(cx)).await,
            future::poll_fn(|cx| conn.poll_open_send(cx)).await,
            future::poll_fn(|cx| conn.poll_open_send(cx)).await,
        );

        let control_send = match control_send {
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                return Err(conn.handle_quic_error_raw(connection_error));
            }
            Err(StreamErrorIncoming::StreamTerminated { error_code: err }) => {
                return Err(
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                    //# If either control
                    //# stream is closed at any point, this MUST be treated as a connection
                    //# error of type H3_CLOSED_CRITICAL_STREAM.
                    conn.close_raw_connection_with_h3_error(InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!(
                            "control stream was requested to stop sending with error code {}",
                            err,
                        ),
                    )),
                );
            }
            Err(StreamErrorIncoming::Unknown(error)) => {
                return Err(
                    conn.close_raw_connection_with_h3_error(InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("an error occurred on the control stream {}", error),
                    )),
                );
            }
            Ok(control_send) => control_send,
        };

        let qpack_streams = QpackStreams {
            decoder_send: qpack_decoder.ok(),
            decoder_recv: None,
            encoder_send: qpack_encoder.ok(),
            encoder_recv: None,
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=implication
        //# The
        //# sender MUST NOT close the control stream, and the receiver MUST NOT
        //# request that the sender close the control stream.
        let mut conn_inner = Self {
            shared,
            conn,
            control_send: control_send,
            control_recv: None,
            qpack_streams,
            handled_connection_error: None,
            pending_recv_streams: Vec::with_capacity(3),
            got_peer_settings: false,
            send_grease_frame: config.send_grease,
            config,
            accepted_streams: Default::default(),
            // send grease stream if configured
            send_grease_stream_flag: config.send_grease,
            // start at first step
            grease_step: GreaseStatus::NotStarted(PhantomData),
        };
        conn_inner.send_control_stream_headers().await?;

        Ok(conn_inner)
    }

    /// Send GOAWAY with specified max_id, iff max_id is smaller than the previous one.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown<T>(
        &mut self,
        sent_closing: &mut Option<T>,
        max_id: T,
    ) -> Result<(), ConnectionError>
    where
        T: From<VarInt> + PartialOrd<T> + Copy,
        VarInt: From<T>,
    {
        if let Some(sent_id) = sent_closing {
            if *sent_id <= max_id {
                return Ok(());
            }
        }

        *sent_closing = Some(max_id);
        self.set_closing();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
        //# When either endpoint chooses to close the HTTP/3
        //# connection, the terminating endpoint SHOULD first send a GOAWAY frame
        //# (Section 5.2) so that both endpoints can reliably determine whether
        //# previously sent frames have been processed and gracefully complete or
        //# terminate any necessary remaining tasks.
        match stream::write(&mut self.control_send, Frame::Goaway(max_id.into())).await {
            Ok(()) => Ok(()),
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                Err(self.handle_connection_error(connection_error))
            }
            Err(StreamErrorIncoming::StreamTerminated { error_code: err }) => Err(self
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If either control
                //# stream is closed at any point, this MUST be treated as a connection
                //# error of type H3_CLOSED_CRITICAL_STREAM.
                .handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!(
                        "control stream was requested to stop sending with error code {}",
                        err
                    ),
                ))),
            Err(StreamErrorIncoming::Unknown(error)) => {
                Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("an error occurred on the control stream {}", error),
                )))
            }
        }
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_accept_bi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<C::BidiStream, ConnectionError>> {
        let _ = self.poll_connection_error(cx)?;

        // Accept the request by accepting the next bidirectional stream
        // .into().into() converts the impl QuicError into crate::error::Error.
        // The `?` operator doesn't work here for some reason.
        self.conn
            .poll_accept_bidi(cx)
            .map_err(|e| self.handle_connection_error(e))
    }

    /// Polls incoming streams
    ///
    /// Accepted streams which are not control, decoder, or encoder streams are buffer in `accepted_recv_streams`
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        let _ = self.poll_connection_error(cx)?;

        // Get all currently pending streams
        loop {
            match self
                .conn
                .poll_accept_recv(cx)
                .map_err(|e| self.handle_connection_error(e))?
            {
                Poll::Ready(stream) => self
                    .pending_recv_streams
                    .push(Some(AcceptRecvStream::new(stream))),
                Poll::Pending => break,
            }
        }

        for stream in self.pending_recv_streams.iter_mut().filter(|s| s.is_some()) {
            let resolved = match stream.as_mut().expect("this cannot be None").poll_type(cx) {
                Poll::Ready(Err(stream::PollTypeError::IncomingError(e))) => {
                    return Err(self.handle_connection_error(e));
                }
                Poll::Ready(Err(stream::PollTypeError::InternalError(e))) => {
                    return Err(self.handle_connection_error(e));
                }
                Poll::Ready(Err(stream::PollTypeError::EndOfStream)) =>
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                //# A receiver MUST tolerate unidirectional streams being
                //# closed or reset prior to the reception of the unidirectional stream
                //# header.
                {
                    // remove the stream if it was closed before the header was received
                    let _ = stream.take();
                    continue;
                }
                Poll::Ready(Ok(())) => stream.take().expect("this cannot be None"),
                Poll::Pending => continue,
            };

            match resolved.into_stream() {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# Only one control stream per peer is permitted;
                //# receipt of a second stream claiming to be a control stream MUST be
                //# treated as a connection error of type H3_STREAM_CREATION_ERROR.
                AcceptedRecvStream::Control(s) => {
                    if self.control_recv.is_some() {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two control streams".to_string(),
                        )));
                    }
                    self.control_recv = Some(s);
                }
                enc @ AcceptedRecvStream::Encoder(_) => {
                    if let Some(_prev) = self.qpack_streams.encoder_recv.replace(enc) {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two encoder streams".to_string(),
                        )));
                    }
                }
                dec @ AcceptedRecvStream::Decoder(_) => {
                    if let Some(_prev) = self.qpack_streams.decoder_recv.replace(dec) {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two decoder streams".to_string(),
                        )));
                    }
                }
                AcceptedRecvStream::WebTransportUni(id, s)
                    if self.config.settings.enable_webtransport =>
                {
                    // Store until someone else picks it up, like a webtransport session which is
                    // not yet established.
                    self.accepted_streams.wt_uni_streams.push((id, s))
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
                //= type=implication
                //# Endpoints MUST NOT consider these streams to have any meaning upon
                //# receipt.
                AcceptedRecvStream::Unknown(mut stream) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //# Recipients of unknown stream types MUST
                    //# either abort reading of the stream or discard incoming data without
                    //# further processing.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //# If reading is aborted, the recipient SHOULD use
                    //# the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    //# (Section 8.1).

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //= type=implication
                    //# The recipient MUST NOT consider unknown stream types
                    //# to be a connection error of any kind.

                    stream.stop_sending(Code::H3_STREAM_CREATION_ERROR.value());
                }
                _ => (),
            };
        }

        // Remove all None values
        self.pending_recv_streams.retain(|s| s.is_some());

        Ok(())
    }

    /// Waits for the control stream to be received and reads subsequent frames.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Frame<PayloadLen>, ConnectionError>> {
        // check if a connection error occurred on a stream
        let _ = self.poll_connection_error(cx)?;

        let recv = {
            // TODO
            self.poll_accept_recv(cx)?;
            if let Some(v) = &mut self.control_recv {
                v
            } else {
                // Try later
                return Poll::Pending;
            }
        };

        let res = match ready!(recv.poll_next(cx)) {
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error,
            })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated {
                error_code: err,
            })) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If either control
            //# stream is closed at any point, this MUST be treated as a connection
            //# error of type H3_CLOSED_CRITICAL_STREAM.
            // TODO: Add Test, that reset also triggers this
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("control stream was reset with error code {}", err),
                    ),
                )));
            }
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(error))) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("an error occurred on the control stream {}", error),
                    ),
                )));
            }
            Err(FrameStreamError::UnexpectedEnd) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
            //# When a stream terminates cleanly, if the last frame on the stream was
            //# truncated, this MUST be treated as a connection error of type
            //# H3_FRAME_ERROR.
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_ERROR,
                        "received incomplete frame".to_string(),
                    ),
                )));
            }
            Err(FrameStreamError::Proto(frame_error)) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::got_frame_error(frame_error),
                )));
            }
            Ok(None) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If either control
            //# stream is closed at any point, this MUST be treated as a connection
            //# error of type H3_CLOSED_CRITICAL_STREAM.
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        "control stream was closed".to_string(),
                    ),
                )));
            }
            Ok(Some(Frame::Settings(settings))) => {
                if !self.got_peer_settings {
                    // Received settings frame

                    self.got_peer_settings = true;
                    self.set_settings((&settings).into());

                    Frame::Settings(settings)
                } else {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a second SETTINGS
                    //# frame on the control stream, the endpoint MUST respond with a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            "second settings frame received".to_string(),
                        ),
                    )));
                }
            }
            Ok(Some(frame)) if !self.got_peer_settings => {
                // We received a frame before the settings frame
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If the first frame of the control stream is any other frame
                //# type, this MUST be treated as a connection error of type
                //# H3_MISSING_SETTINGS.
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_MISSING_SETTINGS,
                        format!("received frame {:?} before settings", frame),
                    ),
                )));
            }
            Ok(Some(
                frame @ Frame::Goaway(_)
                | frame @ Frame::CancelPush(_)
                | frame @ Frame::MaxPushId(_),
            )) => {
                // handle these frames in client/server imples
                frame
            }
            Ok(Some(frame)) => {
                // All other frames are not allowed on the control stream
                // Unknown frames are not covered by the Frame enum and poll_next will just ignore them
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //= type=implication
                //# DATA frames MUST be associated with an HTTP request or response.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //# If
                //# a DATA frame is received on a control stream, the recipient MUST
                //# respond with a connection error of type H3_FRAME_UNEXPECTED.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
                //# If a HEADERS frame is received on a control stream, the recipient
                //# MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        format!("received unexpected frame {:?} on control stream", frame),
                    ),
                )));
            }
        };

        if self.send_grease_stream_flag {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
            //# They MAY also be
            //# sent on connections where no data is currently being transferred.
            ready!(self.poll_grease_stream(cx));
        }

        Poll::Ready(Ok(res))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn process_goaway<T>(
        &mut self,
        recv_closing: &mut Option<T>,
        id: VarInt,
    ) -> Result<(), ConnectionError>
    where
        T: From<VarInt> + Copy,
        VarInt: From<T>,
    {
        {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            //# An endpoint MAY send multiple GOAWAY frames indicating different
            //# identifiers, but the identifier in each frame MUST NOT be greater
            //# than the identifier in any previous frame, since clients might
            //# already have retried unprocessed requests on another HTTP connection.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            //# Like the server,
            //# the client MAY send subsequent GOAWAY frames so long as the specified
            //# push ID is no greater than any previously sent value.
            if let Some(prev_id) = recv_closing.map(VarInt::from) {
                if prev_id < id {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
                    //# Receiving a GOAWAY containing a larger identifier than previously
                    //# received MUST be treated as a connection error of type H3_ID_ERROR.
                    return Err(self.handle_connection_error(InternalConnectionError::new(
                        Code::H3_ID_ERROR,
                        format!(
                            "received a GoAway ({}) greater than the former one ({})",
                            id, prev_id
                        ),
                    )));
                }
            }
            *recv_closing = Some(id.into());
            self.set_closing();
            Ok(())
        }
    }

    // start grease stream and send data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_grease_stream(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if matches!(self.grease_step, GreaseStatus::NotStarted(_)) {
            self.grease_step = match self.conn.poll_open_send(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    // could not create grease stream
                    // don't try again
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("grease stream creation failed with");

                    return Poll::Ready(());
                }
                Poll::Ready(Ok(stream)) => GreaseStatus::Started(Some(stream)),
            };
        };
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
        //# Stream types of the format 0x1f * N + 0x21 for non-negative integer
        //# values of N are reserved to exercise the requirement that unknown
        //# types be ignored.  These streams have no semantics, and they can be
        //# sent when application-layer padding is desired.  They MAY also be
        //# sent on connections where no data is currently being transferred.
        if let GreaseStatus::Started(stream) = &mut self.grease_step {
            if let Some(stream) = stream {
                if stream
                    .send_data((StreamType::grease(), Frame::Grease))
                    .is_err()
                {
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("write data on grease stream failed with");

                    return Poll::Ready(());
                };
            }
            self.grease_step = GreaseStatus::DataPrepared(stream.take());
        };

        if let GreaseStatus::DataPrepared(stream) = &mut self.grease_step {
            if let Some(stream) = stream {
                match stream.poll_ready(cx) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        // could not write grease frame
                        // don't try again
                        self.send_grease_stream_flag = false;

                        #[cfg(feature = "tracing")]
                        warn!("write data on grease stream failed with");

                        return Poll::Ready(());
                    }
                };
            }
            self.grease_step = GreaseStatus::DataSent(match stream.take() {
                Some(stream) => stream,
                None => {
                    // this should never happen
                    self.send_grease_stream_flag = false;
                    return Poll::Ready(());
                }
            });
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
        //= type=implication
        //# When sending a reserved stream type,
        //# the implementation MAY either terminate the stream cleanly or reset
        //# it.
        if let GreaseStatus::DataSent(stream) = &mut self.grease_step {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
            //= type=exception
            //# When resetting the stream, either the H3_NO_ERROR error code or
            //# a reserved error code (Section 8.1) SHOULD be used.
            // We terminate the stream cleanly so no H3_NO_ERROR is needed
            match stream.poll_finish(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    // could not finish grease stream
                    // don't try again
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("finish grease stream failed with");

                    return Poll::Ready(());
                }
            };
            self.grease_step = GreaseStatus::Finished;
        };

        // grease stream is closed
        // don't do another one
        self.send_grease_stream_flag = false;
        Poll::Ready(())
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn accepted_streams_mut(&mut self) -> &mut AcceptedStreams<C, B> {
        &mut self.accepted_streams
    }
}

#[allow(missing_docs)]
pub struct RequestStream<S, B> {
    pub(super) stream: FrameStream<S, B>,
    pub(super) trailers: Option<Bytes>,
    pub(super) conn_state: Arc<SharedState>,
    pub(super) max_field_section_size: u64,
    send_grease_frame: bool,
}

impl<S, B> RequestStream<S, B> {
    #[allow(missing_docs)]
    pub fn new(
        stream: FrameStream<S, B>,
        max_field_section_size: u64,
        conn_state: Arc<SharedState>,
        grease: bool,
    ) -> Self {
        Self {
            stream,
            conn_state,
            max_field_section_size,
            trailers: None,
            send_grease_frame: grease,
        }
    }
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Receive some of the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        // Empty DATA frames do not end the body; keep reading until data or EOF.
        while !self.stream.has_data() {
            match ready!(self.stream.poll_next(cx)) {
                Err(frame_stream_error) => {
                    return Poll::Ready(Err(
                        self.handle_frame_stream_error_on_request_stream(frame_stream_error)
                    ))
                }
                Ok(None) => return Poll::Ready(Ok(None)),
                Ok(Some(Frame::Headers(encoded))) => {
                    self.trailers = Some(encoded);
                    // Received trailers, no more data expected
                    return Poll::Ready(Ok(None));
                }
                Ok(Some(Frame::Data { .. })) => (),
                Ok(Some(other_frame)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                    //# Receiving a
                    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
                    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a SETTINGS frame on a different
                    //# stream, the endpoint MUST respond with a connection error of type
                    //# H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# A client MUST treat a GOAWAY frame on a stream other than
                    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
                    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", other_frame),
                        ),
                    )));
                }
            };
        }

        self.stream
            .poll_data(cx)
            .map_err(|error| self.handle_frame_stream_error_on_request_stream(error))
    }

    /// Poll receive trailers.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let mut trailers = if let Some(encoded) = self.trailers.take() {
            encoded
        } else {
            match ready!(self.stream.poll_next(cx)) {
                Err(frame_stream_error) => {
                    return Poll::Ready(Err(
                        self.handle_frame_stream_error_on_request_stream(frame_stream_error)
                    ))
                }
                Ok(None) => return Poll::Ready(Ok(None)),
                Ok(Some(Frame::Headers(encoded))) => encoded,
                Ok(Some(other_frame)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                    //# Receiving a
                    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
                    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a SETTINGS frame on a different
                    //# stream, the endpoint MUST respond with a connection error of type
                    //# H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# A client MUST treat a GOAWAY frame on a stream other than
                    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
                    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", other_frame),
                        ),
                    )));
                }
            }
        };

        if !self.stream.is_eos() {
            // Get the trailing frame. After trailers no known frame is allowed.
            // But there still can be unknown frames.
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            match self.stream.poll_next(cx) {
                Poll::Ready(Err(frame_stream_error)) => {
                    return Poll::Ready(Err(
                        self.handle_frame_stream_error_on_request_stream(frame_stream_error)
                    ))
                }
                Poll::Ready(Ok(Some(trailing_frame))) => {
                    // Received a known frame after trailers -> fail.
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", trailing_frame),
                        ),
                    )));
                }
                // Stream is finished no problematic frames received
                Poll::Ready(Ok(None)) => (),
                Poll::Pending => {
                    // save the trailers and try again.
                    self.trailers = Some(trailers);
                    return Poll::Pending;
                }
            }
        }

        let qpack::Decoded { fields, .. } =
            match qpack::decode_stateless(&mut trailers, self.max_field_section_size) {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
                //# An HTTP/3 implementation MAY impose a limit on the maximum size of
                //# the message header it will accept on an individual HTTP message.
                Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                    return Poll::Ready(Err(StreamError::HeaderTooBig {
                        actual_size: cancel_size,
                        max_size: self.max_field_section_size,
                    }));
                }
                Ok(decoded) => decoded,
                Err(_e) => {
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError {
                            code: Code::QPACK_DECOMPRESSION_FAILED,
                            message: "Failed to decode trailers".to_string(),
                        },
                    )))
                }
            };

        Poll::Ready(Ok(Some(
            Header::try_from(fields)
                .map_err(|_e| {
                    self.stop_sending(Code::H3_MESSAGE_ERROR);
                    StreamError::StreamError {
                        code: Code::H3_MESSAGE_ERROR,
                        reason: "malformed request".to_string(),
                    }
                })?
                .into_fields(),
        )))
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, err_code: Code) {
        self.stream.stop_sending(err_code);
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the response body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        let frame = Frame::Data(buf);

        stream::write(&mut self.stream, frame)
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;
        Ok(())
    }

    /// Send a set of trailers to end the request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=TODO
        //# Characters in field names MUST be
        //# converted to lowercase prior to their encoding.
        let mut block = BytesMut::new();

        let mem_size =
            qpack::encode_stateless(&mut block, Header::trailer(trailers)).map_err(|_e| {
                self.handle_connection_error_on_stream(InternalConnectionError {
                    code: Code::H3_INTERNAL_ERROR,
                    message: "Failed to encode trailers".to_string(),
                })
            })?;

        let max_mem_size = self.settings().max_field_section_size;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.

        if mem_size > max_mem_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size: max_mem_size,
            });
        }

        stream::write(&mut self.stream, Frame::Headers(block.freeze()))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        Ok(())
    }

    /// Stops a stream with an error code
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_stream(&mut self, code: Code) {
        self.stream.reset(code.into());
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        if self.send_grease_frame {
            // send a grease frame once per Connection
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
            //= type=implication
            //# Frame types of the format 0x1f * N + 0x21 for non-negative integer
            //# values of N are reserved to exercise the requirement that unknown
            //# types be ignored (Section 9).  These frames have no semantics, and
            //# they MAY be sent on any stream where frames are allowed to be sent.
            stream::write(&mut self.stream, Frame::Grease)
                .await
                .map_err(|e| self.handle_quic_stream_error(e))?;
            self.send_grease_frame = false;
        }

        future::poll_fn(|cx| self.stream.poll_finish(cx))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.stream.split();

        (
            RequestStream {
                stream: send,
                trailers: None,
                conn_state: self.conn_state.clone(),
                max_field_section_size: 0,
                send_grease_frame: self.send_grease_frame,
            },
            RequestStream {
                stream: recv,
                trailers: self.trailers,
                conn_state: self.conn_state,
                max_field_section_size: self.max_field_section_size,
                send_grease_frame: self.send_grease_frame,
            },
        )
    }
}
