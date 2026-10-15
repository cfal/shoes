use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes};
use futures_util::{future, ready};
use pin_project_lite::pin_project;
use tokio::io::ReadBuf;

use crate::{
    buf::BufList,
    error::{internal_error::InternalConnectionError, Code},
    frame::FrameStream,
    proto::{
        coding::{Decode as _, Encode},
        frame::{Frame, Settings},
        stream::StreamType,
        varint::VarInt,
    },
    quic::{
        self, BidiStream, ConnectionErrorIncoming, RecvStream, SendStream, SendStreamUnframed,
        StreamErrorIncoming,
    },
    webtransport::SessionId,
};

#[inline]
/// Transmits data by encoding in wire format.
pub(crate) async fn write<S, D, B>(stream: &mut S, data: D) -> Result<(), StreamErrorIncoming>
where
    S: SendStream<B>,
    D: Into<WriteBuf<B>>,
    B: Buf,
{
    stream.send_data(data)?;
    future::poll_fn(|cx| stream.poll_ready(cx)).await?;

    Ok(())
}

const WRITE_BUF_ENCODE_SIZE: usize = StreamType::MAX_ENCODED_SIZE + Frame::MAX_ENCODED_SIZE;

/// Wrap frames to encode their header on the stack before sending them on the wire
///
/// Implements `Buf` so wire data is seamlessly available for transport layer transmits:
/// `Buf::chunk()` will yield the encoded header, then the payload. For unidirectional streams,
/// this type makes it possible to prefix wire data with the `StreamType`.
///
/// Conveying frames as `Into<WriteBuf>` makes it possible to encode only when generating wire-format
/// data is necessary (say, in `quic::SendStream::send_data`). It also has a public API ergonomy
/// advantage: `WriteBuf` doesn't have to appear in public associated types. On the other hand,
/// QUIC implementers have to call `into()`, which will encode the header in `Self::buf`.
pub struct WriteBuf<B> {
    buf: [u8; WRITE_BUF_ENCODE_SIZE],
    len: usize,
    pos: usize,
    frame: Option<Frame<B>>,
}

impl<B> WriteBuf<B>
where
    B: Buf,
{
    fn encode_stream_type(&mut self, ty: StreamType) {
        let mut buf_mut = &mut self.buf[self.len..];

        ty.encode(&mut buf_mut);
        self.len = WRITE_BUF_ENCODE_SIZE - buf_mut.remaining_mut();
    }

    fn encode_value(&mut self, value: impl Encode) {
        let mut buf_mut = &mut self.buf[self.len..];
        value.encode(&mut buf_mut);
        self.len = WRITE_BUF_ENCODE_SIZE - buf_mut.remaining_mut();
    }

    fn encode_frame_header(&mut self) {
        if let Some(frame) = self.frame.as_ref() {
            let mut buf_mut = &mut self.buf[self.len..];
            frame.encode(&mut buf_mut);
            self.len = WRITE_BUF_ENCODE_SIZE - buf_mut.remaining_mut();
        }
    }
}

impl<B> From<StreamType> for WriteBuf<B>
where
    B: Buf,
{
    fn from(ty: StreamType) -> Self {
        let mut me = Self {
            buf: [0; WRITE_BUF_ENCODE_SIZE],
            len: 0,
            pos: 0,
            frame: None,
        };
        me.encode_stream_type(ty);
        me
    }
}

impl<B> From<UniStreamHeader> for WriteBuf<B>
where
    B: Buf,
{
    fn from(header: UniStreamHeader) -> Self {
        let mut this = Self {
            buf: [0; WRITE_BUF_ENCODE_SIZE],
            len: 0,
            pos: 0,
            frame: None,
        };

        this.encode_value(header);
        this
    }
}

pub enum UniStreamHeader {
    Control(Settings),
    WebTransportUni(SessionId),
    Encoder,
    Decoder,
}

impl Encode for UniStreamHeader {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Control(settings) => {
                StreamType::CONTROL.encode(buf);
                settings.encode(buf);
            }
            Self::WebTransportUni(session_id) => {
                StreamType::WEBTRANSPORT_UNI.encode(buf);
                session_id.encode(buf);
            }
            UniStreamHeader::Encoder => {
                StreamType::ENCODER.encode(buf);
            }
            UniStreamHeader::Decoder => {
                StreamType::DECODER.encode(buf);
            }
        }
    }
}

impl<B> From<BidiStreamHeader> for WriteBuf<B>
where
    B: Buf,
{
    fn from(header: BidiStreamHeader) -> Self {
        let mut this = Self {
            buf: [0; WRITE_BUF_ENCODE_SIZE],
            len: 0,
            pos: 0,
            frame: None,
        };

        this.encode_value(header);
        this
    }
}

pub enum BidiStreamHeader {
    WebTransportBidi(SessionId),
}

impl Encode for BidiStreamHeader {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::WebTransportBidi(session_id) => {
                StreamType::WEBTRANSPORT_BIDI.encode(buf);
                session_id.encode(buf);
            }
        }
    }
}

impl<B> From<Frame<B>> for WriteBuf<B>
where
    B: Buf,
{
    fn from(frame: Frame<B>) -> Self {
        let mut me = Self {
            buf: [0; WRITE_BUF_ENCODE_SIZE],
            len: 0,
            pos: 0,
            frame: Some(frame),
        };
        me.encode_frame_header();
        me
    }
}

impl<B> From<(StreamType, Frame<B>)> for WriteBuf<B>
where
    B: Buf,
{
    fn from(ty_stream: (StreamType, Frame<B>)) -> Self {
        let (ty, frame) = ty_stream;
        let mut me = Self {
            buf: [0; WRITE_BUF_ENCODE_SIZE],
            len: 0,
            pos: 0,
            frame: Some(frame),
        };
        me.encode_value(ty);
        me.encode_frame_header();
        me
    }
}

impl<B> Buf for WriteBuf<B>
where
    B: Buf,
{
    fn remaining(&self) -> usize {
        self.len - self.pos
            + self
                .frame
                .as_ref()
                .and_then(|f| f.payload())
                .map_or(0, |x| x.remaining())
    }

    fn chunk(&self) -> &[u8] {
        if self.len - self.pos > 0 {
            &self.buf[self.pos..self.len]
        } else if let Some(payload) = self.frame.as_ref().and_then(|f| f.payload()) {
            payload.chunk()
        } else {
            &[]
        }
    }

    fn advance(&mut self, mut cnt: usize) {
        let remaining_header = self.len - self.pos;
        if remaining_header > 0 {
            let advanced = usize::min(cnt, remaining_header);
            self.pos += advanced;
            cnt -= advanced;
        }

        if let Some(payload) = self.frame.as_mut().and_then(|f| f.payload_mut()) {
            payload.advance(cnt);
        }
    }
}

pub(super) enum AcceptedRecvStream<S, B>
where
    S: quic::RecvStream,
    B: Buf,
{
    Control(FrameStream<S, B>),
    Push(FrameStream<S, B>),
    Encoder(BufRecvStream<S, B>),
    Decoder(BufRecvStream<S, B>),
    WebTransportUni(SessionId, BufRecvStream<S, B>),
    Unknown(BufRecvStream<S, B>),
}

/// Resolves an incoming streams type as well as `PUSH_ID`s and `SESSION_ID`s
pub(super) struct AcceptRecvStream<S, B> {
    stream: BufRecvStream<S, B>,
    ty: Option<StreamType>,
    /// push_id or session_id
    id: Option<VarInt>,
    expected: Option<usize>,
}

impl<S, B> AcceptRecvStream<S, B>
where
    S: RecvStream,
    B: Buf,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: BufRecvStream::new(stream),
            ty: None,
            id: None,
            expected: None,
        }
    }

    pub fn into_stream(self) -> AcceptedRecvStream<S, B> {
        match self.ty.expect("Stream type not resolved yet") {
            StreamType::CONTROL => AcceptedRecvStream::Control(FrameStream::new(self.stream)),
            StreamType::PUSH => AcceptedRecvStream::Push(FrameStream::new(self.stream)),
            StreamType::ENCODER => AcceptedRecvStream::Encoder(self.stream),
            StreamType::DECODER => AcceptedRecvStream::Decoder(self.stream),
            StreamType::WEBTRANSPORT_UNI => AcceptedRecvStream::WebTransportUni(
                SessionId::from_varint(self.id.expect("Session ID not resolved yet")),
                self.stream,
            ),
            _ => AcceptedRecvStream::Unknown(self.stream),
        }
    }

    // helper function to poll the next VarInt from self.stream
    fn poll_next_varint(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(VarInt, Option<StreamEnd>), PollTypeError>> {
        // Flag if the stream was reset or finished by the peer
        let mut stream_stopped = None;

        loop {
            if stream_stopped.is_some() {
                return Poll::Ready(Err(PollTypeError::EndOfStream));
            }
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
            //# A receiver MUST tolerate unidirectional streams being
            //# closed or reset prior to the reception of the unidirectional stream
            //# header.
            stream_stopped = match ready!(self.stream.poll_read(cx)) {
                Ok(false) => None,
                Ok(true) => Some(StreamEnd::EndOfStream),
                Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                    return Poll::Ready(Err(PollTypeError::IncomingError(connection_error)));
                }
                Err(StreamErrorIncoming::StreamTerminated { error_code }) => {
                    Some(StreamEnd::Reset(error_code))
                }
                Err(StreamErrorIncoming::Unknown(err)) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("Unknown error when reading stream {}", err);

                    Some(StreamEnd::Other)
                }
            };

            let mut buf = self.stream.buf_mut();
            if self.expected.is_none() && buf.remaining() >= 1 {
                self.expected = Some(VarInt::encoded_size(buf.chunk()[0]));
            }

            if let Some(expected) = self.expected {
                if buf.remaining() < expected {
                    continue;
                }
            } else {
                continue;
            }

            let reult = VarInt::decode(&mut buf).map_err(|_| {
                PollTypeError::InternalError(InternalConnectionError::new(
                    Code::H3_INTERNAL_ERROR,
                    "Unexpected end parsing varint".to_string(),
                ))
            })?;

            return Poll::Ready(Ok((reult, stream_stopped)));
        }
    }

    pub fn poll_type(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), PollTypeError>> {
        // If we haven't parsed the stream type yet
        if self.ty.is_none() {
            // TODO create a test for the StreamEnd Option
            // If the stream ended or reset directly after the type was received
            // can we poll data again?
            let (var, _) = ready!(self.poll_next_varint(cx))?;
            let ty = StreamType::from_value(var.0);
            self.ty = Some(ty);
        }

        // If the type requires a second VarInt (PUSH or WEBTRANSPORT_UNI)
        if matches!(
            self.ty,
            Some(StreamType::PUSH | StreamType::WEBTRANSPORT_UNI)
        ) && self.id.is_none()
        {
            let (var, _) = ready!(self.poll_next_varint(cx))?;
            self.id = Some(var);
        }

        Poll::Ready(Ok(()))
    }
}

enum StreamEnd {
    EndOfStream,
    Reset(u64),
    // if the quic layer returns an unknown error
    Other,
}

pub(super) enum PollTypeError {
    IncomingError(ConnectionErrorIncoming),
    InternalError(InternalConnectionError),
    // Stream stopped with eos or reset.
    // No Code is received
    EndOfStream,
}

pin_project! {
    /// A stream which allows partial reading of the data without data loss.
    ///
    /// This fixes the problem where `poll_data` returns more than the needed amount of bytes,
    /// requiring correct implementations to hold on to that extra data and return it later.
    ///
    /// # Usage
    ///
    /// Implements `quic::RecvStream` which will first return buffered data, and then read from the
    /// stream
    pub struct BufRecvStream<S, B> {
        buf: BufList<Bytes>,
        // Indicates that the end of the stream has been reached
        //
        // Data may still be available as buffered
        eos: bool,
        stream: S,
        _marker: PhantomData<B>,
    }
}

impl<S, B> std::fmt::Debug for BufRecvStream<S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufRecvStream")
            .field("buf", &self.buf)
            .field("eos", &self.eos)
            .field("stream", &"...")
            .finish()
    }
}

impl<S, B> BufRecvStream<S, B> {
    pub fn new(stream: S) -> Self {
        Self {
            buf: BufList::new(),
            eos: false,
            stream,
            _marker: PhantomData,
        }
    }
}

impl<B, S: RecvStream> BufRecvStream<S, B> {
    /// Reads more data into the buffer, returning the number of bytes read.
    ///
    /// Returns `true` if the end of the stream is reached.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, StreamErrorIncoming>> {
        let data = ready!(self.stream.poll_data(cx))?;

        if let Some(mut data) = data {
            self.buf.push_bytes(&mut data);
            Poll::Ready(Ok(false))
        } else {
            self.eos = true;
            Poll::Ready(Ok(true))
        }
    }

    /// Returns the currently buffered data, allowing it to be partially read
    #[inline]
    pub(crate) fn buf_mut(&mut self) -> &mut BufList<Bytes> {
        &mut self.buf
    }

    /// Returns the next chunk of data from the stream
    ///
    /// Return `None` when there is no more buffered data; use [`Self::poll_read`].
    pub fn take_chunk(&mut self, limit: usize) -> Option<Bytes> {
        self.buf.take_chunk(limit)
    }

    /// Returns true if there is remaining buffered data
    pub fn has_remaining(&mut self) -> bool {
        self.buf.has_remaining()
    }

    #[inline]
    pub(crate) fn buf(&self) -> &BufList<Bytes> {
        &self.buf
    }

    pub fn is_eos(&self) -> bool {
        self.eos
    }
}

impl<S: RecvStream, B> RecvStream for BufRecvStream<S, B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        // There is data buffered, return that immediately
        if let Some(chunk) = self.buf.take_first_chunk() {
            return Poll::Ready(Ok(Some(chunk)));
        }

        if let Some(mut data) = ready!(self.stream.poll_data(cx))? {
            Poll::Ready(Ok(Some(data.copy_to_bytes(data.remaining()))))
        } else {
            self.eos = true;
            Poll::Ready(Ok(None))
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.stream.stop_sending(error_code)
    }

    fn recv_id(&self) -> quic::StreamId {
        self.stream.recv_id()
    }
}

impl<S, B> SendStream<B> for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStream<B>,
{
    fn poll_finish(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> quic::StreamId {
        self.stream.send_id()
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }
}

impl<S, B> SendStreamUnframed<B> for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStreamUnframed<B>,
{
    #[inline]
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.stream.poll_send(cx, buf)
    }
}

impl<S, B> BidiStream<B> for BufRecvStream<S, B>
where
    B: Buf,
    S: BidiStream<B>,
{
    type SendStream = BufRecvStream<S::SendStream, B>;

    type RecvStream = BufRecvStream<S::RecvStream, B>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.stream.split();
        (
            BufRecvStream {
                // Sending is not buffered
                buf: BufList::new(),
                eos: self.eos,
                stream: send,
                _marker: PhantomData,
            },
            BufRecvStream {
                buf: self.buf,
                eos: self.eos,
                stream: recv,
                _marker: PhantomData,
            },
        )
    }
}

impl<S, B> futures_util::io::AsyncRead for BufRecvStream<S, B>
where
    B: Buf,
    S: RecvStream,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures_util::io::Result<usize>> {
        let p = &mut *self;
        // Poll for data if the buffer is empty
        //
        // If there is data available *do not* poll for more data, as that may suspend indefinitely
        // if no more data is sent, causing data loss.
        if !p.has_remaining() {
            let eos = ready!(p.poll_read(cx).map_err(|err| convert_to_std_io_error(err)))?;
            if eos {
                return Poll::Ready(Ok(0));
            }
        }

        let chunk = p.buf_mut().take_chunk(buf.len());
        if let Some(chunk) = chunk {
            assert!(chunk.len() <= buf.len());
            let len = chunk.len().min(buf.len());
            // Write the subset into the destination
            buf[..len].copy_from_slice(&chunk);
            Poll::Ready(Ok(len))
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

impl<S, B> tokio::io::AsyncRead for BufRecvStream<S, B>
where
    B: Buf,
    S: RecvStream,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<futures_util::io::Result<()>> {
        let p = &mut *self;
        // Poll for data if the buffer is empty
        //
        // If there is data available *do not* poll for more data, as that may suspend indefinitely
        // if no more data is sent, causing data loss.
        if !p.has_remaining() {
            let eos = ready!(p.poll_read(cx).map_err(|err| convert_to_std_io_error(err)))?;
            if eos {
                return Poll::Ready(Ok(()));
            }
        }

        let chunk = p.buf_mut().take_chunk(buf.remaining());
        if let Some(chunk) = chunk {
            assert!(chunk.len() <= buf.remaining());
            // Write the subset into the destination
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl<S, B> futures_util::io::AsyncWrite for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStreamUnframed<B>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let p = &mut *self;
        p.poll_send(cx, &mut buf)
            .map_err(|err| convert_to_std_io_error(err))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let p = &mut *self;
        p.poll_finish(cx)
            .map_err(|err| convert_to_std_io_error(err))
    }
}

impl<S, B> tokio::io::AsyncWrite for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStreamUnframed<B>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let p = &mut *self;
        p.poll_send(cx, &mut buf)
            .map_err(|err| convert_to_std_io_error(err))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let p = &mut *self;
        p.poll_finish(cx)
            .map_err(|err| convert_to_std_io_error(err))
    }
}

fn convert_to_std_io_error(error: StreamErrorIncoming) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error)
}

#[cfg(test)]
mod tests {
    use crate::proto::coding::BufExt;

    use super::*;

    #[test]
    fn write_wt_uni_header() {
        let mut w = WriteBuf::<Bytes>::from(UniStreamHeader::WebTransportUni(
            SessionId::from_varint(VarInt(5)),
        ));

        let ty = w.get_var().unwrap();
        println!("Got type: {ty} {ty:#x}");
        assert_eq!(ty, 0x54);

        let id = w.get_var().unwrap();
        println!("Got id: {id}");
    }

    #[test]
    fn write_buf_encode_streamtype() {
        let wbuf = WriteBuf::<Bytes>::from(StreamType::ENCODER);

        assert_eq!(wbuf.chunk(), b"\x02");
        assert_eq!(wbuf.len, 1);
    }

    #[test]
    fn write_buf_encode_frame() {
        let wbuf = WriteBuf::<Bytes>::from(Frame::Goaway(VarInt(2)));

        assert_eq!(wbuf.chunk(), b"\x07\x01\x02");
        assert_eq!(wbuf.len, 3);
    }

    #[test]
    fn write_buf_encode_streamtype_then_frame() {
        let wbuf = WriteBuf::<Bytes>::from((StreamType::ENCODER, Frame::Goaway(VarInt(2))));

        assert_eq!(wbuf.chunk(), b"\x02\x07\x01\x02");
    }

    #[test]
    fn write_buf_advances() {
        let mut wbuf =
            WriteBuf::<Bytes>::from((StreamType::ENCODER, Frame::Data(Bytes::from("hey"))));

        assert_eq!(wbuf.chunk(), b"\x02\x00\x03");
        wbuf.advance(3);
        assert_eq!(wbuf.remaining(), 3);
        assert_eq!(wbuf.chunk(), b"hey");
        wbuf.advance(2);
        assert_eq!(wbuf.chunk(), b"y");
        wbuf.advance(1);
        assert_eq!(wbuf.remaining(), 0);
    }

    #[test]
    fn write_buf_advance_jumps_header_and_payload_start() {
        let mut wbuf =
            WriteBuf::<Bytes>::from((StreamType::ENCODER, Frame::Data(Bytes::from("hey"))));

        wbuf.advance(4);
        assert_eq!(wbuf.chunk(), b"ey");
    }
}
