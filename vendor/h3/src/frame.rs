use std::task::{Context, Poll};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
        }
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            let end = self.try_recv(cx)?;

            return match self.decoder.decode(self.stream.buf_mut())? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))))
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    Poll::Ready(Ok(frame))
                }
                Some(frame) => Poll::Ready(Ok(Some(frame))),
                None => match end {
                    // Received a chunk but frame is incomplete, poll until we get `Pending`.
                    Poll::Ready(false) => continue,
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(true) => {
                        if self.stream.buf_mut().has_remaining() {
                            // Reached the end of receive stream, but there is still some data:
                            // The frame is incomplete.
                            Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
                        } else {
                            Poll::Ready(Ok(None))
                        }
                    }
                },
            };
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            (None, true) => Poll::Ready(Ok(None)),
            (None, false) => Poll::Pending,
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
            },
        )
    }
}

#[derive(Default)]
pub struct FrameDecoder {
    expected: Option<usize>,
}

impl FrameDecoder {
    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Decode in a loop since we ignore unknown frames, and there may be
        // other frames already in our BufList.
        loop {
            if !src.has_remaining() {
                return Ok(None);
            }

            if let Some(min) = self.expected {
                if src.remaining() < min {
                    return Ok(None);
                }
            }

            let (pos, decoded) = {
                let mut cur = src.cursor();
                let decoded = Frame::decode(&mut cur);
                (cur.position(), decoded)
            };

            match decoded {
                Err(frame::FrameError::UnknownFrame(_ty)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                    //# Endpoints MUST
                    //# NOT consider these frames to have any meaning upon receipt.
                    #[cfg(feature = "tracing")]
                    trace!("ignore unknown frame type {:#x}", _ty);

                    src.advance(pos);
                    self.expected = None;
                    continue;
                }
                Err(frame::FrameError::Incomplete(min)) => {
                    self.expected = Some(min);
                    return Ok(None);
                }
                Ok(frame) => {
                    src.advance(pos);
                    self.expected = None;
                    return Ok(Some(frame));
                }
                // -------------- Map the error Values --------------
                Err(frame::FrameError::InvalidStreamId(e)) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidStreamId(e),
                    ));
                }
                Err(frame::FrameError::InvalidPushId(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::InvalidPushId(
                        e,
                    )));
                }
                Err(frame::FrameError::Settings(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)));
                }
                Err(frame::FrameError::UnsupportedFrame(ty)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                        ty,
                    )));
                }
                Err(frame::FrameError::InvalidFrameValue) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidFrameValue,
                    ));
                }
                Err(frame::FrameError::Malformed) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
            }
        }
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::collections::VecDeque;

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
