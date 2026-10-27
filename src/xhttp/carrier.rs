use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use h3::ConnectionState;
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::stream::{Body, Memory, Reader, Tasks, Upload, UploadSignal, UploadWatch, Writer, pipe};
use crate::http2::transport::TransportErrors;
use crate::{
    async_stream::AsyncStream, config::xhttp::XhttpVersion, tcp::carrier_dialer::QuicCarrier,
};

type H3Sender = h3::client::SendRequest<super::h3::Opener, Bytes>;

pub struct Reservation(Option<super::h3::Bidi>);

#[derive(Clone, Copy)]
pub struct Timeouts {
    headers: Duration,
    upload_idle: Option<Duration>,
}

impl Timeouts {
    pub fn headers(timeout: Duration) -> Self {
        Self {
            headers: timeout,
            upload_idle: None,
        }
    }

    pub fn packet(headers: Duration, upload: Duration) -> Self {
        Self {
            headers,
            upload_idle: Some(upload),
        }
    }

    async fn response<B>(
        self,
        response: impl Future<Output = io::Result<Response<B>>>,
        upload: Option<UploadWatch>,
        cancel: &CancellationToken,
    ) -> io::Result<Response<B>> {
        let response = async {
            let response = match self.upload_idle {
                None => tokio::time::timeout(self.headers, response).await?,
                Some(_) => response.await,
            }?;
            if self.upload_idle.is_some() && response.status() != http::StatusCode::OK {
                return Err(io::Error::other(format!(
                    "XHTTP packet status {}",
                    response.status()
                )));
            }
            Ok(response)
        };
        let uploaded = async {
            if let Some((upload, timeout)) = upload.zip(self.upload_idle) {
                upload.wait(timeout).await?;
            }
            Ok::<_, io::Error>(())
        };
        tokio::select! {
            biased;
            result = async { tokio::try_join!(response, uploaded).map(|(response, ())| response) } => result,
            _ = cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
        }
    }
}

enum Sender {
    H1(tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Body>>),
    H2 {
        sender: h2::client::SendRequest<Bytes>,
        errors: TransportErrors,
    },
    H3 {
        sender: H3Sender,
        opener: super::h3::Opener,
        headers: tokio::sync::Mutex<()>,
    },
}

pub struct Carrier {
    sender: Sender,
    retired: AtomicBool,
    _tasks: Tasks,
    _quic: Option<QuicCarrier>,
}

impl Carrier {
    #[cfg(test)]
    pub async fn tcp(
        stream: Box<dyn AsyncStream>,
        version: XhttpVersion,
        header_limit: usize,
    ) -> io::Result<Arc<Self>> {
        Self::tcp_with_windows(
            stream,
            version,
            header_limit,
            crate::config::xhttp::XhttpLimits::default().h2_windows(),
        )
        .await
    }

    pub async fn tcp_with_windows(
        stream: Box<dyn AsyncStream>,
        version: XhttpVersion,
        header_limit: usize,
        (stream_window, connection_window): (u32, u32),
    ) -> io::Result<Arc<Self>> {
        let tasks = Tasks::new();
        let sender = if version == XhttpVersion::H1 {
            let (sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(header_limit.max(8192))
                .handshake(TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
            tasks.spawn(async move {
                if let Err(error) = connection.await {
                    log::debug!("XHTTP H1 carrier ended: {error}");
                }
            });
            Sender::H1(tokio::sync::Mutex::new(sender))
        } else {
            let errors = TransportErrors::default();
            let (sender, mut connection) = h2::client::Builder::new()
                .initial_window_size(stream_window)
                .initial_connection_window_size(connection_window)
                .max_header_list_size(header_limit as u32)
                .handshake(errors.wrap(stream))
                .await
                .map_err(|error| errors.map(error))?;
            errors.start_driver();
            let mut ping = connection.ping_pong().unwrap();
            tasks.spawn(async move {
                if let Err(error) = connection.await {
                    log::debug!("XHTTP H2 carrier ended: {error}");
                }
            });
            // The handshake alone does not read peer SETTINGS. PONG follows their application.
            ping.ping(h2::Ping::opaque())
                .await
                .map_err(|error| errors.map(error))?;
            Sender::H2 { sender, errors }
        };
        Ok(Arc::new(Self {
            sender,
            retired: AtomicBool::new(false),
            _tasks: tasks,
            _quic: None,
        }))
    }

    pub async fn quic(carrier: QuicCarrier, header_limit: usize) -> io::Result<Arc<Self>> {
        let connection = super::h3::Connection::new(carrier.connection.clone());
        let opener = connection.opener();
        let (mut driver, sender) = h3::client::builder()
            .max_field_section_size(header_limit as u64)
            // Known-length peers can stop receiving before finish() writes its optional GREASE frame.
            .send_grease(false)
            .build(connection)
            .await
            .map_err(io::Error::other)?;
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let error = driver.wait_idle().await;
            log::debug!("XHTTP H3 carrier ended: {error}");
        });
        Ok(Arc::new(Self {
            sender: Sender::H3 {
                sender,
                opener,
                headers: tokio::sync::Mutex::new(()),
            },
            retired: AtomicBool::new(false),
            _tasks: tasks,
            _quic: Some(carrier),
        }))
    }

    pub fn closed(&self) -> bool {
        if self.retired.load(Ordering::Relaxed) || self._tasks.cancel.is_cancelled() {
            return true;
        }
        match &self.sender {
            Sender::H1(sender) => sender.try_lock().is_ok_and(|s| s.is_closed()),
            Sender::H2 { sender, .. } => matches!(
                sender
                    .clone()
                    .poll_ready(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                std::task::Poll::Ready(Err(_))
            ),
            Sender::H3 { sender, .. } => {
                sender.is_closing()
                    || sender.get_conn_error().is_some()
                    || self
                        ._quic
                        .as_ref()
                        .unwrap()
                        .connection
                        .close_reason()
                        .is_some()
            }
        }
    }

    pub fn capacity(&self, limit: usize) -> usize {
        match &self.sender {
            Sender::H1(_) => 1,
            Sender::H2 { sender, .. } => limit.min(sender.current_max_send_streams()),
            Sender::H3 { .. } => limit,
        }
    }

    pub fn try_reserve(&self) -> io::Result<Option<Reservation>> {
        if self.closed() {
            return Ok(None);
        }
        let Sender::H3 { opener, .. } = &self.sender else {
            return Ok(Some(Reservation(None)));
        };
        match opener
            .clone()
            .poll_reserve(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        {
            std::task::Poll::Ready(Ok(stream)) => Ok(Some(Reservation(Some(stream)))),
            std::task::Poll::Ready(Err(error)) => {
                self.retired.store(true, Ordering::Relaxed);
                Err(io::Error::other(error))
            }
            std::task::Poll::Pending => Ok(None),
        }
    }

    pub async fn reserve(&self) -> io::Result<Reservation> {
        if self.closed() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let Sender::H3 { opener, .. } = &self.sender else {
            return Ok(Reservation(None));
        };
        let mut opener = opener.clone();
        futures::future::poll_fn(|cx| opener.poll_reserve(cx))
            .await
            .map(|stream| Reservation(Some(stream)))
            .map_err(io::Error::other)
    }

    #[cfg(test)]
    pub async fn request(
        self: &Arc<Self>,
        request: Request<Body>,
        memory: Memory,
        tasks: &Tasks,
        header_timeout: Duration,
    ) -> io::Result<Response<Reader>> {
        let reservation = tokio::time::timeout(header_timeout, self.reserve()).await??;
        self.request_reserved(
            request,
            memory,
            tasks,
            Timeouts::headers(header_timeout),
            reservation,
        )
        .await
    }

    pub async fn request_reserved(
        self: &Arc<Self>,
        mut request: Request<Body>,
        memory: Memory,
        tasks: &Tasks,
        timeouts: Timeouts,
        reservation: Reservation,
    ) -> io::Result<Response<Reader>> {
        let (writer, reader) = pipe(memory);
        let (mut upload, watch) = match timeouts.upload_idle {
            Some(_) => {
                let (mut upload, watch) = Upload::channel();
                upload.written = request.extensions_mut().remove::<UploadSignal>();
                (Some(upload), Some(watch))
            }
            None => (None, None),
        };
        let result = match &self.sender {
            Sender::H1(sender) => {
                if let Some(upload) = upload.take() {
                    request = request.map(|body| body.track_h1(upload));
                }
                let authority = request
                    .uri()
                    .authority()
                    .ok_or_else(|| io::Error::other("missing XHTTP authority"))?
                    .to_string();
                request
                    .headers_mut()
                    .insert("host", authority.parse().map_err(io::Error::other)?);
                *request.uri_mut() = request
                    .uri()
                    .path_and_query()
                    .unwrap()
                    .as_str()
                    .parse()
                    .map_err(io::Error::other)?;
                let (future, guard) = tokio::time::timeout(timeouts.headers, async {
                    let mut sender = sender.lock().await;
                    sender.ready().await.map_err(io::Error::other)?;
                    // A cancelled partial H1 request cannot leave a reusable connection behind.
                    let guard = self._tasks.cancel.clone().drop_guard();
                    Ok::<_, io::Error>((sender.send_request(request), guard))
                })
                .await??;
                let response = timeouts
                    .response(
                        async { future.await.map_err(io::Error::other) },
                        watch,
                        &tasks.cancel,
                    )
                    .await?;
                guard.disarm();
                if response
                    .headers()
                    .get_all(http::header::CONNECTION)
                    .iter()
                    .any(|value| {
                        value.to_str().is_ok_and(|value| {
                            value
                                .split(',')
                                .any(|token| token.trim().eq_ignore_ascii_case("close"))
                        })
                    })
                {
                    self.retired.store(true, Ordering::Relaxed);
                }
                let (parts, incoming) = response.into_parts();
                let carrier = self.clone();
                tasks.spawn(async move {
                    let _carrier = carrier;
                    receive_hyper(incoming, writer, None).await;
                });
                Response::from_parts(parts, reader)
            }
            Sender::H2 { sender, errors } => {
                let (parts, body) = request.into_parts();
                let empty = hyper::body::Body::is_end_stream(&body);
                let streaming = matches!(&body, Body::Stream { .. });
                let mut sender = tokio::time::timeout(timeouts.headers, sender.clone().ready())
                    .await?
                    .map_err(|error| errors.map(error))?;
                let (response, mut send) = sender
                    .send_request(Request::from_parts(parts, ()), empty)
                    .map_err(|error| errors.map(error))?;
                let request_cancel = tasks.cancel.child_token();
                let guard = request_cancel.clone().drop_guard();
                if !empty {
                    let carrier = self.clone();
                    let cancel = tasks.cancel.clone();
                    let errors = errors.clone();
                    tasks.spawn(async move {
                        let _carrier = carrier;
                        let result = tokio::select! {
                            biased;
                            _ = request_cancel.cancelled() => Err(H2SendError::Local(io::ErrorKind::ConnectionAborted.into())),
                            result = send_h2_tracked(body, &mut send, upload, &errors) => result,
                        };
                        if let Err(error) = result {
                            // RFC 9113 section 8.1 allows an early response followed by NO_ERROR.
                            // Drain the response; its END_STREAM, not this reset, establishes EOF.
                            if streaming && error.peer_sent_no_error(&mut send) {
                                return;
                            }
                            let error = error.into_io();
                            log::debug!("XHTTP H2 upload failed: {error}");
                            send.send_reset(h2::Reason::CANCEL);
                            cancel.cancel();
                        }
                    });
                } else if let Some(upload) = &mut upload {
                    upload.finish();
                }
                let response = timeouts
                    .response(
                        async { response.await.map_err(|error| errors.map(error)) },
                        watch,
                        &tasks.cancel,
                    )
                    .await
                    .inspect_err(|error| {
                        if timeouts.upload_idle.is_none() && error.kind() == io::ErrorKind::TimedOut
                        {
                            self.retired.store(true, Ordering::Relaxed);
                        }
                    })?;
                guard.disarm();
                let (parts, incoming) = response.into_parts();
                let carrier = self.clone();
                let errors = errors.clone();
                tasks.spawn(async move {
                    let _carrier = carrier;
                    receive_h2_with_errors(incoming, writer, &errors).await;
                });
                Response::from_parts(parts, reader)
            }
            Sender::H3 {
                sender,
                opener,
                headers,
            } => {
                let (parts, mut body) = request.into_parts();
                let mut sender = sender.clone();
                let request = tokio::time::timeout(timeouts.headers, async {
                    let _lock = headers.lock().await;
                    let _handoff = opener.install(reservation.0.unwrap());
                    sender.send_request(Request::from_parts(parts, ())).await
                })
                .await
                .map_err(|error| {
                    self.retired.store(true, Ordering::Relaxed);
                    io::Error::from(error)
                })?
                .map_err(|error| {
                    self.retired.store(true, Ordering::Relaxed);
                    io::Error::other(error)
                })?;
                let (mut send, mut receive) = request.split();
                let carrier = self.clone();
                let cancel = tasks.cancel.clone();
                let request_cancel = tasks.cancel.child_token();
                let guard = request_cancel.clone().drop_guard();
                let mut sending = upload;
                tasks.spawn(async move {
                    let _carrier = carrier;
                    let result = tokio::select! {
                        biased;
                        _ = request_cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
                        result = send_h3(&mut body, &mut send, &mut sending) => result,
                    };
                    if let Err(error) = result {
                        log::debug!("XHTTP H3 upload failed: {error}");
                        send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                        cancel.cancel();
                    }
                });
                let response = timeouts
                    .response(
                        async { receive.recv_response().await.map_err(io::Error::other) },
                        watch,
                        &tasks.cancel,
                    )
                    .await?;
                guard.disarm();
                let carrier = self.clone();
                tasks.spawn(async move {
                    let _carrier = carrier;
                    let mut writer = writer;
                    let result: io::Result<()> = async {
                        while let Some(mut data) =
                            receive.recv_data().await.map_err(io::Error::other)?
                        {
                            while data.has_remaining() {
                                writer.write_all(data.chunk()).await?;
                                let len = data.chunk().len();
                                data.advance(len);
                            }
                        }
                        writer.shutdown().await
                    }
                    .await;
                    if let Err(error) = result {
                        receive.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                        writer.fail(error).await;
                    }
                });
                response.map(|_| reader)
            }
        };
        Ok(result)
    }
}

async fn send_h3(
    body: &mut Body,
    send: &mut h3::client::RequestStream<super::h3::Send, Bytes>,
    upload: &mut Option<Upload>,
) -> io::Result<()> {
    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(10), body.frame()).await {
            Ok(frame) => frame,
            Err(_) => {
                send.send_data(Bytes::new())
                    .await
                    .map_err(io::Error::other)?;
                continue;
            }
        };
        let Some(frame) = frame else {
            break;
        };
        if let Ok(data) = frame?.into_data() {
            let nonempty = !data.is_empty();
            send.send_data(data).await.map_err(io::Error::other)?;
            if nonempty && let Some(upload) = upload.as_ref() {
                upload.activity.touch();
            }
        }
    }
    send.finish().await.map_err(io::Error::other)?;
    if let Some(upload) = upload {
        upload.finish();
    }
    Ok(())
}

pub async fn receive_hyper(
    mut body: hyper::body::Incoming,
    mut writer: Writer,
    eof: Option<tokio_util::sync::CancellationToken>,
) {
    let result: io::Result<()> = async {
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                writer.write_all(&data).await?;
            }
        }
        if let Some(eof) = eof {
            eof.cancel();
        }
        writer.shutdown().await
    }
    .await;
    if let Err(error) = result {
        log::debug!("XHTTP H1 body failed: {error}");
        writer.fail(error).await;
    }
}

pub async fn receive_h2(body: h2::RecvStream, writer: Writer) {
    receive_h2_with_errors(body, writer, &TransportErrors::default()).await;
}

async fn receive_h2_with_errors(
    mut body: h2::RecvStream,
    mut writer: Writer,
    errors: &TransportErrors,
) {
    let result: io::Result<()> = async {
        while let Some(data) = body.data().await {
            let data = data.map_err(|error| errors.map(error))?;
            writer.write_all(&data).await?;
            body.flow_control()
                .release_capacity(data.len())
                .map_err(|error| errors.map(error))?;
        }
        writer.shutdown().await
    }
    .await;
    if let Err(error) = result {
        log::debug!("XHTTP H2 body failed: {error}");
        writer.fail(error).await;
    }
}

pub async fn send_h2(body: Body, mut send: h2::SendStream<Bytes>) -> io::Result<()> {
    send_h2_tracked(body, &mut send, None, &TransportErrors::default())
        .await
        .map_err(H2SendError::into_io)
}

#[derive(Debug)]
enum H2SendError {
    Local(io::Error),
    Stream(io::Error),
}

impl H2SendError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Local(error) | Self::Stream(error) => error,
        }
    }

    fn peer_sent_no_error(&self, send: &mut h2::SendStream<Bytes>) -> bool {
        // poll_capacity can return None and send_data can return a local stream-state error.
        // Consult the stream's reason without hiding errors from the body producer.
        matches!(self, Self::Stream(_))
            && matches!(
                send.poll_reset(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                std::task::Poll::Ready(Ok(h2::Reason::NO_ERROR))
            )
    }
}

async fn send_h2_tracked(
    mut body: Body,
    send: &mut h2::SendStream<Bytes>,
    mut upload: Option<Upload>,
    errors: &TransportErrors,
) -> Result<(), H2SendError> {
    'frames: loop {
        let frame = tokio::select! {
            frame = body.frame() => frame,
            reset = futures::future::poll_fn(|cx| send.poll_reset(cx)) => return Err(H2SendError::Stream(io::Error::other(format!("XHTTP H2 stream reset: {reset:?}")))),
        };
        let Some(frame) = frame else {
            send.send_data(Bytes::new(), true)
                .map_err(|error| H2SendError::Stream(errors.map(error)))?;
            break;
        };
        let Ok(mut data) = frame.map_err(H2SendError::Local)?.into_data() else {
            continue;
        };
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let capacity = futures::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .ok_or_else(|| H2SendError::Stream(io::ErrorKind::BrokenPipe.into()))?
                .map_err(|error| H2SendError::Stream(errors.map(error)))?;
            let len = capacity.min(data.len());
            if len == 0 {
                continue;
            }
            // Known-length peers may respond and reset immediately after the final bytes.
            let end = len == data.len() && hyper::body::Body::is_end_stream(&body);
            send.send_data(data.split_to(len), end)
                .map_err(|error| H2SendError::Stream(errors.map(error)))?;
            if let Some(upload) = &upload {
                upload.activity.touch();
            }
            if end {
                break 'frames;
            }
        }
    }
    if let Some(upload) = &mut upload {
        upload.finish();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
