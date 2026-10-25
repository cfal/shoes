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
mod tests {
    use super::*;
    use crate::resources::Budget;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn h2_readiness_and_established_receive_preserve_transport_causes() {
        use crate::http2::transport::tests::{cases, peer};
        tokio::time::timeout(Duration::from_secs(5), async {
            for ready in [false, true] {
                for (make_error, local) in cases() {
                    let (client, fault, mut sends, driver) = peer(make_error);
                    if !ready {
                        fault.inject();
                    }
                    let result = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192).await;
                    let error = if ready {
                        let carrier = result.unwrap();
                        let tasks = Tasks::new();
                        let memory = Memory::new(Arc::new(Budget::new(Some(16384))), Some(16384));
                        let request = Request::get("http://example.com/")
                            .body(Body::Empty)
                            .unwrap();
                        let mut response = carrier
                            .request(request, memory, &tasks, Duration::from_secs(1))
                            .await
                            .unwrap()
                            .into_body();
                        let _send = sends.recv().await.unwrap();
                        assert_eq!(response.read_u8().await.unwrap(), b'x');
                        fault.inject();
                        response.read_u8().await.unwrap_err()
                    } else {
                        result.err().expect("readiness PING must fail")
                    };
                    assert_eq!(
                        crate::clash_api::probes::local_failure(&error),
                        local,
                        "ready={ready}: {error:?}"
                    );
                    driver.abort();
                    let _ = driver.await;
                }
            }
        })
        .await
        .unwrap();
    }

    async fn h2_peer() -> (
        Arc<Carrier>,
        tokio::sync::mpsc::UnboundedReceiver<(
            Request<h2::RecvStream>,
            h2::server::SendResponse<Bytes>,
        )>,
        Tasks,
    ) {
        let (client, peer) = tokio::io::duplex(4096);
        let tasks = Tasks::new();
        let (requests, received) = tokio::sync::mpsc::unbounded_channel();
        tasks.spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(1024)
                .handshake(peer)
                .await
                .unwrap();
            while let Some(request) = connection.accept().await {
                if requests.send(request.unwrap()).is_err() {
                    break;
                }
            }
        });
        let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192)
            .await
            .unwrap();
        (carrier, received, tasks)
    }

    #[tokio::test]
    async fn h2_early_response_drains_after_no_error_reset() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for blocked_upload in [false, true] {
                for response_len in [0, 48 * 1024] {
                    let (carrier, mut requests, _server) = h2_peer().await;
                    let tasks = Tasks::new();
                    let budget = Arc::new(Budget::new(Some(16 * 1024)));
                    let memory = Memory::new(budget.clone(), Some(16 * 1024));
                    let (mut upload, body) = pipe(memory.clone());
                    let data = vec![7; if blocked_upload { 2048 } else { 1024 }];
                    upload.write_all(&data).await.unwrap();
                    let expected: Vec<_> = (0..response_len).map(|i| (i % 251) as u8).collect();
                    let request = Request::post("http://localhost/stream-one")
                        .body(Body::stream(body))
                        .unwrap();
                    let (response, ()) = tokio::join!(
                        carrier.request(request, memory.clone(), &tasks, Duration::from_secs(1)),
                        async {
                            let (request, mut respond) = requests.recv().await.unwrap();
                            let mut incoming = request.into_body();
                            assert_eq!(incoming.data().await.unwrap().unwrap(), &data[..1024]);
                            // Leave the upload open, including its exhausted window in the blocked case.
                            let mut send = respond
                                .send_response(Response::new(()), expected.is_empty())
                                .unwrap();
                            if !expected.is_empty() {
                                send.send_data(Bytes::copy_from_slice(&expected), true)
                                    .unwrap();
                            }
                            // h2 queues NO_ERROR after the complete response when these handles drop.
                        }
                    );
                    let mut response = response.unwrap().into_body();
                    upload.closed().await;
                    assert!(upload.write_all(b"after reset").await.is_err());
                    let mut actual = Vec::new();
                    response.read_to_end(&mut actual).await.unwrap();
                    assert_eq!(actual, expected);
                    tasks.wait().await;
                    assert!(!tasks.cancel.is_cancelled());
                    drop(response);
                    drop(upload);
                    assert_eq!(budget.snapshot().active, 0);

                    // The reset belongs to one stream, not the pooled connection.
                    let probe_tasks = Tasks::new();
                    let (probe, ()) = tokio::join!(
                        carrier.request(
                            Request::get("http://localhost/probe")
                                .body(Body::Empty)
                                .unwrap(),
                            memory,
                            &probe_tasks,
                            Duration::from_secs(1),
                        ),
                        async {
                            let (_, mut respond) = requests.recv().await.unwrap();
                            let mut send = respond.send_response(Response::new(()), false).unwrap();
                            send.send_data(Bytes::from_static(b"reused"), true).unwrap();
                        }
                    );
                    let mut actual = Vec::new();
                    probe
                        .unwrap()
                        .into_body()
                        .read_to_end(&mut actual)
                        .await
                        .unwrap();
                    assert_eq!(actual, b"reused");
                    probe_tasks.wait().await;
                    assert_eq!(budget.snapshot().active, 0);
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_upload_failures_and_truncated_responses_are_not_eof() {
        enum Failure {
            Reset(h2::Reason),
            Body,
            Cancel,
            Disconnect,
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            for failure in [
                Failure::Reset(h2::Reason::NO_ERROR),
                Failure::Reset(h2::Reason::CANCEL),
                Failure::Reset(h2::Reason::INTERNAL_ERROR),
                Failure::Body,
                Failure::Cancel,
                Failure::Disconnect,
            ] {
                let (carrier, mut requests, server) = h2_peer().await;
                let tasks = Tasks::new();
                let memory = Memory::new(Arc::new(Budget::new(Some(16 * 1024))), Some(16 * 1024));
                let (mut upload, body) = pipe(memory.clone());
                let request = Request::post("http://localhost/stream-one")
                    .body(Body::stream(body))
                    .unwrap();
                let (response, mut send) = tokio::join!(
                    carrier.request(request, memory, &tasks, Duration::from_secs(1)),
                    async {
                        let (_request, mut respond) = requests.recv().await.unwrap();
                        let mut send = respond.send_response(Response::new(()), false).unwrap();
                        send.send_data(Bytes::from_static(b"prefix"), false)
                            .unwrap();
                        send
                    }
                );
                let mut response = response.unwrap().into_body();
                let mut prefix = [0; 6];
                response.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"prefix");
                match failure {
                    Failure::Reset(reason) => send.send_reset(reason),
                    Failure::Body => upload.fail(io::ErrorKind::UnexpectedEof.into()).await,
                    Failure::Cancel => tasks.cancel.cancel(),
                    Failure::Disconnect => server.cancel.cancel(),
                }
                upload.closed().await;
                assert!(response.read(&mut [0; 1]).await.is_err());
                tasks.wait().await;
                let quiet = matches!(failure, Failure::Reset(h2::Reason::NO_ERROR));
                assert_eq!(tasks.cancel.is_cancelled(), !quiet);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_no_error_goaway_does_not_complete_a_truncated_response() {
        use bytes::{BufMut, BytesMut};

        fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Bytes {
            let mut frame = BytesMut::new();
            frame.put_uint(payload.len() as u64, 3);
            frame.put_u8(kind);
            frame.put_u8(flags);
            frame.put_u32(stream);
            frame.extend_from_slice(payload);
            frame.freeze()
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, mut peer) = tokio::io::duplex(4096);
            let server = Tasks::new();
            let shutdown = CancellationToken::new();
            let stop = shutdown.clone();
            let release_peer = CancellationToken::new();
            let release = release_peer.clone();
            server.spawn(async move {
                let mut preface = [0; 24];
                peer.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                peer.write_all(&frame(4, 0, 0, &[])).await.unwrap();
                loop {
                    let mut header = [0; 9];
                    peer.read_exact(&mut header).await.unwrap();
                    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                    let mut payload = vec![0; len];
                    peer.read_exact(&mut payload).await.unwrap();
                    match (header[3], header[4] & 1) {
                        // Acknowledge SETTINGS and the carrier's readiness PING.
                        (4, 0) => peer.write_all(&frame(4, 1, 0, &[])).await.unwrap(),
                        (6, 0) => peer.write_all(&frame(6, 1, 0, &payload)).await.unwrap(),
                        (1, _) => {
                            assert_eq!(&header[5..], &1_u32.to_be_bytes());
                            break;
                        }
                        _ => {}
                    }
                }
                // HEADERS (:status 200) and DATA without END_STREAM.
                peer.write_all(&frame(1, 4, 1, &[0x88])).await.unwrap();
                peer.write_all(&frame(0, 0, 1, b"prefix")).await.unwrap();
                stop.cancelled().await;
                // Exclude stream 1 from GOAWAY so it receives NO_ERROR, not transport EOF.
                peer.write_all(&frame(7, 0, 0, &[0; 8])).await.unwrap();
                release.cancelled().await;
                drop(peer);
            });
            let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192)
                .await
                .unwrap();
            let tasks = Tasks::new();
            let memory = Memory::new(Arc::new(Budget::new(Some(16 * 1024))), Some(16 * 1024));
            let (upload, body) = pipe(memory.clone());
            let mut response = carrier
                .request(
                    Request::post("http://localhost/stream-one")
                        .body(Body::stream(body))
                        .unwrap(),
                    memory,
                    &tasks,
                    Duration::from_secs(1),
                )
                .await
                .unwrap()
                .into_body();
            let mut prefix = [0; 6];
            response.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"prefix");
            shutdown.cancel();
            let error = response.read(&mut [0; 1]).await.unwrap_err();
            let error = error
                .get_ref()
                .unwrap()
                .downcast_ref::<h2::Error>()
                .unwrap();
            assert!(error.is_go_away());
            assert_eq!(error.reason(), Some(h2::Reason::NO_ERROR));
            upload.closed().await;
            tasks.wait().await;
            assert!(!tasks.cancel.is_cancelled());
            release_peer.cancel();
            server.wait().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_early_response_does_not_acknowledge_incomplete_packet() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (carrier, mut requests, _server) = h2_peer().await;
            let tasks = Tasks::new();
            let budget = Arc::new(Budget::new(Some(16 * 1024)));
            let memory = Memory::new(budget.clone(), Some(16 * 1024));
            let (signal, written) = UploadSignal::channel();
            let request = Request::post("http://localhost/packet/0")
                .extension(signal)
                .body(Body::Chunks(vec![memory.copy(&[7; 2048]).unwrap()].into()))
                .unwrap();
            let reservation = carrier.reserve().await.unwrap();
            let (response, ()) = tokio::join!(
                carrier.request_reserved(
                    request,
                    memory,
                    &tasks,
                    Timeouts::packet(Duration::from_secs(1), Duration::from_secs(1)),
                    reservation,
                ),
                async {
                    let (request, mut respond) = requests.recv().await.unwrap();
                    let mut incoming = request.into_body();
                    assert_eq!(incoming.data().await.unwrap().unwrap().len(), 1024);
                    respond.send_response(Response::new(()), true).unwrap();
                }
            );
            assert!(response.is_err());
            assert!(written.await.is_err());
            tasks.wait().await;
            assert!(tasks.cancel.is_cancelled());
            assert_eq!(budget.snapshot().active, 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_no_error_does_not_hide_body_errors_or_finish_server_sends() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (carrier, mut requests, _server) = h2_peer().await;
            let Sender::H2 { sender, .. } = &carrier.sender else {
                unreachable!()
            };
            let mut sender = sender.clone().ready().await.unwrap();
            let (response, mut send) = sender
                .send_request(
                    Request::post("http://localhost/stream-one")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let (request, mut respond) = requests.recv().await.unwrap();
            respond.send_response(Response::new(()), true).unwrap();
            drop((request, respond));
            let reason = futures::future::poll_fn(|cx| send.poll_reset(cx))
                .await
                .unwrap();
            assert_eq!(reason, h2::Reason::NO_ERROR);

            assert!(
                futures::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .is_none()
            );
            let error = H2SendError::Stream(io::ErrorKind::BrokenPipe.into());
            assert!(error.peer_sent_no_error(&mut send));
            // A reset can arrive between the body EOF poll and sending the final DATA frame.
            let error = H2SendError::Stream(io::Error::other(
                send.send_data(Bytes::new(), true).unwrap_err(),
            ));
            assert!(error.peer_sent_no_error(&mut send));
            let error = H2SendError::Local(io::ErrorKind::UnexpectedEof.into());
            assert!(!error.peer_sent_no_error(&mut send));
            assert!(send_h2(Body::Empty, send).await.is_err());
            assert!(response.await.unwrap().into_body().data().await.is_none());
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn packet_response_wait_requires_upload_completion_and_observes_cancellation() {
        let timeouts = Timeouts::packet(Duration::from_secs(1), Duration::from_secs(10));
        let (upload, watch) = Upload::channel();
        let cancel = CancellationToken::new();
        let mut response =
            Box::pin(timeouts.response(async { Ok(Response::new(())) }, Some(watch), &cancel));
        assert!(futures::poll!(&mut response).is_pending());
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(9)).await;
            upload.activity.touch();
            assert!(futures::poll!(&mut response).is_pending());
        }
        tokio::time::advance(Duration::from_millis(9999)).await;
        assert!(futures::poll!(&mut response).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(response.await.unwrap_err().kind(), io::ErrorKind::TimedOut);

        let (mut upload, watch) = Upload::channel();
        upload.finish();
        let mut response = Box::pin(timeouts.response(
            std::future::pending::<io::Result<Response<()>>>(),
            Some(watch),
            &cancel,
        ));
        assert!(futures::poll!(&mut response).is_pending());
        tokio::time::advance(Duration::from_secs(1000)).await;
        assert!(futures::poll!(&mut response).is_pending());
        cancel.cancel();
        assert_eq!(
            response.await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );

        let (_upload, watch) = Upload::channel();
        let error = timeouts
            .response(
                async { Ok(Response::builder().status(413).body(()).unwrap()) },
                Some(watch),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("413"));
    }
}
