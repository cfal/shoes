use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;

use super::stream::{Body, Memory, Reader, Tasks, Writer, pipe};
use crate::{
    async_stream::AsyncStream, config::xhttp::XhttpVersion, tcp::carrier_dialer::QuicCarrier,
};

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

enum Sender {
    H1(tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Body>>),
    H2(h2::client::SendRequest<Bytes>),
    H3(H3Sender),
}

pub struct Carrier {
    sender: Sender,
    retired: AtomicBool,
    _tasks: Tasks,
    _quic: Option<QuicCarrier>,
}

impl Carrier {
    pub async fn tcp(
        stream: Box<dyn AsyncStream>,
        version: XhttpVersion,
        header_limit: usize,
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
            let (sender, connection) = h2::client::Builder::new()
                .initial_window_size(256 * 1024)
                .initial_connection_window_size(256 * 1024)
                .max_header_list_size(header_limit as u32)
                .handshake(stream)
                .await
                .map_err(io::Error::other)?;
            tasks.spawn(async move {
                if let Err(error) = connection.await {
                    log::debug!("XHTTP H2 carrier ended: {error}");
                }
            });
            Sender::H2(sender)
        };
        Ok(Arc::new(Self {
            sender,
            retired: AtomicBool::new(false),
            _tasks: tasks,
            _quic: None,
        }))
    }

    pub async fn quic(carrier: QuicCarrier, header_limit: usize) -> io::Result<Arc<Self>> {
        let (mut driver, sender) = h3::client::builder()
            .max_field_section_size(header_limit as u64)
            .build(h3_quinn::Connection::new(carrier.connection.clone()))
            .await
            .map_err(io::Error::other)?;
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let error = driver.wait_idle().await;
            log::debug!("XHTTP H3 carrier ended: {error}");
        });
        Ok(Arc::new(Self {
            sender: Sender::H3(sender),
            retired: AtomicBool::new(false),
            _tasks: tasks,
            _quic: Some(carrier),
        }))
    }

    pub fn closed(&self) -> bool {
        if self.retired.load(Ordering::Relaxed) {
            return true;
        }
        match &self.sender {
            Sender::H1(sender) => sender.try_lock().is_ok_and(|s| s.is_closed()),
            Sender::H2(sender) => matches!(
                sender
                    .clone()
                    .poll_ready(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                std::task::Poll::Ready(Err(_))
            ),
            Sender::H3(_) => self
                ._quic
                .as_ref()
                .unwrap()
                .connection
                .close_reason()
                .is_some(),
        }
    }

    pub async fn request(
        self: &Arc<Self>,
        mut request: Request<Body>,
        memory: Memory,
        tasks: &Tasks,
        header_timeout: Duration,
    ) -> io::Result<Response<Reader>> {
        let (writer, reader) = pipe(memory);
        let result = match &self.sender {
            Sender::H1(sender) => {
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
                let future = tokio::time::timeout(header_timeout, async {
                    let mut sender = sender.lock().await;
                    sender.ready().await.map_err(io::Error::other)?;
                    Ok::<_, io::Error>(sender.send_request(request))
                })
                .await??;
                let response = tokio::time::timeout(header_timeout, future)
                    .await?
                    .map_err(io::Error::other)?;
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
                    receive_hyper(incoming, writer).await;
                });
                Response::from_parts(parts, reader)
            }
            Sender::H2(sender) => {
                let (parts, body) = request.into_parts();
                let empty = hyper::body::Body::is_end_stream(&body);
                let mut sender = tokio::time::timeout(header_timeout, sender.clone().ready())
                    .await?
                    .map_err(io::Error::other)?;
                let (response, send) = sender
                    .send_request(Request::from_parts(parts, ()), empty)
                    .map_err(io::Error::other)?;
                if !empty {
                    let carrier = self.clone();
                    let cancel = tasks.cancel.clone();
                    tasks.spawn(async move {
                        let _carrier = carrier;
                        if let Err(error) = send_h2(body, send).await {
                            log::debug!("XHTTP H2 upload failed: {error}");
                            cancel.cancel();
                        }
                    });
                }
                let response = tokio::time::timeout(header_timeout, response)
                    .await?
                    .map_err(io::Error::other)?;
                let (parts, incoming) = response.into_parts();
                let carrier = self.clone();
                tasks.spawn(async move {
                    let _carrier = carrier;
                    receive_h2(incoming, writer).await;
                });
                Response::from_parts(parts, reader)
            }
            Sender::H3(sender) => {
                let (parts, mut body) = request.into_parts();
                let mut sender = sender.clone();
                let request = tokio::time::timeout(
                    header_timeout,
                    sender.send_request(Request::from_parts(parts, ())),
                )
                .await?
                .map_err(|error| {
                    // h3 exposes no readiness probe. Stop assigning requests after
                    // an open failure without closing any already-active streams.
                    self.retired.store(true, Ordering::Relaxed);
                    io::Error::other(error)
                })?;
                let (mut send, mut receive) = request.split();
                let carrier = self.clone();
                let cancel = tasks.cancel.clone();
                tasks.spawn(async move {
                    let _carrier = carrier;
                    let result: io::Result<()> = async {
                        while let Some(frame) = body.frame().await {
                            if let Ok(data) = frame?.into_data() {
                                send.send_data(data).await.map_err(io::Error::other)?;
                            }
                        }
                        send.finish().await.map_err(io::Error::other)
                    }
                    .await;
                    if let Err(error) = result {
                        log::debug!("XHTTP H3 upload failed: {error}");
                        send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                        cancel.cancel();
                    }
                });
                let response = tokio::time::timeout(header_timeout, receive.recv_response())
                    .await?
                    .map_err(io::Error::other)?;
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

pub async fn receive_hyper(mut body: hyper::body::Incoming, mut writer: Writer) {
    let result: io::Result<()> = async {
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                writer.write_all(&data).await?;
            }
        }
        writer.shutdown().await
    }
    .await;
    if let Err(error) = result {
        log::debug!("XHTTP H1 body failed: {error}");
        writer.fail(error).await;
    }
}

pub async fn receive_h2(mut body: h2::RecvStream, mut writer: Writer) {
    let result: io::Result<()> = async {
        while let Some(data) = body.data().await {
            let data = data.map_err(io::Error::other)?;
            writer.write_all(&data).await?;
            body.flow_control()
                .release_capacity(data.len())
                .map_err(io::Error::other)?;
        }
        writer.shutdown().await
    }
    .await;
    if let Err(error) = result {
        log::debug!("XHTTP H2 body failed: {error}");
        writer.fail(error).await;
    }
}

pub async fn send_h2(mut body: Body, mut send: h2::SendStream<Bytes>) -> io::Result<()> {
    loop {
        let frame = tokio::select! {
            frame = body.frame() => frame,
            reset = futures::future::poll_fn(|cx| send.poll_reset(cx)) => return Err(io::Error::other(format!("XHTTP H2 stream reset: {reset:?}"))),
        };
        let Some(frame) = frame else {
            break;
        };
        let Ok(mut data) = frame?.into_data() else {
            continue;
        };
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let capacity = futures::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
                .map_err(io::Error::other)?;
            let len = capacity.min(data.len());
            if len != 0 {
                send.send_data(data.split_to(len), false)
                    .map_err(io::Error::other)?;
            }
        }
    }
    send.send_data(Bytes::new(), true).map_err(io::Error::other)
}
