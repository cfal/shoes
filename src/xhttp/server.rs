use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::IpAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;

use super::{
    carrier,
    stream::{Body, Memory, Reader, Stream, Tasks, Writer, pipe},
    wire::{self, Kind, Path},
};
use crate::{
    async_stream::AsyncStream,
    client_proxy_selector::ClientProxySelector,
    config::xhttp::{XhttpServerConfig, XhttpVersion},
    resolver::Resolver,
    resources::{Budget, BudgetPermit},
    tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
};

#[derive(Clone, Debug)]
pub struct XhttpServer {
    state: Arc<State>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Debug)]
    struct Echo;
    #[async_trait]
    impl TcpServerHandler for Echo {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::Session(Box::pin(async move {
                let mut buffer = [0; 1024];
                while let Ok(size) = stream.read(&mut buffer).await {
                    if size == 0 {
                        let _ = stream.shutdown().await;
                        break;
                    }
                    if stream.write_all(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
            })))
        }
    }

    fn service() -> Arc<State> {
        let config: XhttpServerConfig = serde_json::from_value(json!({"path":"/t", "sc_max_buffered_posts":2, "sc_max_each_post_bytes":16, "limits":{"max_sessions":2,"max_pending_sessions":2},"protocol":{"type":"socks"}})).unwrap();
        Arc::new(State {
            path: Path::new(&config.path).unwrap(),
            inner: Arc::new(Echo),
            resolver: Arc::new(crate::resolver::NativeResolver::new()),
            memory: Arc::new(Budget::new(Some(1024))),
            admission: Arc::new(Budget::new(Some(2))),
            sessions: parking_lot::Mutex::new(HashMap::new()),
            tasks: Tasks::new(),
            config,
        })
    }

    async fn request(
        state: &Arc<State>,
        method: &str,
        suffix: &str,
        data: &[u8],
    ) -> Response<Body> {
        let request = Request::builder()
            .method(method)
            .uri(format!("http://localhost/t/{suffix}"))
            .header(
                "referer",
                format!("https://localhost/t/?x_padding={}", "X".repeat(100)),
            )
            .body(())
            .unwrap();
        let (mut writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();
        state.handle(request, body).await
    }

    #[tokio::test]
    async fn packet_reordering_duplicates_and_download_ownership() {
        let state = service();
        assert_eq!(
            request(&state, "POST", "a/1", b"second").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/1", b"second").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/1", b"different").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "a/0", b"first").await.status(),
            StatusCode::OK
        );
        let response = request(&state, "GET", "a", b"").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        let mut body = response.into_body();
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            while data.len() < 11 {
                data.extend(body.frame().await.unwrap().unwrap().into_data().unwrap());
            }
        })
        .await
        .unwrap();
        assert_eq!(data, b"firstsecond");
        assert_eq!(
            request(&state, "POST", "a/2", b"").await.status(),
            StatusCode::OK
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), body.frame())
                .await
                .is_err()
        );
        drop(body);
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        state.close("a");
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn orphan_expiry_and_tombstones_release_admission() {
        let state = service();
        assert_eq!(
            request(&state, "POST", "a/1", b"queued").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "b/1", b"queued").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "GET", "c", b"").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        tokio::task::yield_now().await;
        assert!(state.sessions.lock().is_empty());
        assert_eq!(
            request(&state, "GET", "c", b"").await.status(),
            StatusCode::OK
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        tokio::task::yield_now().await;
        assert!(state.sessions.lock().is_empty());
    }

    #[tokio::test]
    async fn queue_exhaustion_oversize_and_stream_conflicts_are_bounded() {
        let state = service();
        assert_eq!(
            request(&state, "POST", "a/2", b"x").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/3", b"x").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/4", b"x").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "b/0", &[0; 17]).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            request(&state, "GET", "b", b"").await.status(),
            StatusCode::CONFLICT
        );
        let state = service();
        let response = request(&state, "POST", "a", b"payload").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            request(&state, "POST", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "a/0", b"x").await.status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn stream_one_admission_and_service_drop_release_resources() {
        let state = service();
        let first = request(&state, "POST", "", b"first").await;
        let second = request(&state, "POST", "", b"second").await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            request(&state, "POST", "", b"third").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(first);
        assert_eq!(
            request(&state, "POST", "", b"third").await.status(),
            StatusCode::OK
        );
        drop(second);
        let memory = state.memory.clone();
        let weak = Arc::downgrade(&state);
        let upload = request(&state, "POST", "orphan", b"queued").await;
        drop(upload);
        drop(state);
        tokio::task::yield_now().await;
        assert!(weak.upgrade().is_none());
        assert_eq!(memory.snapshot().active, 0);
    }
}

struct State {
    config: XhttpServerConfig,
    path: Path,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    memory: Arc<Budget>,
    admission: Arc<Budget>,
    sessions: parking_lot::Mutex<HashMap<String, Entry>>,
    tasks: Tasks,
}
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpService").finish_non_exhaustive()
    }
}

enum Entry {
    Live(Arc<Session>),
    Closed {
        when: tokio::time::Instant,
        _permit: BudgetPermit,
    },
}
#[derive(Default, PartialEq)]
enum Upload {
    #[default]
    Unclaimed,
    Packet,
    Stream,
}
struct SessionState {
    upload: Upload,
    writer: Option<Writer>,
    reader: Option<Reader>,
    pending: BTreeMap<u64, Vec<Bytes>>,
    next: u64,
    downloaded: bool,
    permit: Option<BudgetPermit>,
}
struct Session {
    state: parking_lot::Mutex<SessionState>,
    memory: Memory,
    ready: Notify,
    cancel: CancellationToken,
    created: tokio::time::Instant,
    admission: parking_lot::Mutex<Option<BudgetPermit>>,
}

struct DownloadGuard {
    state: Weak<State>,
    id: String,
    cancel: CancellationToken,
}
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(state) = self.state.upgrade() {
            state.close(&self.id);
        }
    }
}

impl XhttpServer {
    pub fn new(
        config: XhttpServerConfig,
        selector: &Arc<ClientProxySelector>,
        resolver: &Arc<dyn Resolver>,
        bind_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        config.validate()?;
        let inner = crate::tcp::tcp_server_handler_factory::create_tcp_server_handler(
            *config.protocol.clone(),
            selector,
            resolver,
            bind_ip,
        )?
        .into();
        let state = Arc::new(State {
            path: Path::new(&config.path)?,
            inner,
            resolver: resolver.clone(),
            memory: Arc::new(Budget::new(Some(config.limits.max_buffered_bytes))),
            admission: Arc::new(Budget::new(Some(config.limits.max_sessions))),
            sessions: parking_lot::Mutex::new(HashMap::new()),
            tasks: Tasks::new(),
            config,
        });
        let weak = Arc::downgrade(&state);
        state.tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(state) = weak.upgrade() else {
                    break;
                };
                state.reap();
            }
        });
        Ok(Self { state })
    }

    pub async fn serve_h3(&self, connection: quinn::Connection) -> io::Result<()> {
        let mut driver = h3::server::builder()
            .max_field_section_size(self.state.config.header_limit() as u64)
            .build(h3_quinn::Connection::new(connection))
            .await
            .map_err(io::Error::other)?;
        let mut requests = tokio::task::JoinSet::new();
        loop {
            let resolver = tokio::select! {
                result = driver.accept() => result.map_err(io::Error::other)?,
                _ = requests.join_next(), if !requests.is_empty() => continue,
            };
            let Some(resolver) = resolver else {
                return Ok(());
            };
            if requests.len() >= self.state.config.limits.request_limit() {
                drop(resolver);
                continue;
            }
            let state = self.state.clone();
            requests.spawn(async move {
                let Ok(Ok((request, stream))) = tokio::time::timeout(
                    Duration::from_secs(state.config.limits.setup_timeout_secs),
                    resolver.resolve_request(),
                )
                .await
                else {
                    return;
                };
                let (mut send, mut receive) = stream.split();
                let workers = Tasks::new();
                let memory = Memory::new(
                    state.memory.clone(),
                    state.config.limits.max_session_buffered_bytes,
                );
                let (mut writer, reader) = pipe(memory);
                workers.spawn(async move {
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
                let response = state.handle(request, reader).await;
                let (parts, mut body) = response.into_parts();
                let result: io::Result<()> = async {
                    send.send_response(Response::from_parts(parts, ()))
                        .await
                        .map_err(io::Error::other)?;
                    loop {
                        // h3 0.0.8 has no send-side cancellation waiter. An empty
                        // DATA frame detects STOP_SENDING without changing the
                        // inner byte stream or closing a shared QUIC connection.
                        let frame =
                            match tokio::time::timeout(Duration::from_secs(10), body.frame()).await
                            {
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
                            send.send_data(data).await.map_err(io::Error::other)?;
                        }
                    }
                    send.finish().await.map_err(io::Error::other)
                }
                .await;
                if result.is_err() {
                    send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                }
            });
        }
    }
}

#[async_trait]
impl TcpServerHandler for XhttpServer {
    async fn setup_server_stream(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let state = self.state.clone();
        let version = state.config.http_version;
        if version == XhttpVersion::H3 {
            return Err(io::Error::other("H3 requires a QUIC listener"));
        }
        let mut prefix = [0; 3];
        tokio::time::timeout(
            Duration::from_secs(state.config.limits.setup_timeout_secs),
            stream.read_exact(&mut prefix),
        )
        .await??;
        let h2 = &prefix == b"PRI";
        if (version == XhttpVersion::H1 && h2) || (version == XhttpVersion::H2 && !h2) {
            return Err(io::Error::other("unexpected XHTTP version"));
        }
        let stream = crate::prepend_stream::PrependStream::new(stream, Some(Box::new(prefix)));
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let result = if h2 {
                state.serve_h2(Box::new(stream)).await
            } else {
                state.serve_h1(Box::new(stream)).await
            };
            if let Err(error) = result {
                log::debug!("XHTTP carrier ended: {error}");
            }
        })))
    }
}

impl State {
    fn close(&self, id: &str) {
        let mut sessions = self.sessions.lock();
        if !matches!(sessions.get(id), Some(Entry::Live(_))) {
            return;
        }
        if let Some(Entry::Live(session)) = sessions.remove(id) {
            session.cancel.cancel();
            if let Some(permit) = session.admission.lock().take() {
                sessions.insert(
                    id.into(),
                    Entry::Closed {
                        when: tokio::time::Instant::now(),
                        _permit: permit,
                    },
                );
            }
        }
    }

    fn reap(&self) {
        self.sessions.lock().retain(|_, entry| match entry {
            Entry::Closed { when, .. } => when.elapsed() < Duration::from_secs(30),
            Entry::Live(session) => {
                if !session.state.lock().downloaded
                    && session.created.elapsed() >= Duration::from_secs(30)
                {
                    session.cancel.cancel();
                    false
                } else {
                    true
                }
            }
        });
    }

    fn session(&self, id: &str) -> Result<Arc<Session>, StatusCode> {
        let mut sessions = self.sessions.lock();
        if let Some(entry) = sessions.get(id) {
            return match entry {
                Entry::Live(s) if !s.cancel.is_cancelled() => Ok(s.clone()),
                Entry::Live(_) => Err(StatusCode::CONFLICT),
                Entry::Closed { .. } => Err(StatusCode::CONFLICT),
            };
        }
        if sessions.len() >= self.config.limits.max_sessions
            || sessions
                .values()
                .filter(|entry| matches!(entry, Entry::Live(s) if !s.state.lock().downloaded))
                .count()
                >= self.config.limits.max_pending_sessions
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let permit = crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let admission = self
            .admission
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let memory = Memory::new(
            self.memory.clone(),
            self.config.limits.max_session_buffered_bytes,
        );
        let (writer, reader) = pipe(memory.clone());
        let session = Arc::new(Session {
            state: parking_lot::Mutex::new(SessionState {
                upload: Upload::Unclaimed,
                writer: Some(writer),
                reader: Some(reader),
                pending: BTreeMap::new(),
                next: 0,
                downloaded: false,
                permit: Some(permit),
            }),
            memory,
            ready: Notify::new(),
            cancel: CancellationToken::new(),
            created: tokio::time::Instant::now(),
            admission: parking_lot::Mutex::new(Some(admission)),
        });
        sessions.insert(id.into(), Entry::Live(session.clone()));
        Ok(session)
    }

    fn response(&self, status: StatusCode, body: Body, downstream: bool) -> Response<Body> {
        let mut response = Response::builder()
            .status(status)
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .header("access-control-allow-origin", "*")
            .header(
                "x-padding",
                "X".repeat(wire::sample(
                    self.config
                        .x_padding_bytes
                        .bounds((100, 1000), false)
                        .unwrap(),
                ) as usize),
            );
        if downstream && !self.config.no_sse_header {
            response = response.header("content-type", "text/event-stream");
        }
        response.body(body).unwrap()
    }

    fn spawn_inner_session(&self, stream: Stream, permit: BudgetPermit, cancel: CancellationToken) {
        let inner = self.inner.clone();
        let resolver = self.resolver.clone();
        let timeout = Duration::from_secs(self.config.limits.setup_timeout_secs);
        self.tasks.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {},
                result = crate::tcp::tcp_server::process_stream_with_permit(
                    stream, inner, resolver, permit, timeout,
                ) => {
                    if let Err(error) = result {
                        log::debug!("XHTTP inner session failed: {error}");
                    }
                }
            }
        });
    }

    async fn dispatch(
        self: &Arc<Self>,
        request: &Request<()>,
        mut body: Reader,
    ) -> Result<(Body, bool), StatusCode> {
        match wire::classify(&self.config, &self.path, request)? {
            Kind::Options => Ok((Body::Empty, false)),
            Kind::One => {
                let admission = self
                    .admission
                    .acquire(1)
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                let permit =
                    crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                let memory = Memory::new(
                    self.memory.clone(),
                    self.config.limits.max_session_buffered_bytes,
                );
                let (writer, reader) = pipe(memory);
                let tasks = Arc::new(Tasks::new());
                let stream = Stream {
                    read: body,
                    write: writer,
                    _tasks: tasks.clone(),
                };
                // The response owns the guard. The session future owns only the
                // token, not the task collection which would retain itself.
                self.spawn_inner_session(stream, permit, tasks.cancel.clone());
                Ok((
                    Body::stream(reader).with_guard((tasks.cancel.clone().drop_guard(), admission)),
                    true,
                ))
            }
            Kind::Download(id) => {
                let session = self.session(&id)?;
                let (reader, permit) = {
                    let mut state = session.state.lock();
                    if state.downloaded {
                        return Err(StatusCode::CONFLICT);
                    }
                    state.downloaded = true;
                    (state.reader.take().unwrap(), state.permit.take().unwrap())
                };
                let (writer, output) = pipe(session.memory.clone());
                let tasks = Arc::new(Tasks::new());
                let stream = Stream {
                    read: reader,
                    write: writer,
                    _tasks: tasks,
                };
                self.spawn_inner_session(stream, permit, session.cancel.clone());
                let guard = DownloadGuard {
                    state: Arc::downgrade(self),
                    id,
                    cancel: session.cancel.clone(),
                };
                Ok((Body::stream(output).with_guard(guard), true))
            }
            Kind::Upload(id) => {
                let session = self.session(&id)?;
                let mut writer = {
                    let mut state = session.state.lock();
                    if state.upload != Upload::Unclaimed {
                        return Err(StatusCode::CONFLICT);
                    }
                    state.upload = Upload::Stream;
                    state.writer.take().unwrap()
                };
                let (mut padding_writer, padding_reader) = pipe(session.memory.clone());
                let interval = if request
                    .headers()
                    .get("referer")
                    .is_some_and(|v| !v.is_empty())
                {
                    self.config
                        .sc_stream_up_server_secs
                        .bounds((20, 80), true)
                        .unwrap()
                } else {
                    (0, 0)
                };
                let padding = self
                    .config
                    .x_padding_bytes
                    .bounds((100, 1000), false)
                    .unwrap();
                let cancel = session.cancel.clone();
                self.tasks.spawn(async move {
                    let upload = async {
                        tokio::io::copy(&mut body, &mut writer).await?;
                        writer.shutdown().await
                    };
                    let padding = async {
                        if interval.1 == 0 {
                            std::future::pending::<()>().await;
                        }
                        loop {
                            padding_writer
                                .write_all(&vec![b'X'; wire::sample(padding) as usize])
                                .await?;
                            tokio::time::sleep(Duration::from_secs(wire::sample(interval) as u64))
                                .await;
                        }
                        #[allow(unreachable_code)]
                        Ok::<_, io::Error>(())
                    };
                    tokio::select! {
                        _ = cancel.cancelled() => {},
                        result = upload => {
                            if result.is_err() {
                                cancel.cancel();
                            }
                        },
                        _ = padding => { cancel.cancel(); }
                    }
                    let _ = padding_writer.shutdown().await;
                });
                Ok((Body::stream(padding_reader), false))
            }
            Kind::Packet(id, sequence) => {
                let session = self.session(&id)?;
                let max = self
                    .config
                    .sc_max_each_post_bytes
                    .bounds((1_000_000, 1_000_000), false)
                    .unwrap()
                    .1 as usize;
                let initial =
                    wire::header_payload(request.headers()).map_err(|_| StatusCode::BAD_REQUEST)?;
                let mut size = initial.len();
                if size > max {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                let mut chunks = vec![
                    session
                        .memory
                        .copy(&initial)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                ];
                tokio::time::timeout(
                    Duration::from_secs(self.config.limits.packet_timeout_secs),
                    async {
                        let mut buffer = [0; super::stream::CHUNK];
                        loop {
                            let len = body
                                .read(&mut buffer)
                                .await
                                .map_err(|_| StatusCode::BAD_REQUEST)?;
                            if len == 0 {
                                break;
                            }
                            size = size.checked_add(len).ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
                            if size > max {
                                return Err(StatusCode::PAYLOAD_TOO_LARGE);
                            }
                            chunks.push(
                                session
                                    .memory
                                    .copy(&buffer[..len])
                                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                            );
                        }
                        Ok::<_, StatusCode>(())
                    },
                )
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
                let writer = {
                    let mut state = session.state.lock();
                    if state.upload == Upload::Stream {
                        return Err(StatusCode::CONFLICT);
                    }
                    state.upload = Upload::Packet;
                    if sequence < state.next {
                        return Ok((Body::Empty, false));
                    }
                    if let Some(previous) = state.pending.get(&sequence) {
                        if previous
                            .iter()
                            .flat_map(|b| b.iter())
                            .eq(chunks.iter().flat_map(|b| b.iter()))
                        {
                            return Ok((Body::Empty, false));
                        }
                        return Err(StatusCode::CONFLICT);
                    }
                    if state.pending.len() >= self.config.buffered_posts() {
                        session.cancel.cancel();
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    state.pending.insert(sequence, chunks);
                    state.writer.take()
                };
                if let Some(mut writer) = writer {
                    let session = session.clone();
                    self.tasks.spawn(async move {
                        let work = async {
                            loop {
                                let chunks = {
                                    let mut state = session.state.lock();
                                    let next = state.next;
                                    let chunks = state.pending.remove(&next);
                                    if chunks.is_some() {
                                        state.next = next.checked_add(1).ok_or_else(|| {
                                            io::Error::other("sequence exhausted")
                                        })?;
                                    }
                                    chunks
                                };
                                match chunks {
                                    Some(chunks) => {
                                        for chunk in chunks {
                                            writer.forward(chunk).await?;
                                        }
                                    }
                                    None => session.ready.notified().await,
                                }
                            }
                            #[allow(unreachable_code)]
                            Ok::<_, io::Error>(())
                        };
                        tokio::select! {
                            _ = session.cancel.cancelled() => {},
                            _ = work => { session.cancel.cancel(); }
                        }
                    });
                }
                session.ready.notify_one();
                Ok((Body::Empty, false))
            }
        }
    }

    async fn handle(self: &Arc<Self>, request: Request<()>, body: Reader) -> Response<Body> {
        let result = self.dispatch(&request, body).await;
        let mut response = match result {
            Ok((body, downstream)) => self.response(StatusCode::OK, body, downstream),
            Err(status) => {
                if status != StatusCode::CONFLICT
                    && let Ok(Kind::Packet(id, _)) =
                        wire::classify(&self.config, &self.path, &request)
                {
                    self.close(&id);
                }
                self.response(status, Body::Empty, false)
            }
        };
        if let Some(origin) = request
            .headers()
            .get("origin")
            .filter(|value| !value.is_empty())
        {
            response
                .headers_mut()
                .insert("access-control-allow-origin", origin.clone());
        }
        if request.method() == http::Method::OPTIONS {
            for (requested, allowed) in [
                (
                    "access-control-request-method",
                    "access-control-allow-methods",
                ),
                (
                    "access-control-request-headers",
                    "access-control-allow-headers",
                ),
            ] {
                response.headers_mut().insert(
                    allowed,
                    request
                        .headers()
                        .get(requested)
                        .filter(|value| !value.is_empty())
                        .cloned()
                        .unwrap_or(http::HeaderValue::from_static("*")),
                );
            }
        }
        response
    }

    async fn serve_h1(self: Arc<Self>, stream: Box<dyn AsyncStream>) -> io::Result<()> {
        let header_limit = self.config.header_limit();
        let header_timeout = Duration::from_secs(self.config.limits.setup_timeout_secs);
        let tasks = Arc::new(Tasks::new());
        let owner = tasks.clone();
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
            let state = self.clone();
            let tasks = tasks.clone();
            async move {
                let (parts, body) = request.into_parts();
                let (writer, reader) = pipe(Memory::new(
                    state.memory.clone(),
                    state.config.limits.max_session_buffered_bytes,
                ));
                tasks.spawn(carrier::receive_hyper(body, writer));
                Ok::<_, io::Error>(state.handle(Request::from_parts(parts, ()), reader).await)
            }
        });
        let result = hyper::server::conn::http1::Builder::new()
            .half_close(true)
            .max_buf_size(header_limit.max(8192))
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(header_timeout)
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await
            .map_err(io::Error::other);
        drop(owner);
        result
    }

    async fn serve_h2(self: Arc<Self>, stream: Box<dyn AsyncStream>) -> io::Result<()> {
        let mut connection = tokio::time::timeout(
            Duration::from_secs(self.config.limits.setup_timeout_secs),
            h2::server::Builder::new()
                .max_header_list_size(self.config.header_limit().min(u32::MAX as usize) as u32)
                .max_concurrent_streams(self.config.limits.request_limit() as u32)
                .initial_window_size(256 * 1024)
                .initial_connection_window_size(256 * 1024)
                .handshake(stream),
        )
        .await?
        .map_err(io::Error::other)?;
        let mut requests = tokio::task::JoinSet::new();
        loop {
            let request = tokio::select! {
                request = connection.accept() => request,
                _ = requests.join_next(), if !requests.is_empty() => continue,
            };
            let Some(request) = request else {
                return Ok(());
            };
            let (request, mut respond) = request.map_err(io::Error::other)?;
            if requests.len() >= self.config.limits.request_limit() {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            }
            let state = self.clone();
            requests.spawn(async move {
                let (parts, body) = request.into_parts();
                let (writer, reader) = pipe(Memory::new(
                    state.memory.clone(),
                    state.config.limits.max_session_buffered_bytes,
                ));
                let tasks = Tasks::new();
                tasks.spawn(carrier::receive_h2(body, writer));
                let response = state.handle(Request::from_parts(parts, ()), reader).await;
                let (parts, body) = response.into_parts();
                if let Ok(send) = respond.send_response(Response::from_parts(parts, ()), false) {
                    let _ = carrier::send_h2(body, send).await;
                }
            });
        }
    }
}
