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
    stream::{Activity, Body, Event, Memory, Reader, Stream, Tasks, Writer, pipe},
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
mod tests;

struct State {
    config: XhttpServerConfig,
    path: Path,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    memory: Arc<Budget>,
    admission: Arc<Budget>,
    pending: Arc<Budget>,
    requests: Arc<Budget>,
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
    Closed { when: tokio::time::Instant },
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
    receiving: BTreeMap<u64, usize>,
    reserved: BTreeMap<u64, usize>,
    next: u64,
    downloaded: bool,
    upload_deadline: Option<tokio::time::Instant>,
    permit: Option<BudgetPermit>,
    pending_permit: Option<BudgetPermit>,
}
impl SessionState {
    fn predecessors_available(&self, sequence: u64, in_progress: &BTreeMap<u64, usize>) -> bool {
        self.downloaded
            && (self.next..sequence).all(|number| {
                self.pending.contains_key(&number) || in_progress.contains_key(&number)
            })
    }
}
struct Session {
    state: parking_lot::Mutex<SessionState>,
    memory: Memory,
    ready: Notify,
    cancel: CancellationToken,
    created: tokio::time::Instant,
    admission: parking_lot::Mutex<Option<BudgetPermit>>,
    progress: Notify,
    activity: Arc<Activity>,
    packet_requests: Arc<Budget>,
    head_request: Arc<Budget>,
}

impl Session {
    fn claim_download(&self) -> Result<(Reader, BudgetPermit), StatusCode> {
        let mut state = self.state.lock();
        // close_entry cancels before taking this lock and removing the handles.
        if self.cancel.is_cancelled() || state.downloaded {
            return Err(StatusCode::CONFLICT);
        }
        state.downloaded = true;
        state.pending_permit.take();
        Ok((state.reader.take().unwrap(), state.permit.take().unwrap()))
    }

    fn claim_stream_upload(&self) -> Result<Writer, StatusCode> {
        let mut state = self.state.lock();
        if self.cancel.is_cancelled()
            || state.upload != Upload::Unclaimed
            || state
                .upload_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return Err(StatusCode::CONFLICT);
        }
        state.upload = Upload::Stream;
        state.upload_deadline = None;
        Ok(state.writer.take().unwrap())
    }
}

struct PacketRequest {
    session: Arc<Session>,
    sequence: u64,
    reserved: bool,
    primary: bool,
}

#[derive(Debug, PartialEq)]
enum Rejection {
    Status(StatusCode),
    Full,
}

impl From<StatusCode> for Rejection {
    fn from(status: StatusCode) -> Self {
        Self::Status(status)
    }
}

#[derive(Clone)]
struct Refused;

#[derive(Clone)]
struct RequestReset(CancellationToken);

impl PacketRequest {
    fn new(session: Arc<Session>, sequence: u64) -> Result<(Self, BudgetPermit), Rejection> {
        let (primary, permit) = {
            let mut state = session.state.lock();
            if session.cancel.is_cancelled() {
                return Err(StatusCode::SERVICE_UNAVAILABLE.into());
            }
            if state.upload == Upload::Stream || state.upload_deadline.is_some() {
                return Err(StatusCode::CONFLICT.into());
            }
            let permit = session
                .packet_requests
                .acquire(1)
                .or_else(|| {
                    // Far requests and duplicates cannot consume the missing head's last slot.
                    if sequence == state.next && !state.receiving.contains_key(&sequence) {
                        session.head_request.acquire(1)
                    } else {
                        None
                    }
                })
                .ok_or(Rejection::Full)?;
            let count = state.receiving.entry(sequence).or_default();
            *count += 1;
            (*count == 1, permit)
        };
        Ok((
            Self {
                session,
                sequence,
                reserved: false,
                primary,
            },
            permit,
        ))
    }

    fn touch(&self) {
        if self.primary {
            let state = self.session.state.lock();
            // Only the original receiver of the missing head packet can sustain other POSTs.
            if self.sequence == state.next && !state.pending.contains_key(&self.sequence) {
                self.session.activity.touch();
            }
        }
    }

    fn decrement(counts: &mut BTreeMap<u64, usize>, sequence: u64) {
        let count = counts.get_mut(&sequence).unwrap();
        *count -= 1;
        if *count == 0 {
            counts.remove(&sequence);
        }
    }
}

impl Drop for PacketRequest {
    fn drop(&mut self) {
        let mut state = self.session.state.lock();
        Self::decrement(&mut state.receiving, self.sequence);
        if self.reserved {
            Self::decrement(&mut state.reserved, self.sequence);
        }
        self.session.progress.notify_waiters();
    }
}

struct DownloadGuard {
    state: Weak<State>,
    session: Option<Weak<Session>>,
    id: String,
    cancel: CancellationToken,
    eof: CancellationToken,
}
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        if self.eof.is_cancelled() {
            let Some(session) = &self.session else {
                return;
            };
            if let Some(session) = session.upgrade() {
                let mut state = session.state.lock();
                if state.upload == Upload::Stream {
                    return;
                }
                if !session.cancel.is_cancelled()
                    && state.upload == Upload::Unclaimed
                    && state.receiving.is_empty()
                    && self.state.upgrade().is_some_and(|service| {
                        matches!(
                            service.config.mode,
                            crate::config::xhttp::XhttpMode::Auto
                                | crate::config::xhttp::XhttpMode::StreamUp
                        )
                    })
                {
                    state.upload_deadline =
                        Some(tokio::time::Instant::now() + Duration::from_secs(30));
                    return;
                }
            }
        }
        self.cancel.cancel();
        if let Some(state) = self.state.upgrade()
            && let Some(session) = self.session.as_ref().and_then(Weak::upgrade)
        {
            state.close_session(&self.id, &session);
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
            memory: Arc::new(Budget::new(config.limits.max_buffered_bytes)),
            admission: Arc::new(Budget::new(config.limits.max_sessions)),
            pending: Arc::new(Budget::new(config.limits.max_pending_sessions)),
            requests: Arc::new(Budget::new(config.limits.max_requests)),
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
                log::debug!(
                    "XHTTP server resources: requests={:?} bytes={:?}",
                    state.requests.snapshot(),
                    state.memory.snapshot()
                );
            }
        });
        Ok(Self { state })
    }

    pub async fn serve_h3(&self, connection: quinn::Connection) -> io::Result<()> {
        let peer = connection.remote_address();
        let mut driver = h3::server::builder()
            .max_field_section_size(self.state.config.header_limit() as u64)
            .build(super::h3::Connection::new(connection))
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
            while requests.try_join_next().is_some() {}
            let request_permit = if requests.len() < self.state.config.limits.request_limit() {
                self.state.requests.acquire(1)
            } else {
                None
            };
            let Some(request_permit) = request_permit else {
                drop(resolver);
                continue;
            };
            let state = self.state.clone();
            requests.spawn(async move {
                let _request_permit = request_permit;
                let Ok(Ok((mut request, stream))) = tokio::time::timeout(
                    Duration::from_secs(state.config.limits.setup_timeout_secs),
                    resolver.resolve_request(),
                )
                .await
                else {
                    return;
                };
                request.extensions_mut().insert(peer);
                let (mut send, mut receive) = stream.split();
                let workers = Tasks::new();
                let memory = state.new_memory();
                let (mut writer, mut reader) = pipe(memory);
                let ready = reader.defer();
                let upload_closed = writer.closed();
                let peer_reset = CancellationToken::new();
                let receive_reset = peer_reset.clone();
                workers.spawn(async move {
                    if ready.await.is_err() {
                        return;
                    }
                    let result: io::Result<()> = async {
                        while let Some(mut data) = receive.recv_data().await.map_err(|error| {
                            if matches!(error, h3::error::StreamError::RemoteTerminate { .. }) {
                                receive_reset.cancel();
                            }
                            io::Error::other(error)
                        })? {
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
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let response = state.handle(request, reader).await;
                // A response to a reset upload can block on flow control until the peer reads or
                // sends STOP_SENDING, holding the request permit.
                if peer_reset.is_cancelled() {
                    send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    return;
                }
                let keep_upload = streaming_upload && response.status() == StatusCode::OK;
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
                } else if keep_upload {
                    tokio::select! {
                        _ = workers.wait() => {},
                        _ = upload_closed => {},
                    }
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
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(state.config.limits.setup_timeout_secs.min(4));
        tokio::time::timeout_at(deadline, stream.read_exact(&mut prefix)).await??;
        let h2 = &prefix == b"PRI";
        if (version == XhttpVersion::H1 && h2) || (version == XhttpVersion::H2 && !h2) {
            return Err(io::Error::other("unexpected XHTTP version"));
        }
        let stream = crate::prepend_stream::PrependStream::new(stream, Some(Box::new(prefix)));
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let result = if h2 {
                state.serve_h2(Box::new(stream), deadline).await
            } else {
                state.serve_h1(Box::new(stream), deadline).await
            };
            if let Err(error) = result {
                log::debug!("XHTTP carrier ended: {error}");
            }
        })))
    }
}

impl State {
    fn new_memory(&self) -> Memory {
        Memory::new(self.memory.clone(), self.config.limits.session_byte_limit())
    }

    #[cfg(test)]
    fn close(&self, id: &str) {
        let mut sessions = self.sessions.lock();
        self.close_entry(&mut sessions, id);
    }

    fn close_session(&self, id: &str, session: &Arc<Session>) {
        let mut sessions = self.sessions.lock();
        if matches!(sessions.get(id), Some(Entry::Live(current)) if Arc::ptr_eq(current, session)) {
            self.close_entry(&mut sessions, id);
        }
    }

    fn close_entry(&self, sessions: &mut HashMap<String, Entry>, id: &str) {
        if !matches!(sessions.get(id), Some(Entry::Live(_))) {
            return;
        }
        if let Some(Entry::Live(session)) = sessions.remove(id) {
            session.cancel.cancel();
            session.admission.lock().take();
            {
                let mut state = session.state.lock();
                state.pending.clear();
                state.permit.take();
                state.pending_permit.take();
                state.writer.take();
                state.reader.take();
            }
            if self.config.limits.max_sessions.is_some_and(|limit| {
                sessions
                    .values()
                    .filter(|entry| matches!(entry, Entry::Closed { .. }))
                    .count()
                    >= limit
            }) {
                let oldest = sessions
                    .iter()
                    .filter_map(|(id, entry)| match entry {
                        Entry::Closed { when } => Some((id, when)),
                        Entry::Live(_) => None,
                    })
                    .min_by_key(|(_, when)| *when)
                    .map(|(id, _)| id.clone());
                if let Some(oldest) = oldest {
                    sessions.remove(&oldest);
                }
            }
            sessions.insert(
                id.into(),
                Entry::Closed {
                    when: tokio::time::Instant::now(),
                },
            );
        }
    }

    fn reap(&self) {
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, entry| match entry {
            Entry::Closed { when } => when.elapsed() < Duration::from_secs(30),
            Entry::Live(_) => true,
        });
        let expired: Vec<_> = sessions
            .iter()
            .filter_map(|(id, entry)| match entry {
                Entry::Live(session) => {
                    let state = session.state.lock();
                    ((!state.downloaded && session.created.elapsed() >= Duration::from_secs(30))
                        || state
                            .upload_deadline
                            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline))
                    .then(|| id.clone())
                }
                _ => None,
            })
            .collect();
        for id in expired {
            self.close_entry(&mut sessions, &id);
        }
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
        let permit = crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let admission = self
            .admission
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let pending_permit = self
            .pending
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let memory = self.new_memory();
        let (writer, mut reader) = pipe(memory.clone());
        let activity = Arc::new(Activity::new());
        reader.activity = Some(activity.clone());
        let session = Arc::new(Session {
            state: parking_lot::Mutex::new(SessionState {
                upload: Upload::Unclaimed,
                writer: Some(writer),
                reader: Some(reader),
                pending: BTreeMap::new(),
                receiving: BTreeMap::new(),
                reserved: BTreeMap::new(),
                next: 0,
                downloaded: false,
                upload_deadline: None,
                permit: Some(permit),
                pending_permit: Some(pending_permit),
            }),
            memory,
            ready: Notify::new(),
            cancel: CancellationToken::new(),
            created: tokio::time::Instant::now(),
            admission: parking_lot::Mutex::new(Some(admission)),
            activity,
            progress: Notify::new(),
            packet_requests: Arc::new(Budget::new(
                self.config
                    .limits
                    .session_request_limit()
                    .map(|limit| limit - 1),
            )),
            head_request: Arc::new(Budget::new(Some(1))),
        });
        sessions.insert(id.into(), Entry::Live(session.clone()));
        Ok(session)
    }

    fn success_response(&self, body: Body, downstream: bool) -> Response<Body> {
        let mut response = Response::builder()
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

    fn spawn_inner_session(
        &self,
        stream: Stream,
        permit: BudgetPermit,
        cancel: CancellationToken,
        finished: impl FnOnce() + Send + 'static,
    ) {
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
            finished();
        });
    }

    async fn dispatch(
        self: &Arc<Self>,
        request: &Request<()>,
        body: Reader,
    ) -> Result<(Body, bool), Rejection> {
        if !wire::has_matching_headers(&self.config, request.headers()) {
            log::debug!("XHTTP request rejected: headers do not match");
            return Err(StatusCode::NOT_FOUND.into());
        }
        match wire::classify(&self.config, &self.path, request)? {
            Kind::Options => Ok((Body::Empty, false)),
            Kind::One => self
                .stream_one(body, request.extensions().get().copied())
                .map_err(Into::into),
            Kind::Download(id) => self
                .download(id, request.extensions().get().copied())
                .map_err(Into::into),
            Kind::Upload(id) => self.stream_upload(request, body, id).map_err(Into::into),
            Kind::Packet(id, sequence) => self.packet(request, body, id, sequence).await,
        }
    }

    fn stream_one(
        self: &Arc<Self>,
        body: Reader,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<(Body, bool), StatusCode> {
        let admission = self
            .admission
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let permit = crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let memory = self.new_memory();
        let (writer, reader) = pipe(memory);
        let tasks = Arc::new(Tasks::new());
        let stream = Stream {
            read: body,
            write: writer,
            _tasks: tasks.clone(),
            peer,
        };
        self.spawn_inner_session(stream, permit, tasks.cancel.clone(), move || {
            drop(admission);
        });
        let guard = DownloadGuard {
            state: Weak::new(),
            session: None,
            id: String::new(),
            cancel: tasks.cancel.clone(),
            eof: reader.eof.clone(),
        };
        Ok((Body::stream(reader).with_guard(guard), true))
    }

    fn download(
        self: &Arc<Self>,
        id: String,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<(Body, bool), StatusCode> {
        let session = self.session(&id)?;
        let (reader, permit) = session.claim_download()?;
        session.progress.notify_waiters();
        let (writer, output) = pipe(self.new_memory());
        let tasks = Arc::new(Tasks::new());
        let stream = Stream {
            read: reader,
            write: writer,
            _tasks: tasks,
            peer,
        };
        let state = Arc::downgrade(self);
        let session_id = id.clone();
        let completed = Arc::downgrade(&session);
        self.spawn_inner_session(stream, permit, session.cancel.clone(), move || {
            if let Some(state) = state.upgrade()
                && let Some(session) = completed.upgrade()
            {
                state.close_session(&session_id, &session);
            }
        });
        let guard = DownloadGuard {
            state: Arc::downgrade(self),
            session: Some(Arc::downgrade(&session)),
            id,
            cancel: session.cancel.clone(),
            eof: output.eof.clone(),
        };
        Ok((Body::stream(output).with_guard(guard), true))
    }

    fn stream_upload(
        self: &Arc<Self>,
        request: &Request<()>,
        mut body: Reader,
        id: String,
    ) -> Result<(Body, bool), StatusCode> {
        let session = self.session(&id)?;
        let mut writer = session.claim_stream_upload()?;
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
                body.forward_to(&mut writer).await?;
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
                    tokio::time::sleep(Duration::from_secs(wire::sample(interval) as u64)).await;
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

    async fn packet(
        self: &Arc<Self>,
        request: &Request<()>,
        mut body: Reader,
        id: String,
        sequence: u64,
    ) -> Result<(Body, bool), Rejection> {
        let session = self.session(&id)?;
        let admission = match PacketRequest::new(session.clone(), sequence) {
            Ok(admission) => admission,
            Err(Rejection::Full) if request.version() == http::Version::HTTP_2 => {
                log::debug!(
                    "XHTTP session {id} request limit reached; refusing unaccepted packet {sequence}"
                );
                return Err(Rejection::Full);
            }
            Err(error) => {
                if error != Rejection::Status(StatusCode::CONFLICT) {
                    self.close_session(&id, &session);
                }
                return Err(match error {
                    Rejection::Full => StatusCode::SERVICE_UNAVAILABLE.into(),
                    error => error,
                });
            }
        };
        let result = self
            .packet_body(request, &mut body, &session, sequence, admission)
            .await;
        if matches!(result, Err(status) if status != StatusCode::CONFLICT) {
            self.close_session(&id, &session);
        }
        result.map_err(Into::into)
    }

    async fn packet_body(
        self: &Arc<Self>,
        request: &Request<()>,
        body: &mut Reader,
        session: &Arc<Session>,
        sequence: u64,
        (mut packet_request, _request_permit): (PacketRequest, BudgetPermit),
    ) -> Result<(Body, bool), StatusCode> {
        use std::ops::ControlFlow;

        {
            let state = session.state.lock();
            if session.cancel.is_cancelled() {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            if state.upload == Upload::Stream {
                return Err(StatusCode::CONFLICT);
            }
        }
        let max = self
            .config
            .sc_max_each_post_bytes
            .bounds((1_000_000, 1_000_000), false)
            .unwrap()
            .1 as usize;
        let initial =
            wire::header_payload(request.headers()).map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut size = initial.len();
        let session_limit = self
            .config
            .limits
            .session_byte_limit()
            .unwrap_or(usize::MAX);
        let mut reservation = max.min(session_limit);
        if let Some(length) = request.headers().get(http::header::CONTENT_LENGTH) {
            let length = length
                .to_str()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or(StatusCode::BAD_REQUEST)?;
            if length > max.saturating_sub(size) as u64 {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            reservation = size + length as usize;
        }
        if size > max {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if reservation > session_limit {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let arrived = tokio::time::Instant::now();
        let timeout = Duration::from_secs(self.config.limits.packet_timeout_secs);
        let ingest = async {
            let admission = async {
                loop {
                    let released = session.memory.packet_space_released();
                    let progress = session.progress.notified();
                    tokio::pin!(released, progress);
                    released.as_mut().enable();
                    progress.as_mut().enable();
                    {
                        let mut state = session.state.lock();
                        if session.cancel.is_cancelled() {
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }
                        if state.upload == Upload::Stream {
                            return Err(StatusCode::CONFLICT);
                        }
                        state.upload = Upload::Packet;
                        if sequence < state.next {
                            return Ok(ControlFlow::Break(()));
                        }
                        if sequence.saturating_sub(state.next)
                            >= self.config.buffered_posts() as u64
                        {
                            if !state.downloaded {
                                return Err(StatusCode::SERVICE_UNAVAILABLE);
                            }
                        } else {
                            let contiguous =
                                state.predecessors_available(sequence, &state.reserved);
                            // Out-of-order packets must leave space for their missing predecessor.
                            let headroom = if contiguous || sequence == state.next {
                                0
                            } else {
                                max.min(session_limit)
                            };
                            if let Some(memory) =
                                session.memory.reserve_packet(reservation, headroom)
                            {
                                *state.reserved.entry(sequence).or_default() += 1;
                                packet_request.reserved = true;
                                session.progress.notify_waiters();
                                break Ok(ControlFlow::Continue(memory));
                            }
                        }
                    }
                    tokio::select! {
                        _ = released => {},
                        _ = progress => {},
                    }
                }
            };
            let cancelled = async {
                match request.extensions().get::<RequestReset>() {
                    Some(reset) => reset.0.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            let admitted = tokio::select! {
                biased;
                // A reset before body admission withdraws only this request, not the session.
                _ = cancelled => return Err(StatusCode::CONFLICT),
                result = session.activity.idle(arrived, timeout, admission) => {
                    result.map_err(|_| StatusCode::REQUEST_TIMEOUT)??
                }
            };
            let mut memory = match admitted {
                ControlFlow::Break(()) => return Ok(()),
                ControlFlow::Continue(memory) => memory,
            };
            body.start();
            let mut chunks = Vec::new();
            // On cancellation, remove admission markers before releasing byte permits.
            let body_request = packet_request;
            let body_activity = Activity::new();
            let intake = async {
                if !initial.is_empty() {
                    chunks.push(
                        memory
                            .copy(&initial)
                            .await
                            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                    );
                    body_activity.touch();
                    body_request.touch();
                }
                loop {
                    let data = match body.receiver.recv().await {
                        Some(Event::Allocated(data)) => data,
                        Some(Event::Flush(ack) | Event::Drain(ack)) => {
                            let _ = ack.send(());
                            continue;
                        }
                        Some(Event::Finish) => break,
                        Some(Event::Data(_) | Event::Error(_)) | None => {
                            return Err(StatusCode::BAD_REQUEST);
                        }
                    };
                    size = size
                        .checked_add(data.len())
                        .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
                    if size > max {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    if data.len() == 0 {
                        continue;
                    }
                    memory
                        .retain(data, &mut chunks)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    body_activity.touch();
                    body_request.touch();
                }
                Ok::<_, StatusCode>(())
            };
            body_activity
                .idle(tokio::time::Instant::now(), timeout, intake)
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
            let writer = {
                let mut state = session.state.lock();
                if session.cancel.is_cancelled() {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                if sequence < state.next {
                    return Ok(());
                }
                if let Some(previous) = state.pending.get(&sequence) {
                    if previous
                        .iter()
                        .flat_map(|b| b.iter())
                        .eq(chunks.iter().flat_map(|b| b.as_ref().iter()))
                    {
                        return Ok(());
                    }
                    return Err(StatusCode::CONFLICT);
                }
                if state.pending.len() >= self.config.buffered_posts() {
                    session.cancel.cancel();
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                state.pending.insert(
                    sequence,
                    chunks.into_iter().map(|chunk| chunk.into_bytes()).collect(),
                );
                state.writer.take()
            };
            drop(memory);
            if let Some(writer) = writer {
                self.spawn_packet_forwarder(session.clone(), writer);
            }
            session.ready.notify_one();
            Ok(())
        };
        let work = async {
            ingest.await?;
            if session.cancel.is_cancelled() {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            } else {
                Ok((Body::Empty, false))
            }
        };
        tokio::select! {
            result = work => result,
            _ = session.cancel.cancelled() => Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    fn spawn_packet_forwarder(&self, session: Arc<Session>, mut writer: Writer) {
        self.tasks.spawn(async move {
            let work = async {
                loop {
                    let packet = {
                        let mut state = session.state.lock();
                        let next = state.next;
                        let packet = state.pending.remove(&next);
                        if packet.is_some() {
                            state.next = next
                                .checked_add(1)
                                .ok_or_else(|| io::Error::other("sequence exhausted"))?;
                            session.progress.notify_waiters();
                        }
                        packet
                    };
                    match packet {
                        Some(packet) => {
                            for chunk in packet {
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

    async fn handle(self: &Arc<Self>, request: Request<()>, body: Reader) -> Response<Body> {
        let (body, downstream) = match self.dispatch(&request, body).await {
            Ok(result) => result,
            Err(Rejection::Full) => {
                return Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .extension(Refused)
                    .body(Body::Empty)
                    .unwrap();
            }
            Err(Rejection::Status(status)) => {
                if status != StatusCode::NOT_FOUND {
                    log::debug!("XHTTP request {} rejected: {status}", request.uri().path());
                }
                return Response::builder()
                    .status(status)
                    .body(Body::Empty)
                    .unwrap();
            }
        };
        let mut response = self.success_response(body, downstream);
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

    async fn serve_h1(
        self: Arc<Self>,
        stream: Box<dyn AsyncStream>,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        let peer = stream.peer_addr();
        let header_limit = self.config.header_limit();
        let first_header = Arc::new(Notify::new());
        let received_header = first_header.clone();
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
            received_header.notify_one();
            let state = self.clone();
            async move {
                let Some(request_permit) = state.requests.acquire(1) else {
                    return Ok::<_, io::Error>(
                        Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .header("connection", "close")
                            .body(Body::Empty)
                            .unwrap(),
                    );
                };
                let (parts, body) = request.into_parts();
                let mut request = Request::from_parts(parts, ());
                if let Some(peer) = peer {
                    request.extensions_mut().insert(peer);
                }
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let (writer, mut reader) = pipe(state.new_memory());
                let ready = reader.defer();
                let tasks = Arc::new(Tasks::new());
                let eof = CancellationToken::new();
                if hyper::body::Body::is_end_stream(&body) {
                    eof.cancel();
                }
                let received = eof.clone();
                tasks.spawn(async move {
                    if ready.await.is_ok() {
                        carrier::receive_hyper(body, writer, Some(received)).await;
                    }
                });
                let mut response = state
                    .handle(request, reader)
                    .await
                    .map(|body| body.with_guard(request_permit));
                if streaming_upload && response.status() == StatusCode::OK {
                    return Ok::<_, io::Error>(response.map(|body| body.with_guard(tasks)));
                }
                if !eof.is_cancelled() {
                    response
                        .headers_mut()
                        .insert("connection", http::HeaderValue::from_static("close"));
                }
                Ok(response)
            }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .max_buf_size(header_limit.max(8192))
            .timer(hyper_util::rt::TokioTimer::new())
            // Hyper starts this timer while idle, not at the first header byte.
            .header_read_timeout(None);
        let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
        tokio::pin!(connection);
        tokio::select! {
            result = &mut connection => return result.map_err(io::Error::other),
            result = tokio::time::timeout_at(deadline, first_header.notified()) => { result?; }
        }
        connection.await.map_err(io::Error::other)
    }

    async fn serve_h2(
        self: Arc<Self>,
        stream: Box<dyn AsyncStream>,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        let peer = stream.peer_addr();
        let (stream_window, connection_window) = self.config.limits.h2_windows();
        let mut connection = tokio::time::timeout_at(
            deadline,
            h2::server::Builder::new()
                .max_header_list_size(self.config.header_limit().min(u32::MAX as usize) as u32)
                .max_concurrent_streams(self.config.limits.request_limit() as u32)
                .initial_window_size(stream_window)
                .initial_connection_window_size(connection_window)
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
            while requests.try_join_next().is_some() {}
            let request_permit = if requests.len() < self.config.limits.request_limit() {
                self.requests.acquire(1)
            } else {
                None
            };
            let Some(request_permit) = request_permit else {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            };
            let state = self.clone();
            requests.spawn(async move {
                let _request_permit = request_permit;
                let (parts, body) = request.into_parts();
                let mut request = Request::from_parts(parts, ());
                if let Some(peer) = peer {
                    request.extensions_mut().insert(peer);
                }
                let reset = CancellationToken::new();
                request.extensions_mut().insert(RequestReset(reset.clone()));
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let (writer, mut reader) = pipe(state.new_memory());
                let ready = reader.defer();
                let tasks = Tasks::new();
                let upload_closed = writer.closed();
                tasks.spawn(async move {
                    if ready.await.is_ok() {
                        carrier::receive_h2(body, writer).await;
                    }
                });
                let handle = state.handle(request, reader);
                tokio::pin!(handle);
                // Poll the reset first so a packet whose admission becomes ready in the same
                // wakeup sees RequestReset and withdraws instead of closing its session.
                let response = tokio::select! {
                    biased;
                    _ = futures::future::poll_fn(|cx| respond.poll_reset(cx)) => {
                        reset.cancel();
                        let _ = handle.await;
                        return;
                    },
                    response = &mut handle => response,
                };
                if response.extensions().get::<Refused>().is_some() {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return;
                }
                let keep_upload = streaming_upload && response.status() == StatusCode::OK;
                let (parts, body) = response.into_parts();
                if let Ok(send) = respond.send_response(Response::from_parts(parts, ()), false)
                    && carrier::send_h2(body, send).await.is_ok()
                    && keep_upload
                {
                    tokio::select! {
                        _ = tasks.wait() => {},
                        _ = upload_closed => {},
                    }
                }
            });
        }
    }
}
