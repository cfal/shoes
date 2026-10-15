use std::{io, sync::Arc, time::Duration};

use futures::StreamExt;
use http::{Request, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OnceCell, OwnedSemaphorePermit, Semaphore},
};

use super::{
    carrier::{Carrier, Reservation, Timeouts},
    connector::Security,
    stream::{Body, Event, Memory, Reader, Stream, Tasks, pipe},
    wire::{self, Path},
};
use crate::{
    address::NetLocation,
    config::xhttp::{XhttpClientConfig, XhttpMode, XhttpVersion},
    resources::Budget,
    tcp::carrier_dialer::{CarrierDialer, RouteKey},
};

struct Slot {
    key: RouteKey,
    _dialer: Arc<dyn CarrierDialer>,
    carrier: OnceCell<Arc<Carrier>>,
    requests: Arc<Semaphore>,
    limit: usize,
    last_used: parking_lot::Mutex<tokio::time::Instant>,
}

impl Slot {
    fn active(&self) -> usize {
        self.limit - self.requests.available_permits()
    }

    fn retain(&self, idle: Duration) -> bool {
        self.active() != 0
            || self.carrier.get().is_some_and(|carrier| !carrier.closed())
                && self.last_used.lock().elapsed() < idle
    }
}

struct SlotPermit {
    _permit: OwnedSemaphorePermit,
    slot: Option<Arc<Slot>>,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        if let Some(slot) = &self.slot {
            *slot.last_used.lock() = tokio::time::Instant::now();
        }
    }
}

struct Lease {
    carrier: Arc<Carrier>,
    reservation: Option<Reservation>,
    _permit: SlotPermit,
}

impl Lease {
    async fn request(
        &mut self,
        client: &Client,
        request: Request<Body>,
        memory: Memory,
        tasks: &Tasks,
        packet: bool,
    ) -> io::Result<http::Response<Reader>> {
        let reservation = match self.reservation.take() {
            Some(reservation) => reservation,
            None => {
                tokio::time::timeout(
                    Duration::from_secs(client.config.limits.setup_timeout_secs),
                    self.carrier.reserve(),
                )
                .await??
            }
        };
        if self._permit.slot.as_ref().is_some_and(|slot| {
            slot.active() > self.carrier.capacity(client.config.limits.request_limit())
        }) {
            return Err(crate::resources::exhausted());
        }
        let timeouts = if packet {
            Timeouts::packet(
                client.header_timeout(),
                Duration::from_secs(client.config.limits.packet_timeout_secs),
            )
        } else {
            Timeouts::headers(client.header_timeout())
        };
        self.carrier
            .request_reserved(request, memory, tasks, timeouts, reservation)
            .await
    }
}

pub struct Client {
    config: XhttpClientConfig,
    endpoint: NetLocation,
    authority: String,
    path: Path,
    version: XhttpVersion,
    mode: XhttpMode,
    security: Security,
    memory: Arc<Budget>,
    admission: Arc<Budget>,
    tasks: Tasks,
    reaper_started: std::sync::Once,
    slots: parking_lot::Mutex<Vec<Arc<Slot>>>,
    h1_slots: Arc<Semaphore>,
    allocation: parking_lot::Mutex<
        std::collections::HashMap<RouteKey, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
    pending: Arc<Budget>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpClient")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(
        config: XhttpClientConfig,
        endpoint: NetLocation,
        authority: String,
        version: XhttpVersion,
        mode: XhttpMode,
        security: Security,
    ) -> io::Result<Self> {
        let path = Path::new(&config.path)?;
        Ok(Self {
            memory: Arc::new(Budget::new(Some(config.limits.max_buffered_bytes))),
            admission: Arc::new(Budget::new(Some(config.limits.max_sessions))),
            pending: Arc::new(Budget::new(Some(config.limits.max_pending_sessions))),
            allocation: parking_lot::Mutex::new(std::collections::HashMap::new()),
            tasks: Tasks::new(),
            reaper_started: std::sync::Once::new(),
            h1_slots: Arc::new(Semaphore::new(config.pool.max_h1_connections)),
            config,
            endpoint,
            authority,
            path,
            version,
            mode,
            security,
            slots: parking_lot::Mutex::new(Vec::new()),
        })
    }

    pub fn start_reaper(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        self.tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(client) = weak.upgrade() else {
                    break;
                };
                let idle = Duration::from_secs(client.config.pool.idle_timeout_secs);
                client.slots.lock().retain(|slot| slot.retain(idle));
            }
        });
    }

    async fn dial(&self, dialer: &Arc<dyn CarrierDialer>) -> io::Result<Arc<Carrier>> {
        let header_limit =
            8192 + self.config.x_padding_bytes.bounds((100, 1000), false)?.1 as usize;
        tokio::time::timeout(
            Duration::from_secs(self.config.limits.setup_timeout_secs),
            async {
                if self.version == XhttpVersion::H3 {
                    Carrier::quic(dialer.open_quic().await?, header_limit).await
                } else {
                    Carrier::tcp(
                        self.security
                            .wrap(dialer.open_stream().await?, &self.endpoint, self.version)
                            .await?,
                        self.version,
                        header_limit,
                    )
                    .await
                }
            },
        )
        .await?
    }

    async fn lease(&self, dialer: &Arc<dyn CarrierDialer>, allow_dial: bool) -> io::Result<Lease> {
        let (slot, permit) = {
            let mut slots = self.slots.lock();
            let idle = Duration::from_secs(self.config.pool.idle_timeout_secs);
            slots.retain(|slot| slot.retain(idle));
            for slot in slots.iter().filter(|slot| slot.key == *dialer.route_key()) {
                let Some(carrier) = slot.carrier.get() else {
                    continue;
                };
                if slot.active() >= carrier.capacity(self.config.limits.request_limit()) {
                    continue;
                }
                let Ok(Some(reservation)) = carrier.try_reserve() else {
                    continue;
                };
                return Ok(Lease {
                    carrier: carrier.clone(),
                    reservation: Some(reservation),
                    _permit: SlotPermit {
                        _permit: slot
                            .requests
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| crate::resources::exhausted())?,
                        slot: Some(slot.clone()),
                    },
                });
            }
            if !allow_dial {
                return Err(crate::resources::exhausted());
            }
            if slots.len() >= self.config.pool.max_connections
                && let Some(oldest) = slots
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| slot.active() == 0)
                    .min_by_key(|(_, slot)| *slot.last_used.lock())
                    .map(|(index, _)| index)
            {
                slots.remove(oldest);
            }
            if slots.len() >= self.config.pool.max_connections {
                return Err(crate::resources::exhausted());
            }
            let limit = self.config.limits.max_requests_per_connection;
            let slot = Arc::new(Slot {
                key: dialer.route_key().clone(),
                _dialer: dialer.clone(),
                carrier: OnceCell::new(),
                requests: Arc::new(Semaphore::new(limit)),
                limit,
                last_used: parking_lot::Mutex::new(tokio::time::Instant::now()),
            });
            let permit = SlotPermit {
                _permit: slot
                    .requests
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| crate::resources::exhausted())?,
                slot: Some(slot.clone()),
            };
            slots.push(slot.clone());
            (slot, permit)
        };
        let initialized = async {
            let carrier = slot
                .carrier
                .get_or_try_init(|| self.dial(&slot._dialer))
                .await?
                .clone();
            if carrier.capacity(self.config.limits.request_limit()) == 0 {
                return Err(crate::resources::exhausted());
            }
            let reservation = carrier
                .try_reserve()?
                .ok_or_else(crate::resources::exhausted)?;
            Ok(Lease {
                carrier,
                reservation: Some(reservation),
                _permit: permit,
            })
        }
        .await;
        if initialized.is_err() {
            self.slots.lock().retain(|entry| !Arc::ptr_eq(entry, &slot));
        }
        initialized
    }

    pub async fn open(self: &Arc<Self>, dialer: Arc<dyn CarrierDialer>) -> io::Result<Stream> {
        log::debug!("XHTTP opening {:?} over {:?}", self.mode, self.version);
        self.reaper_started.call_once(|| self.start_reaper());
        let admission = self
            .admission
            .acquire(1)
            .ok_or_else(crate::resources::exhausted)?;
        let pending = self
            .pending
            .acquire(1)
            .ok_or_else(crate::resources::exhausted)?;
        let (download, upload) = tokio::time::timeout(
            Duration::from_secs(self.config.limits.setup_timeout_secs),
            async {
                // Serialize same-route batches without blocking healthy routes on another route's dial.
                let gate = if self.version != XhttpVersion::H1 {
                    let mut gates = self.allocation.lock();
                    gates.retain(|_, gate| gate.strong_count() != 0);
                    let entry = gates.entry(dialer.route_key().clone()).or_default();
                    let gate = entry
                        .upgrade()
                        .unwrap_or_else(|| Arc::new(tokio::sync::Mutex::new(())));
                    *entry = Arc::downgrade(&gate);
                    Some(gate)
                } else {
                    None
                };
                let _allocation = match gate {
                    Some(gate) => Some(gate.lock_owned().await),
                    None => None,
                };
                let count = if self.mode == XhttpMode::StreamOne {
                    1
                } else {
                    2
                };
                let mut lanes = Vec::new();
                if self.version == XhttpVersion::H1 {
                    let mut permit = self
                        .h1_slots
                        .clone()
                        .try_acquire_many_owned(count)
                        .map_err(|_| crate::resources::exhausted())?;
                    for _ in 0..count {
                        lanes.push(Lease {
                            carrier: self.dial(&dialer).await?,
                            reservation: None,
                            _permit: SlotPermit {
                                _permit: permit.split(1).unwrap(),
                                slot: None,
                            },
                        });
                    }
                } else {
                    for _ in 0..count {
                        lanes.push(self.lease(&dialer, true).await?);
                    }
                }
                let download = lanes.remove(0);
                if self.mode == XhttpMode::PacketUp {
                    // Unsent QUIC stream IDs become visible when later requests open higher IDs.
                    // Release the admission probe until a POST actually has data to send.
                    lanes[0].reservation.take();
                }
                Ok::<_, io::Error>((download, lanes))
            },
        )
        .await??;
        drop(pending);
        let memory = Memory::new(
            self.memory.clone(),
            self.config.limits.max_session_buffered_bytes,
        );
        let tasks = Arc::new(Tasks::new());
        let (mut write, upload_reader) = pipe(memory.clone());
        write.drain_before_shutdown = self.mode == XhttpMode::PacketUp;
        let (mut download_writer, read) = pipe(memory.clone());
        let client = self.clone();
        // The stream owns cancellation; workers must not retain the task owner.
        tasks.spawn(async move {
            let _admission = admission;
            let result = client
                .run_session(
                    download,
                    upload,
                    dialer,
                    upload_reader,
                    &mut download_writer,
                    memory,
                )
                .await;
            if let Err(error) = result {
                log::debug!("XHTTP session failed: {error}");
                download_writer.fail(error).await;
            }
        });
        Ok(Stream {
            read,
            write,
            _tasks: tasks,
        })
    }

    async fn run_session(
        self: &Arc<Self>,
        mut download: Lease,
        upload: Vec<Lease>,
        dialer: Arc<dyn CarrierDialer>,
        upload_reader: Reader,
        download_writer: &mut super::stream::Writer,
        memory: Memory,
    ) -> io::Result<()> {
        let local = Tasks::new();
        let session = if self.mode == XhttpMode::StreamOne {
            String::new()
        } else {
            crate::uuid_util::generate_uuid()
        };
        let (errors, mut error_receiver) = tokio::sync::mpsc::channel(1);
        let upload_finished = tokio_util::sync::CancellationToken::new();
        let finished = upload_finished.clone();
        let body = if self.mode == XhttpMode::StreamOne {
            Body::stream(upload_reader)
        } else {
            let client = self.clone();
            let session = session.clone();
            let memory = memory.clone();
            local.spawn(async move {
                if let Err(error) = client
                    .upload(upload, dialer, upload_reader, &session, memory)
                    .await
                {
                    let _ = errors.send(error).await;
                } else {
                    finished.cancel();
                }
            });
            Body::Empty
        };
        // Packet-up has no upload FIN on the wire. Bound its download-only tail.
        let linger = async {
            if self.mode != XhttpMode::PacketUp {
                std::future::pending::<()>().await;
            }
            upload_finished.cancelled().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        tokio::pin!(linger);
        let request = self.request(&session, None, self.mode == XhttpMode::StreamOne, body)?;
        let response = tokio::select! {
            Some(error) = error_receiver.recv() => return Err(error),
            _ = local.cancel.cancelled() => return Err(io::ErrorKind::ConnectionAborted.into()),
            _ = &mut linger => return download_writer.shutdown().await,
            result = download.request(self, request, memory, &local, false) => result?,
        };
        if response.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "XHTTP download status {}",
                response.status()
            )));
        }
        let mut body = response.into_body();
        tokio::select! {
            Some(error) = error_receiver.recv() => return Err(error),
            _ = local.cancel.cancelled() => return Err(io::ErrorKind::ConnectionAborted.into()),
            _ = &mut linger => return download_writer.shutdown().await,
            result = tokio::io::copy(&mut body, download_writer) => {
                result?;
            }
        }
        download_writer.shutdown().await?;
        tokio::select! {
            biased;
            Some(error) = error_receiver.recv() => Err(error),
            _ = local.cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
            _ = local.wait() => Ok(()),
        }
    }

    async fn upload(
        &self,
        mut lanes: Vec<Lease>,
        dialer: Arc<dyn CarrierDialer>,
        reader: Reader,
        session: &str,
        memory: Memory,
    ) -> io::Result<()> {
        let tasks = Tasks::new();
        if self.mode == XhttpMode::PacketUp {
            return self
                .packets(
                    lanes.pop().unwrap(),
                    dialer,
                    reader,
                    session,
                    memory,
                    &tasks,
                )
                .await;
        }
        let request = self.request(session, None, true, Body::stream(reader))?;
        let mut upload = lanes.pop().unwrap();
        let response = upload.request(self, request, memory, &tasks, false).await?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "XHTTP upload status {}",
                response.status()
            )));
        }
        let mut body = response.into_body();
        let mut buffer = [0; 4096];
        while body.read(&mut buffer).await? != 0 {}
        tokio::select! {
            biased;
            _ = tasks.cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
            _ = tasks.wait() => Ok(()),
        }
    }

    fn header_timeout(&self) -> Duration {
        Duration::from_secs(self.config.limits.response_header_timeout_secs)
    }

    fn request(
        &self,
        session: &str,
        sequence: Option<u64>,
        upload: bool,
        body: Body,
    ) -> io::Result<Request<Body>> {
        let mut request = wire::request(
            &self.config,
            &self.path,
            &self.authority,
            self.version == XhttpVersion::H3 || !matches!(self.security, Security::Plain),
            session,
            sequence,
            upload,
        )?
        .map(|_| body);
        if self.version == XhttpVersion::H1 && sequence.is_none() {
            request
                .headers_mut()
                .insert("connection", http::HeaderValue::from_static("close"));
        }
        Ok(request)
    }

    async fn packets(
        &self,
        lane: Lease,
        dialer: Arc<dyn CarrierDialer>,
        mut reader: Reader,
        session: &str,
        memory: Memory,
        tasks: &Tasks,
    ) -> io::Result<()> {
        let max_packet_bytes = wire::sample(
            self.config
                .sc_max_each_post_bytes
                .bounds((1_000_000, 1_000_000), false)?,
        ) as usize;
        let concurrency = if self.version == XhttpVersion::H1 {
            1
        } else {
            4
        };
        let mut inflight = futures::stream::FuturesUnordered::new();
        let mut idle_lane = Some(lane);
        let mut pending = std::collections::VecDeque::new();
        let mut sequence = 0u64;
        let mut next_post_at = tokio::time::Instant::now();
        loop {
            while inflight.len() >= concurrency {
                idle_lane.get_or_insert(inflight.next().await.unwrap()?);
            }
            let event = if let Some(event) = pending.pop_front() {
                Some(event)
            } else {
                tokio::select! {
                    event = reader.receiver.recv() => event,
                    done = inflight.next(), if !inflight.is_empty() => {
                        idle_lane.get_or_insert(done.unwrap()?);
                        continue;
                    }
                }
            };
            let Some(event) = event else {
                return Err(io::ErrorKind::BrokenPipe.into());
            };
            match event {
                Event::Data(data) => {
                    let mut chunks = std::collections::VecDeque::new();
                    let mut size = 0;
                    let mut event = Some(Event::Data(data));
                    while let Some(item) = event {
                        match item {
                            Event::Data(mut data) => {
                                let len = data.len().min(max_packet_bytes - size);
                                chunks.push_back(data.split_to(len));
                                size += len;
                                if !data.is_empty() {
                                    pending.push_front(Event::Data(data));
                                    break;
                                }
                            }
                            Event::Flush(ack) => {
                                let _ = ack.send(());
                            }
                            barrier => {
                                pending.push_front(barrier);
                                break;
                            }
                        }
                        if size == max_packet_bytes {
                            break;
                        }
                        event = match reader.receiver.try_recv() {
                            Ok(event) => Some(event),
                            Err(_) if tokio::time::Instant::now() < next_post_at => loop {
                                tokio::select! {
                                    biased;
                                    _ = tokio::time::sleep_until(next_post_at) => break None,
                                    done = inflight.next(), if !inflight.is_empty() => {
                                        idle_lane.get_or_insert(done.unwrap()?);
                                    }
                                    event = reader.receiver.recv() => break event,
                                }
                            },
                            Err(_) => None,
                        };
                    }
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep_until(next_post_at) => break,
                            done = inflight.next(), if !inflight.is_empty() => {
                                idle_lane.get_or_insert(done.unwrap()?);
                            }
                        }
                    }
                    let mut lane = if let Some(lane) = idle_lane.take() {
                        lane
                    } else if let Ok(lane) = self.lease(&dialer, false).await {
                        lane
                    } else {
                        inflight.next().await.unwrap()?
                    };
                    if self.version == XhttpVersion::H1 && lane.carrier.closed() {
                        lane.carrier = self.dial(&dialer).await?;
                    }
                    let request =
                        self.request(session, Some(sequence), true, Body::Chunks(chunks.clone()))?;
                    next_post_at = tokio::time::Instant::now()
                        + Duration::from_millis(wire::sample(
                            self.config
                                .sc_min_posts_interval_ms
                                .bounds((30, 30), false)?,
                        ) as u64);
                    let memory = memory.clone();
                    let dialer = dialer.clone();
                    inflight.push(async move {
                        let _retained_until_ack = chunks;
                        if self.version == XhttpVersion::H3 && lane.reservation.is_none() {
                            if let Ok(Some(reservation)) = lane.carrier.try_reserve() {
                                lane.reservation = Some(reservation);
                            } else if let Ok(replacement) = self.lease(&dialer, true).await {
                                // No request has been sent; another session may own this carrier's credit.
                                lane = replacement;
                            }
                        }
                        let response = lane.request(self, request, memory, tasks, true).await?;
                        if response.status() != StatusCode::OK {
                            return Err(io::Error::other(format!(
                                "XHTTP packet status {}",
                                response.status()
                            )));
                        }
                        let mut body = response.into_body();
                        if body.read(&mut [0; 1]).await? != 0 {
                            return Err(io::Error::other("nonempty XHTTP packet acknowledgement"));
                        }
                        Ok::<_, io::Error>(lane)
                    });
                    sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("XHTTP sequence exhausted"))?;
                }
                Event::Flush(ack) => {
                    let _ = ack.send(());
                }
                Event::Drain(ack) => {
                    while let Some(result) = inflight.next().await {
                        idle_lane.get_or_insert(result?);
                    }
                    let _ = ack.send(());
                }
                Event::Finish => {
                    while let Some(result) = inflight.next().await {
                        result?;
                    }
                    return Ok(());
                }
                Event::Error(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::NamedGroup;
    use serde_json::json;

    #[test]
    fn tls_connector_preserves_key_exchange_policy() {
        let resolver = Arc::new(crate::resolver::NativeResolver::new());
        for (groups, expected) in [
            (json!(["X25519"]), vec![NamedGroup::X25519]),
            (json!(["X25519MLKEM768"]), vec![NamedGroup::X25519MLKEM768]),
            (
                json!(["SecP256r1MLKEM768", "X25519"]),
                vec![NamedGroup::secp256r1MLKEM768, NamedGroup::X25519],
            ),
        ] {
            for (version, alpn) in [("h1", b"http/1.1".as_slice()), ("h2", b"h2")] {
                let config = serde_json::from_value(json!({
                    "address":"localhost:443", "protocol":{
                        "type":"tls", "verify":false, "key_exchange_groups":groups,
                        "protocol":{"type":"xhttp", "http_version":version,
                            "protocol":{"type":"socks"}}
                    }
                }))
                .unwrap();
                let (client, _) = super::super::connector::build(&config, resolver.clone())
                    .unwrap()
                    .unwrap();
                let Security::Tls { config, .. } = &client.security else {
                    panic!("expected TLS carrier");
                };
                assert_eq!(
                    config
                        .crypto_provider()
                        .kx_groups
                        .iter()
                        .map(|g| g.name())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(config.alpn_protocols, [alpn]);
            }
        }
    }
}
