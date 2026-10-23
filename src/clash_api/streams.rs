use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::{
    Message,
    protocol::{CloseFrame, frame::coding::CloseCode},
};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::{ApiState, json_bytes};

pub struct Sample {
    sequence: u64,
    pub connections: Result<Bytes, Arc<io::Error>>,
    pub traffic: Bytes,
    pub memory: Bytes,
    pub rss: u64,
}

impl Sample {
    pub fn initial() -> Self {
        Self {
            sequence: 0,
            connections: Ok(Bytes::from_static(
                b"{\"uploadTotal\":0,\"downloadTotal\":0,\"memory\":0,\"connections\":[]}",
            )),
            traffic: Bytes::from_static(b"{\"up\":0,\"down\":0,\"upTotal\":0,\"downTotal\":0}"),
            memory: Bytes::from_static(b"{\"inuse\":0,\"oslimit\":0}"),
            rss: 0,
        }
    }
}

struct SerializedConnections {
    sequence: u64,
    bytes: Result<Bytes, Arc<io::Error>>,
    upload_total: u64,
    download_total: u64,
}

impl SerializedConnections {
    fn new(snapshot: crate::control::flows::ConnectionsSnapshot) -> Self {
        Self {
            sequence: snapshot.sequence,
            bytes: json_bytes(&snapshot).map_err(Arc::new),
            upload_total: snapshot.upload_total,
            download_total: snapshot.download_total,
        }
    }
}

async fn snapshot(
    flows: Arc<crate::control::flows::FlowRegistry>,
    gate: Arc<tokio::sync::Semaphore>,
    rss: u64,
) -> io::Result<SerializedConnections> {
    let permit = gate.acquire_owned().await.map_err(io::Error::other)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SerializedConnections::new(flows.snapshot(rss))
    })
    .await
    .map_err(io::Error::other)
}

pub(super) async fn connections(state: &ApiState) -> io::Result<Bytes> {
    let rss = state.samples.borrow().rss;
    snapshot(state.runtime.flows.clone(), state.snapshots.clone(), rss)
        .await?
        .bytes
        .map_err(|error| io::Error::new(error.kind(), error))
}

pub async fn sample(state: Arc<ApiState>, sender: watch::Sender<Sample>) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut previous_upload, mut previous_download, mut rss) = (0, 0, 0);
    let mut previous = Instant::now();
    let mut oversized = false;
    let mut rss_failed = false;
    loop {
        tokio::select! { _ = state.cancel.cancelled() => return, _ = interval.tick() => {} }
        match memory_stats::memory_stats() {
            Some(memory) => {
                rss = memory.physical_mem as u64;
                rss_failed = false;
            }
            None if !rss_failed => {
                log::warn!("Clash API could not sample process RSS; keeping last sample");
                rss_failed = true;
            }
            None => {}
        }
        let Ok(SerializedConnections {
            sequence,
            bytes: connections,
            upload_total,
            download_total,
        }) = snapshot(state.runtime.flows.clone(), state.snapshots.clone(), rss).await
        else {
            return;
        };
        let elapsed = previous.elapsed().as_secs_f64();
        previous = Instant::now();
        let upload_rate = (upload_total.saturating_sub(previous_upload) as f64 / elapsed) as u64;
        let download_rate =
            (download_total.saturating_sub(previous_download) as f64 / elapsed) as u64;
        let traffic = json_bytes(&json!({
            "up": upload_rate,
            "down": download_rate,
            "upTotal": upload_total,
            "downTotal": download_total,
        }))
        .expect("bounded traffic DTO");
        (previous_upload, previous_download) = (upload_total, download_total);
        if connections.is_err() && !oversized {
            log::warn!(
                "Clash API connection snapshot exceeds response limit; retaining complete tracking"
            );
        }
        oversized = connections.is_err();
        sender.send_replace(Sample {
            sequence,
            connections,
            traffic,
            memory: json_bytes(&json!({"inuse":rss,"oslimit":0})).unwrap(),
            rss,
        });
    }
}

#[derive(Clone, Copy)]
pub enum Kind {
    Connections,
    Traffic,
    Memory,
    Logs,
}

pub struct Subscription {
    pub kind: Kind,
    interval: Duration,
    level: log::LevelFilter,
    structured: bool,
}

impl Subscription {
    pub fn parse(path: &str, query: &HashMap<String, String>) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid stream parameters");
        let kind = match path {
            "connections" => Kind::Connections,
            "traffic" => Kind::Traffic,
            "memory" => Kind::Memory,
            "logs" => Kind::Logs,
            _ => return Err(invalid()),
        };
        let interval: u64 = query
            .get("interval")
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or(1000);
        if !(250..=60000).contains(&interval) {
            return Err(invalid());
        }
        let level = query.get("level").map(String::as_str).unwrap_or("info");
        let level = crate::logging::parse_log_level(match level {
            "warning" => "warn",
            "silent" => "off",
            level => level,
        })
        .ok_or_else(invalid)?;
        let structured = match query.get("format").map(String::as_str) {
            None | Some("") => false,
            Some("structured") => true,
            _ => return Err(invalid()),
        };
        Ok(Self {
            kind,
            interval: Duration::from_millis(interval),
            level,
            structured,
        })
    }
}

struct Source {
    runtime: Arc<crate::control::runtime::ControlRuntime>,
    first: bool,
    last_sequence: u64,
    subscription: Subscription,
    samples: watch::Receiver<Sample>,
    logs: Option<tokio::sync::broadcast::Receiver<crate::control::logs::LogEvent>>,
    interval: tokio::time::Interval,
    snapshots: Arc<tokio::sync::Semaphore>,
}

impl Source {
    fn new(state: &ApiState, subscription: Subscription) -> Self {
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + subscription.interval,
            subscription.interval,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let logs =
            matches!(subscription.kind, Kind::Logs).then(|| state.runtime.logs.sender.subscribe());
        let mut samples = state.samples.clone();
        samples.borrow_and_update();
        Self {
            runtime: state.runtime.clone(),
            first: true,
            last_sequence: 0,
            subscription,
            samples,
            logs,
            interval,
            snapshots: state.snapshots.clone(),
        }
    }

    async fn next(&mut self) -> io::Result<Bytes> {
        match self.subscription.kind {
            Kind::Logs => loop {
                match self.logs.as_mut().expect("log subscription").recv().await {
                    Ok(event) if event.level.to_level_filter() <= self.subscription.level => {
                        let level = crate::control::logs::level_name(event.level.to_level_filter());
                        return json_bytes(&if self.subscription.structured {
                            json!({"time":event.time,"level":level,"message":event.message,"fields":[]})
                        } else {
                            json!({"type":level,"payload":event.message})
                        });
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return Err(io::ErrorKind::BrokenPipe.into()),
                }
            },
            Kind::Connections => {
                if self.first || self.subscription.interval != Duration::from_secs(1) {
                    if !self.first {
                        self.interval.tick().await;
                    }
                    let rss = self.samples.borrow().rss;
                    let snapshot =
                        snapshot(self.runtime.flows.clone(), self.snapshots.clone(), rss).await?;
                    self.first = false;
                    self.last_sequence = snapshot.sequence;
                    return snapshot
                        .bytes
                        .map_err(|error| io::Error::new(error.kind(), error));
                }
                loop {
                    self.samples.changed().await.map_err(io::Error::other)?;
                    let sample = self.samples.borrow_and_update();
                    // A shared snapshot may finish serializing after a newer first frame.
                    if sample.sequence > self.last_sequence {
                        self.last_sequence = sample.sequence;
                        return sample
                            .connections
                            .clone()
                            .map_err(|error| io::Error::new(error.kind(), error));
                    }
                }
            }
            Kind::Traffic | Kind::Memory => {
                if std::mem::take(&mut self.first) && matches!(self.subscription.kind, Kind::Memory)
                {
                    return Ok(Sample::initial().memory);
                }
                self.samples.changed().await.map_err(io::Error::other)?;
                let sample = self.samples.borrow_and_update();
                Ok(match self.subscription.kind {
                    Kind::Traffic => sample.traffic.clone(),
                    _ => sample.memory.clone(),
                })
            }
        }
    }
}

pub async fn websocket(
    state: Arc<ApiState>,
    websocket: hyper_tungstenite::HyperWebsocket,
    subscription: Subscription,
    permit: OwnedSemaphorePermit,
    connection_permit: Arc<OwnedSemaphorePermit>,
) {
    let Ok(websocket) = websocket.await else {
        return;
    };
    serve_websocket(state, websocket, subscription, permit, connection_permit).await;
}

async fn serve_websocket<S>(
    state: Arc<ApiState>,
    websocket: hyper_tungstenite::WebSocketStream<S>,
    subscription: Subscription,
    _permit: OwnedSemaphorePermit,
    _connection_permit: Arc<OwnedSemaphorePermit>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut incoming) = websocket.split();
    let mut source = Source::new(&state, subscription);
    'stream: loop {
        // Ping/Pong handling must not cancel a pending initial snapshot or interval tick.
        let next = source.next();
        tokio::pin!(next);
        loop {
            let (message, data_frame) = tokio::select! {
                _ = state.cancel.cancelled() => break 'stream,
                data = &mut next => match data {
                    Ok(data) => (Message::Text(String::from_utf8(data.to_vec()).expect("JSON UTF8").into()), true),
                    Err(error) if error.kind() == io::ErrorKind::FileTooLarge => (Message::Close(Some(CloseFrame {
                        code: CloseCode::Size,
                        reason: "response exceeds 32 MiB".into(),
                    })), true),
                    Err(_) => break 'stream,
                },
                received = incoming.next() => match received {
                    Some(Ok(Message::Ping(bytes))) => (Message::Pong(bytes), false),
                    Some(Ok(Message::Pong(_))) => continue,
                    _ => break 'stream,
                },
            };
            let closing = message.is_close();
            if !matches!(
                tokio::time::timeout(Duration::from_secs(5), sink.send(message)).await,
                Ok(Ok(()))
            ) {
                break 'stream;
            }
            if closing {
                break 'stream;
            }
            if data_frame {
                break;
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_millis(250), sink.close()).await;
}

pub async fn http(
    state: Arc<ApiState>,
    sender: mpsc::Sender<Result<hyper::body::Frame<Bytes>, io::Error>>,
    subscription: Subscription,
    connection: CancellationToken,
    _permit: OwnedSemaphorePermit,
) {
    let mut source = Source::new(&state, subscription);
    loop {
        let data = tokio::select! {
            _ = state.cancel.cancelled() => break,
            _ = sender.closed() => return,
            data = source.next() => match data { Ok(data) => data, Err(_) => break },
        };
        let mut line = Vec::with_capacity(data.len() + 1);
        line.extend_from_slice(&data);
        line.push(b'\n');
        if !matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                sender.send(Ok(hyper::body::Frame::data(line.into())))
            )
            .await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
    connection.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::flows::{FlowContext, FlowInfo};
    use crate::control::runtime::ControlService;
    use futures::FutureExt;

    #[tokio::test(start_paused = true)]
    async fn websocket_write_deadline_releases_subscription_and_connection() {
        let service = ControlService::new(Default::default()).unwrap();
        let runtime = service.runtime.clone();
        let subscriptions = runtime.subscribers.available_permits();
        let connections = runtime.connections.available_permits();
        let (_sender, samples) = watch::channel(Sample::initial());
        let state = Arc::new(ApiState {
            runtime: runtime.clone(),
            samples,
            tasks: Default::default(),
            cancel: CancellationToken::new(),
            snapshots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        let (_client, server) = tokio::io::duplex(1);
        let server = hyper_tungstenite::WebSocketStream::from_raw_socket(
            server,
            hyper_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        let task = serve_websocket(
            state,
            server,
            Subscription::parse("memory", &HashMap::new()).unwrap(),
            runtime.subscribers.clone().try_acquire_owned().unwrap(),
            Arc::new(runtime.connections.clone().try_acquire_owned().unwrap()),
        );
        tokio::pin!(task);
        assert!(task.as_mut().now_or_never().is_none());
        assert_eq!(runtime.subscribers.available_permits(), subscriptions - 1);
        assert_eq!(runtime.connections.available_permits(), connections - 1);
        tokio::time::advance(Duration::from_millis(4999)).await;
        assert!(task.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(task.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(250)).await;
        assert!(task.as_mut().now_or_never().is_some());
        assert_eq!(runtime.subscribers.available_permits(), subscriptions);
        assert_eq!(runtime.connections.available_permits(), connections);
    }

    #[tokio::test(start_paused = true)]
    async fn http_write_deadline_releases_subscription_and_cancels_connection() {
        let service = ControlService::new(Default::default()).unwrap();
        let runtime = service.runtime.clone();
        let subscriptions = runtime.subscribers.available_permits();
        let (samples_sender, samples) = watch::channel(Sample::initial());
        let state = Arc::new(ApiState {
            runtime: runtime.clone(),
            samples,
            tasks: Default::default(),
            cancel: CancellationToken::new(),
            snapshots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        let (sender, receiver) = mpsc::channel(1);
        let connection = CancellationToken::new();
        let task = http(
            state,
            sender,
            Subscription::parse("memory", &HashMap::new()).unwrap(),
            connection.clone(),
            runtime.subscribers.clone().try_acquire_owned().unwrap(),
        );
        tokio::pin!(task);
        assert!(task.as_mut().now_or_never().is_none());
        assert_eq!(receiver.len(), 1);
        samples_sender.send_replace(Sample::initial());
        assert!(task.as_mut().now_or_never().is_none());
        assert_eq!(runtime.subscribers.available_permits(), subscriptions - 1);
        tokio::time::advance(Duration::from_millis(4999)).await;
        assert!(task.as_mut().now_or_never().is_none());
        assert!(!connection.is_cancelled());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(task.as_mut().now_or_never().is_some());
        assert_eq!(runtime.subscribers.available_permits(), subscriptions);
        assert!(connection.is_cancelled());
    }

    #[tokio::test]
    async fn oversized_snapshot_closes_websocket_with_size_reason() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let error = json_bytes(&"x".repeat(32 * 1024 * 1024)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
            let service = ControlService::new(Default::default()).unwrap();
            let (sender, samples) = watch::channel(Sample::initial());
            let state = Arc::new(ApiState {
                runtime: service.runtime.clone(),
                samples,
                tasks: Default::default(),
                cancel: CancellationToken::new(),
                snapshots: Arc::new(tokio::sync::Semaphore::new(2)),
            });
            let (client, server) = tokio::io::duplex(4096);
            let server = hyper_tungstenite::WebSocketStream::from_raw_socket(
                server,
                hyper_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            let mut client = hyper_tungstenite::WebSocketStream::from_raw_socket(
                client,
                hyper_tungstenite::tungstenite::protocol::Role::Client,
                None,
            )
            .await;
            let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(serve_websocket(
                state,
                server,
                Subscription::parse("connections", &HashMap::new()).unwrap(),
                service
                    .runtime
                    .subscribers
                    .clone()
                    .try_acquire_owned()
                    .unwrap(),
                Arc::new(
                    service
                        .runtime
                        .connections
                        .clone()
                        .try_acquire_owned()
                        .unwrap(),
                ),
            )));
            assert!(client.next().await.unwrap().unwrap().is_text());
            sender.send_replace(Sample {
                sequence: u64::MAX,
                connections: Err(Arc::new(error)),
                ..Sample::initial()
            });
            let Message::Close(Some(frame)) = client.next().await.unwrap().unwrap() else {
                panic!("expected a close frame")
            };
            assert_eq!(frame.code, CloseCode::Size);
            assert_eq!(frame.reason, "response exceeds 32 MiB");
            task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_first_snapshot_stays_immediate() {
        let service = ControlService::new(Default::default()).unwrap();
        let (_sender, samples) = watch::channel(Sample::initial());
        let state = ApiState {
            runtime: service.runtime.clone(),
            samples,
            tasks: Default::default(),
            cancel: CancellationToken::new(),
            snapshots: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        let mut source = Source::new(
            &state,
            Subscription::parse("connections", &HashMap::new()).unwrap(),
        );
        assert!(source.next().now_or_never().is_none());
        state.snapshots.add_permits(1);
        let bytes = tokio::time::timeout(Duration::from_millis(500), source.next())
            .await
            .unwrap()
            .unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(snapshot["connections"], json!([]));
        assert!(source.last_sequence > 0);
    }

    #[tokio::test]
    async fn initial_snapshot_fences_an_older_shared_snapshot_published_later() {
        let service = ControlService::new(Default::default()).unwrap();
        let (sender, samples) = watch::channel(Sample::initial());
        let state = ApiState {
            runtime: service.runtime.clone(),
            samples,
            tasks: Default::default(),
            cancel: CancellationToken::new(),
            snapshots: Arc::new(tokio::sync::Semaphore::new(2)),
        };
        let mut source = Source::new(
            &state,
            Subscription::parse("connections", &HashMap::new()).unwrap(),
        );
        let guard = FlowContext {
            registry: state.runtime.flows.clone(),
            generation: 1,
            inbound: "test".into(),
            scope: "root".into(),
            protocol: "Socks5".into(),
        }
        .register(
            "tcp",
            &crate::address::NetLocation::from_str("example.com:80", None)
                .unwrap()
                .into(),
            Vec::new(),
            "all",
            FlowInfo::default(),
        );
        guard.entry.counters.upload(10);
        let older = state.runtime.flows.snapshot(0);
        guard.entry.counters.upload(20);
        drop(guard);

        let first: serde_json::Value =
            serde_json::from_slice(&source.next().await.unwrap()).unwrap();
        assert_eq!(first["uploadTotal"], 30);
        assert_eq!(first["connections"], json!([]));
        assert!(first.get("sequence").is_none());

        // Hold serialization/publication of the shared sample until after the first frame.
        let older = SerializedConnections::new(older);
        sender.send_replace(Sample {
            sequence: older.sequence,
            connections: older.bytes,
            ..Sample::initial()
        });
        let next = source.next();
        tokio::pin!(next);
        assert!(next.as_mut().now_or_never().is_none());

        let newer = SerializedConnections::new(state.runtime.flows.snapshot(0));
        sender.send_replace(Sample {
            sequence: newer.sequence,
            connections: newer.bytes,
            ..Sample::initial()
        });
        let second: serde_json::Value = serde_json::from_slice(&next.await.unwrap()).unwrap();
        assert_eq!(first, second);
    }
}
