use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message;
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::{ApiState, json_bytes};

pub struct Sample {
    pub connections: Result<Bytes, String>,
    pub traffic: Bytes,
    pub memory: Bytes,
    pub rss: u64,
}

impl Sample {
    pub fn initial() -> Self {
        Self {
            connections: Ok(Bytes::from_static(
                b"{\"uploadTotal\":0,\"downloadTotal\":0,\"memory\":0,\"connections\":[]}",
            )),
            traffic: Bytes::from_static(b"{\"up\":0,\"down\":0,\"upTotal\":0,\"downTotal\":0}"),
            memory: Bytes::from_static(b"{\"inuse\":0,\"oslimit\":0}"),
            rss: 0,
        }
    }
}

pub async fn sample(state: Arc<ApiState>, sender: watch::Sender<Arc<Sample>>) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut up, mut down, mut rss) = (0, 0, 0);
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
        let snapshot = state.runtime.flows.snapshot(rss);
        let elapsed = previous.elapsed().as_secs_f64();
        previous = Instant::now();
        let traffic = json_bytes(&json!({"up":((snapshot.upload_total.saturating_sub(up)) as f64 / elapsed) as u64,"down":((snapshot.download_total.saturating_sub(down)) as f64 / elapsed) as u64,"upTotal":snapshot.upload_total,"downTotal":snapshot.download_total})).expect("bounded traffic DTO");
        (up, down) = (snapshot.upload_total, snapshot.download_total);
        let connections = json_bytes(&snapshot).map_err(|error| error.to_string());
        if connections.is_err() && !oversized {
            log::warn!(
                "Clash API connection snapshot exceeds response limit; retaining complete tracking"
            );
        }
        oversized = connections.is_err();
        sender.send_replace(Arc::new(Sample {
            connections,
            traffic,
            memory: json_bytes(&json!({"inuse":rss,"oslimit":0})).unwrap(),
            rss,
        }));
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
    subscription: Subscription,
    samples: watch::Receiver<Arc<Sample>>,
    logs: Option<tokio::sync::broadcast::Receiver<crate::control::logs::LogEvent>>,
    interval: tokio::time::Interval,
}

impl Source {
    fn new(state: &ApiState, subscription: Subscription) -> Self {
        let mut interval = tokio::time::interval(subscription.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let logs =
            matches!(subscription.kind, Kind::Logs).then(|| state.runtime.logs.sender.subscribe());
        Self {
            runtime: state.runtime.clone(),
            first: true,
            subscription,
            samples: state.samples.clone(),
            logs,
            interval,
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
                self.interval.tick().await;
                if std::mem::take(&mut self.first)
                    || self.subscription.interval != Duration::from_secs(1)
                {
                    return json_bytes(&self.runtime.flows.snapshot(self.samples.borrow().rss));
                }
                self.samples
                    .borrow()
                    .connections
                    .clone()
                    .map_err(io::Error::other)
            }
            Kind::Traffic | Kind::Memory => {
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
    _permit: OwnedSemaphorePermit,
    _connection_permit: Arc<OwnedSemaphorePermit>,
) {
    let Ok(websocket) = websocket.await else {
        return;
    };
    let (mut sink, mut incoming) = websocket.split();
    let mut source = Source::new(&state, subscription);
    loop {
        let message = tokio::select! {
            _ = state.cancel.cancelled() => break,
            data = source.next() => match data { Ok(data) => Message::Text(String::from_utf8(data.to_vec()).expect("JSON UTF8").into()), Err(_) => break },
            received = incoming.next() => match received {
                Some(Ok(Message::Ping(bytes))) => Message::Pong(bytes),
                Some(Ok(Message::Pong(_))) => continue,
                _ => break,
            },
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), sink.send(message)).await,
            Ok(Ok(()))
        ) {
            break;
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
