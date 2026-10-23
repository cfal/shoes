mod auth;
pub(crate) mod dto;
mod listener;
pub(crate) mod probes;
mod router;
mod streams;

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::control::runtime::ControlRuntime;

pub type Body = http_body_util::combinators::UnsyncBoxBody<Bytes, io::Error>;

struct ApiState {
    runtime: Arc<ControlRuntime>,
    samples: watch::Receiver<streams::Sample>,
    tasks: TaskTracker,
    cancel: CancellationToken,
    snapshots: Arc<tokio::sync::Semaphore>,
}

pub struct ApiService {
    state: Arc<ApiState>,
    listeners: Vec<tokio_util::task::AbortOnDropHandle<()>>,
}

impl ApiService {
    pub async fn start(runtime: Arc<ControlRuntime>) -> io::Result<Self> {
        let binds = listener::bind(&runtime.config.listeners).await?;
        let (sender, samples) = watch::channel(streams::Sample::initial());
        let state = Arc::new(ApiState {
            cancel: runtime.shutdown.child_token(),
            runtime,
            samples,
            tasks: TaskTracker::new(),
            snapshots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        state.runtime.logs.install();
        state.tasks.spawn(streams::sample(state.clone(), sender));
        let listeners = binds
            .into_iter()
            .map(|bind| {
                tokio_util::task::AbortOnDropHandle::new(tokio::spawn(listener::serve(
                    bind,
                    state.clone(),
                )))
            })
            .collect();
        Ok(Self { state, listeners })
    }

    pub async fn shutdown(&mut self) {
        self.state.cancel.cancel();
        self.listeners.clear();
        self.state.tasks.close();
        if tokio::time::timeout(std::time::Duration::from_secs(6), self.state.tasks.wait())
            .await
            .is_err()
        {
            log::warn!("Clash API shutdown deadline exceeded");
        }
    }
}

impl Drop for ApiService {
    fn drop(&mut self) {
        self.state.cancel.cancel();
    }
}

pub(crate) fn json_bytes(value: &impl serde::Serialize) -> io::Result<Bytes> {
    struct Bounded(Vec<u8>);
    impl io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > 32 * 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "response exceeds 32 MiB",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = Bounded(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(|error| {
        io::Error::new(error.io_error_kind().unwrap_or(io::ErrorKind::Other), error)
    })?;
    Ok(bytes.0.into())
}

fn full(bytes: Bytes) -> Body {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn json(status: hyper::StatusCode, value: &impl serde::Serialize) -> hyper::Response<Body> {
    match json_bytes(value) {
        Ok(bytes) => hyper::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(full(bytes))
            .unwrap(),
        Err(_) => error(
            hyper::StatusCode::INSUFFICIENT_STORAGE,
            "response exceeds 32 MiB",
        ),
    }
}

fn error(status: hyper::StatusCode, message: &str) -> hyper::Response<Body> {
    json(status, &serde_json::json!({"message":message}))
}

fn no_content() -> hyper::Response<Body> {
    hyper::Response::builder()
        .status(204)
        .body(full(Bytes::new()))
        .unwrap()
}
