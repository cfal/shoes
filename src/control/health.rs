//! Generation-local health for concrete paths, never passive application failures.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::{StreamExt, stream::FuturesUnordered};
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::probes::{ProbeQuery, local_failure, request_via};
use super::selection::{Choices, SelectionView};
use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain};
use crate::config::HealthCheckConfig;
use crate::resolver::Resolver;

pub(crate) const MAX_PATHS: usize = 256;
const MAX_CHECKS: usize = 1024;
const CONCURRENCY: usize = 16;

#[cfg(test)]
mod tests;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl HealthCheckConfig {
    pub(crate) fn query(&self) -> io::Result<ProbeQuery> {
        ProbeQuery::parse(
            &HashMap::from([
                ("url".into(), self.url.clone()),
                ("timeout".into(), self.timeout_ms.to_string()),
                ("expected".into(), self.expected_status.to_string()),
            ]),
            false,
        )
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if !(1..=86_400).contains(&self.interval_secs)
            || !(100..=599).contains(&self.expected_status)
        {
            return Err(invalid(
                "health_check interval_secs must be 1..86400 and expected_status 100..599",
            ));
        }
        self.query()?.validate_automatic_target()
    }

    fn freshness(&self) -> Duration {
        Duration::from_secs(self.interval_secs * 3) + Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Debug)]
pub(crate) struct FallbackDefinition {
    pub members: Vec<String>,
    pub check: HealthCheckConfig,
}

#[derive(Debug, Default)]
pub(crate) struct HealthState {
    pub definitions: BTreeMap<String, FallbackDefinition>,
    jobs: Mutex<HashMap<ProbeKey, Weak<ProbeJob>>>,
    changed: Notify,
}

// Configuration bytes are hashed, not retained in diagnostics. Resolver identity prevents
// sharing a sample across different DNS policies; the enclosing state supplies generation identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProbeKey {
    path: [u8; 32],
    resolver: usize,
    check: HealthCheckConfig,
    selectors: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Health {
    Unknown,
    Healthy,
    Failed,
    Stale,
}

struct Sample {
    healthy: bool,
    at: Instant,
    choices: Arc<Choices>,
}

struct JobState {
    sample: Option<Sample>,
    due: Instant,
}

pub(crate) struct ProbeJob {
    check: HealthCheckConfig,
    query: ProbeQuery,
    chain: ClientChainGroup,
    resolver: Arc<dyn Resolver>,
    selectors: Vec<(String, String)>,
    state: Mutex<JobState>,
}

impl std::fmt::Debug for ProbeJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeJob").finish_non_exhaustive()
    }
}

impl ProbeJob {
    pub(crate) fn health(&self, choices: &Choices, now: Instant) -> Health {
        let state = self.state.lock();
        let Some(sample) = &state.sample else {
            return Health::Unknown;
        };
        if sample.choices.as_ref() != choices {
            return Health::Unknown;
        }
        if now.duration_since(sample.at) >= self.check.freshness() {
            Health::Stale
        } else if sample.healthy {
            Health::Healthy
        } else {
            Health::Failed
        }
    }

    pub(crate) fn record(
        &self,
        result: io::Result<(u16, bool)>,
        choices: Arc<Choices>,
        now: Instant,
    ) {
        let mut state = self.state.lock();
        if result
            .as_ref()
            .err()
            .is_none_or(|error| !local_failure(error))
        {
            state.sample = Some(Sample {
                healthy: result.is_ok_and(|(_, expected)| expected),
                at: now,
                choices,
            });
        }
    }
}

impl HealthState {
    pub(crate) fn new(definitions: BTreeMap<String, FallbackDefinition>) -> Self {
        Self {
            definitions,
            ..Self::default()
        }
    }

    pub(crate) fn register(
        &self,
        path: [u8; 32],
        check: &HealthCheckConfig,
        resolver: Arc<dyn Resolver>,
        selectors: Vec<(String, String)>,
        chain: impl FnOnce() -> ClientProxyChain,
    ) -> io::Result<Arc<ProbeJob>> {
        let key = ProbeKey {
            path,
            resolver: Arc::as_ptr(&resolver) as *const () as usize,
            check: check.clone(),
            selectors: selectors.clone(),
        };
        let mut jobs = self.jobs.lock();
        if let Some(job) = jobs.get(&key).and_then(Weak::upgrade) {
            return Ok(job);
        }
        jobs.retain(|_, job| job.strong_count() != 0);
        if jobs.len() >= MAX_CHECKS {
            return Err(invalid("fallback exceeds 1024 active path checks"));
        }
        let job = Arc::new(ProbeJob {
            check: check.clone(),
            query: check.query()?,
            chain: ClientChainGroup::new(vec![chain()]),
            resolver,
            selectors,
            state: Mutex::new(JobState {
                sample: None,
                due: Instant::now(),
            }),
        });
        jobs.insert(key, Arc::downgrade(&job));
        self.changed.notify_one();
        Ok(job)
    }
}

pub(crate) struct HealthService {
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HealthService {
    pub(crate) fn start(
        view: Arc<SelectionView>,
        budget: Arc<Semaphore>,
        forbidden: Vec<ipnetwork::IpNetwork>,
    ) -> Self {
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(view, budget, forbidden, cancel.clone()));
        Self {
            cancel,
            task: Some(task),
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for HealthService {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run(
    view: Arc<SelectionView>,
    budget: Arc<Semaphore>,
    forbidden: Vec<ipnetwork::IpNetwork>,
    cancel: CancellationToken,
) {
    let mut active = HashSet::new();
    let mut pending = FuturesUnordered::new();
    loop {
        let now = Instant::now();
        let mut next = now + Duration::from_secs(86_400);
        let jobs: Vec<_> = view
            .health
            .jobs
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for job in jobs {
            let id = Arc::as_ptr(&job) as usize;
            if active.contains(&id) {
                continue;
            }
            let due = job.state.lock().due;
            if due <= now && active.len() < CONCURRENCY {
                active.insert(id);
                pending.push(check(job, view.clone(), budget.clone(), &forbidden));
            } else if active.len() < CONCURRENCY {
                next = next.min(due);
            }
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(id) = pending.next(), if !pending.is_empty() => { active.remove(&id); }
            _ = view.health.changed.notified() => {},
            _ = tokio::time::sleep_until(next) => {},
        }
    }
    // Dropping inline futures releases both the transport and shared admission permits.
}

async fn check(
    job: Arc<ProbeJob>,
    view: Arc<SelectionView>,
    budget: Arc<Semaphore>,
    forbidden: &[ipnetwork::IpNetwork],
) -> usize {
    let deadline = Instant::now() + job.query.timeout;
    if let Ok(Ok(_permit)) = tokio::time::timeout_at(deadline, budget.acquire()).await
        && Instant::now() < deadline
    {
        let choices = view.snapshot();
        if job
            .selectors
            .iter()
            .all(|(group, member)| choices.get(group) == Some(member))
        {
            let result = tokio::time::timeout_at(
                deadline,
                super::url_test::BACKGROUND.scope(
                    (),
                    request_via(
                        &job.chain,
                        job.resolver.clone(),
                        forbidden,
                        &job.query,
                        crate::rustls_config_util::create_dns_client_config,
                    ),
                ),
            )
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
            job.record(result, choices, Instant::now());
        }
    }
    let interval_ms = job.check.interval_secs * 1000;
    let jitter = rand::random::<u64>() % (interval_ms / 5 + 1);
    job.state.lock().due =
        Instant::now() + Duration::from_millis(interval_ms - interval_ms / 10 + jitter);
    Arc::as_ptr(&job) as usize
}
