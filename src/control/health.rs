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
use tokio_util::task::AbortOnDropHandle;

use super::probes::{PROBE_CONCURRENCY, ProbeQuery, local_failure, request_via};
use super::selection::{Choices, ManualSelectorPath, SelectionView, manual_choices_changed};
use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain};
use crate::config::HealthCheckConfig;
use crate::resolver::Resolver;

pub(crate) const MAX_PATHS: usize = 256;
const MAX_CHECKS: usize = 1024;

#[derive(Debug)]
pub(crate) struct HealthCapacity(String);

impl std::fmt::Display for HealthCapacity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for HealthCapacity {}

pub(crate) fn capacity_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, HealthCapacity(message))
}

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
        self.query()
            .map_err(|_| invalid("health_check url must be HTTP(S), at most 2048 bytes, without credentials or fragments; timeout_ms must be 1..32767"))?
            .validate_automatic_target("fallback URL")
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
    stopped_at: Mutex<Option<Instant>>,
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
    choices: Choices,
}

struct JobState {
    sample: Option<Sample>,
    due: Instant,
    revision: u64,
}

pub(crate) struct ProbeJob {
    check: HealthCheckConfig,
    query: ProbeQuery,
    chain: ClientChainGroup,
    resolver: Arc<dyn Resolver>,
    selectors: Vec<(String, String)>,
    dynamic_selectors: Vec<ManualSelectorPath>,
    resolver_selectors: Vec<ManualSelectorPath>,
    state: Mutex<JobState>,
}

impl ProbeJob {
    fn selected(&self, choices: &Choices) -> bool {
        self.selectors
            .iter()
            .all(|(group, member)| choices.get(group) == Some(member))
    }

    pub(crate) fn health(&self, choices: &Choices, now: Instant) -> Health {
        let state = self.state.lock();
        let Some(sample) = &state.sample else {
            return Health::Unknown;
        };
        if manual_choices_changed(&self.dynamic_selectors, &sample.choices, choices) {
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

    #[cfg(test)]
    pub(crate) fn record(
        &self,
        result: io::Result<(u16, bool)>,
        choices: Arc<Choices>,
        now: Instant,
    ) {
        let revision = self.state.lock().revision;
        self.record_if_current(result, choices, now, revision);
    }

    fn record_if_current(
        &self,
        result: io::Result<(u16, bool)>,
        choices: Arc<Choices>,
        now: Instant,
        revision: u64,
    ) {
        if result.as_ref().is_err_and(local_failure) {
            return;
        }
        let mut state = self.state.lock();
        if revision != state.revision {
            return;
        }
        state.sample = Some(Sample {
            healthy: result.is_ok_and(|(_, satisfied)| satisfied),
            at: now,
            choices: self
                .dynamic_selectors
                .iter()
                .flatten()
                .filter_map(|(group, _)| {
                    choices
                        .get(group)
                        .map(|member| (group.clone(), member.clone()))
                })
                .collect(),
        });
    }
}

impl HealthState {
    pub(crate) fn choices_changed(&self, previous: &Choices, current: &Choices) {
        let now = Instant::now();
        for job in self.jobs.lock().values().filter_map(Weak::upgrade) {
            let path_changed = manual_choices_changed(&job.dynamic_selectors, previous, current);
            if path_changed
                || manual_choices_changed(&job.resolver_selectors, previous, current)
                || job.selected(previous) != job.selected(current)
            {
                let mut state = job.state.lock();
                state.revision = state.revision.wrapping_add(1);
                state.due = state.due.min(now);
                if path_changed {
                    state.sample = None;
                }
            }
        }
        self.changed.notify_one();
    }

    pub(crate) fn sample_time(&self) -> Instant {
        // Draining sessions keep the retired generation's last health snapshot.
        self.stopped_at.lock().unwrap_or_else(Instant::now)
    }

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
        dynamic_selectors: Vec<ManualSelectorPath>,
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
            return Err(capacity_error(format!(
                "fallback exceeds {MAX_CHECKS} active path checks"
            )));
        }
        let job = Arc::new(ProbeJob {
            check: check.clone(),
            query: check.query()?,
            chain: ClientChainGroup::new(vec![chain()]),
            resolver_selectors: resolver.manual_selector_paths(),
            resolver,
            selectors,
            dynamic_selectors,
            state: Mutex::new(JobState {
                sample: None,
                due: Instant::now(),
                revision: 0,
            }),
        });
        jobs.insert(key, Arc::downgrade(&job));
        self.changed.notify_one();
        Ok(job)
    }
}

pub(crate) struct HealthService {
    cancel: CancellationToken,
    task: AbortOnDropHandle<()>,
}

struct HealthLifetime(Arc<SelectionView>);

impl Drop for HealthLifetime {
    fn drop(&mut self) {
        *self.0.health.stopped_at.lock() = Some(Instant::now());
    }
}

impl HealthService {
    pub(crate) fn start(
        view: Arc<SelectionView>,
        budget: Arc<Semaphore>,
        forbidden: Vec<ipnetwork::IpNetwork>,
    ) -> Self {
        *view.health.stopped_at.lock() = None;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(HealthLifetime(view), budget, forbidden, cancel.clone()));
        Self {
            cancel,
            task: AbortOnDropHandle::new(task),
        }
    }

    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

async fn run(
    lifetime: HealthLifetime,
    budget: Arc<Semaphore>,
    forbidden: Vec<ipnetwork::IpNetwork>,
    cancel: CancellationToken,
) {
    let view = &lifetime.0;
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
        let mut waiting: Vec<_> = jobs
            .into_iter()
            .filter(|job| !active.contains(&(Arc::as_ptr(job) as usize)))
            .map(|job| {
                let due = job.state.lock().due;
                (due, job)
            })
            .collect();
        waiting.sort_by_key(|(due, _)| *due);
        for (due, job) in waiting {
            if active.len() >= PROBE_CONCURRENCY {
                break;
            }
            let id = Arc::as_ptr(&job) as usize;
            if due <= now {
                active.insert(id);
                pending.push(check(job, view.clone(), budget.clone(), &forbidden));
            } else {
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
    let mut revision = job.state.lock().revision;
    let mut choices = view.snapshot();
    let deadline = Instant::now() + job.query.timeout;
    let admission = if !job.selected(&choices) {
        None
    } else {
        match budget.try_acquire() {
            Ok(permit) => Some((permit, false)),
            Err(_) => tokio::time::timeout_at(deadline, budget.acquire())
                .await
                .ok()
                .and_then(Result::ok)
                .map(|permit| (permit, true)),
        }
    };
    if let Some((_permit, queued)) = admission
        && Instant::now() < deadline
    {
        // Read revision before choices: publication updates revisions while holding
        // the selection write lock, so a concurrent change can only discard this attempt.
        revision = job.state.lock().revision;
        choices = view.snapshot();
        if job.selected(&choices) {
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
            .await;
            match result {
                Ok(result) => job.record_if_current(result, choices, Instant::now(), revision),
                // Admission shortened this attempt, so expiry says nothing about the path.
                Err(_) if queued => {}
                Err(_) => job.record_if_current(
                    Err(io::ErrorKind::TimedOut.into()),
                    choices,
                    Instant::now(),
                    revision,
                ),
            }
        }
    }
    let interval_ms = job.check.interval_secs * 1000;
    let jitter = rand::random::<u64>() % (interval_ms / 5 + 1);
    let mut state = job.state.lock();
    if state.revision == revision {
        state.due = Instant::now() + Duration::from_millis(interval_ms - interval_ms / 10 + jitter);
    }
    Arc::as_ptr(&job) as usize
}
