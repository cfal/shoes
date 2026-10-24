use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;

use crate::config::UrlTestConfig;

tokio::task_local! {
    pub static BACKGROUND: ();
}

pub fn is_background() -> bool {
    BACKGROUND.try_with(|_| ()).is_ok()
}

// Only unambiguous transport failures request a recheck. A user destination's
// failure is not evidence that the configured probe URL is unreachable.
pub fn remote_failure(error: &io::Error) -> bool {
    if crate::resources::is_exhausted(error) {
        return false;
    }
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
    )
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    at: Instant,
    delay: Option<u16>,
}

#[derive(Debug, Default)]
struct State {
    samples: HashMap<String, Sample>,
    incumbent: [Option<String>; 2],
    last_touch: Option<Instant>,
    last_check: Option<Instant>,
    last_unqueued_admission: Option<Instant>,
    recheck: bool,
    cursor: usize,
}

#[derive(Debug)]
pub struct AutomaticGroup {
    pub config: UrlTestConfig,
    pub members: Vec<String>,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
pub struct AutomaticGroups(pub BTreeMap<String, AutomaticGroup>);

impl AutomaticGroups {
    pub fn filter(
        &self,
        origins: &[Option<super::catalog::MemberOrigin>],
        candidates: &mut Vec<usize>,
        udp: bool,
    ) {
        let mut depths = HashMap::<&str, usize>::new();
        for &index in candidates.iter() {
            let Some(origin) = &origins[index] else {
                continue;
            };
            for (depth, (group, _)) in origin.path.iter().enumerate() {
                if self.0.contains_key(group) {
                    depths
                        .entry(group)
                        .and_modify(|value| *value = (*value).max(depth))
                        .or_insert(depth);
                }
            }
        }
        let mut groups: Vec<_> = depths.into_iter().collect();
        groups.sort_unstable_by_key(|(_, depth)| std::cmp::Reverse(*depth));
        for (group, _) in groups {
            let eligible = candidates
                .iter()
                .filter_map(|&index| origins[index].as_ref())
                .flat_map(|origin| &origin.path)
                .filter(|(name, _)| name == group)
                .map(|(_, member)| member.as_str())
                .collect();
            if let Some(selected) = self.0[group].choose(&eligible, udp) {
                candidates.retain(|&index| {
                    origins[index].as_ref().is_none_or(|origin| {
                        origin
                            .path
                            .iter()
                            .all(|(name, member)| name != group || member == &selected)
                    })
                });
            }
        }
    }

    pub fn insert(
        &mut self,
        name: String,
        mut config: UrlTestConfig,
        members: Vec<String>,
    ) -> io::Result<()> {
        config.validate()?;
        if members.is_empty() || members.iter().collect::<HashSet<_>>().len() != members.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "url-test requires nonempty, distinct members",
            ));
        }
        config.url = url::Url::parse(&config.url)
            .map_err(io::Error::other)?
            .to_string();
        self.0.insert(
            name,
            AutomaticGroup {
                config,
                members,
                state: Mutex::default(),
            },
        );
        Ok(())
    }

    pub fn record(&self, member: &str, url: &str, delay: Option<u16>) {
        for group in self.0.values() {
            if group.config.url == url && group.members.iter().any(|name| name == member) {
                group.state.lock().samples.insert(
                    member.into(),
                    Sample {
                        at: Instant::now(),
                        delay,
                    },
                );
            }
        }
    }

    pub fn touch(&self, name: &str, failed: bool) {
        if !is_background()
            && let Some(group) = self.0.get(name)
        {
            let mut state = group.state.lock();
            state.last_touch = Some(Instant::now());
            state.recheck |= failed;
        }
    }
}

impl AutomaticGroup {
    fn fresh(&self, sample: &Sample, now: Instant) -> bool {
        now.duration_since(sample.at)
            <= Duration::from_secs(self.config.interval * 2)
                + Duration::from_millis(self.config.timeout)
    }

    pub fn choose(&self, eligible: &HashSet<&str>, udp: bool) -> Option<String> {
        let mut state = self.state.lock();
        let now = Instant::now();
        let delay = |name: &str| {
            state
                .samples
                .get(name)
                .filter(|sample| self.fresh(sample, now))
                .and_then(|sample| sample.delay)
        };
        let best = self
            .members
            .iter()
            .filter(|name| eligible.contains(name.as_str()))
            .filter_map(|name| delay(name).map(|delay| (name, delay)))
            .min_by_key(|(_, delay)| *delay);
        let incumbent = state.incumbent[usize::from(udp)]
            .as_ref()
            .filter(|name| eligible.contains(name.as_str()));
        let selected = match (best, incumbent) {
            (Some((best, best_delay)), Some(current)) => {
                if delay(current).is_some_and(|delay| {
                    u32::from(delay) <= u32::from(best_delay) + u32::from(self.config.tolerance)
                }) {
                    Some(current.clone())
                } else {
                    Some(best.clone())
                }
            }
            (Some((best, _)), None) => Some(best.clone()),
            (None, Some(current)) => Some(current.clone()),
            (None, None) => self
                .members
                .iter()
                .find(|name| eligible.contains(name.as_str()))
                .cloned(),
        };
        state.incumbent[usize::from(udp)] = selected.clone();
        selected
    }

    pub fn health(&self, member: &str) -> &'static str {
        let state = self.state.lock();
        match state.samples.get(member) {
            None => "unprobed",
            Some(sample) if !self.fresh(sample, Instant::now()) => "stale",
            Some(Sample { delay: Some(_), .. }) => "healthy",
            Some(_) => "dead",
        }
    }

    pub fn due_members(&self, now: Instant) -> Option<Vec<usize>> {
        let mut state = self.state.lock();
        let interval = Duration::from_secs(self.config.interval);
        if let Some(last_check) = state.last_check {
            let elapsed = now.duration_since(last_check);
            let recheck_due = state.recheck && elapsed >= Duration::from_secs(1);
            if !recheck_due {
                if elapsed < interval {
                    return None;
                }
                let idle = state
                    .last_touch
                    .is_none_or(|touch| now.duration_since(touch) >= interval);
                if self.config.lazy && idle {
                    return None;
                }
            }
        }
        state.last_check = Some(now);
        state.recheck = false;
        let members = (state.cursor..self.members.len())
            .chain(0..state.cursor)
            .collect();
        Some(members)
    }

    pub fn admitted(&self, index: usize, queued: bool) {
        let mut state = self.state.lock();
        state.cursor = (index + 1) % self.members.len();
        if !queued {
            state.last_unqueued_admission = Some(Instant::now());
        }
    }

    pub fn last_unqueued_admission(&self) -> Option<Instant> {
        self.state.lock().last_unqueued_admission
    }

    pub fn cancel_check(&self) {
        self.state.lock().last_check = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups() -> AutomaticGroups {
        let mut groups = AutomaticGroups::default();
        for (name, url) in [
            ("one", "http://one.invalid/"),
            ("two", "http://two.invalid/"),
        ] {
            groups
                .insert(
                    name.into(),
                    UrlTestConfig {
                        url: url.into(),
                        interval: 10,
                        timeout: 1000,
                        tolerance: 50,
                        lazy: true,
                    },
                    vec!["a".into(), "b".into()],
                )
                .unwrap();
        }
        groups
    }

    #[tokio::test(start_paused = true)]
    async fn selection_health_tolerance_failure_recovery_and_staleness_are_url_scoped() {
        let groups = groups();
        let group = &groups.0["one"];
        let both = HashSet::from(["a", "b"]);
        assert_eq!(group.choose(&both, false).as_deref(), Some("a"));
        assert_eq!(group.health("a"), "unprobed");
        groups.record("b", "http://two.invalid/", Some(1));
        assert_eq!(group.choose(&both, false).as_deref(), Some("a"));
        assert_eq!(groups.0["two"].choose(&both, false).as_deref(), Some("b"));
        groups.record("a", &group.config.url, Some(100));
        groups.record("b", &group.config.url, Some(50));
        assert_eq!(group.choose(&both, false).as_deref(), Some("a"));
        groups.record("b", &group.config.url, Some(49));
        assert_eq!(group.choose(&both, false).as_deref(), Some("b"));
        groups.record("b", &group.config.url, None);
        assert_eq!(group.choose(&both, false).as_deref(), Some("a"));
        groups.record("b", &group.config.url, Some(1));
        assert_eq!(group.choose(&both, false).as_deref(), Some("b"));
        assert_eq!(
            group.choose(&HashSet::from(["a"]), true).as_deref(),
            Some("a")
        );
        assert_eq!(group.choose(&both, false).as_deref(), Some("b"));
        groups.record("a", &group.config.url, None);
        groups.record("b", &group.config.url, None);
        assert_eq!(group.health("b"), "dead");
        assert_eq!(group.choose(&both, false).as_deref(), Some("b"));
        groups.record("b", &group.config.url, Some(1));
        tokio::time::advance(Duration::from_secs(22)).await;
        assert_eq!(group.health("b"), "stale");
        assert_eq!(group.choose(&both, false).as_deref(), Some("b"));
        assert!(group.choose(&HashSet::new(), true).is_none());
        groups.record("a", &group.config.url, Some(150));
        assert_eq!(group.choose(&both, false).as_deref(), Some("a"));
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_startup_probe_suppression_touch_and_rate_limited_recheck() {
        let groups = groups();
        let group = &groups.0["one"];
        assert!(group.due_members(Instant::now()).is_some());
        tokio::time::advance(Duration::from_secs(10)).await;
        BACKGROUND
            .scope((), async {
                groups.touch("one", true);
            })
            .await;
        assert!(group.due_members(Instant::now()).is_none());
        groups.touch("one", false);
        assert!(group.due_members(Instant::now()).is_some());
        groups.touch("one", true);
        assert!(group.due_members(Instant::now()).is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(group.due_members(Instant::now()).is_some());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(group.due_members(Instant::now()).is_none());
    }

    #[test]
    fn local_errors_do_not_request_remote_health_changes() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Unsupported,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::ResourceBusy,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
        ] {
            assert!(!remote_failure(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(remote_failure(&io::Error::from(kind)), "{kind:?}");
        }
    }
}
