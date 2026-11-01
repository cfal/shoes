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
    revision: u64,
    samples: HashMap<String, Sample>,
    incumbent: [Option<String>; 2],
    last_touch: Option<Instant>,
    last_check: Option<Instant>,
    recheck: bool,
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

    #[cfg(test)]
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

    pub(crate) fn tickets(&self, member: &str, url: &str) -> Vec<(&AutomaticGroup, u64)> {
        self.0
            .values()
            .filter(|group| {
                group.config.url == url && group.members.iter().any(|name| name == member)
            })
            .map(|group| (group, group.state.lock().revision))
            .collect()
    }

    pub(crate) fn choices_changed(&self) {
        for group in self.0.values() {
            let mut state = group.state.lock();
            state.revision = state.revision.wrapping_add(1);
            state.samples.clear();
            state.incumbent = [None, None];
            state.last_check = None;
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
    pub(crate) fn revision(&self) -> u64 {
        self.state.lock().revision
    }

    pub(crate) fn record_if_current(&self, member: &str, revision: u64, delay: Option<u16>) {
        let mut state = self.state.lock();
        if state.revision == revision {
            state.samples.insert(
                member.into(),
                Sample {
                    at: Instant::now(),
                    delay,
                },
            );
        }
    }
    fn fresh(&self, sample: &Sample, now: Instant) -> bool {
        now.duration_since(sample.at)
            <= Duration::from_secs(self.config.interval * 2)
                + Duration::from_millis(self.config.timeout)
    }

    pub fn choose(&self, eligible: &HashSet<&str>, udp: bool) -> Option<String> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let selected = self.select_member(&state, eligible, udp, now);
        state.incumbent[usize::from(udp)] = selected.clone();
        selected
    }

    pub(crate) fn peek(&self, eligible: &HashSet<&str>, udp: bool) -> Option<String> {
        let now = Instant::now();
        self.select_member(&self.state.lock(), eligible, udp, now)
    }

    fn select_member(
        &self,
        state: &State,
        eligible: &HashSet<&str>,
        udp: bool,
        now: Instant,
    ) -> Option<String> {
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
        match (best, incumbent) {
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
        }
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

    pub fn due_members(&self, now: Instant) -> Option<std::ops::Range<usize>> {
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
        Some(0..self.members.len())
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

    #[test]
    fn every_selector_change_invalidates_all_groups_but_noops_preserve_samples() {
        use crate::control::selection::{SelectionOwner, SelectorDefinition};
        use std::sync::Arc;

        let mut owner = SelectionOwner::new(None).unwrap();
        let mut view = owner
            .prepare(BTreeMap::from([(
                "unrelated".into(),
                SelectorDefinition {
                    members: vec!["a".into(), "b".into()],
                    default: None,
                },
            )]))
            .unwrap();
        Arc::get_mut(&mut view).unwrap().automatic = groups();
        owner.activate(view.clone()).unwrap();
        let groups = &view.automatic;
        let group = &groups.0["one"];
        let eligible = HashSet::from(["a", "b"]);
        for group in groups.0.values() {
            groups.record("b", &group.config.url, Some(5));
            assert_eq!(group.choose(&eligible, false).as_deref(), Some("b"));
            assert_eq!(group.choose(&eligible, true).as_deref(), Some("b"));
            assert!(group.due_members(Instant::now()).is_some());
        }
        let (_, revision) = groups.tickets("b", &group.config.url)[0];
        owner.select("unrelated", "a").unwrap();
        assert_eq!(group.revision(), revision);
        for group in groups.0.values() {
            assert_eq!(group.health("b"), "healthy");
            assert!(group.due_members(Instant::now()).is_none());
        }

        owner.select("unrelated", "b").unwrap();
        owner.select("unrelated", "a").unwrap();
        group.record_if_current("b", revision, Some(1));
        for group in groups.0.values() {
            assert_eq!(group.health("b"), "unprobed");
            assert_eq!(group.choose(&eligible, false).as_deref(), Some("a"));
            assert_eq!(group.choose(&eligible, true).as_deref(), Some("a"));
            assert!(group.due_members(Instant::now()).is_some());
        }
        let (_, revision) = groups.tickets("a", &group.config.url)[0];
        group.record_if_current("a", revision, Some(3));
        assert_eq!(group.health("a"), "healthy");
        assert_eq!(groups.0["two"].health("a"), "unprobed");
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

    #[test]
    fn peeking_with_different_eligibility_preserves_forwarding_incumbents() {
        let groups = groups();
        let group = &groups.0["one"];
        let both = HashSet::from(["a", "b"]);
        let only_b = HashSet::from(["b"]);
        groups.record("a", &group.config.url, Some(100));
        groups.record("b", &group.config.url, Some(140));
        for udp in [false, true] {
            assert_eq!(group.peek(&only_b, udp).as_deref(), Some("b"));
            assert_eq!(group.state.lock().incumbent[usize::from(udp)], None);
            assert_eq!(group.choose(&both, udp).as_deref(), Some("a"));
            assert_eq!(group.peek(&only_b, udp).as_deref(), Some("b"));
            assert_eq!(
                group.state.lock().incumbent[usize::from(udp)].as_deref(),
                Some("a")
            );
            assert_eq!(group.choose(&both, udp).as_deref(), Some("a"));
            assert_eq!(group.choose(&only_b, udp).as_deref(), Some("b"));
            assert!(group.peek(&HashSet::new(), udp).is_none());
            assert_eq!(group.peek(&both, udp).as_deref(), Some("b"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_startup_probe_suppression_touch_and_rate_limited_recheck() {
        let groups = groups();
        let group = &groups.0["one"];
        assert_eq!(group.due_members(Instant::now()), Some(0..2));
        tokio::time::advance(Duration::from_secs(10)).await;
        BACKGROUND
            .scope((), async {
                groups.touch("one", true);
            })
            .await;
        assert!(group.due_members(Instant::now()).is_none());
        groups.touch("one", false);
        assert_eq!(group.due_members(Instant::now()), Some(0..2));
        groups.touch("one", true);
        assert!(group.due_members(Instant::now()).is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(group.due_members(Instant::now()), Some(0..2));
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
