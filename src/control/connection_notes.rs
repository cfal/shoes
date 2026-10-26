//! Bounded setup notes attached to active connections, without retained history.
use std::fmt::{self, Write};
use std::sync::{Arc, Weak};
use std::time::Instant;

use parking_lot::Mutex;
use serde::{Serialize, Serializer};
use tokio::sync::OwnedSemaphorePermit;

use crate::address::NetLocation;
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

pub const MAX_FLOWS: usize = 256;
pub const MAX_EVENTS: usize = 32;
pub const TEXT_BYTES: usize = 128;
pub const BUFFER_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub struct Text {
    bytes: [u8; TEXT_BYTES],
    len: usize,
}

impl Write for Text {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let count = value.floor_char_boundary(TEXT_BYTES - self.len);
        self.bytes[self.len..self.len + count].copy_from_slice(&value.as_bytes()[..count]);
        self.len += count;
        // Stop subsequent formatters even when this fragment fits exactly.
        if self.len == TEXT_BYTES || count < value.len() {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

impl Text {
    fn new(args: fmt::Arguments<'_>) -> Self {
        let mut text = Self {
            bytes: [0; TEXT_BYTES],
            len: 0,
        };
        let _ = text.write_fmt(args);
        text
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(std::str::from_utf8(&self.bytes[..self.len]).unwrap())
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepare,
    Routing,
    Dial,
    Setup,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub elapsed_us: u64,
    pub phase: Phase,
    pub text: Text,
}

#[derive(Debug)]
struct State {
    events: Vec<Note>,
    omitted: u64,
}

#[derive(Debug)]
pub struct ConnectionNotes {
    began: Instant,
    state: Mutex<State>,
    // One permit bounds the buffer until its last owner releases it.
    _permit: OwnedSemaphorePermit,
}

// Allow for Arc headers and the shared admission semaphore, not allocator/RSS overhead.
const _: () = assert!(
    std::mem::size_of::<ConnectionNotes>() + MAX_EVENTS * std::mem::size_of::<Note>() + 256
        <= BUFFER_BYTES
);

impl ConnectionNotes {
    pub(super) fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            began: Instant::now(),
            state: Mutex::new(State {
                events: Vec::with_capacity(MAX_EVENTS),
                omitted: 0,
            }),
            _permit: permit,
        }
    }

    pub fn event(&self, phase: Phase, args: fmt::Arguments<'_>) {
        let mut state = self.state.lock();
        if state.events.len() == MAX_EVENTS {
            state.omitted = state.omitted.saturating_add(1);
            return;
        }
        state.events.push(Note {
            elapsed_us: micros(self.began),
            phase,
            text: Text::new(args),
        });
    }

    pub fn snapshot(&self) -> Vec<Note> {
        let state = self.state.lock();
        let mut notes = Vec::with_capacity(state.events.len() + usize::from(state.omitted != 0));
        notes.extend_from_slice(&state.events);
        if state.omitted != 0 {
            notes.push(Note {
                elapsed_us: micros(self.began),
                phase: state.events.last().unwrap().phase,
                text: Text::new(format_args!("{} events omitted", state.omitted)),
            });
        }
        notes
    }
}

fn micros(began: Instant) -> u64 {
    began.elapsed().as_micros().min(u64::MAX as u128) as u64
}

#[derive(Debug)]
struct NotedResolver {
    inner: Arc<dyn Resolver>,
    notes: Weak<ConnectionNotes>,
    phase: Phase,
}

pub fn resolver(
    inner: &Arc<dyn Resolver>,
    notes: Option<&Arc<ConnectionNotes>>,
    phase: Phase,
) -> Arc<dyn Resolver> {
    match notes {
        Some(notes) => Arc::new(NotedResolver {
            inner: inner.clone(),
            notes: Arc::downgrade(notes),
            phase,
        }),
        None => inner.clone(),
    }
}

impl Resolver for NotedResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let Some(notes) = self.notes.upgrade() else {
            return self.inner.resolve_location(location);
        };
        notes.event(
            self.phase,
            format_args!("DNS via inbound resolver: {location}"),
        );
        let future = self.inner.resolve_location(location);
        let weak_notes = self.notes.clone();
        let phase = self.phase;
        let began = Instant::now();
        Box::pin(async move {
            let result = future.await;
            if let Some(notes) = weak_notes.upgrade() {
                match &result {
                    Ok(addresses) => notes.event(
                        phase,
                        format_args!("DNS answer {:?}; {} us", addresses.first(), micros(began)),
                    ),
                    Err(error) => notes.event(
                        phase,
                        format_args!("DNS failed {:?}; {} us", error.kind(), micros(began)),
                    ),
                }
            }
            result
        })
    }

    fn fake_dns_context(&self) -> Option<Arc<crate::dns::fake_ip::FakeDnsContext>> {
        self.inner.fake_dns_context()
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.inner.exchange(request)
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.inner.exchange_with_deadline(request, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::flows::FlowRegistry;

    #[test]
    fn connection_notes_bound_text_events_and_admission() {
        struct NeverFormat;
        impl fmt::Display for NeverFormat {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("formatted beyond the bound")
            }
        }
        let huge = "\u{00e9}".repeat(1_000_000);
        let text = Text::new(format_args!("{huge}{}", NeverFormat));
        assert_eq!(text.len, TEXT_BYTES);
        assert_eq!(
            serde_json::to_value(text).unwrap().as_str().unwrap().len(),
            TEXT_BYTES
        );
        let exact = "x".repeat(TEXT_BYTES);
        let text = Text::new(format_args!("{exact}{}", NeverFormat));
        assert_eq!(serde_json::to_value(text).unwrap(), exact);

        let registry = FlowRegistry::new(true);
        let mut buffers: Vec<_> = (0..MAX_FLOWS)
            .map(|_| registry.start_notes().unwrap())
            .collect();
        assert!(registry.start_notes().is_none());
        let notes = buffers.last().unwrap();
        for _ in 0..MAX_EVENTS {
            notes.event(Phase::Routing, format_args!("{huge}"));
        }
        notes.event(Phase::Routing, format_args!("{}", NeverFormat));
        let snapshot = serde_json::to_value(notes.snapshot()).unwrap();
        assert_eq!(snapshot.as_array().unwrap().len(), MAX_EVENTS + 1);
        assert_eq!(snapshot[MAX_EVENTS]["text"], "1 events omitted");
        assert!(
            snapshot
                .as_array()
                .unwrap()
                .iter()
                .all(|note| note["text"].as_str().unwrap().len() <= TEXT_BYTES)
        );
        drop(buffers.pop());
        assert!(registry.start_notes().is_some());
        assert!(FlowRegistry::default().start_notes().is_none());
    }

    #[tokio::test]
    async fn connection_notes_resolver_forwards_without_retaining_buffers() {
        use crate::dns::fake_ip::FakeDnsContext;
        struct Fixture {
            fake_dns: Arc<FakeDnsContext>,
            deadline: tokio::time::Instant,
        }
        impl std::fmt::Debug for Fixture {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("Fixture")
            }
        }
        impl Resolver for Fixture {
            fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
                let fail = location.address().hostname() == Some("fail.test");
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    if fail {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "secret error",
                        ))
                    } else {
                        Ok(vec!["192.0.2.1:443".parse().unwrap()])
                    }
                })
            }
            fn fake_dns_context(&self) -> Option<Arc<FakeDnsContext>> {
                Some(self.fake_dns.clone())
            }
            fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
                Box::pin(async move { Ok(request) })
            }
            fn exchange_with_deadline(
                &self,
                request: Vec<u8>,
                deadline: tokio::time::Instant,
            ) -> DnsExchangeFuture {
                assert_eq!(deadline, self.deadline);
                self.exchange(request)
            }
        }
        let fake_dns = Arc::new(
            FakeDnsContext::new(
                Default::default(),
                Arc::new(crate::resolver::NativeResolver),
            )
            .unwrap(),
        );
        let deadline = tokio::time::Instant::now();
        let inner: Arc<dyn Resolver> = Arc::new(Fixture {
            fake_dns: fake_dns.clone(),
            deadline,
        });
        assert!(Arc::ptr_eq(&resolver(&inner, None, Phase::Dial), &inner));
        let registry = FlowRegistry::new(true);
        let notes = registry.start_notes().unwrap();
        let weak = Arc::downgrade(&notes);
        let noted = resolver(&inner, Some(&notes), Phase::Routing);
        assert!(Arc::ptr_eq(&noted.fake_dns_context().unwrap(), &fake_dns));
        assert_eq!(noted.exchange(vec![1, 2]).await.unwrap(), [1, 2]);
        assert_eq!(
            noted
                .exchange_with_deadline(vec![3, 4], deadline)
                .await
                .unwrap(),
            [3, 4]
        );
        let target = NetLocation::from_str("answer.test:443", None).unwrap();
        let future = noted.resolve_location(&target);
        assert_eq!(
            tokio::spawn(future).await.unwrap().unwrap(),
            ["192.0.2.1:443".parse().unwrap()]
        );
        let failed = NetLocation::from_str("fail.test:443", None).unwrap();
        assert_eq!(
            noted.resolve_location(&failed).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let snapshot = serde_json::to_string(&notes.snapshot()).unwrap();
        assert!(snapshot.contains("DNS answer") && snapshot.contains("NotFound"));
        assert!(!snapshot.contains("secret"));
        let pending = noted.resolve_location(&target);
        drop(notes);
        assert!(
            weak.upgrade().is_none(),
            "resolver and futures must not own note buffers"
        );
        assert!(pending.await.is_ok());
        assert!(noted.resolve_location(&target).await.is_ok());
    }
}
