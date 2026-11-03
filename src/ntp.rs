use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use sntpc::{KissOfDeathCode, NtpContext, NtpTimestampGenerator, NtpUdpSocket};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::clock::{Clock, Published};
use crate::config::NtpConfig;
use crate::resolver::NativeResolver;

#[derive(Clone)]
pub(crate) struct Prepared {
    config: Option<NtpConfig>,
    state: Arc<State>,
    previous_clock: Option<Arc<Clock>>,
}

struct State {
    clock: Arc<Clock>,
    schedule: Mutex<Schedule>,
}

#[derive(Default)]
struct Schedule {
    initialized: bool,
    next: Option<Instant>,
}

impl Prepared {
    pub(crate) fn new(config: Option<NtpConfig>, previous: Option<&Self>) -> Self {
        if let Some(previous) = previous
            && config == previous.config
        {
            return previous.clone();
        }
        let previous_clock = if config.is_some() {
            previous.map(|previous| previous.state.clock.clone())
        } else {
            None
        };
        Self {
            config,
            previous_clock,
            state: Arc::new(State {
                clock: Arc::new(Clock::default()),
                schedule: Mutex::new(Schedule::default()),
            }),
        }
    }

    pub(crate) async fn start(&self, forbidden: Arc<[IpNetwork]>) -> Running {
        if let Some(config) = &self.config {
            let initialized = self.state.schedule.lock().initialized;
            if !initialized {
                // Preparation overlaps the old worker; inherit its final sample after retirement.
                if let Some(previous) = &self.previous_clock {
                    self.state.clock.copy_offset_from(previous);
                }
                refresh(config, &self.state, forbidden.clone()).await;
            }
        }
        let publication = crate::clock::publish(self.state.clock.clone());
        let task = self.config.clone().map(|config| {
            let state = self.state.clone();
            tokio::spawn(async move {
                loop {
                    let next = state.schedule.lock().next;
                    let Some(next) = next else { return };
                    sleep_until(next).await;
                    refresh(&config, &state, forbidden.clone()).await;
                }
            })
        });
        Running {
            task,
            _publication: publication,
        }
    }
}

pub(crate) struct Running {
    task: Option<JoinHandle<()>>,
    _publication: Published,
}

impl Running {
    pub(crate) async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn refresh(config: &NtpConfig, state: &State, forbidden: Arc<[IpNetwork]>) {
    let result = query(config, forbidden).await.and_then(|offset| {
        state.clock.set_offset(offset)?;
        Ok(offset)
    });
    let refused = result.as_ref().is_err_and(QueryError::is_refusal);
    match result {
        Ok(offset) => log::info!("NTP {}: updated clock offset to {offset} us", config.server),
        Err(error) => log::warn!(
            "NTP {}: {error}; retaining previous clock offset",
            config.server
        ),
    }
    if refused {
        log::warn!(
            "NTP {}: server refused synchronization; polling stopped until settings change or restart",
            config.server
        );
    }
    let mut schedule = state.schedule.lock();
    schedule.initialized = true;
    schedule.next = (!refused).then(|| Instant::now() + Duration::from_secs(config.interval_secs));
}

#[derive(Debug)]
enum QueryError {
    Io(io::Error),
    Protocol(sntpc::Error),
}

impl QueryError {
    fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::Protocol(sntpc::Error::KissOfDeath(
                KissOfDeathCode::Deny | KissOfDeathCode::Rstr | KissOfDeathCode::Rate
            ))
        )
    }
}

impl From<io::Error> for QueryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Protocol(sntpc::Error::Network) => f.write_str("NTP socket send/receive failed"),
            Self::Protocol(error) => write!(f, "invalid NTP response: {error:?}"),
        }
    }
}

async fn query(config: &NtpConfig, forbidden: Arc<[IpNetwork]>) -> Result<i64, QueryError> {
    let deadline = Instant::now() + Duration::from_secs(config.timeout_secs);
    timeout_at(deadline, async {
        let resolver = crate::dns::real_only(Arc::new(NativeResolver::new()), forbidden);
        let addresses = resolver.resolve_location(&config.server).await?;
        query_addresses(&addresses, deadline).await
    })
    .await
    .unwrap_or_else(|_| Err(timed_out()))
}

async fn query_addresses(addresses: &[SocketAddr], deadline: Instant) -> Result<i64, QueryError> {
    let mut last_error = io::Error::other("NTP server resolved to no usable addresses").into();
    for (index, peer) in addresses.iter().copied().enumerate() {
        if let Err(rejected) = crate::config::ntp::validate_server_ip(peer.ip())
            .and_then(|()| crate::socket_policy::check_outbound_address(peer.ip()))
        {
            last_error = rejected.into();
            continue;
        }
        // Shares the remaining deadline so a blackholed family cannot starve alternatives.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let budget = remaining / u32::try_from(addresses.len() - index).unwrap_or(u32::MAX);
        let result = timeout_at(Instant::now() + budget, exchange(peer))
            .await
            .unwrap_or_else(|_| Err(timed_out()));
        match result {
            Ok(offset) => return Ok(offset),
            Err(error) if error.is_refusal() => return Err(error),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn timed_out() -> QueryError {
    io::Error::new(io::ErrorKind::TimedOut, "NTP synchronization timed out").into()
}

async fn exchange(peer: SocketAddr) -> Result<i64, QueryError> {
    let socket = crate::socket_util::new_udp_socket(peer.is_ipv6(), None)?;
    socket.connect(peer).await?;
    let socket = Socket { socket, peer };
    let invalid = AtomicBool::new(false);
    let raw_start = SystemTime::now();
    raw_start
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?;
    let start = std::time::Instant::now();
    let result = sntpc::get_time(
        peer,
        &socket,
        NtpContext::new(RawClock {
            sample: Duration::ZERO,
            invalid: &invalid,
        }),
    )
    .await;
    finish_exchange(
        result.map(|response| response.offset()),
        invalid.load(Ordering::Relaxed),
        raw_start,
        SystemTime::now(),
        start.elapsed(),
    )
}

fn finish_exchange(
    result: sntpc::Result<i64>,
    invalid: bool,
    raw_start: SystemTime,
    raw_end: SystemTime,
    elapsed: Duration,
) -> Result<i64, QueryError> {
    // A validated refusal remains authoritative even if the local clock stepped.
    let offset = result.map_err(QueryError::Protocol)?;
    if invalid {
        return Err(io::Error::other("system clock is before the Unix epoch").into());
    }
    let wall_elapsed = raw_end
        .duration_since(raw_start)
        .map_err(|_| io::Error::other("system clock moved backward during NTP exchange"))?;
    if wall_elapsed.abs_diff(elapsed) > Duration::from_secs(1) {
        return Err(io::Error::other("system clock changed during NTP exchange").into());
    }
    Ok(offset)
}

#[derive(Clone, Copy)]
struct RawClock<'a> {
    sample: Duration,
    invalid: &'a AtomicBool,
}

impl RawClock<'_> {
    fn capture(&mut self, raw: SystemTime) {
        self.sample = raw
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| {
                self.invalid.store(true, Ordering::Relaxed);
                Duration::ZERO
            });
    }
}

impl NtpTimestampGenerator for RawClock<'_> {
    fn init(&mut self) {
        self.capture(SystemTime::now());
    }
    fn timestamp_sec(&self) -> u64 {
        self.sample.as_secs()
    }
    fn timestamp_subsec_micros(&self) -> u32 {
        self.sample.subsec_micros()
    }
}

struct Socket {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl NtpUdpSocket for Socket {
    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> sntpc::Result<usize> {
        if peer != self.peer {
            return Err(sntpc::Error::ResponseAddressMismatch);
        }
        self.socket
            .send(bytes)
            .await
            .map_err(|_| sntpc::Error::Network)
    }

    async fn recv_from(&self, bytes: &mut [u8]) -> sntpc::Result<(usize, SocketAddr)> {
        const PACKET_LEN: usize = 48;
        // The extra byte detects oversized datagrams instead of silently truncating them.
        let mut packet = [0; PACKET_LEN + 1];
        let count = self
            .socket
            .recv(&mut packet)
            .await
            .map_err(|_| sntpc::Error::Network)?;
        if count != PACKET_LEN || bytes.len() != PACKET_LEN {
            return Err(sntpc::Error::IncorrectPayload);
        }
        if !(1..=4).contains(&((packet[0] >> 3) & 7)) {
            return Err(sntpc::Error::IncorrectResponseVersion);
        }
        // KoD replies need classification even when their timestamps are zero.
        if packet[1] != 0 && packet[32..40].iter().all(|byte| *byte == 0) {
            return Err(sntpc::Error::InvalidTimestamp);
        }
        bytes.copy_from_slice(&packet[..PACKET_LEN]);
        Ok((PACKET_LEN, self.peer))
    }
}

#[cfg(test)]
mod tests;
