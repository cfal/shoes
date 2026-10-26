use std::io;
use std::net::IpAddr;
use std::time::Duration;

use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};

mod http;

pub(crate) const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_INSPECTED_BYTES: usize = 64 * 1024;

pub(crate) struct SniffResult {
    pub hostname: Option<String>,
    pub prefix: Vec<u8>,
}

pub(crate) struct StreamProbe {
    prefix: Vec<u8>,
    acceptor: Option<Box<Acceptor>>,
    fed: usize,
    finished: bool,
    hostname: Option<String>,
    http: http::HttpProbe,
}

impl StreamProbe {
    pub fn from_prefix(prefix: Vec<u8>) -> Self {
        let mut probe = Self {
            prefix,
            acceptor: None,
            fed: 0,
            finished: false,
            hostname: None,
            http: http::HttpProbe::default(),
        };
        probe.inspect();
        probe
    }

    pub fn needs_more(&self) -> bool {
        !self.finished
    }

    fn inspect(&mut self) {
        if self.finished || self.prefix.is_empty() {
            return;
        }
        let limit = self.prefix.len().min(MAX_INSPECTED_BYTES);
        if self.prefix[0] != 0x16 {
            if let http::Inspection::Finished(hostname) = self.http.inspect(&self.prefix[..limit]) {
                self.hostname = hostname;
                self.finished = true;
            }
            self.finished |= limit == MAX_INSPECTED_BYTES;
            return;
        }
        let acceptor = self.acceptor.get_or_insert_with(Box::default);
        while self.fed < limit {
            // An exhausted slice signals EOF to rustls, not a temporary read boundary.
            match acceptor.read_tls(&mut &self.prefix[self.fed..limit]) {
                Ok(0) | Err(_) => {
                    self.finished = true;
                    break;
                }
                Ok(read) => self.fed += read,
            }
            match acceptor.accept() {
                Ok(None) => {}
                Ok(Some(accepted)) => {
                    self.hostname = accepted
                        .client_hello()
                        .server_name()
                        .filter(|name| name.trim_end_matches('.').parse::<IpAddr>().is_err())
                        .map(str::to_owned);
                    self.finished = true;
                    break;
                }
                Err(_) => {
                    // This is passive inspection: never send the returned TLS alert.
                    self.finished = true;
                    break;
                }
            }
        }
        self.finished |= limit == MAX_INSPECTED_BYTES;
        if self.finished {
            self.acceptor = None;
        }
    }

    pub async fn finish<R: AsyncRead + Unpin + ?Sized>(
        mut self,
        reader: &mut R,
        budget: Duration,
    ) -> io::Result<SniffResult> {
        let deadline = Instant::now() + budget;
        let mut buf = Vec::new();
        while self.needs_more() && Instant::now() < deadline {
            if buf.is_empty() {
                buf.resize(4096, 0);
            }
            let capacity = buf.len().min(MAX_INSPECTED_BYTES - self.prefix.len());
            // The timed read borrows scratch storage; retained bytes outlive its cancellation.
            match timeout_at(deadline, reader.read(&mut buf[..capacity])).await {
                Err(_) | Ok(Ok(0)) => break,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(read)) => self.prefix.extend_from_slice(&buf[..read]),
            }
            self.inspect();
        }
        Ok(SniffResult {
            hostname: self.hostname,
            prefix: self.prefix,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
