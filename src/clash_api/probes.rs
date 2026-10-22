use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Empty;
use indexmap::IndexMap;
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection};
use crate::control::catalog::{Catalog, CatalogNode, MemberOrigin};
use crate::control::runtime::{ControlRuntime, Generation};
use crate::option_util::OneOrSome;
use crate::resolver::Resolver;

#[derive(Default)]
struct History {
    history: Vec<Value>,
    alive: bool,
    urls: IndexMap<String, (bool, Vec<Value>)>,
}

pub struct ProbeState {
    connectors: Mutex<HashMap<String, Arc<ClientChainGroup>>>,
    history: Mutex<HashMap<String, History>>,
    resolver: Arc<dyn Resolver>,
    forbidden: Vec<ipnetwork::IpNetwork>,
}

impl ProbeState {
    pub fn new(resolver: Arc<dyn Resolver>, forbidden: Vec<ipnetwork::IpNetwork>) -> Self {
        Self {
            connectors: Mutex::new(HashMap::new()),
            history: Mutex::new(HashMap::new()),
            resolver,
            forbidden,
        }
    }

    pub fn decorate(&self, name: &str, object: &mut Value) {
        let histories = self.history.lock();
        let Some(history) = histories.get(name) else {
            object["alive"] = json!(true);
            object["history"] = json!([]);
            return;
        };
        object["alive"] = json!(history.alive);
        object["history"] = json!(history.history);
        let mut extra = serde_json::Map::new();
        for (url, (alive, samples)) in &history.urls {
            extra.insert(url.clone(), json!({"alive":alive,"history":samples}));
        }
        object["extra"] = Value::Object(extra);
    }

    fn record(&self, name: &str, url: &str, delay: u16, satisfied: bool) {
        let mut histories = self.history.lock();
        let history = histories.entry(name.into()).or_default();
        let sample = json!({"time":chrono::Utc::now().to_rfc3339(),"delay":delay});
        history.alive = delay != 0;
        history.history.push(sample.clone());
        if history.history.len() > 10 {
            history.history.remove(0);
        }
        let mut samples = history
            .urls
            .shift_remove(url)
            .map(|(_, samples)| samples)
            .unwrap_or_default();
        if history.urls.len() >= 8 {
            history.urls.shift_remove_index(0);
        }
        let mut url_sample = sample;
        if !satisfied {
            url_sample["delay"] = json!(0);
        }
        samples.push(url_sample);
        if samples.len() > 10 {
            samples.remove(0);
        }
        history.urls.insert(url.into(), (satisfied, samples));
    }

    fn connector(&self, catalog: &Catalog, name: &str) -> io::Result<Arc<ClientChainGroup>> {
        if let Some(connector) = self.connectors.lock().get(name) {
            return Ok(connector.clone());
        }
        let mut clients = Vec::new();
        expand(catalog, name, &mut Vec::new(), &mut clients)?;
        let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(
                clients.into_iter().map(ConfigSelection::Config).collect(),
            ))),
            self.resolver.clone(),
        )?;
        let connector = Arc::new(ClientChainGroup::new(vec![chain]));
        Ok(self
            .connectors
            .lock()
            .entry(name.into())
            .or_insert(connector)
            .clone())
    }
}

fn expand(
    catalog: &Catalog,
    name: &str,
    path: &mut Vec<(String, String)>,
    clients: &mut Vec<ClientConfig>,
) -> io::Result<()> {
    if clients.len() >= 16_384 || path.len() >= 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe subject expansion exceeds limit",
        ));
    }
    match catalog.nodes.get(name) {
        Some(CatalogNode::Leaf(config)) => {
            let mut config = (**config).clone();
            config.control = Some(MemberOrigin {
                name: Arc::from(name),
                path: path.clone(),
                selection: catalog.selection.clone(),
            });
            clients.push(config);
        }
        Some(CatalogNode::Group { members, .. }) => {
            for member in members {
                path.push((name.into(), member.clone()));
                expand(catalog, member, path, clients)?;
                path.pop();
            }
        }
        Some(CatalogNode::Reject) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REJECT cannot carry a probe",
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "proxy does not exist",
            ));
        }
    }
    Ok(())
}

pub struct ProbeQuery {
    url: url::Url,
    timeout: Duration,
    expected: Vec<(u16, u16)>,
}

impl ProbeQuery {
    pub fn parse(query: &HashMap<String, String>, group: bool) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "invalid delay test query");
        let raw = query.get("url").ok_or_else(bad)?;
        if raw.len() > 2048 {
            return Err(bad());
        }
        let url = url::Url::parse(raw).map_err(|_| bad())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(bad());
        }
        let timeout: u64 = query
            .get("timeout")
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        if timeout == 0 || timeout > if group { 60_000 } else { 32_767 } {
            return Err(bad());
        }
        let mut expected = Vec::new();
        if let Some(value) = query
            .get("expected")
            .filter(|value| !value.trim().is_empty() && value.trim() != "*")
        {
            for part in value.split([',', '/']) {
                let (start, end) = part.split_once('-').unwrap_or((part, part));
                let start: u16 = start.trim().parse().map_err(|_| bad())?;
                let end: u16 = end.trim().parse().map_err(|_| bad())?;
                if start > end {
                    return Err(bad());
                }
                expected.push((start, end));
            }
        }
        Ok(Self {
            url,
            timeout: Duration::from_millis(timeout),
            expected,
        })
    }
}

pub async fn probe(
    runtime: &ControlRuntime,
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
) -> io::Result<u16> {
    if runtime
        .activating
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "generation is activating",
        ));
    }
    let _permit = runtime
        .probes
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "probe limit reached"))?;
    probe_until(
        runtime,
        generation,
        name,
        query,
        tokio::time::Instant::now() + query.timeout,
    )
    .await
}

pub async fn probe_group(
    runtime: &ControlRuntime,
    generation: &Generation,
    members: &[String],
    query: &ProbeQuery,
) -> io::Result<serde_json::Map<String, Value>> {
    let deadline = tokio::time::Instant::now() + query.timeout;
    let mut results =
        futures::stream::iter(members.iter().cloned().map(|name: String| async move {
            let activating = || {
                runtime
                    .activating
                    .load(std::sync::atomic::Ordering::Acquire)
            };
            if activating() || tokio::time::Instant::now() >= deadline {
                return (name, None);
            }
            let permit = tokio::select! {
                _ = runtime.shutdown.cancelled() => return (name, None),
                permit = tokio::time::timeout_at(deadline, runtime.probes.acquire()) => permit,
            };
            let Ok(Ok(_permit)) = permit else {
                return (name, None);
            };
            if activating() || tokio::time::Instant::now() >= deadline {
                return (name, None);
            }
            let result = probe_until(runtime, generation, &name, query, deadline).await;
            (name, Some(result))
        }))
        .buffer_unordered(16);
    let mut started = false;
    let mut successes = serde_json::Map::new();
    while let Some((name, result)) = results.next().await {
        if let Some(result) = result {
            started = true;
            if let Ok(delay) = result {
                successes.insert(name.clone(), json!(delay));
            }
        }
    }
    if !successes.is_empty() {
        Ok(successes)
    } else if started {
        Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout"))
    } else {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "group probes unavailable",
        ))
    }
}

async fn probe_until(
    runtime: &ControlRuntime,
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
    deadline: tokio::time::Instant,
) -> io::Result<u16> {
    let result = tokio::select! {
        result = tokio::time::timeout_at(deadline, request(generation, name, query)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Timeout")).and_then(|result| result),
        _ = runtime.shutdown.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "controller stopped")),
    };
    let (delay, satisfied) = result.as_ref().copied().unwrap_or((0, false));
    generation
        .probes
        .record(name, query.url.as_str(), delay, satisfied);
    result.map(|(delay, _)| delay)
}

async fn request(
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
) -> io::Result<(u16, bool)> {
    let started = Instant::now();
    let host = query
        .url
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = query.url.port_or_known_default().unwrap();
    let target = NetLocation::from_str(
        &format!(
            "{}:{port}",
            if host.contains(':') {
                format!("[{host}]")
            } else {
                host.into()
            }
        ),
        None,
    )?;
    let resolver = ProbeResolver {
        inner: generation.probes.resolver.clone(),
        target: target.clone(),
        forbidden_ranges: generation.probes.forbidden.clone(),
        denied: forbidden,
    };
    if let Some(address) = target.to_socket_addr_nonblocking() {
        resolver.check(&[address])?;
    }
    let resolver: Arc<dyn Resolver> = Arc::new(resolver);
    let chain = generation.probes.connector(&generation.catalog, name)?;
    let setup = chain.connect_tcp(target.into(), &resolver).await?;
    if setup
        .early_data
        .as_ref()
        .is_some_and(|bytes| !bytes.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsolicited probe data",
        ));
    }
    let stream: Box<dyn ProbeIo> = if query.url.scheme() == "https" {
        let server =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let connection = rustls::ClientConnection::new(
            Arc::new(crate::rustls_config_util::create_dns_client_config()),
            server,
        )
        .map_err(io::Error::other)?;
        Box::new(
            crate::crypto::CryptoTlsStream::handshake(
                setup.client_stream,
                crate::crypto::CryptoConnection::new_rustls_client(connection),
                crate::crypto::TlsReadMode::Stream,
                &[],
            )
            .await?,
        )
    } else {
        Box::new(setup.client_stream)
    };
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
    let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let path = &query.url[url::Position::BeforePath..url::Position::AfterQuery];
    let authority = &query.url[url::Position::BeforeHost..url::Position::AfterPort];
    let request = hyper::Request::builder()
        .method("HEAD")
        .uri(if path.is_empty() { "/" } else { path })
        .header("Host", authority)
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    let status = response.status().as_u16();
    let satisfied = query.expected.is_empty()
        || query
            .expected
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&status));
    Ok((
        started.elapsed().as_millis().clamp(1, u16::MAX as u128) as u16,
        satisfied,
    ))
}

trait ProbeIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ProbeIo for T {}

#[derive(Debug)]
struct ProbeResolver {
    inner: Arc<dyn Resolver>,
    target: NetLocation,
    forbidden_ranges: Vec<ipnetwork::IpNetwork>,
    denied: fn(IpAddr) -> bool,
}

impl ProbeResolver {
    fn check(&self, addresses: &[std::net::SocketAddr]) -> io::Result<()> {
        if addresses.is_empty()
            || addresses.iter().any(|address| {
                (self.denied)(address.ip())
                    || self
                        .forbidden_ranges
                        .iter()
                        .any(|range| range.contains(address.ip().to_canonical()))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe destination is not allowed",
            ));
        }
        Ok(())
    }
}

impl Resolver for ProbeResolver {
    fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
        let resolve = self.inner.resolve_location(location);
        if location != &self.target {
            return resolve;
        }
        let policy = Self {
            inner: self.inner.clone(),
            target: self.target.clone(),
            forbidden_ranges: self.forbidden_ranges.clone(),
            denied: self.denied,
        };
        Box::pin(async move {
            let addresses = resolve.await?;
            policy.check(&addresses)?;
            Ok(addresses)
        })
    }
}

fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || (ip.octets()[0] == 198 && ip.octets()[1] & 254 == 18)
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| forbidden(IpAddr::V4(ip)))
            .unwrap_or_else(|| {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug)]
    struct Answers(Vec<SocketAddr>);
    impl Resolver for Answers {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    fn generation(catalog: Catalog, resolver: Arc<dyn Resolver>) -> Generation {
        Generation {
            id: 1,
            catalog,
            rules: Vec::new(),
            probes: ProbeState::new(resolver, Vec::new()),
            udp: HashMap::new(),
        }
    }

    fn catalog() -> Catalog {
        Catalog {
            nodes: IndexMap::from([("DIRECT".into(), CatalogNode::Leaf(Box::default()))]),
            selection: crate::control::selection::SelectionOwner::new(None)
                .unwrap()
                .prepare(Default::default())
                .unwrap(),
        }
    }

    fn query() -> ProbeQuery {
        ProbeQuery::parse(
            &HashMap::from([
                ("url".into(), "http://probe.invalid/".into()),
                ("timeout".into(), "1000".into()),
            ]),
            false,
        )
        .unwrap()
    }

    #[derive(Debug, Default)]
    struct PendingAnswers(std::sync::atomic::AtomicUsize);

    impl Resolver for PendingAnswers {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn group_deadline_includes_members_waiting_for_capacity() {
        let service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        service
            .runtime
            .activating
            .store(false, std::sync::atomic::Ordering::Release);
        let resolver = Arc::new(PendingAnswers::default());
        let mut catalog = catalog();
        let members: Vec<_> = (0..32).map(|index| format!("direct-{index}")).collect();
        for name in &members {
            catalog
                .nodes
                .insert(name.clone(), CatalogNode::Leaf(Box::default()));
        }
        let generation = generation(catalog, resolver.clone());
        let start = tokio::time::Instant::now();
        let error = probe_group(&service.runtime, &generation, &members, &query())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(resolver.0.load(std::sync::atomic::Ordering::Relaxed), 16);
        assert_eq!(generation.probes.history.lock().len(), 16);
        assert_eq!(service.runtime.probes.available_permits(), 16);
    }

    #[tokio::test(start_paused = true)]
    async fn group_capacity_exhaustion_does_not_record_probe_failures() {
        let service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        service
            .runtime
            .activating
            .store(false, std::sync::atomic::Ordering::Release);
        let resolver = Arc::new(PendingAnswers::default());
        let generation = generation(catalog(), resolver.clone());
        let members = vec!["DIRECT".into(), "DIRECT".into()];
        let permits = service.runtime.probes.acquire_many(16).await.unwrap();
        let start = tokio::time::Instant::now();
        let error = probe_group(&service.runtime, &generation, &members, &query())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(resolver.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(generation.probes.history.lock().is_empty());
        drop(permits);
        service
            .runtime
            .activating
            .store(true, std::sync::atomic::Ordering::Release);
        let start = tokio::time::Instant::now();
        assert_eq!(
            probe_group(&service.runtime, &generation, &members, &query())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(generation.probes.history.lock().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn inactive_wireguard_member_only_fails_when_selected() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            let peer = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let config = json!([
                {"clash_api_address":"127.0.0.1:0","secret":"test-secret"},
                crate::wireguard::test_support::client(peer.local_addr().unwrap().port()),
                {"client_group":"outbound","strategy":"selector","default":"http","client_proxies":[
                    "wg", {"name":"http","address":proxy,"protocol":{"type":"http"}}
                ]},
                {"address":"127.0.0.1:0","protocol":{"type":"socks"},"rules":"allow-all-direct"}
            ]);
            let mut validated =
                crate::config::create_server_configs(serde_json::from_value(config).unwrap())
                    .unwrap();
            assert!(validated.wireguard_endpoints.is_empty());
            let _prepared = crate::wireguard::Prepared::new(&mut validated)
                .await
                .unwrap();
            assert!(validated.wireguard_endpoints.is_empty());
            let generation = generation(
                validated.catalog.take().unwrap(),
                Arc::new(Answers(Vec::new())),
            );
            let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
            owner
                .activate(generation.catalog.selection.clone())
                .unwrap();
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    assert!(header.starts_with(b"CONNECT probe.invalid:80 HTTP/1.1\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    header.clear();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    assert!(header.starts_with(b"HEAD / HTTP/1.1\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                }
            }));
            assert!(request(&generation, "outbound", &query()).await.unwrap().0 > 0);
            owner.select("outbound", "wg").unwrap();
            let error = request(&generation, "outbound", &query())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            assert!(error.to_string().contains("not active"));
            owner.select("outbound", "http").unwrap();
            assert!(request(&generation, "outbound", &query()).await.unwrap().0 > 0);
            server.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), peer.recv(&mut [0; 2048]))
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cached_connectors_reject_forbidden_hostname_candidates() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let local = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let resolver: Arc<dyn Resolver> =
            Arc::new(Answers(vec!["192.0.2.1:80".parse().unwrap(), local]));
        let mut catalog = catalog();
        catalog.nodes.insert(
            "http".into(),
            CatalogNode::Leaf(Box::new(
                serde_json::from_value(json!({
                    "address":local.to_string(),
                    "protocol":{"type":"http","resolve_hostname":true},
                }))
                .unwrap(),
            )),
        );
        let generation = generation(catalog, resolver);
        for name in ["DIRECT", "http"] {
            let cached = generation
                .probes
                .connector(&generation.catalog, name)
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        request(&generation, name, &query())
                    )
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert!(Arc::ptr_eq(
                    &cached,
                    &generation
                        .probes
                        .connector(&generation.catalog, name)
                        .unwrap()
                ));
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn carrier_probe_checks_http_hostname_before_connecting() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let local = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let config = json!([
            {"client_group":"outbound","strategy":"selector","default":"http","client_proxies":[
                {"name":"http","address":local.to_string(),"protocol":{"type":"http","resolve_hostname":true}},
                {"name":"xhttp","address":local.to_string(),"protocol":{"type":"xhttp","protocol":{"type":"socks"}}}
            ]}
        ]);
        let mut validated =
            crate::config::create_server_configs(serde_json::from_value(config).unwrap()).unwrap();
        let generation = generation(
            validated.catalog.take().unwrap(),
            Arc::new(Answers(vec!["192.0.2.1:80".parse().unwrap(), local])),
        );
        let cached = generation
            .probes
            .connector(&generation.catalog, "outbound")
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    request(&generation, "outbound", &query())
                )
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(Arc::ptr_eq(
                &cached,
                &generation
                    .probes
                    .connector(&generation.catalog, "outbound")
                    .unwrap()
            ));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cached_http2_reuse_checks_each_requests_resolver() {
        #[derive(Debug)]
        struct ChangingAnswers(Arc<Mutex<Vec<SocketAddr>>>);
        impl Resolver for ChangingAnswers {
            fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
                let addresses = self.0.lock().clone();
                Box::pin(async move { Ok(addresses) })
            }
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let local = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = accepted.clone();
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let mut tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        incoming = connection.accept() => {
                            let Some(Ok((request, mut respond))) = incoming else { break };
                            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            assert_eq!(request.uri().authority().unwrap(), "192.0.2.1:80");
                            let send = respond.send_response(http::Response::new(()), false).unwrap();
                            tasks.spawn(async move {
                                let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                                let mut header = Vec::new();
                                while !header.ends_with(b"\r\n\r\n") { header.push(stream.read_u8().await.unwrap()); }
                                assert!(header.starts_with(b"HEAD / HTTP/1.1\r\n"));
                                stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.unwrap();
                                stream.shutdown().await.unwrap();
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {}
                    }
                }
            }));
            let answers = Arc::new(Mutex::new(vec!["192.0.2.1:80".parse().unwrap()]));
            let mut catalog = catalog();
            // Cleartext transport isolates HTTP/2 reuse from the TLS handshake in this fixture.
            catalog.nodes.insert("http".into(), CatalogNode::Leaf(Box::new(serde_json::from_value(json!({
                "address":local.to_string(),
                "protocol":{"type":"http","resolve_hostname":true,"http_version":"h2"},
            })).unwrap())));
            let generation = generation(catalog, Arc::new(ChangingAnswers(answers.clone())));
            for _ in 0..2 { assert!(request(&generation, "http", &query()).await.unwrap().0 > 0); }
            assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 2);
            answers.lock().push("127.0.0.1:80".parse().unwrap());
            assert_eq!(request(&generation, "http", &query()).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 2);
            server.abort();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn guarded_direct_resolution_keeps_fallback_candidates() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let live = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let closed = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let refused = SocketAddr::from(([127, 0, 0, 1], closed.local_addr().unwrap().port()));
        drop(closed);
        let target = NetLocation::from_str("probe.invalid:80", None).unwrap();
        let base: Arc<dyn Resolver> = Arc::new(Answers(vec![refused, live]));
        let resolver: Arc<dyn Resolver> = Arc::new(ProbeResolver {
            inner: base.clone(),
            target: target.clone(),
            forbidden_ranges: Vec::new(),
            denied: |_| false,
        });
        let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            base,
        )
        .unwrap();
        let mut setup = tokio::time::timeout(
            Duration::from_secs(2),
            chain.connect_tcp(target.into(), &resolver),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        setup.client_stream.write_all(b"ok").await.unwrap();
        let mut response = [0; 2];
        accepted.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
    }

    #[tokio::test]
    async fn guarded_resolution_rejects_any_forbidden_candidate() {
        let target = NetLocation::from_str("probe.invalid:80", None).unwrap();
        let resolver = ProbeResolver {
            inner: Arc::new(Answers(vec![
                "192.0.2.1:80".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
            ])),
            target: target.clone(),
            forbidden_ranges: Vec::new(),
            denied: forbidden,
        };
        assert_eq!(
            resolver.resolve_location(&target).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
