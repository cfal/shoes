use super::*;
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TRANSPORT_DATA: &[u8] = b"transport";

#[test]
fn url_test_nested_groups_and_each_chain_hop_preserve_udp_eligibility() {
    for route in ["outer", "[inner, inner]"] {
        let yaml = format!(
            "
- client_group: inner
  type: url-test
  url: http://inner.invalid/
  client_proxies:
    - name: http
      address: 127.0.0.1:8000
      protocol: {{type: http}}
    - name: udp
      address: 127.0.0.1:8001
      protocol: {{type: vless, user_id: 550e8400-e29b-41d4-a716-446655440000}}
- client_group: manual
  type: selector
  client_proxies: [inner, direct]
- client_group: outer
  type: url-test
  url: http://outer.invalid/
  client_proxies: [manual, direct]
- address: 127.0.0.1:1080
  protocol: {{type: socks}}
  rules: [{{mask: 0.0.0.0/0, action: allow, client_chain: {route}}}]
"
        );
        let mut validated =
            crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
        assert!(validated.control.listeners.is_empty());
        let catalog = validated.catalog.take().unwrap();
        let crate::config::Config::Server(server) = validated.configs.remove(0) else {
            panic!()
        };
        let crate::config::ConfigSelection::Config(rule) = server.rules.into_vec().remove(0) else {
            panic!()
        };
        let crate::config::RuleActionConfig::Allow { client_chains, .. } = rule.action else {
            panic!()
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let group =
            crate::tcp::chain_builder::try_build_client_chain_group(client_chains, resolver)
                .unwrap();
        let chain = &group.chains[0];
        let auto = &catalog.selection.automatic;
        auto.record("http", "http://inner.invalid/", Some(10));
        auto.record("udp", "http://inner.invalid/", Some(100));
        auto.record("manual", "http://outer.invalid/", Some(10));
        auto.record("DIRECT", "http://outer.invalid/", Some(200));
        if route == "outer" {
            assert_eq!(chain.select_indices(false).unwrap(), [0]);
            assert_eq!(chain.select_indices(true).unwrap(), [1]);
            let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
            owner.activate(catalog.selection.clone()).unwrap();
            assert!(owner.select("inner", "udp").is_err());
            owner.select("manual", "DIRECT").unwrap();
            assert_eq!(chain.select_indices(false).unwrap(), [2]);
            assert_eq!(chain.select_indices(true).unwrap(), [2]);
        } else {
            assert_eq!(chain.select_indices(false).unwrap(), [0, 0]);
            assert_eq!(chain.select_indices(true).unwrap(), [0, 1]);
        }
    }
}

#[test]
fn url_test_deep_udp_selection_survives_dashboard_reads() {
    use serde_json::json;
    let mut configs: Vec<_> = (0..128)
        .map(|index| {
            let member = if index == 127 {
                "direct".into()
            } else {
                format!("deep-{}", index + 1)
            };
            json!({
                "client_group": format!("deep-{index}"),
                "client_proxies": [member]
            })
        })
        .collect();
    configs.push(json!({
        "client_group":"auto", "type":"url-test", "url":"http://probe.invalid/",
        "client_proxies":["deep-0", {"name":"other", "protocol":{"type":"direct"}}]
    }));
    configs.push(json!({
        "address":"127.0.0.1:1080", "protocol":{"type":"socks"},
        "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"auto"}]
    }));
    let mut validated =
        crate::config::create_server_configs(serde_json::from_value(json!(configs)).unwrap())
            .unwrap();
    let catalog = validated.catalog.take().unwrap();
    let crate::config::Config::Server(server) = validated.configs.remove(0) else {
        panic!()
    };
    let crate::config::ConfigSelection::Config(rule) = server.rules.into_vec().remove(0) else {
        panic!()
    };
    let crate::config::RuleActionConfig::Allow { client_chains, .. } = rule.action else {
        panic!()
    };
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let group =
        crate::tcp::chain_builder::try_build_client_chain_group(client_chains, resolver.clone())
            .unwrap();
    let generation = crate::control::runtime::Generation {
        id: 1,
        leaf_udp_support: crate::clash_api::dto::leaf_udp_support(&catalog).unwrap(),
        catalog,
        rules: Vec::new(),
        probes: crate::clash_api::probes::ProbeState::new(resolver, Vec::new()),
    };
    let chain = &group.chains[0];
    assert_eq!(chain.select_indices(true).unwrap(), [0]);
    let nodes = crate::clash_api::dto::proxies(&generation);
    assert_eq!(chain.select_indices(true).unwrap(), [0]);
    assert_eq!(nodes["proxies"]["auto"]["udpNow"], "deep-0");
}

#[test]
fn unselected_large_pools_keep_constant_time_round_robin() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let chain = ClientProxyChain::new(
        (0..10_000)
            .map(|index| InitialHopEntry::Direct(Arc::new(Socket(index, events.clone()))))
            .collect(),
        Vec::new(),
    );
    assert!(chain.selection.is_none());
    for index in 0..20_000 {
        assert_eq!(chain.select_indices(false).unwrap(), [index % 10_000]);
        assert_eq!(chain.select_indices(true).unwrap(), [index % 10_000]);
    }
}

#[test]
fn selectors_filter_all_hops_without_changing_flattened_weights() {
    let yaml = "
- client_group: leaves
  client_proxies:
    - name: http
      address: 127.0.0.1:8000
      protocol: {type: http}
    - name: udp
      address: 127.0.0.1:8001
      protocol: {type: vless, user_id: 550e8400-e29b-41d4-a716-446655440000}
- client_group: weighted
  client_proxies: [leaves, leaves, direct]
- client_group: choose
  type: selector
  client_proxies: [weighted, direct]
- address: 127.0.0.1:1080
  protocol: {type: socks}
  rules: [{mask: 0.0.0.0/0, action: allow, client_chain: choose}]
";
    let mut validated =
        crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap()).unwrap();
    let catalog = validated.catalog.take().unwrap();
    let crate::config::Config::Server(server) = validated.configs.remove(0) else {
        panic!()
    };
    let crate::config::ConfigSelection::Config(rule) = server.rules.into_vec().remove(0) else {
        panic!()
    };
    let crate::config::RuleActionConfig::Allow { client_chains, .. } = rule.action else {
        panic!()
    };
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let group =
        crate::tcp::chain_builder::try_build_client_chain_group(client_chains, resolver).unwrap();
    let chain = &group.chains[0];
    for index in 0..10 {
        assert_eq!(chain.select_indices(false).unwrap(), [index % 5]);
    }
    for index in [1, 3, 4, 1, 3, 4] {
        assert_eq!(chain.select_indices(true).unwrap(), [index]);
    }
    let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
    owner.activate(catalog.selection.clone()).unwrap();
    owner.select("choose", "DIRECT").unwrap();
    assert_eq!(chain.select_indices(false).unwrap(), [5]);
    assert_eq!(chain.select_indices(true).unwrap(), [5]);
}

#[test]
fn udp_selection_rejects_ineligible_member_without_falling_back() {
    let yaml = "
- client_group: leaves
  type: selector
  default: http
  client_proxies:
    - name: http
      address: 127.0.0.1:8000
      protocol: {type: http}
    - name: udp
      address: 127.0.0.1:8001
      protocol: {type: vless, user_id: 550e8400-e29b-41d4-a716-446655440000}
- address: 127.0.0.1:1080
  protocol: {type: socks}
  rules: [{mask: 0.0.0.0/0, action: allow, client_chain: leaves}]
";
    let mut validated =
        crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap()).unwrap();
    let catalog = validated.catalog.take().unwrap();
    let crate::config::Config::Server(server) = validated.configs.remove(0) else {
        panic!()
    };
    let crate::config::ConfigSelection::Config(rule) = server.rules.into_vec().remove(0) else {
        panic!()
    };
    let crate::config::RuleActionConfig::Allow { client_chains, .. } = rule.action else {
        panic!()
    };
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let group =
        crate::tcp::chain_builder::try_build_client_chain_group(client_chains, resolver).unwrap();
    let chain = &group.chains[0];
    let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
    owner.activate(catalog.selection.clone()).unwrap();
    assert!(chain.select_indices(true).is_err());
    owner.select("leaves", "udp").unwrap();
    assert_eq!(chain.select_indices(true).unwrap(), [1]);
}

#[derive(Debug)]
struct Socket(usize, Arc<Mutex<Vec<String>>>);
#[async_trait::async_trait]
impl SocketConnector for Socket {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        self.1
            .lock()
            .unwrap()
            .push(format!("socket {} -> {}", self.0, target));
        let (stream, mut peer) = tokio::io::duplex(64);
        peer.write_all(TRANSPORT_DATA).await?;
        Ok(Box::new(stream))
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        _: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        unreachable!()
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

#[derive(Debug)]
struct Proxy {
    location: NetLocation,
    lazy: bool,
    early_data: Option<Vec<u8>>,
    calls: Arc<Mutex<Vec<String>>>,
}
#[async_trait::async_trait]
impl ProxyConnector for Proxy {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }
    fn supports_udp_over_tcp(&self) -> bool {
        true
    }
    fn needs_carrier_dialer(&self) -> bool {
        self.lazy
    }
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        _: &Arc<dyn Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("prepare {} -> {}", self.location, target));
        Ok(target)
    }
    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{} -> {}", self.location, target));
        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: self.early_data.clone(),
        })
    }
    async fn connect_tcp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if self.lazy {
            drop(dialer.open_stream().await?);
        }
        self.setup_tcp_stream(dialer.open_stream().await?, target)
            .await
    }
    async fn setup_udp_bidirectional(
        &self,
        mut stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("udp {} -> {}", self.location, target));
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_to_end(&mut bytes),
        )
        .await
        .expect("UDP chain transport did not reach EOF")?;
        assert_eq!(bytes, TRANSPORT_DATA, "intermediate early data leaked");
        Ok(Box::new(crate::vless::VlessMessageStream::new(stream)))
    }
}

#[tokio::test]
async fn redial_replays_exact_selected_prefix_without_round_robin_or_direct_bypass() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let location = |s| NetLocation::from_str(s, None).unwrap();
    let proxy = |address, lazy| {
        Box::new(Proxy {
            location: location(address),
            lazy,
            early_data: None,
            calls: calls.clone(),
        }) as Box<dyn ProxyConnector>
    };
    let chain = ClientProxyChain::new(
        (0..2)
            .map(|i| InitialHopEntry::Proxy {
                socket: Arc::new(Socket(i, calls.clone())),
                proxy: proxy("first.test:80", false),
            })
            .collect(),
        vec![vec![proxy("xhttp.test:443", true)]],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    for index in 0..2 {
        chain
            .connect_tcp(location("target.test:80").into(), &resolver)
            .await
            .unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                "prepare xhttp.test:443 -> target.test:80".into(),
                "prepare first.test:80 -> xhttp.test:443".into(),
                format!("socket {index} -> first.test:80"),
                "first.test:80 -> xhttp.test:443".into(),
                "prepare first.test:80 -> xhttp.test:443".into(),
                format!("socket {index} -> first.test:80"),
                "first.test:80 -> xhttp.test:443".into(),
                "xhttp.test:443 -> target.test:80".into(),
            ]
        );
        calls.lock().unwrap().clear();
    }
}

#[tokio::test]
async fn udp_chain_preserves_preparation_order_and_ignores_intermediate_early_data() {
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    for initial in ["direct", "wireguard", "proxy"] {
        for intermediates in [0, 2] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let proxy = |address| {
                Box::new(Proxy {
                    location: NetLocation::from_str(address, None).unwrap(),
                    lazy: false,
                    early_data: Some(vec![1, 2, 3]),
                    calls: calls.clone(),
                }) as Box<dyn ProxyConnector>
            };
            let socket = Arc::new(Socket(0, calls.clone()));
            let entry = match initial {
                "direct" => InitialHopEntry::Direct(socket),
                "wireguard" => InitialHopEntry::Wireguard(socket),
                "proxy" => InitialHopEntry::Proxy {
                    socket,
                    proxy: proxy("initial.test:80"),
                },
                _ => unreachable!(),
            };
            let mut hops = Vec::new();
            if intermediates == 2 {
                hops.push(vec![proxy("middle1.test:80")]);
                hops.push(vec![proxy("middle2.test:80")]);
            }
            hops.push(vec![proxy("final.test:80")]);
            let chain = ClientProxyChain::new(vec![entry], hops);
            chain
                .connect_udp_bidirectional(
                    &resolver,
                    NetLocation::from_str("target.test:53", None)
                        .unwrap()
                        .into(),
                )
                .await
                .unwrap();

            let first = if intermediates == 0 {
                "final.test:80"
            } else {
                "middle1.test:80"
            };
            let mut expected = if initial == "proxy" {
                vec![
                    format!("prepare initial.test:80 -> {first}"),
                    "socket 0 -> initial.test:80".into(),
                    format!("initial.test:80 -> {first}"),
                ]
            } else {
                vec![format!("socket 0 -> {first}")]
            };
            if intermediates == 2 {
                expected.extend([
                    "prepare middle1.test:80 -> middle2.test:80".into(),
                    "middle1.test:80 -> middle2.test:80".into(),
                    "prepare middle2.test:80 -> final.test:80".into(),
                    "middle2.test:80 -> final.test:80".into(),
                ]);
            }
            expected.push("udp final.test:80 -> target.test:53".into());
            assert_eq!(
                *calls.lock().unwrap(),
                expected,
                "{initial}/{intermediates}"
            );
        }
    }
}

#[test]
fn pooled_prefix_does_not_retain_its_own_proxy() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let chain = ClientProxyChain::new(
        vec![InitialHopEntry::Proxy {
            socket: Arc::new(Socket(0, calls.clone())),
            proxy: Box::new(Proxy {
                location: NetLocation::from_str("xhttp.test:443", None).unwrap(),
                lazy: true,
                early_data: None,
                calls,
            }),
        }],
        vec![],
    );
    let initial = Arc::downgrade(&chain.initial_hop[0]);
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let prefix = chain
        .selected_route(&resolver, &chain.select_indices(false).unwrap())
        .prefix(
            NetLocation::from_str("xhttp.test:443", None)
                .unwrap()
                .into(),
        );
    drop(chain);
    assert!(initial.upgrade().is_none());
    assert_eq!(prefix.route_key().0.len(), 1);
}
