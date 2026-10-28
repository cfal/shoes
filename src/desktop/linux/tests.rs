use super::*;
use serde_json::json;

const KERNEL_TEST_ARGS: [&str; 5] = [
    "--exact",
    "desktop::linux::tests::managed_kernel_capture_and_cleanup",
    "--ignored",
    "--nocapture",
    "--test-threads=1",
];

fn configuration(redirect: bool) -> crate::config::TunConfig {
    serde_json::from_value(json!({
        "device_name":"shoes0", "auto_route":true, "auto_redirect":redirect,
        "auto_dns":false, "dns_hijack":false, "addresses":["10.233.0.1/30", "fd73::1/126"],
        "bootstrap_dns":["192.0.2.53:53"], "rules":"allow-all-direct"
    }))
    .unwrap()
}

fn spec(redirect: bool) -> Spec {
    Spec::from_configs(&[crate::config::Config::TunServer(configuration(redirect))])
        .unwrap()
        .unwrap()
}

#[test]
fn managed_configuration_is_explicit_dual_stack_and_restart_identifiable() {
    let base = configuration(false);
    let validate = |config| Spec::from_configs(&[crate::config::Config::TunServer(config)]);
    assert!(validate(base.clone()).is_ok());
    for field in [
        "device_fd",
        "address",
        "netmask",
        "destination",
        "packet_information",
    ] {
        let mut config = serde_json::to_value(&base).unwrap();
        config[field] = match field {
            "device_fd" => json!(42),
            "packet_information" => json!(true),
            _ => json!("10.233.0.1"),
        };
        assert!(
            validate(serde_json::from_value(config).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut config = base.clone();
    config.addresses.pop();
    assert!(validate(config.clone()).is_err());
    config.route_address = vec!["0.0.0.0/0".parse().unwrap()];
    assert!(validate(config).is_ok());
    for endpoint in [
        "127.0.0.53:53",
        "[::1]:53",
        "10.233.0.2:53",
        "0.0.0.0:53",
        "192.0.2.53:0",
    ] {
        let mut config = base.clone();
        config.bootstrap_dns = vec![endpoint.parse().unwrap()];
        assert!(validate(config).is_err(), "{endpoint}");
    }
    let mut config = base.clone();
    config.auto_dns = Some(true);
    assert!(validate(config.clone()).is_err());
    config.dns_hijack = Some(true);
    let spec = validate(config).unwrap().unwrap();
    assert_eq!(
        spec.dns_addresses().unwrap(),
        vec![
            "10.233.0.2".parse::<std::net::IpAddr>().unwrap(),
            "fd73::2".parse().unwrap()
        ]
    );
    assert_eq!(
        serde_json::from_slice::<Spec>(&serde_json::to_vec(&spec).unwrap()).unwrap(),
        spec
    );
    assert!(
        Spec::from_configs(&[
            crate::config::Config::TunServer(base.clone()),
            crate::config::Config::TunServer(base)
        ])
        .is_err()
    );
}

#[test]
fn managed_firewall_schema_preserves_masks_reply_exemption_and_exact_ownership() {
    let spec = spec(true);
    let policy = nft::install(
        &spec,
        "shoes_test",
        "token",
        &[
            "192.0.2.0/24".parse().unwrap(),
            "192.0.2.64/26".parse().unwrap(),
        ],
        [Some(12345), Some(12346)],
    );
    let typed: nftables::schema::Nftables<'_> = serde_json::from_value(policy.clone()).unwrap();
    let serialized = serde_json::to_value(typed).unwrap();
    assert_eq!(
        command::encode_nft(policy.clone()).unwrap(),
        serde_json::to_vec(&serialized).unwrap(),
    );
    assert!(nft::same_policy(&serialized, &policy), "{serialized}");
    let text = serialized.to_string();
    assert!(text.contains("reply"));
    assert!(text.contains(&(!spec.linux.mark_mask).to_string()));
    assert!(!text.contains("192.0.2.64"));
    let mut changed = policy.clone();
    let entries = changed["nftables"].as_array_mut().unwrap();
    entries.pop();
    assert!(!nft::same_policy(&changed, &policy));
    let mut changed = policy.clone();
    changed["nftables"][1]["add"]["chain"]["prio"] = json!(-149);
    assert!(!nft::same_policy(&changed, &policy));
    for batch in [
        nft::update_onlink("shoes_test", &[]),
        nft::remove("shoes_test"),
    ] {
        serde_json::from_value::<nftables::schema::Nftables<'_>>(batch).unwrap();
    }
}

#[test]
fn firewall_comparison_rejects_malformed_documents() {
    for (listing, valid) in [
        (json!({}), false),
        (json!({"nftables": null}), false),
        (json!({"nftables": []}), true),
        (json!({"nftables": [{"metainfo": {}}]}), true),
        (json!({"nftables": [{"unknown": {}}]}), false),
        (json!({"nftables": [{"table": {}, "chain": {}}]}), false),
        (json!({"nftables": [{"table": null}]}), false),
        (json!({"nftables": [{"table": {}}]}), false),
        (json!({"nftables": [{"table": {"name": "owned"}}]}), true),
        (
            json!({"nftables": [{"set": {"name": "onlink4", "elem": null}}]}),
            false,
        ),
        (json!({"nftables": [{"rule": {"chain": "output"}}]}), false),
        (
            json!({"nftables": [{"rule": {"chain": "output", "expr": []}}]}),
            true,
        ),
    ] {
        assert_eq!(nft::same_policy(&listing, &listing), valid, "{listing}");
    }
}

#[test]
fn firewall_comparison_accepts_flag_renderings_from_newer_nft() {
    fn singleton_flags(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(serde_json::Value::Array(flags)) = object.get("flags")
                    && flags.len() == 1
                {
                    object.insert("flags".into(), flags[0].clone());
                }
                for value in object.values_mut() {
                    singleton_flags(value);
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(singleton_flags),
            _ => {}
        }
    }
    let policy = nft::install(
        &spec(true),
        "shoes_test",
        "token",
        &[],
        [Some(12345), Some(12346)],
    );
    let mut listing = policy.clone();
    singleton_flags(&mut listing);
    assert_ne!(listing, policy);
    assert!(nft::same_policy(&listing, &policy));
    let tcp_rule = listing["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|entry| {
            let rule = entry.get_mut("add")?.get_mut("rule")?;
            (rule["comment"] == "token:not-tcp-establishment").then_some(rule)
        })
        .unwrap();
    tcp_rule["expr"][0]["match"]["left"]["&"][1] = json!({"|": ["syn", "ack"]});
    assert!(nft::same_policy(&listing, &policy));
    let set = listing["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|entry| entry.get_mut("add")?.get_mut("set"))
        .unwrap();
    set["flags"] = json!("constant");
    assert!(!nft::same_policy(&listing, &policy));
}

#[test]
fn firewall_comparison_accepts_prefix_ranges_from_older_nft() {
    fn render_ranges(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(prefix) = object.get("prefix") {
                    let network = ipnetwork::IpNetwork::new(
                        prefix["addr"].as_str().unwrap().parse().unwrap(),
                        prefix["len"].as_u64().unwrap().try_into().unwrap(),
                    )
                    .unwrap();
                    if network.network() != network.broadcast() {
                        *value = json!({"range": [network.network(), network.broadcast()]});
                    }
                } else {
                    for value in object.values_mut() {
                        render_ranges(value);
                    }
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(render_ranges),
            _ => {}
        }
    }
    let policy = nft::install(&spec(false), "shoes_test", "token", &[], [None, None]);
    let mut listing = policy.clone();
    render_ranges(&mut listing);
    assert_ne!(listing, policy);
    assert!(nft::same_policy(&listing, &policy));
    let set = listing["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|entry| entry.get_mut("add")?.get_mut("set"))
        .unwrap();
    assert_eq!(set["name"], "include4");
    set["elem"][0]["range"][1] = json!("255.255.255.254");
    assert!(!nft::same_policy(&listing, &policy));
}

#[test]
fn managed_routing_rule_matches_bypass_never_even_after_native_lookup_fails() {
    use rtnetlink::packet_route::rule::RuleAttribute;
    let spec = spec(false);
    for ipv6 in [false, true] {
        let expected = routes::rule(&spec, ipv6);
        assert_ne!(
            spec.linux.bypass_mark & spec.linux.mark_mask,
            spec.linux.capture_mark
        );
        assert_ne!(
            (spec.linux.bypass_mark | spec.linux.capture_mark) & spec.linux.mark_mask,
            spec.linux.capture_mark
        );
        let mut actual = expected.clone();
        actual.attributes.reverse();
        actual
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        assert!(routes::same_rule(&actual, &expected));
        actual
            .attributes
            .push(RuleAttribute::Oifname("foreign".into()));
        assert!(!routes::same_rule(&actual, &expected));
    }
}

#[test]
fn managed_native_default_requires_unconstrained_selectors() {
    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
    for ipv6 in [false, true] {
        let mut route = routes::default_route(&spec(false), 42, ipv6);
        route
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::Table(_)));
        route.header.table = 254;
        assert!(routes::native_default(&route));
        let mut changed = route.clone();
        changed.header.source_prefix_length = 64;
        assert!(!routes::native_default(&changed));
        let mut changed = route.clone();
        changed.header.tos = 16;
        assert!(!routes::native_default(&changed));
        let address = if ipv6 {
            RouteAddress::Inet6("fd00:1::1".parse().unwrap())
        } else {
            RouteAddress::Inet("192.0.2.1".parse().unwrap())
        };
        for attribute in [
            RouteAttribute::Source(address.clone()),
            RouteAttribute::Iif(7),
            RouteAttribute::Mark(1),
        ] {
            let mut changed = route.clone();
            changed.attributes.push(attribute);
            assert!(!routes::native_default(&changed));
        }
        route.attributes.push(RouteAttribute::PrefSource(address));
        assert!(routes::native_default(&route));
    }
}

#[test]
fn managed_mark_reservation_checks_masks_including_zero_and_inverted_values() {
    use rtnetlink::packet_route::rule::{RuleAttribute, RuleFlags};
    let spec = spec(false);
    for ipv6 in [false, true] {
        for flags in [RuleFlags::empty(), RuleFlags::Invert] {
            for mark in [0, 1, spec.linux.capture_mark, spec.linux.bypass_mark] {
                for (mask, conflicts) in [
                    (None, mark != 0),
                    (Some(0), false),
                    (Some(0xff), false),
                    (Some(spec.linux.capture_mark), true),
                    (Some(spec.linux.bypass_mark), true),
                    (Some(spec.linux.mark_mask), true),
                ] {
                    let mut rule = routes::rule(&spec, ipv6);
                    rule.header.flags = flags;
                    rule.attributes = vec![RuleAttribute::FwMark(mark)];
                    if let Some(mask) = mask {
                        rule.attributes.push(RuleAttribute::FwMask(mask));
                    }
                    assert_eq!(
                        routes::check_mark_reservation(&rule, &spec).is_err(),
                        conflicts
                    );
                    if mark == 0 {
                        rule.attributes
                            .retain(|attribute| !matches!(attribute, RuleAttribute::FwMark(_)));
                        assert_eq!(
                            routes::check_mark_reservation(&rule, &spec).is_err(),
                            conflicts
                        );
                    }
                }
            }
        }
        let mut rule = routes::rule(&spec, ipv6);
        rule.attributes.clear();
        assert!(routes::check_mark_reservation(&rule, &spec).is_ok());
    }
}

#[test]
fn managed_default_route_comparison_preserves_selectors_and_attributes() {
    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RoutePreference};
    for redirect in [false, true] {
        for ipv6 in [false, true] {
            let expected = routes::default_route(&spec(redirect), 42, ipv6);
            let mut actual = expected.clone();
            actual.header.table = 0;
            actual.attributes.reverse();
            if ipv6 {
                actual.attributes.extend([
                    RouteAttribute::Priority(1024),
                    RouteAttribute::Preference(RoutePreference::Medium),
                ]);
            }
            assert!(routes::same_route(&actual, &expected));
            let mut changed = actual.clone();
            changed.header.source_prefix_length = 64;
            assert!(!routes::same_route(&changed, &expected));
            let mut changed = actual.clone();
            changed.header.tos = 16;
            assert!(!routes::same_route(&changed, &expected));
            let address = if ipv6 {
                RouteAddress::Inet6("fd00:1::1".parse().unwrap())
            } else {
                RouteAddress::Inet("192.0.2.1".parse().unwrap())
            };
            for attribute in [
                RouteAttribute::Source(address.clone()),
                RouteAttribute::PrefSource(address),
                RouteAttribute::Priority(99),
                RouteAttribute::Iif(7),
                RouteAttribute::Expires(1),
            ] {
                let mut changed = actual.clone();
                changed.attributes.push(attribute);
                assert!(!routes::same_route(&changed, &expected));
            }
        }
    }
}

#[test]
fn redirect_gateways_are_reserved_in_every_native_next_hop_form() {
    use rtnetlink::packet_route::route::{
        RouteAddress, RouteAttribute, RouteMessage, RouteNextHop, RouteVia,
    };
    let peer4 = "10.233.0.2".parse().unwrap();
    let peer6 = "fd73::2".parse().unwrap();
    let mut hop = RouteNextHop::default();
    hop.attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet(peer4)));
    for attribute in [
        RouteAttribute::Gateway(RouteAddress::Inet(peer4)),
        RouteAttribute::Gateway(RouteAddress::Inet6(peer6)),
        RouteAttribute::Via(RouteVia::Inet(peer4)),
        RouteAttribute::Via(RouteVia::Inet6(peer6)),
        RouteAttribute::MultiPath(vec![hop]),
        RouteAttribute::NhId(42),
    ] {
        let mut route = RouteMessage::default();
        route.header.table = 254;
        route.attributes.push(attribute);
        assert!(routes::check_redirect_gateways(&[route.clone()], &spec(true)).is_err());
        assert!(routes::check_redirect_gateways(&[route], &spec(false)).is_ok());
    }
    let mut route = RouteMessage::default();
    route.header.table = 254;
    route
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet(
            "192.0.2.2".parse().unwrap(),
        )));
    assert!(routes::check_redirect_gateways(&[route], &spec(true)).is_ok());

    let mut config = configuration(true);
    config.addresses = vec![
        "10.233.0.1/32".parse().unwrap(),
        "fd73::1/128".parse().unwrap(),
    ];
    assert!(Spec::from_configs(&[crate::config::Config::TunServer(config)]).is_err());
    let peers: Vec<_> = configuration(true).virtual_dns_addresses().collect();
    assert_eq!(
        peers,
        vec![std::net::IpAddr::V4(peer4), std::net::IpAddr::V6(peer6)]
    );
}

fn run(program: &str, arguments: &[&str]) -> io::Result<String> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
#[ignore = "requires sudo, nft, iproute2, util-linux and /dev/net/tun; runs only inside disposable namespaces"]
fn managed_kernel_capture_and_cleanup() -> io::Result<()> {
    const PARENT: &str = "SHOES_MANAGED_PARENT_NETNS";
    const MOUNT: &str = "SHOES_MANAGED_PARENT_MOUNTNS";
    let namespace = std::fs::read_link("/proc/self/ns/net")?;
    if std::env::var_os("SHOES_ORPHAN_HELPER").is_some() {
        assert_ne!(namespace.as_os_str(), std::env::var_os(PARENT).unwrap());
        return tokio::runtime::Builder::new_current_thread().enable_all().build()?
            .block_on(async {
                let mut session = Session::prepare(spec(false)).await?;
                session.prepare_network().await?;
                session.record.firewall_pending = true;
                session.journal.save(&session.record)?;
                let batch = serde_json::to_vec(&expected_policy(&session.record, &session.record.on_link))?;
                command::run(session.journal.lease(), "/bin/sh", &["-c",
                    "cat > /run/helper.batch; echo $$ > /run/helper.pid; kill -STOP $$; exec nft -j -f /run/helper.batch"], &batch).await?;
                Ok(())
            });
    }
    if let Some(config) = std::env::var_os("SHOES_MANAGED_PROCESS_CONFIG") {
        assert_ne!(namespace.as_os_str(), std::env::var_os(PARENT).unwrap());
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(crate::process::run(
                vec![config.to_string_lossy().into_owned()],
                false,
                true,
            ));
    }
    if let Some(parent) = std::env::var_os(PARENT) {
        assert_ne!(
            namespace.as_os_str(),
            parent,
            "refusing to alter host networking"
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/mnt")?.as_os_str(),
            std::env::var_os(MOUNT).unwrap()
        );
        let links: serde_json::Value = serde_json::from_str(&run("ip", &["-j", "link", "show"])?)?;
        assert_eq!(links.as_array().unwrap().len(), 1);
        assert_eq!(links[0]["ifname"], "lo");
        run(
            "mount",
            &["-t", "tmpfs", "-o", "size=16m,mode=755", "tmpfs", "/run"],
        )?;
        run("ip", &["link", "set", "lo", "up"])?;
        run("ip", &["netns", "add", "peer"])?;
        run(
            "ip",
            &[
                "link", "add", "native0", "type", "veth", "peer", "name", "remote0",
            ],
        )?;
        run("ip", &["link", "set", "remote0", "netns", "peer"])?;
        run("ip", &["link", "set", "native0", "up"])?;
        run("ip", &["addr", "add", "192.0.2.1/24", "dev", "native0"])?;
        run(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "fd00:1::1/64",
                "dev",
                "native0",
                "nodad",
            ],
        )?;
        run("ip", &["route", "add", "default", "via", "192.0.2.2"])?;
        run("ip", &["-6", "route", "add", "default", "via", "fd00:1::2"])?;
        for arguments in [
            vec!["link", "set", "lo", "up"],
            vec!["link", "set", "remote0", "up"],
            vec!["addr", "add", "192.0.2.2/24", "dev", "remote0"],
            vec![
                "-6",
                "addr",
                "add",
                "fd00:1::2/64",
                "dev",
                "remote0",
                "nodad",
            ],
            vec!["addr", "add", "198.51.100.2/32", "dev", "lo"],
            vec!["-6", "addr", "add", "fd00:2::2/128", "dev", "lo", "nodad"],
        ] {
            let mut args = vec!["-n", "peer"];
            args.extend(arguments);
            run("ip", &args)?;
        }
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut daemons = resolved_fixture().await?;
                let result =
                    tokio::time::timeout(Duration::from_secs(90), kernel_capture()).await?;
                for child in &mut daemons {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
                result
            });
    }
    let output = std::process::Command::new("sudo")
        .args([
            "-n",
            "--",
            "timeout",
            "--kill-after=5s",
            "120s",
            "unshare",
            "--net",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child",
            "--",
            "env",
        ])
        .arg(format!("{PARENT}={}", namespace.display()))
        .arg(format!(
            "{MOUNT}={}",
            std::fs::read_link("/proc/self/ns/mnt")?.display()
        ))
        .args(
            std::env::var("SHOES_RESOLVED_ROOT")
                .ok()
                .map(|root| format!("SHOES_RESOLVED_ROOT={root}")),
        )
        .arg(std::env::current_exe()?)
        .args(KERNEL_TEST_ARGS)
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn kernel_capture() -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    run("nft", &["add", "table", "inet", "strict_rpf"])?;
    run(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "strict_rpf",
            "prerouting",
            "{ type filter hook prerouting priority -150; }",
        ],
    )?;
    run(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            "strict_rpf",
            "prerouting",
            "meta",
            "nfproto",
            "ipv6",
            "fib",
            "saddr",
            ".",
            "mark",
            ".",
            "iif",
            "oif",
            "missing",
            "counter",
            "drop",
        ],
    )?;
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = tcp.local_addr()?.port();
    let udp = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let tcp_echo = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            connections.spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    }));
    let udp_echo = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut packet = [0; 4096];
        loop {
            let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
            udp.send_to(&packet[..length], peer).await.unwrap();
        }
    }));
    for redirect in [false, true] {
        let mut native_dns = native_dns_connections().await?;
        if !redirect {
            run("nft", &["add", "table", "inet", "native_tracker"])?;
            run(
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    "native_tracker",
                    "output",
                    "{ type filter hook output priority -200; }",
                ],
            )?;
            run(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    "native_tracker",
                    "output",
                    "ct",
                    "state",
                    "established",
                    "counter",
                ],
            )?;
        }
        native_dns.extend(native_dns_connections().await?);
        let mut config = serde_json::to_value(configuration(redirect))?;
        config["dns_hijack"] = json!(true);
        config["rules"] = json!([
            {"masks":["10.233.0.0/30", "fd73::/126"], "action":"allow"},
            {"masks":["0.0.0.0/0", "::/0"], "action":"allow", "override_address":format!("127.0.0.1:{port}")}
        ]);
        let config: crate::config::TunConfig = serde_json::from_value(config)?;
        let mut validated =
            crate::config::create_server_configs(vec![crate::config::Config::TunServer(config)])?;
        let spec = Spec::from_configs(&validated.configs)?.unwrap();
        let crate::config::Config::TunServer(config) = validated.configs.remove(0) else {
            unreachable!()
        };
        let mut session = Session::prepare(spec).await?;
        session.prepare_network().await?;
        let ingress = session.ingress().unwrap();
        let resolver: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        if !redirect {
            let unexpanded = serde_json::from_value(json!({
                "device_name":"unused", "rules":"unexpanded-rule"
            }))?;
            assert!(
                ingress
                    .start_redirects(&unexpanded, resolver.clone(), None)?
                    .is_empty()
            );
        }
        let admission = Ingress::tcp_admission(&config);
        let mut tasks = ingress.start_redirects(&config, resolver.clone(), admission.clone())?;
        tasks.push(
            crate::tun::start_tun_server_retained(
                config.clone(),
                resolver.clone(),
                ingress.device.clone(),
                admission,
            )
            .await?,
        );
        resolved::ready(&session.record).await?;
        tun_subnet_rejected(&session, false)
            .await
            .map_err(|error| io::Error::other(format!("pre-capture subnet guard: {error}")))?;
        if let Err(error) = session.activate().await {
            eprintln!("rules: {}", run("ip", &["-j", "rule", "show"])?);
            eprintln!("firewall: {}", run("nft", &["-j", "list", "ruleset"])?);
            return Err(error);
        }
        native_services(&session)
            .await
            .map_err(|error| io::Error::other(format!("native services: {error}")))?;
        device_bound_connections(&session).await.map_err(|error| {
            io::Error::other(format!("device-bound TCP (redirect={redirect}): {error}"))
        })?;
        for (client, server) in &mut native_dns {
            exchange_native_dns(client, server)
                .await
                .map_err(|error| io::Error::other(format!("established DNS: {error}")))?;
        }
        tun_subnet_rejected(&session, true).await?;
        for (ipv6, port) in session.record.redirect_ports.iter().enumerate() {
            if let Some(port) = port {
                let address = std::net::SocketAddr::new(
                    if ipv6 == 0 { "127.0.0.1" } else { "::1" }.parse().unwrap(),
                    *port,
                );
                assert!(!matches!(
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        tokio::net::TcpStream::connect(address)
                    )
                    .await,
                    Ok(Ok(_))
                ));
            }
        }
        for (source, destination) in [("192.0.2.1", "198.51.100.2"), ("fd00:1::1", "fd00:2::2")] {
            let source: std::net::IpAddr = source.parse().unwrap();
            let target = std::net::SocketAddr::new(destination.parse().unwrap(), port);
            for bound in [false, true] {
                let bind = std::net::SocketAddr::new(
                    if bound {
                        source
                    } else if source.is_ipv4() {
                        "0.0.0.0".parse().unwrap()
                    } else {
                        "::".parse().unwrap()
                    },
                    0,
                );
                let socket = tokio::net::UdpSocket::bind(bind).await?;
                socket.send_to(b"captured-udp", target).await?;
                let mut bytes = [0; 128];
                let (length, peer) =
                    tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut bytes))
                        .await??;
                assert_eq!(peer, target);
                assert_eq!(&bytes[..length], b"captured-udp");
                let socket = if source.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                if bound {
                    socket.bind(bind)?;
                }
                let mut stream =
                    tokio::time::timeout(Duration::from_secs(3), socket.connect(target)).await??;
                stream.write_all(b"captured-tcp").await?;
                let mut answer = [0; 12];
                tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut answer))
                    .await??;
                assert_eq!(&answer, b"captured-tcp");
            }
        }
        session.reconcile().await?;
        let index = session.record.ifindex;
        session.validate(&[crate::config::Config::TunServer(config.clone())])?;
        let mut changed = config.clone();
        changed.mtu += 1;
        assert!(
            session
                .validate(&[crate::config::Config::TunServer(changed)])
                .is_err()
        );
        for task in tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        assert_eq!(session.record.ifindex, index);
        let mut limited = config.clone();
        limited.resource_limits.max_tcp_connections = Some(1);
        let admission = Ingress::tcp_admission(&limited);
        tasks.push(
            crate::tun::start_tun_server_retained(
                limited.clone(),
                resolver.clone(),
                ingress.device.clone(),
                admission.clone(),
            )
            .await?,
        );
        tasks.extend(ingress.start_redirects(&limited, resolver, admission.clone())?);
        if redirect {
            redirect_dual_stack_limit(port, &session, admission.as_ref().unwrap()).await?;
        }
        session.reconcile().await?;
        session.deactivate().await?;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        session.close().await?;
        assert_no_owned_firewall()?;
        drop(ingress);
        drop(session);
        let (connection, handle, _) = rtnetlink::new_connection().map_err(io::Error::other)?;
        let _connection = AbortOnDropHandle::new(tokio::spawn(connection));
        assert!(routes::link(&handle, "shoes0").await?.is_none());
        for ipv6 in [false, true] {
            assert!(!routes::rules(&handle, ipv6).await?.iter().any(|rule| {
                rule.attributes
                    .contains(&rtnetlink::packet_route::rule::RuleAttribute::Priority(
                        12000,
                    ))
            }));
        }
    }
    process_recovery(port).await?;
    orphan_helper_recovery().await?;
    preflight_failures().await?;
    ownership_failures().await?;
    route_ownership_failures().await?;
    interception_validation().await?;
    if std::env::var_os("SHOES_RESOLVED_ROOT").is_some() {
        for redirect in [false, true] {
            for limit in [1, 2] {
                resolved_integration(limit, redirect).await?;
            }
        }
    }
    drop((tcp_echo, udp_echo));
    Ok(())
}

async fn interception_validation() -> io::Result<()> {
    let target = std::fs::canonicalize("/etc/resolv.conf")?;
    std::fs::write("/run/interception-resolv.conf", "nameserver 10.250.0.1\n")?;
    run(
        "mount",
        &[
            "--bind",
            "/run/interception-resolv.conf",
            target.to_str().unwrap(),
        ],
    )?;
    let mut configs = json!([
        {"dns_group":"fake", "dns_servers":"system", "fake_ip":true},
        {"device_name":"manual", "address":"10.250.0.1", "dns_hijack":true, "rules":"allow-all-direct"}
    ]);
    for fake in [false, true] {
        configs[0]["fake_ip"] = json!(fake);
        std::fs::write(
            "/run/interception-resolv.conf",
            format!(
                "nameserver {}\n",
                if fake { "198.18.0.2" } else { "10.250.0.1" }
            ),
        )?;
        let validated =
            crate::config::create_server_configs(serde_json::from_value(configs.clone())?)?;
        assert!(
            crate::dns::check_interception(&validated.configs, &validated.dns_groups)
                .await
                .is_err()
        );
    }
    run("umount", &[target.to_str().unwrap()])?;
    Ok(())
}

async fn resolved_fixture() -> io::Result<Vec<tokio::process::Child>> {
    let Some(root) = std::env::var_os("SHOES_RESOLVED_ROOT") else {
        return Ok(Vec::new());
    };
    let root = std::path::PathBuf::from(root);
    for name in ["passwd", "group"] {
        let original = format!("/etc/{name}");
        let mut contents = std::fs::read_to_string(&original)?;
        if !contents
            .lines()
            .any(|line| line.starts_with("systemd-resolve:"))
        {
            contents.push_str(if name == "passwd" {
                "systemd-resolve:x:60000:60000:Resolver:/:/usr/sbin/nologin\n"
            } else {
                "systemd-resolve:x:60000:\n"
            });
        }
        let copy = format!("/run/{name}");
        std::fs::write(&copy, contents)?;
        run("mount", &["--bind", &copy, &original])?;
    }
    std::fs::create_dir_all("/run/dbus")?;
    std::fs::create_dir_all("/run/systemd/resolved.conf.d")?;
    std::fs::create_dir_all("/run/systemd/resolve")?;
    run(
        "chown",
        &["systemd-resolve:systemd-resolve", "/run/systemd/resolve"],
    )?;
    std::fs::write(
        "/run/systemd/resolved.conf.d/zz-test.conf",
        "[Resolve]\nDNS=\nFallbackDNS=\nDNSOverTLS=yes\nDNSSEC=yes\nLLMNR=yes\nMulticastDNS=yes\n",
    )?;
    std::fs::write(
        "/run/managed-bus.conf",
        "<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><policy context=\"default\"><allow user=\"*\"/><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>",
    )?;
    let bus = tokio::process::Command::new("dbus-daemon")
        .args(["--config-file=/run/managed-bus.conf", "--nofork"])
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while tokio::net::UnixStream::connect("/run/dbus/system_bus_socket")
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let resolver = tokio::process::Command::new(root.join("lib/systemd/systemd-resolved"))
        .kill_on_drop(true)
        .spawn()?;
    let journal = Journal::lock()?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if resolved::Resolved::preflight(journal.lease()).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(vec![resolver, bus])
}

async fn resolved_integration(udp_limit: usize, redirect: bool) -> io::Result<()> {
    use hickory_resolver::proto::{
        op::{Message, Query},
        rr::{Name, RData, Record, RecordType, rdata},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[derive(Debug)]
    struct Answer;
    impl crate::resolver::Resolver for Answer {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            Box::pin(async { Err(io::Error::other("unexpected hostname bootstrap")) })
        }
        fn exchange(&self, request: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
            Box::pin(async move {
                let mut reply = Message::from_vec(&request)
                    .map_err(io::Error::other)?
                    .into_response();
                let texts = if reply.queries[0].name().to_ascii().starts_with("tcp") {
                    vec!["x".repeat(255); 8]
                } else {
                    vec!["real-answer".into()]
                };
                reply.add_answer(Record::from_rdata(
                    reply.queries[0].name().clone(),
                    60,
                    RData::TXT(rdata::TXT::new(texts)),
                ));
                reply.to_vec().map_err(io::Error::other)
            })
        }
    }
    let mut config = configuration(redirect);
    config.dns_hijack = Some(true);
    config.auto_dns = Some(true);
    config.resource_limits.max_udp_destinations = Some(udp_limit);
    config.resource_limits.max_tcp_connections = Some(1);
    let mut validated =
        crate::config::create_server_configs(vec![crate::config::Config::TunServer(config)])?;
    let spec = Spec::from_configs(&validated.configs)?.unwrap();
    let crate::config::Config::TunServer(config) = validated.configs.remove(0) else {
        unreachable!()
    };
    let mut session = Session::prepare(spec).await?;
    session.prepare_network().await?;
    let ingress = session.ingress().unwrap();
    let admission = Ingress::tcp_admission(&config);
    let mut tasks = ingress.start_redirects(&config, Arc::new(Answer), admission.clone())?;
    tasks.push(
        crate::tun::start_tun_server_retained(
            config,
            Arc::new(Answer),
            ingress.device.clone(),
            admission,
        )
        .await?,
    );
    session.activate().await?;
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(format!("managed{udp_limit}-{redirect}.example.")).unwrap(),
        RecordType::TXT,
    ));
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(&query.to_vec().unwrap(), "127.0.0.53:53")
        .await?;
    let mut bytes = [0; 4096];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut bytes)).await??;
    let reply = Message::from_vec(&bytes[..length]).map_err(io::Error::other)?;
    assert_eq!(reply.answers.len(), 1, "{reply:?}");
    assert_eq!(
        &reply.answers[0].data,
        &RData::TXT(rdata::TXT::new(vec!["real-answer".into()]))
    );
    if udp_limit == 2 {
        query.queries[0] = Query::query(
            Name::from_ascii(format!("tcp{udp_limit}-{redirect}.example.")).unwrap(),
            RecordType::TXT,
        );
        let query = query.to_vec().map_err(io::Error::other)?;
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut tcp = tokio::net::TcpStream::connect("127.0.0.53:53").await?;
            tcp.write_u16(query.len() as u16).await?;
            tcp.write_all(&query).await?;
            let length = tcp.read_u16().await? as usize;
            let mut bytes = vec![0; length];
            tcp.read_exact(&mut bytes).await?;
            let reply = Message::from_vec(&bytes).map_err(io::Error::other)?;
            assert_eq!(reply.answers.len(), 1, "{reply:?}");
            assert_eq!(
                reply.answers[0].data,
                RData::TXT(rdata::TXT::new(vec!["x".repeat(255); 8]))
            );
            Ok::<_, io::Error>(())
        })
        .await??;
    }
    session.reconcile().await?;
    session.deactivate().await?;
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    session.close().await?;
    assert_no_owned_firewall()?;
    Ok(())
}

async fn orphan_helper_recovery() -> io::Result<()> {
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .env("SHOES_ORPHAN_HELPER", "1")
        .args(KERNEL_TEST_ARGS)
        .kill_on_drop(true)
        .spawn()?;
    let pid: i32 = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(pid) = std::fs::read_to_string("/run/helper.pid")
                && let Ok(pid) = pid.trim().parse::<i32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    child.kill().await?;
    child.wait().await?;
    assert!(
        cleanup().await.is_err(),
        "recovery raced a surviving helper"
    );
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(journal) = Journal::lock() {
                let record = journal.load().unwrap().unwrap();
                run("nft", &["list", "table", "inet", &record.table()]).unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    cleanup().await?;
    assert!(Journal::lock()?.load()?.is_none());
    assert_no_owned_firewall()?;
    Ok(())
}

async fn exchange_native_dns(
    client: &mut tokio::net::TcpStream,
    server: &mut tokio::net::TcpStream,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(3), async {
        client.write_all(b"native-dns").await?;
        let mut bytes = [0; 10];
        server.read_exact(&mut bytes).await?;
        server.write_all(&bytes).await?;
        client.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"native-dns");
        Ok::<_, io::Error>(())
    })
    .await?
}

async fn native_dns_connections() -> io::Result<Vec<(tokio::net::TcpStream, tokio::net::TcpStream)>>
{
    let mut streams = Vec::new();
    for ip in ["198.51.100.2", "fd00:2::2"] {
        let listener = in_peer(move || {
            let listener = std::net::TcpListener::bind((ip, 53))?;
            listener.set_nonblocking(true)?;
            Ok(listener)
        })?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let mut client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (mut server, _) = listener.accept().await?;
        exchange_native_dns(&mut client, &mut server).await?;
        streams.push((client, server));
    }
    Ok(streams)
}

async fn tun_subnet_rejected(session: &Session, active: bool) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let descriptors = || std::fs::read_dir("/proc/self/fd").map(|entries| entries.count());
    let before = descriptors()?;
    for ip in session.record.spec.dns_addresses()? {
        let udp =
            tokio::net::UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
        for _ in 0..8 {
            udp.send_to(b"no-recursion", (ip, 9)).await?;
        }
        let connection = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect((ip, 80)),
        )
        .await?;
        match connection {
            Ok(mut stream) => {
                let _ = stream.write_all(b"no-recursion").await;
                let mut bytes = [0; 32];
                assert!(
                    !matches!(tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes)).await?, Ok(n) if n > 0)
                );
            }
            Err(error) => assert!(matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
            )),
        }
        if active {
            let protected = crate::socket_util::new_udp_socket(ip.is_ipv6(), None)?;
            let _ = protected.send_to(b"guard", (ip, 9)).await;
        }
    }
    assert!(
        descriptors()? <= before + 8,
        "TUN subnet traffic leaked descriptors"
    );
    if active {
        let listing = firewall_listing(session.journal.lease(), &session.nft, &session.record)
            .await?
            .unwrap();
        let guard = listing["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.get("rule"))
            .find(|rule| {
                rule["comment"]
                    .as_str()
                    .is_some_and(|s| s.ends_with(":recursive-egress"))
            })
            .unwrap();
        assert!(
            guard["expr"]
                .as_array()
                .unwrap()
                .iter()
                .any(|expr| expr["counter"]["packets"].as_u64().is_some_and(|n| n >= 2))
        );
    }
    Ok(())
}

async fn redirect_dual_stack_limit(
    port: u16,
    session: &Session,
    admission: &tokio::sync::Semaphore,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let before = redirect_counts(session).await?;
    let mut first = tokio::net::TcpStream::connect(("198.51.100.2", port)).await?;
    first.write_all(b"one").await?;
    let mut bytes = [0; 3];
    tokio::time::timeout(Duration::from_secs(3), first.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"one");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(("10.233.0.2", 53)),
        )
        .await
        .is_err(),
        "TUN admitted TCP while REDIRECT held the only permit",
    );
    let mut second = tokio::net::TcpStream::connect(("fd00:2::2", port)).await?;
    let _ = second.write_all(b"two").await;
    assert!(
        !matches!(tokio::time::timeout(Duration::from_secs(2), second.read(&mut bytes)).await?, Ok(n) if n > 0),
        "{}",
        run(
            "nft",
            &["-j", "list", "table", "inet", &session.record.table()]
        )?
    );
    first.write_all(b"one").await?;
    tokio::time::timeout(Duration::from_secs(3), first.read_exact(&mut bytes)).await??;
    let after = redirect_counts(session).await?;
    assert!(
        after[0] > before[0] && after[1] > before[1],
        "both flows must traverse REDIRECT: {before:?} -> {after:?}"
    );
    socket2::SockRef::from(&first).set_linger(Some(Duration::ZERO))?;
    drop(first);
    drop(
        tokio::time::timeout(Duration::from_secs(3), admission.acquire())
            .await?
            .unwrap(),
    );
    let mut dns = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(("fd73::2", 53)),
    )
    .await??;
    let query = hickory_resolver::proto::op::Message::query()
        .to_vec()
        .unwrap();
    dns.write_u16(query.len() as u16).await?;
    dns.write_all(&query).await?;
    let length = tokio::time::timeout(Duration::from_secs(3), dns.read_u16()).await??;
    let mut answer = vec![0; length as usize];
    dns.read_exact(&mut answer).await?;
    assert_eq!(
        hickory_resolver::proto::op::Message::from_vec(&answer)
            .unwrap()
            .response_code,
        hickory_resolver::proto::op::ResponseCode::FormErr,
    );
    assert_eq!(admission.available_permits(), 0);
    let mut redirected = tokio::net::TcpStream::connect(("198.51.100.2", port)).await?;
    let _ = redirected.write_all(b"two").await;
    assert!(
        !matches!(tokio::time::timeout(Duration::from_secs(2), redirected.read(&mut bytes)).await?, Ok(n) if n > 0),
        "REDIRECT admitted TCP while TUN held the only permit",
    );
    socket2::SockRef::from(&dns).set_linger(Some(Duration::ZERO))?;
    drop(dns);
    drop(
        tokio::time::timeout(Duration::from_secs(3), admission.acquire())
            .await?
            .unwrap(),
    );
    Ok(())
}

async fn redirect_counts(session: &Session) -> io::Result<[u64; 2]> {
    let listing = firewall_listing(session.journal.lease(), &session.nft, &session.record)
        .await?
        .unwrap();
    let mut counts = [0; 2];
    for rule in listing["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry.get("rule"))
    {
        if rule["chain"] != "redirect" {
            continue;
        }
        let expressions = rule["expr"].as_array().unwrap();
        let ipv6 = expressions
            .iter()
            .any(|expr| expr["match"]["left"]["rt"]["family"] == "ip6");
        counts[usize::from(ipv6)] = expressions
            .iter()
            .find_map(|expr| expr["counter"]["packets"].as_u64())
            .unwrap();
    }
    Ok(counts)
}

async fn process_recovery(port: u16) -> io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let mut config = serde_json::to_value(configuration(true))?;
    if std::env::var_os("SHOES_RESOLVED_ROOT").is_some() {
        config["auto_dns"] = json!(true);
        config["dns_hijack"] = json!(true);
    }
    config["rules"] = json!([{"masks":["0.0.0.0/0", "::/0"], "action":"allow", "override_address":format!("127.0.0.1:{port}")}]);
    let path = "/run/process-test.yaml";
    let write = |config: &serde_json::Value| -> io::Result<()> {
        std::fs::write(
            path,
            serde_yaml::to_string(&vec![config]).map_err(io::Error::other)?,
        )
    };
    async fn line(
        reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
        expected: &str,
    ) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).await? == 0 {
                    return Err(io::Error::other(format!(
                        "process exited before {expected}"
                    )));
                }
                if line.contains(expected) {
                    return Ok(());
                }
            }
        })
        .await?
    }
    async fn captured(port: u16) -> io::Result<()> {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(("198.51.100.2", port)),
        )
        .await??;
        stream.write_all(b"process").await?;
        let mut bytes = [0; 7];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut bytes)).await??;
        assert_eq!(&bytes, b"process");
        Ok(())
    }
    let (connection, handle, _) = rtnetlink::new_connection().map_err(io::Error::other)?;
    let _connection = AbortOnDropHandle::new(tokio::spawn(connection));
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        write(&config)?;
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .env("SHOES_MANAGED_PROCESS_CONFIG", path)
            .args(KERNEL_TEST_ARGS)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut stderr = tokio::io::BufReader::new(child.stderr.take().unwrap());
        if let Err(error) = line(&mut stdout, "Servers ready").await {
            let mut diagnostic = String::new();
            tokio::time::timeout(
                Duration::from_secs(1),
                stderr.read_to_string(&mut diagnostic),
            )
            .await??;
            return Err(io::Error::other(format!("{error}: {diagnostic}")));
        }
        let index = routes::link(&handle, "shoes0").await?.unwrap().header.index;
        captured(port).await?;
        let mut changed = config.clone();
        changed["mtu"] = json!(1400);
        write(&changed)?;
        assert_eq!(
            unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGHUP) },
            0
        );
        line(&mut stderr, "Reload rejected; current servers retained").await?;
        captured(port).await?;
        write(&config)?;
        assert_eq!(
            unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGHUP) },
            0
        );
        line(&mut stdout, "Servers ready").await?;
        assert_eq!(
            routes::link(&handle, "shoes0").await?.unwrap().header.index,
            index
        );
        captured(port).await?;
        assert_eq!(unsafe { libc::kill(child.id().unwrap() as i32, signal) }, 0);
        let status = tokio::time::timeout(Duration::from_secs(15), child.wait()).await??;
        assert_eq!(status.success(), signal == libc::SIGTERM);
        assert!(routes::link(&handle, "shoes0").await?.is_none());
        if signal == libc::SIGTERM {
            assert!(Journal::lock()?.load()?.is_none());
            assert_no_owned_firewall()?;
        }
        cleanup().await?;
        cleanup().await?;
        assert!(Journal::lock()?.load()?.is_none());
        assert_no_owned_firewall()?;
    }
    Ok(())
}

fn in_peer<T: Send + 'static>(
    operation: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        let namespace = std::fs::File::open("/run/netns/peer")?;
        if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        operation()
    })
    .join()
    .unwrap()
}

async fn device_bound_connections(session: &Session) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let before = redirect_counts(session).await?;
    let link: serde_json::Value = serde_json::from_str(&run(
        "ip",
        &["-n", "peer", "-j", "link", "show", "remote0"],
    )?)?;
    let mac = link[0]["address"].as_str().unwrap();
    for (remote, gateway, family) in [
        ("198.51.100.2", "192.0.2.2", "-4"),
        ("fd00:2::2", "fd00:1::2", "-6"),
    ] {
        for gatewayless in [false, true] {
            if gatewayless {
                run(
                    "ip",
                    &[
                        family,
                        "neigh",
                        "replace",
                        remote,
                        "lladdr",
                        mac,
                        "nud",
                        "permanent",
                        "dev",
                        "native0",
                    ],
                )?;
                run(
                    "ip",
                    &[family, "route", "replace", "default", "dev", "native0"],
                )?;
            }
            let remote: std::net::IpAddr = remote.parse().unwrap();
            let listener = in_peer(move || {
                let listener = std::net::TcpListener::bind((remote, 0))?;
                listener.set_nonblocking(true)?;
                Ok(listener)
            })?;
            let listener = tokio::net::TcpListener::from_std(listener)?;
            let socket = if remote.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            socket2::SockRef::from(&socket).bind_device(Some(b"native0"))?;
            tokio::time::timeout(Duration::from_secs(3), async {
                let mut client = socket.connect(listener.local_addr()?).await?;
                let (mut server, _) = listener.accept().await?;
                server.write_all(b"native").await?;
                let mut bytes = [0; 6];
                client.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"native");
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|error| io::Error::other(format!("{remote}: {error}")))??;
            if gatewayless {
                run(
                    "ip",
                    &[
                        family, "route", "replace", "default", "via", gateway, "dev", "native0",
                    ],
                )?;
                run(
                    "ip",
                    &[
                        family,
                        "neigh",
                        "del",
                        &remote.to_string(),
                        "dev",
                        "native0",
                    ],
                )?;
            }
        }
    }
    assert_eq!(
        redirect_counts(session).await?,
        before,
        "device-bound TCP entered REDIRECT"
    );
    Ok(())
}

async fn native_services(session: &Session) -> io::Result<()> {
    use std::net::{IpAddr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (local, remote, wildcard) in [
        ("192.0.2.1", "198.51.100.2", "0.0.0.0"),
        ("fd00:1::1", "fd00:2::2", "::"),
    ] {
        let local: IpAddr = local.parse().unwrap();
        let remote: IpAddr = remote.parse().unwrap();
        let wildcard: IpAddr = wildcard.parse().unwrap();
        let socket = in_peer(move || {
            let socket = std::net::UdpSocket::bind((remote, 0))?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        })?;
        let peer = tokio::net::UdpSocket::from_std(socket)?;
        let server = tokio::net::UdpSocket::bind((wildcard, 0)).await?;
        let destination = SocketAddr::new(local, server.local_addr()?.port());
        let mut bytes = [0; 128];
        peer.send_to(b"inbound", destination).await?;
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(3), server.recv_from(&mut bytes)).await??;
        server.send_to(&bytes[..length], source).await?;
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut bytes)).await??;
        assert_eq!(source, destination);
        assert_eq!(&bytes[..length], b"inbound");

        let protected = crate::socket_util::new_udp_socket(local.is_ipv6(), None)?;
        assert_eq!(
            socket2::SockRef::from(&protected).mark()?,
            session.record.spec.linux.bypass_mark
        );
        socket2::SockRef::from(&protected).set_mark(7)?;
        crate::socket_policy::apply(socket2::SockRef::from(&protected), None)?;
        assert_eq!(
            socket2::SockRef::from(&protected).mark()?,
            session.record.spec.linux.bypass_mark | 7
        );
        protected.send_to(b"protected", peer.local_addr()?).await?;
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut bytes)).await??;
        assert_eq!(&bytes[..length], b"protected");
        peer.send_to(&bytes[..length], source).await?;
        let length =
            tokio::time::timeout(Duration::from_secs(3), protected.recv(&mut bytes)).await??;
        assert_eq!(&bytes[..length], b"protected");
        let family = if local.is_ipv4() { "-4" } else { "-6" };
        let gateway = if local.is_ipv4() {
            "192.0.2.2"
        } else {
            "fd00:1::2"
        };
        run(
            "ip",
            &[
                family, "route", "add", "table", "13000", "default", "via", gateway, "dev",
                "native0",
            ],
        )?;
        run(
            "ip",
            &[
                family,
                "rule",
                "add",
                "priority",
                "12001",
                "fwmark",
                "0x40000000/0x60000000",
                "table",
                "13000",
            ],
        )?;
        run("ip", &[family, "route", "del", "default"])?;
        protected
            .send_to(b"no-main-route", peer.local_addr()?)
            .await?;
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut bytes)).await??;
        assert_eq!(&bytes[..length], b"no-main-route");
        run("ip", &[family, "route", "add", "default", "via", gateway])?;
        run(
            "ip",
            &[family, "rule", "del", "priority", "12001", "table", "13000"],
        )?;
        run("ip", &[family, "route", "del", "table", "13000", "default"])?;
        let listener =
            crate::socket_util::new_tcp_listener(SocketAddr::new(wildcard, 0), 16, None)?;
        assert_eq!(
            socket2::SockRef::from(&listener).mark()?,
            session.record.spec.linux.bypass_mark
        );
        let destination = SocketAddr::new(local, listener.local_addr()?.port());
        let client = in_peer(move || {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(destination),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            socket.bind(&SocketAddr::new(remote, 0).into())?;
            socket.connect_timeout(&destination.into(), Duration::from_secs(3))?;
            socket.set_nonblocking(true)?;
            Ok(std::net::TcpStream::from(socket))
        })?;
        let mut client = tokio::net::TcpStream::from_std(client)?;
        let (mut accepted, _) =
            tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
        assert_eq!(
            socket2::SockRef::from(&accepted).mark()?,
            session.record.spec.linux.bypass_mark
        );
        accepted.write_all(b"listener").await?;
        let mut answer = [0; 8];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut answer)).await??;
        assert_eq!(&answer, b"listener");
    }
    Ok(())
}

async fn preflight_failures() -> io::Result<()> {
    for (family, gateway, selector) in [
        ("-4", "192.0.2.2", ["tos", "0x10"]),
        ("-6", "fd00:1::2", ["from", "fd00:99::/64"]),
    ] {
        run("ip", &[family, "route", "del", "default"])?;
        let mut route = vec![family, "route", "add", "default"];
        route.extend(selector);
        route.extend(["via", gateway, "dev", "native0"]);
        run("ip", &route)?;
        let error = Session::prepare(spec(false)).await.err().unwrap();
        assert!(
            error.to_string().contains("underlying main-table default"),
            "{error}"
        );
        route[2] = "del";
        run("ip", &route)?;
        run("ip", &[family, "route", "add", "default", "via", gateway])?;
        drop(Session::prepare(spec(false)).await?);
    }
    let mut ipv4_only = spec(false);
    ipv4_only.addresses.retain(ipnetwork::IpNetwork::is_ipv4);
    ipv4_only.routes.retain(ipnetwork::IpNetwork::is_ipv4);
    for family in ["-4", "-6"] {
        for inverted in [false, true] {
            for mark in ["0/0x40000000", "0x40000000/0x40000000"] {
                let mut rule = vec![family, "rule", "add", "priority", "13000"];
                if inverted {
                    rule.push("not");
                }
                rule.extend(["fwmark", mark, "table", "13000"]);
                run("ip", &rule)?;
                for spec in [spec(false), ipv4_only.clone()] {
                    let error = Session::prepare(spec)
                        .await
                        .err()
                        .unwrap_or_else(|| panic!("accepted {rule:?}"));
                    assert!(error.to_string().contains("mark reservation"), "{error}");
                }
                rule[2] = "del";
                run("ip", &rule)?;
            }
        }
        let mut session = Session::prepare(ipv4_only.clone()).await?;
        session.prepare_network().await?;
        session.activate().await?;
        run(
            "ip",
            &[
                family,
                "rule",
                "add",
                "priority",
                "13000",
                "fwmark",
                "0/0x40000000",
                "table",
                "13000",
            ],
        )?;
        let error = session.reconcile().await.unwrap_err();
        assert!(error.to_string().contains("mark reservation"), "{error}");
        session.close().await?;
        run(
            "ip",
            &[family, "rule", "del", "priority", "13000", "table", "13000"],
        )?;
    }
    assert!(Journal::lock()?.load()?.is_none());
    assert_no_owned_firewall()?;
    Ok(())
}

async fn ownership_failures() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    run(
        "ip",
        &[
            "-6",
            "nexthop",
            "add",
            "id",
            "42",
            "via",
            "fd00:1::2",
            "dev",
            "native0",
        ],
    )?;
    run("ip", &["-6", "route", "add", "fd00:3::/64", "nhid", "42"])?;
    let mut config = configuration(true);
    config.addresses.retain(ipnetwork::IpNetwork::is_ipv4);
    config.route_address = vec!["0.0.0.0/0".parse().unwrap()];
    let ipv4_only = Spec::from_configs(&[crate::config::Config::TunServer(config)])?.unwrap();
    run(
        "ip",
        &["-6", "rule", "add", "priority", "100", "table", "12000"],
    )?;
    run(
        "ip",
        &[
            "-6",
            "route",
            "add",
            "table",
            "12000",
            "default",
            "via",
            "fd00:1::2",
            "dev",
            "native0",
        ],
    )?;
    let mut session = Session::prepare(ipv4_only.clone()).await?;
    session.prepare_network().await?;
    session.activate().await?;
    session.reconcile().await?;
    session.close().await?;
    drop(session);
    assert!(run("ip", &["-6", "rule", "show"])?.contains("100:"));
    assert!(run("ip", &["-6", "route", "show", "table", "12000"])?.contains("default"));
    assert!(Session::prepare(spec(true)).await.is_err());
    run(
        "ip",
        &["-6", "rule", "del", "priority", "100", "table", "12000"],
    )?;
    run("ip", &["-6", "route", "del", "table", "12000", "default"])?;
    assert!(Session::prepare(spec(true)).await.is_err());
    run(
        "ip",
        &[
            "-6",
            "rule",
            "add",
            "priority",
            "13000",
            "fwmark",
            "0x40000000/0x60000000",
            "table",
            "main",
        ],
    )?;
    assert!(Session::prepare(ipv4_only).await.is_err());
    run(
        "ip",
        &["-6", "rule", "del", "priority", "13000", "table", "main"],
    )?;
    run("ip", &["-6", "route", "del", "fd00:3::/64"])?;
    run("ip", &["nexthop", "del", "id", "42"])?;

    let mut session = Session::prepare(spec(false)).await?;
    session.prepare_network().await?;
    let executable = session.nft.clone();
    let table = session.record.table();
    let helper = "/run/nft-change-before-readback";
    std::fs::write(
        helper,
        format!(
            "#!/bin/sh\n{executable} \"$@\" || exit $?\nif [ \"$*\" = '-j -f -' ]; then\n{executable} flush chain inet {table} output\nfi\n"
        ),
    )?;
    std::fs::set_permissions(helper, std::fs::Permissions::from_mode(0o700))?;
    session.nft = helper.into();
    assert!(session.activate().await.is_err());
    assert!(session.record.firewall.is_none());
    assert!(session.journal.load()?.unwrap().firewall.is_none());
    session.nft = executable;
    command::nft(session.journal.lease(), &session.nft, nft::remove(&table)).await?;
    session.close().await?;
    drop(session);

    let mut session = Session::prepare(spec(false)).await?;
    session.prepare_network().await?;
    session.activate().await?;
    let old_policy = session.record.firewall.clone().unwrap();
    let executable = session.nft.clone();
    std::fs::write(
        "/run/old-onlink.json",
        command::encode_nft(nft::update_onlink(
            &session.record.table(),
            &session.record.on_link,
        ))?,
    )?;
    std::fs::write(
        helper,
        format!(
            "#!/bin/sh\n{executable} \"$@\" || exit $?\nif [ \"$*\" = '-j -f -' ]; then\n{executable} -j -f /run/old-onlink.json\nfi\n"
        ),
    )?;
    session.nft = helper.into();
    run("ip", &["addr", "add", "192.0.3.1/24", "dev", "native0"])?;
    assert!(session.reconcile().await.is_err());
    let record = session.journal.load()?.unwrap();
    assert_eq!(record.previous_firewall, Some(old_policy.clone()));
    assert!(!matches_current_policy(&old_policy, &record));
    assert!(matches_recovery_policy(&old_policy, &record));
    session.nft = executable;
    session.close().await?;
    drop(session);
    assert!(Journal::lock()?.load()?.is_none());
    assert_no_owned_firewall()?;
    run("ip", &["addr", "del", "192.0.3.1/24", "dev", "native0"])?;

    for family in ["-4", "-6"] {
        let mut session = Session::prepare(spec(false)).await?;
        session.prepare_network().await?;
        session.activate().await?;
        run(
            "ip",
            &[
                family,
                "rule",
                "add",
                "priority",
                "12001",
                "fwmark",
                "0x20000000/0x60000000",
                "table",
                "12000",
            ],
        )?;
        run(
            "ip",
            &[family, "rule", "del", "priority", "12000", "table", "12000"],
        )?;
        assert!(session.close().await.is_err());
        assert!(session.journal.load()?.is_some());
        drop(session);
        assert!(cleanup().await.is_err());
        assert!(Journal::lock()?.load()?.is_some());
        assert!(run("ip", &[family, "rule", "show"])?.contains("12001:"));
        run(
            "ip",
            &[family, "rule", "del", "priority", "12001", "table", "12000"],
        )?;
        cleanup().await?;
        assert!(Journal::lock()?.load()?.is_none());
        assert_no_owned_firewall()?;
    }

    let mut session = Session::prepare(spec(false)).await?;
    session.record.firewall = Some(json!({"large_snapshot": "x".repeat(128 * 1024)}));
    session.record.previous_firewall = session.record.firewall.clone();
    session.journal.save(&session.record)?;
    let recovered = session.journal.load()?.unwrap();
    assert_eq!(recovered.firewall, session.record.firewall);
    assert_eq!(
        recovered.previous_firewall,
        session.record.previous_firewall
    );
    session.journal.clear()?;
    drop(session);
    run("nft", &["add", "table", "inet", "foreign_preserved"])?;
    run("ip", &["rule", "add", "priority", "12000", "table", "main"])?;
    assert!(Session::prepare(spec(false)).await.is_err());
    assert!(run("ip", &["rule", "show"])?.contains("12000:"));
    run("ip", &["rule", "del", "priority", "12000", "table", "main"])?;
    let mut session = Session::prepare(spec(false)).await?;
    assert!(Session::prepare(spec(false)).await.is_err());
    let executable = session.nft.clone();
    session.nft = "/bin/false".into();
    assert!(session.prepare_network().await.is_err());
    session.nft = executable;
    session.close().await?;
    drop(session);
    assert!(Journal::lock()?.load()?.is_none());

    let mut session = Session::prepare(spec(false)).await?;
    session.prepare_network().await?;
    session.activate().await?;
    run("ip", &["addr", "add", "192.0.3.1/24", "dev", "native0"])?;
    session.reconcile().await?;
    assert!(
        session
            .record
            .on_link
            .contains(&"192.0.3.0/24".parse().unwrap())
    );
    run("ip", &["addr", "del", "192.0.3.1/24", "dev", "native0"])?;
    session.reconcile().await?;
    let table = session.record.table();
    run("nft", &["add", "rule", "inet", &table, "output", "counter"])?;
    assert!(session.reconcile().await.is_err());
    assert!(session.deactivate().await.is_err());
    assert!(run("nft", &["list", "table", "inet", &table])?.contains("counter"));
    command::nft(session.journal.lease(), &session.nft, nft::remove(&table)).await?;
    command::nft(
        session.journal.lease(),
        &session.nft,
        expected_policy(&session.record, &session.record.on_link),
    )
    .await?;
    session.close().await?;
    run("nft", &["list", "table", "inet", "foreign_preserved"])?;
    assert_no_owned_firewall()?;
    Ok(())
}

async fn route_ownership_failures() -> io::Result<()> {
    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};

    for redirect in [false, true] {
        for ipv6 in [false, true] {
            let mut session = Session::prepare(spec(redirect)).await?;
            session.prepare_network().await?;
            session.activate().await?;
            let expected =
                routes::default_route(&session.record.spec, session.record.ifindex.unwrap(), ipv6);
            routes::request(session.handle.route().del(expected.clone()).execute()).await?;
            let mut changed = expected;
            if ipv6 {
                changed.header.source_prefix_length = 64;
                changed
                    .attributes
                    .push(RouteAttribute::Source(RouteAddress::Inet6(
                        "fd00:99::".parse().unwrap(),
                    )));
            } else {
                changed.header.tos = 16;
            }
            routes::request(session.handle.route().add(changed).execute()).await?;
            assert!(session.reconcile().await.is_err());
            assert!(session.close().await.is_err());
            assert!(session.journal.load()?.is_some());
            drop(session);
            cleanup().await?;
            assert!(Journal::lock()?.load()?.is_none());
        }
    }
    for ipv6 in [false, true] {
        for orphan in [false, true] {
            let mut session = Session::prepare(spec(false)).await?;
            session.prepare_network().await?;
            session.activate().await?;
            let native = routes::link(&session.handle, "native0")
                .await?
                .unwrap()
                .header
                .index;
            routes::request(
                session
                    .handle
                    .route()
                    .add(routes::default_route(&session.record.spec, native, ipv6))
                    .replace()
                    .execute(),
            )
            .await?;
            assert!(session.reconcile().await.is_err());
            let family = if ipv6 { "-6" } else { "-4" };
            run(
                "ip",
                &[
                    family,
                    "rule",
                    "add",
                    "priority",
                    "12001",
                    "fwmark",
                    "0x20000000/0x60000000",
                    "table",
                    "12000",
                ],
            )?;
            run(
                "ip",
                &[family, "rule", "del", "priority", "12000", "table", "12000"],
            )?;
            let expected_errors = concat!(
                "managed TUN routing table was changed externally; refusing to forget it; ",
                "managed TUN rule was changed externally; refusing to remove it",
            );
            if !orphan {
                let retained = session.ingress().unwrap();
                assert_eq!(
                    session.close().await.unwrap_err().to_string(),
                    expected_errors
                );
                assert!(routes::link(&session.handle, "shoes0").await?.is_none());
                assert!(session.ingress.is_none());
                assert!(session.journal.load()?.is_some());
                drop(retained);
            }
            drop(session);
            assert_eq!(cleanup().await.unwrap_err().to_string(), expected_errors);
            assert!(Journal::lock()?.load()?.is_some());
            assert!(run("ip", &[family, "rule", "show"])?.contains("12001:"));
            assert!(run("ip", &[family, "route", "show", "table", "12000"])?.contains("native0"));
            run(
                "ip",
                &[family, "rule", "del", "priority", "12001", "table", "12000"],
            )?;
            run("ip", &[family, "route", "del", "table", "12000", "default"])?;
            cleanup().await?;
            assert!(Journal::lock()?.load()?.is_none());
            assert_no_owned_firewall()?;
        }
    }
    Ok(())
}

fn assert_no_owned_firewall() -> io::Result<()> {
    let listing: serde_json::Value = serde_json::from_str(&run("nft", &["-j", "list", "tables"])?)?;
    assert!(
        !listing["nftables"].as_array().unwrap().iter().any(|entry| {
            entry["table"]["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("shoes_"))
        }),
        "owned firewall survived cleanup: {listing}"
    );
    Ok(())
}
