use super::*;

#[test]
fn tun_routes_tcp_and_udp_through_wireguard_to_a_kernel_peer() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::network::tun_routes_tcp_and_udp_through_wireguard_to_a_kernel_peer",
        async {
            for offload in [false, true] {
                let kernel = KernelPeer::start(false, 1408, true, 0)?;
                let name = if offload { "shwgt1" } else { "shwgt0" };
                let tun = json!({
                    "device_name": name, "address": "10.90.0.2",
                    "netmask": "255.255.255.255", "mtu": 1500,
                    "segmentation_offload": offload,
                    "rules": [
                        {"masks": "198.18.0.77/32", "action": "allow", "override_address": "10.77.0.1:0",
                         "client_chain": "wg"},
                        {"masks": "fd88::77/128", "action": "allow", "override_address": "[fd77::1]:0",
                         "client_chain": "wg"},
                    ],
                });
                let (_process, _config) = start_shoes_server(
                    &serde_yaml::to_string(&json!([config::client(kernel.port()?), tun,])).unwrap(),
                )?;
                timeout(Duration::from_secs(10), async {
                    loop {
                        if let Ok(addresses) =
                            run("ip", &["-j", "-4", "address", "show", "dev", name])
                        {
                            let addresses: Value = serde_json::from_str(&addresses)?;
                            if addresses[0]["addr_info"].as_array().is_some_and(|items| {
                                items.iter().any(|address| address["local"] == "10.90.0.2")
                            }) {
                                return io::Result::Ok(());
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await??;
                run(
                    "ip",
                    &["-6", "address", "add", "fd90::2/128", "dev", name, "nodad"],
                )?;
                for (family, route) in [("-4", "198.18.0.77/32"), ("-6", "fd88::77/128")] {
                    run("ip", &[family, "route", "add", route, "dev", name])?;
                    let destination = route.split_once('/').unwrap().0;
                    let lookup: Value = serde_json::from_str(&run(
                        "ip",
                        &["-j", family, "route", "get", destination],
                    )?)?;
                    assert_eq!(lookup[0]["dev"], name);
                    assert_ne!(lookup[0]["type"], "local");
                }
                for ipv6 in [false, true] {
                    timeout(Duration::from_secs(25), async {
                        let echo = EchoTargets::new(ipv6).await?;
                        let before = kernel.counters()?;
                        let target: IpAddr = if ipv6 { "fd88::77" } else { "198.18.0.77" }
                            .parse()
                            .unwrap();
                        bulk_echo(
                            TcpStream::connect(SocketAddr::new(target, echo.tcp().port())).await?,
                        )
                        .await?;
                        let udp = UdpSocket::bind(if ipv6 { "[fd90::2]:0" } else { "10.90.0.2:0" })
                            .await?;
                        udp.connect(SocketAddr::new(target, echo.udp().port()))
                            .await?;
                        for size in [0, 1, 1200] {
                            let payload = vec![0x73; size];
                            udp.send(&payload).await?;
                            let mut reply = [0; 1500];
                            let length = udp.recv(&mut reply).await?;
                            assert_eq!(&reply[..length], payload);
                        }
                        kernel.assert_transfer(before, TCP_BYTES)
                    })
                    .await??;
                }
            }
            Ok(())
        },
    )
}

#[test]
fn native_ipv6_outer_transport_interoperates_with_kernel_in_both_roles() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::network::native_ipv6_outer_transport_interoperates_with_kernel_in_both_roles",
        async {
            for shoes_server in [false, true] {
                let reservation = std::net::UdpSocket::bind("[::1]:0")?;
                let port = reservation.local_addr()?.port();
                let kernel = KernelPeer::configured(
                    1408,
                    true,
                    KernelConfig {
                        name: "wg0",
                        local_key_seed: if shoes_server { 42 } else { 41 },
                        peer_key_seed: if shoes_server { 41 } else { 42 },
                        addresses: if shoes_server {
                            ["10.77.0.2/32", "fd77::2/128"]
                        } else {
                            ["10.77.0.1/32", "fd77::1/128"]
                        },
                        routes: if shoes_server {
                            ["10.88.0.1/32", "fd88::1/128"]
                        } else {
                            ["10.77.0.2/32", "fd77::2/128"]
                        },
                        endpoint: shoes_server
                            .then(|| SocketAddr::new("::1".parse().unwrap(), port)),
                    },
                )?;
                let mut endpoint = if shoes_server {
                    config::server(port)
                } else {
                    config::client(kernel.port()?)
                };
                if shoes_server {
                    endpoint["address"] = json!(format!("[::1]:{port}"));
                } else {
                    endpoint["client_proxies"][0]["address"] =
                        json!(format!("[::1]:{}", kernel.port()?));
                }
                let mut ports = PortHelper::new();
                let (_, entry) = ports.get_localhost_listener_port();
                let mut socks = config::socks(entry);
                if shoes_server {
                    socks["rules"] = json!("allow-all-direct");
                }
                drop(reservation);
                let (_process, _config) =
                    start_shoes_server(&serde_yaml::to_string(&json!([endpoint, socks])).unwrap())?;
                ports.wait_for_all_ports().await?;
                for ipv6 in [false, true] {
                    let echo = EchoTargets::new(ipv6).await?;
                    let before = kernel.counters()?;
                    if shoes_server {
                        let target: IpAddr =
                            if ipv6 { "fd88::1" } else { "10.88.0.1" }.parse().unwrap();
                        timeout(Duration::from_secs(20), async {
                            bulk_echo(
                                TcpStream::connect(SocketAddr::new(target, echo.tcp().port()))
                                    .await?,
                            )
                            .await?;
                            let udp =
                                UdpSocket::bind(if ipv6 { "[fd77::2]:0" } else { "10.77.0.2:0" })
                                    .await?;
                            udp.send_to(b"ipv6 outer", SocketAddr::new(target, echo.udp().port()))
                                .await?;
                            let mut bytes = [0; 100];
                            let length = udp.recv(&mut bytes).await?;
                            assert_eq!(&bytes[..length], b"ipv6 outer");
                            io::Result::Ok(())
                        })
                        .await??;
                        kernel.assert_transfer(before, TCP_BYTES)?;
                    } else {
                        let target = if ipv6 { "fd77::1" } else { "10.77.0.1" }.parse().unwrap();
                        echo.check(entry, Some(target)).await?;
                        kernel.assert_transfer(before, ECHO_TCP_BYTES)?;
                    }
                    assert!(wg(&["show", kernel.name, "endpoints"])?.contains("[::1]:"));
                }
            }
            Ok(())
        },
    )
}
