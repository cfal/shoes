use super::*;
use std::net::ToSocketAddrs;

fn isolated_hosts(contents: &str) -> io::Result<tempfile::NamedTempFile> {
    let parent = std::env::var_os(PARENT_MOUNTNS).expect("missing parent mount namespace");
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt")?.as_os_str(),
        parent,
        "refusing to replace host resolver files"
    );
    let mut hosts = tempfile::NamedTempFile::new()?;
    hosts.write_all(contents.as_bytes())?;
    hosts.flush()?;
    run(
        "mount",
        &["--bind", hosts.path().to_str().unwrap(), "/etc/hosts"],
    )?;
    Ok(hosts)
}

fn deny_ipv6_udp_sockets() -> io::Result<()> {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let equal = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let args = std::mem::offset_of!(libc::seccomp_data, args)
        + if cfg!(target_endian = "big") { 4 } else { 0 };
    // The explicit UDP protocol excludes libc's protocol-zero getaddrinfo routing probes.
    let mut filter = [
        instruction(
            load,
            0,
            0,
            std::mem::offset_of!(libc::seccomp_data, nr) as u32,
        ),
        instruction(equal, 0, 5, libc::SYS_socket as u32),
        instruction(load, 0, 0, args as u32),
        instruction(equal, 0, 3, libc::AF_INET6 as u32),
        instruction(load, 0, 0, (args + 2 * std::mem::size_of::<u64>()) as u32),
        instruction(equal, 0, 1, libc::IPPROTO_UDP as u32),
        instruction(
            ret,
            0,
            0,
            libc::SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32,
        ),
        instruction(ret, 0, 0, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let error = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EAFNOSUPPORT));
    Ok(())
}

#[test]
fn ipv6_first_peer_hostname_falls_back_when_ipv6_udp_is_unavailable() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::resolution::ipv6_first_peer_hostname_falls_back_when_ipv6_udp_is_unavailable",
        async {
            let _hosts = isolated_hosts(
                "127.0.0.1 localhost\n::1 localhost\n::1 peer.wireguard.test\n127.0.0.1 peer.wireguard.test\n",
            )?;
            let kernel = KernelPeer::start(false, 1408, true, 0)?;
            let port = kernel.port()?;
            deny_ipv6_udp_sockets()?;
            let candidates: Vec<_> = ("peer.wireguard.test", port).to_socket_addrs()?.collect();
            assert!(
                candidates[0].is_ipv6(),
                "fixture did not resolve IPv6 first: {candidates:?}"
            );
            assert!(candidates.iter().any(SocketAddr::is_ipv4));
            let mut endpoint = config::client(port);
            endpoint["client_proxies"][0]["address"] = json!(format!("peer.wireguard.test:{port}"));
            let mut ports = PortHelper::new();
            let (_, entry) = ports.get_localhost_listener_port();
            let (_process, _config) = start_shoes_server(
                &serde_yaml::to_string(&json!([endpoint, config::socks(entry)])).unwrap(),
            )?;
            ports.wait_for_all_ports().await?;
            let before = kernel.counters()?;
            EchoTargets::new(false)
                .await?
                .check(entry, Some("10.77.0.1".parse().unwrap()))
                .await?;
            kernel.assert_transfer(before, ECHO_TCP_BYTES)?;
            assert!(wg(&["show", kernel.name, "endpoints"])?.contains("127.0.0.1:"));
            Ok(())
        },
    )
}

#[test]
fn peer_hostname_is_resolved_again_on_process_reload() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::resolution::peer_hostname_is_resolved_again_on_process_reload",
        async {
            let hosts = isolated_hosts("127.0.0.1 localhost peer.wireguard.test\n")?;
            let reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let port = reservation.local_addr()?.port();
            let second = std::net::UdpSocket::bind(("127.0.0.2", port))?;
            let mut server = config::server(port);
            server["address"] = json!(format!("127.0.0.1:{port}"));
            drop(reservation);
            let first = start_shoes_server(&serde_yaml::to_string(&json!([server])).unwrap())?;
            server["address"] = json!(format!("127.0.0.2:{port}"));
            drop(second);
            let _second = start_shoes_server(&serde_yaml::to_string(&json!([server])).unwrap())?;
            let mut endpoint = config::client(port);
            endpoint["client_proxies"][0]["address"] = json!(format!("peer.wireguard.test:{port}"));
            let mut ports = PortHelper::new();
            let (_, entry) = ports.get_localhost_listener_port();
            let (process, _config) = start_shoes_server(
                &serde_yaml::to_string(&json!([endpoint, config::socks(entry)])).unwrap(),
            )?;
            ports.wait_for_all_ports().await?;
            let echo = EchoTargets::new(false).await?;
            let target = SocketAddr::new("198.18.0.1".parse().unwrap(), echo.tcp().port());
            let mut stream = connect(entry, target).await?;
            stream.write_all(b"old").await?;
            let mut bytes = [0; 3];
            stream.read_exact(&mut bytes).await?;
            assert_eq!(&bytes, b"old");
            // Updating the mounted inode affects only this namespace's native resolver.
            std::fs::write(
                hosts.path(),
                "127.0.0.1 localhost\n127.0.0.2 peer.wireguard.test\n",
            )?;
            assert_eq!(
                ("peer.wireguard.test", port)
                    .to_socket_addrs()?
                    .next()
                    .unwrap()
                    .ip(),
                "127.0.0.2".parse::<IpAddr>().unwrap()
            );
            stream.write_all(b"old").await?;
            stream.read_exact(&mut bytes).await?;
            assert_eq!(&bytes, b"old");
            drop(first);
            assert_eq!(
                unsafe { libc::kill(process.id() as libc::pid_t, libc::SIGHUP) },
                0
            );
            assert!(!matches!(
                timeout(Duration::from_secs(5), stream.read(&mut [0])).await,
                Err(_) | Ok(Ok(1))
            ));
            timeout(Duration::from_secs(10), async {
                loop {
                    if TcpStream::connect(("127.0.0.1", entry)).await.is_ok() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await?;
            echo.check(entry, Some("198.18.0.1".parse().unwrap()))
                .await?;
            Ok(())
        },
    )
}
