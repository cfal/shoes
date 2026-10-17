use super::*;

#[tokio::test]
#[ignore = "requires SHOES_BASELINE_BINARY built from 001495285ac16e2121a539682d1a1f6a7c07c5ed"]
async fn legacy_baseline_matches_backpressure_and_half_close() {
    let baseline = std::env::var_os("SHOES_BASELINE_BINARY").expect("baseline binary required");
    let transport = Transport::Tls;
    for shoes_server in [false, true] {
        let mut observations = Vec::new();
        for binary in [PathBuf::from(&baseline), Kind::Shoes.binary()] {
            observations.push(
                timeout(
                    Duration::from_secs(30),
                    exchange_legacy(binary, transport, shoes_server),
                )
                .await
                .unwrap(),
            );
        }
        assert_eq!(
            observations[0], observations[1],
            "{transport:?}, server={shoes_server}"
        );
    }
}

async fn exchange_legacy(
    binary: PathBuf,
    transport: Transport,
    shoes_server: bool,
) -> (usize, blake3::Hash) {
    let (target, connector, mut target_task) = tls_echo(false).await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_kind = if shoes_server {
        Kind::Shoes
    } else {
        Kind::Xray
    };
    let client_kind = if shoes_server {
        Kind::Xray
    } else {
        Kind::Shoes
    };
    let server_port = free_port().await;
    let client_port = free_port().await;
    let mut server_config = wrap(
        server_kind,
        server_config(server_kind, server_port, "none", !shoes_server),
        true,
        transport,
        &cert,
        &key,
        target,
    );
    let mut client_config = wrap(
        client_kind,
        client_config(client_kind, client_port, server_port, "none", shoes_server),
        false,
        transport,
        &cert,
        &key,
        target,
    );
    if shoes_server {
        match transport {
            Transport::Tls => {
                server_config[0]["protocol"]["default_target"]["vision"] = json!(true)
            }
            Transport::Reality => {
                server_config[0]["protocol"]["reality_targets"]["localhost"]["vision"] = json!(true)
            }
            _ => unreachable!(),
        }
    } else {
        client_config[0]["rules"][0]["client_chain"]["protocol"]["vision"] = json!(true);
    }
    let server = start_binary(
        server_kind,
        server_port,
        server_config,
        if shoes_server {
            binary.clone()
        } else {
            server_kind.binary()
        },
    )
    .await;
    let client = start_binary(
        client_kind,
        client_port,
        client_config,
        if shoes_server {
            client_kind.binary()
        } else {
            binary
        },
    )
    .await;
    let socket = socks_connect(client_port, target).await.unwrap();
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    // Small records finish the Vision decision before the backpressured DIRECT transfer.
    for _ in 0..2 {
        tls.write_all(&[42; 64]).await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = [0; 64];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [42; 64]);
    }
    let (mut read, mut write) = tokio::io::split(tls);
    let data: Vec<_> = (0..2 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let ((), output) = tokio::join!(
        async {
            for chunk in data.chunks(8192) {
                write.write_all(chunk).await.unwrap();
            }
            write.flush().await.unwrap();
            write.shutdown().await.unwrap();
        },
        async {
            let mut output = Vec::new();
            let mut buf = [0; 8192];
            while output.len() < data.len() {
                let n = buf.len().min(data.len() - output.len());
                read.read_exact(&mut buf[..n]).await.unwrap();
                output.extend_from_slice(&buf[..n]);
                if output.len().is_multiple_of(65536) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            output
        }
    );
    assert_eq!(output, data);
    drop((client, server));
    target_task.stop().await;
    (output.len(), blake3::hash(&output))
}
