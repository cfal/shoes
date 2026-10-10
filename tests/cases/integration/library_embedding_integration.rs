use common::port_helper::PortHelper;
use common::test_servers::start_tcp_stream_echo_server;
/// Integration tests for embedding shoes as a library
///
/// Starts a server with `start_servers` and connects through a client proxy
/// chain built from a `ClientConfig`, in-process and through the public
/// library API only (no TUN device, no shoes binary).
use shoes_test_support as common;
use std::sync::Arc;

use shoes::config::{ClientChainHop, ClientConfig, Config, ConfigSelection, create_server_configs};
use shoes::resolver::{NativeResolver, Resolver};
use shoes::tcp::chain_builder::build_client_proxy_chain;
use shoes::tcp::tcp_server::start_servers;
use shoes::{NetLocation, OneOrSome, ResolvedLocation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_PASSWORD: &str = "test-library-embedding-password";

#[tokio::test]
async fn test_library_client_chain_to_library_server() -> Result<(), Box<dyn std::error::Error>> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();

    let (echo_ip, echo_port) = ports.get_localhost_listener_port();
    let echo_server = start_tcp_stream_echo_server(&echo_ip, echo_port).await?;

    let (server_ip, server_port) = ports.get_localhost_listener_port();
    let server_yaml = format!(
        r#"
- address: "{server_ip}:{server_port}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#
    );
    let server_configs: Vec<Config> = serde_yaml::from_str(&server_yaml)?;
    let validated = create_server_configs(server_configs)?;
    let mut server_handles = Vec::new();
    for config in validated.configs {
        server_handles.extend(start_servers(config, resolver.clone()).await?);
    }
    ports.wait_for_all_ports().await?;

    let client_yaml = format!(
        r#"
address: "{server_ip}:{server_port}"
protocol:
  type: shadowsocks
  cipher: aes-256-gcm
  password: "{TEST_PASSWORD}"
"#
    );
    let client: ClientConfig = serde_yaml::from_str(&client_yaml)?;
    let chain = build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
        resolver.clone(),
    );

    let echo_location = NetLocation::from_str(&echo_server.local_addr().to_string(), None)?;
    let target = ResolvedLocation::from(echo_location);
    let mut setup = chain.connect_tcp(target, &resolver).await?;

    let payload = b"hello through an embedded client chain";
    setup.client_stream.write_all(payload).await?;
    setup.client_stream.flush().await?;
    let mut echoed = vec![0u8; payload.len()];
    setup.client_stream.read_exact(&mut echoed).await?;
    assert_eq!(echoed, payload);

    for handle in server_handles {
        handle.abort();
    }
    Ok(())
}
