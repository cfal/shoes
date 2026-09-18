//! Shared test fixture infrastructure for integration tests
//!
//! This module provides a builder pattern for constructing integration tests
//! with minimal boilerplate. It supports VLESS, VMess, SOCKS, and other protocols.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::process::spawn_privileged_process;
pub use crate::process::{
    ProcessGuard, SingBoxCapability, find_singbox_binary, find_singbox_naive_binary,
    start_singbox_server, start_singbox_server_with, start_singbox_server_with_binary,
};

/// Helper to start a shoes proxy server
pub fn start_shoes_server(
    config: &str,
) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    start_shoes_server_internal(config, false)
}

/// Helper to start a shoes proxy server with sudo (for TUN tests)
///
/// This allows running `cargo test` directly without needing to run the
/// entire test binary with sudo. Only the shoes process runs as root.
pub fn start_shoes_server_with_sudo(
    config: &str,
) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    start_shoes_server_internal(config, true)
}

#[must_use = "the route is removed when its guard is dropped"]
pub struct RouteGuard {
    destination: String,
    device: String,
}

pub fn add_route_via_device(destination: &str, device: &str) -> std::io::Result<RouteGuard> {
    let output = Command::new("sudo")
        .args(["-n", "ip", "route", "add", destination, "dev", device])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "failed to add route {destination} via {device}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(RouteGuard {
        destination: destination.to_string(),
        device: device.to_string(),
    })
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        match Command::new("sudo")
            .args([
                "-n",
                "ip",
                "route",
                "del",
                &self.destination,
                "dev",
                &self.device,
            ])
            .output()
        {
            Ok(output) if !output.status.success() => eprintln!(
                "[TUN] Failed to remove route {} via {}: {}",
                self.destination,
                self.device,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!(
                "[TUN] Failed to invoke route cleanup for {} via {}: {}",
                self.destination, self.device, error
            ),
            _ => {}
        }
    }
}

fn start_shoes_server_internal(
    config: &str,
    use_sudo: bool,
) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    use std::io::Write;

    let mut config_file = tempfile::NamedTempFile::new()?;

    // Debug: Print config if it contains TUN or other notable keywords
    if config.contains("device_name") || config.contains("reality") || config.contains("vless") {
        eprintln!("========== SHOES CONFIG ==========");
        eprintln!("{}", config);
        eprintln!("========== END CONFIG ==========");
    }

    config_file.write_all(config.as_bytes())?;
    config_file.flush()?;
    let config_path = config_file.path().to_owned();

    let shoes_bin = find_shoes_binary()?;

    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".to_string());
    let guard = if use_sudo {
        spawn_privileged_process(&shoes_bin, "sudo-shoes", |command| {
            command
                .arg("-t")
                .arg("2")
                .arg("--no-reload")
                .arg(&config_path)
                .env("RUST_LOG", &rust_log)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        })?
    } else {
        let child = Command::new(&shoes_bin)
            .arg("-t")
            .arg("2")
            .arg("--no-reload")
            .arg(&config_path)
            .env("RUST_LOG", rust_log)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        ProcessGuard::new(child, "shoes")
    };

    Ok((guard, config_file))
}

fn find_shoes_binary() -> std::io::Result<PathBuf> {
    for variable in ["SHOES_TEST_SHOES_BIN", "CARGO_BIN_EXE_shoes"] {
        if let Some(path) = std::env::var_os(variable) {
            return Ok(path.into());
        }
    }

    let mut path = std::env::current_exe()?;
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push(format!("shoes{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        return Ok(path);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "shoes test binary not found; set SHOES_TEST_SHOES_BIN",
    ))
}

/// Find naive binary (NaiveProxy client) in common locations
pub fn find_naive_binary() -> Option<String> {
    let locations = vec![
        format!("{}/naive/naive", std::env::var("HOME").unwrap_or_default()),
        "/usr/local/bin/naive".to_string(),
        "/usr/bin/naive".to_string(),
        "naive".to_string(),
    ];

    eprintln!("[DEBUG] Searching for naive binary...");

    for location in &locations {
        if std::path::Path::new(location).exists() {
            eprintln!("[DEBUG] Found naive at: {}", location);
            return Some(location.clone());
        }
    }

    // Try which command
    if let Ok(output) = Command::new("which").arg("naive").output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            eprintln!("[DEBUG] Found naive via which: {}", path);
            return Some(path);
        }
    }

    eprintln!("[DEBUG] naive binary not found");
    None
}

/// Find caddy binary (with forwardproxy for NaiveProxy server) in common locations
pub fn find_naive_caddy_binary() -> Option<String> {
    let locations = vec![
        format!("{}/naive/caddy", std::env::var("HOME").unwrap_or_default()),
        "/usr/local/bin/caddy-naive".to_string(),
        "/usr/bin/caddy-naive".to_string(),
    ];

    eprintln!("[DEBUG] Searching for naive caddy binary...");

    for location in &locations {
        if std::path::Path::new(location).exists() {
            // Verify it has forwardproxy module
            if let Ok(output) = Command::new(location).arg("list-modules").output() {
                let modules = String::from_utf8_lossy(&output.stdout);
                if modules.contains("forward_proxy") {
                    eprintln!("[DEBUG] Found naive caddy at: {}", location);
                    return Some(location.clone());
                }
            }
        }
    }

    eprintln!("[DEBUG] naive caddy binary not found");
    None
}

/// Helper to start a naive client proxy
pub fn start_naive_client(
    config: &str,
) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    use std::io::Write;

    eprintln!("========== NAIVE CLIENT CONFIG ==========");
    eprintln!("{}", config);
    eprintln!("========== END CONFIG ==========");

    let naive_bin = find_naive_binary().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "naive binary not found")
    })?;

    let mut config_file = tempfile::NamedTempFile::new()?;
    config_file.write_all(config.as_bytes())?;
    config_file.flush()?;
    let config_path = config_file.path().to_owned();

    let child = Command::new(&naive_bin)
        .arg(&config_path)
        .arg("--log")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let guard = ProcessGuard::new(child, "naive".to_string());

    Ok((guard, config_file))
}

/// Helper to start a naive caddy server (forwardproxy)
pub fn start_naive_caddy_server(
    config: &str,
) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    use std::io::Write;

    eprintln!("========== NAIVE CADDY CONFIG ==========");
    eprintln!("{}", config);
    eprintln!("========== END CONFIG ==========");

    let caddy_bin = find_naive_caddy_binary().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "naive caddy binary not found")
    })?;

    let mut config_file = tempfile::NamedTempFile::new()?;
    config_file.write_all(config.as_bytes())?;
    config_file.flush()?;
    let config_path = config_file.path().to_owned();

    let child = Command::new(&caddy_bin)
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let guard = ProcessGuard::new(child, "caddy".to_string());

    Ok((guard, config_file))
}

// TEST BUILDER INFRASTRUCTURE

use super::certs::generate_test_cert_files as generate_test_cert;
use super::test_servers::{self, TlsVersion};

/// UUID used across all tests for consistency
pub const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

/// Proxy role in the test chain
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyRole {
    /// Entry point - receives requests from curl/test client
    Entry,
    /// Intermediate proxy in the chain
    Intermediate,
    /// Exit proxy - sends requests to final destination
    Exit,
}

/// VMess cipher type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmessCipher {
    ChaCha20Poly1305,
    Aes128Gcm,
}

impl VmessCipher {
    pub fn as_str(&self) -> &'static str {
        match self {
            VmessCipher::ChaCha20Poly1305 => "chacha20-poly1305",
            VmessCipher::Aes128Gcm => "aes-128-gcm",
        }
    }
}

/// Shadowsocks cipher type
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowsocksCipher {
    Aes256Gcm,
    Aes128Gcm,
    ChaCha20IetfPoly1305,
    // 2022 ciphers require base64-encoded keys
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3ChaCha20Poly1305,
}

impl ShadowsocksCipher {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShadowsocksCipher::Aes256Gcm => "aes-256-gcm",
            ShadowsocksCipher::Aes128Gcm => "aes-128-gcm",
            ShadowsocksCipher::ChaCha20IetfPoly1305 => "chacha20-ietf-poly1305",
            ShadowsocksCipher::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            ShadowsocksCipher::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            ShadowsocksCipher::Blake3ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// Returns the method string for sing-box config
    pub fn singbox_method(&self) -> &'static str {
        self.as_str()
    }

    /// Returns the required key length in bytes for this cipher
    pub fn key_len(&self) -> usize {
        match self {
            ShadowsocksCipher::Aes128Gcm | ShadowsocksCipher::Blake3Aes128Gcm => 16,
            ShadowsocksCipher::Aes256Gcm
            | ShadowsocksCipher::ChaCha20IetfPoly1305
            | ShadowsocksCipher::Blake3Aes256Gcm
            | ShadowsocksCipher::Blake3ChaCha20Poly1305 => 32,
        }
    }

    /// Returns true if this is a 2022 cipher that requires base64 key
    pub fn is_2022(&self) -> bool {
        matches!(
            self,
            ShadowsocksCipher::Blake3Aes128Gcm
                | ShadowsocksCipher::Blake3Aes256Gcm
                | ShadowsocksCipher::Blake3ChaCha20Poly1305
        )
    }
}

/// Inner protocol for REALITY
#[derive(Debug, Clone)]
pub enum RealityInnerProtocol {
    Vless,
    VlessVision,
    Trojan { password: String },
}

/// REALITY configuration
#[derive(Debug, Clone)]
pub struct RealityConfig {
    pub private_key: String,
    pub public_key: String,
    pub server_name: String,
    pub short_id: String,
    pub dest: String,
    pub inner_protocol: RealityInnerProtocol,
}

/// Type of proxy server
#[derive(Debug, Clone)]
pub enum ProxyType {
    // VLESS
    ShoesTlsVisionServer,
    ShoesTlsVisionClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    ShoesVlessServer,
    ShoesVlessClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    ShoesVlessTlsServer,
    ShoesVlessTlsClient {
        upstream_ip: String,
        upstream_port: u16,
    },

    // REALITY
    ShoesRealityServer {
        config: RealityConfig,
    },
    ShoesRealityClient {
        upstream_ip: String,
        upstream_port: u16,
        config: RealityConfig,
    },
    ShoesRealityVisionServer {
        config: RealityConfig,
    },
    ShoesRealityVisionClient {
        upstream_ip: String,
        upstream_port: u16,
        config: RealityConfig,
    },

    // VMess
    ShoesVmessServer {
        cipher: VmessCipher,
    },
    ShoesVmessClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: VmessCipher,
    },
    ShoesVmessTlsServer {
        cipher: VmessCipher,
    },
    ShoesVmessTlsClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: VmessCipher,
    },

    // SOCKS
    ShoesSocksServer,
    ShoesSocksClient {
        upstream_ip: String,
        upstream_port: u16,
    },

    // HTTP
    ShoesHttpProxy,

    // Sing-box
    SingboxVisionServer,
    SingboxVisionClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    SingboxVlessServer,
    SingboxVlessClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    SingboxVlessTlsServer,
    SingboxVlessTlsClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    SingboxRealityVlessServer {
        config: RealityConfig,
    },
    SingboxRealityTrojanServer {
        config: RealityConfig,
    },
    SingboxRealityVlessClient {
        upstream_ip: String,
        upstream_port: u16,
        config: RealityConfig,
    },
    SingboxRealityTrojanClient {
        upstream_ip: String,
        upstream_port: u16,
        config: RealityConfig,
    },
    SingboxRealityVisionServer {
        config: RealityConfig,
    },
    SingboxRealityVisionClient {
        upstream_ip: String,
        upstream_port: u16,
        config: RealityConfig,
    },
    SingboxVmessServer {
        cipher: VmessCipher,
    },
    SingboxVmessClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: VmessCipher,
    },
    SingboxVmessTlsServer {
        cipher: VmessCipher,
    },
    SingboxVmessTlsClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: VmessCipher,
    },
    SingboxSocksServer,
    SingboxSocksClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    SingboxHttpProxy {
        upstream_ip: String,
        upstream_port: u16,
    },

    // ShadowTLS (wraps inner protocol - VLESS by default)
    ShoesShadowTlsLocalServer {
        password: String,
    },
    ShoesShadowTlsRemoteServer {
        password: String,
        handshake_server: String,
    },
    ShoesShadowTlsClient {
        upstream_ip: String,
        upstream_port: u16,
        password: String,
        sni: String,
    },
    SingboxShadowTlsServer {
        password: String,
        inner_port: u16, // sing-box needs separate port for inner protocol
    },
    SingboxShadowTlsClient {
        upstream_ip: String,
        upstream_port: u16,
        password: String,
        server_name: String,
    },

    // Shadowsocks
    ShoesShadowsocksServer {
        cipher: ShadowsocksCipher,
        password: String,
    },
    ShoesShadowsocksClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: ShadowsocksCipher,
        password: String,
    },
    SingboxShadowsocksServer {
        cipher: ShadowsocksCipher,
        password: String,
    },
    SingboxShadowsocksClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: ShadowsocksCipher,
        password: String,
    },

    // Shadowsocks with UDP-over-TCP
    SingboxShadowsocksUotClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: ShadowsocksCipher,
        password: String,
        uot_version: u8, // 1 or 2
    },

    // Snell (uses Shadowsocks ciphers but different key derivation)
    ShoesSnellServer {
        cipher: ShadowsocksCipher,
        password: String,
    },
    ShoesSnellClient {
        upstream_ip: String,
        upstream_port: u16,
        cipher: ShadowsocksCipher,
        password: String,
    },

    // AnyTLS
    ShoesAnyTlsServer {
        password: String,
        sni: String,
    },
    ShoesAnyTlsClient {
        upstream_ip: String,
        upstream_port: u16,
        password: String,
        sni: String,
    },
    SingboxAnyTlsClient {
        upstream_ip: String,
        upstream_port: u16,
        password: String,
        sni: String,
    },
    SingboxAnyTlsServer {
        password: String,
        sni: String,
    },
    // NaiveProxy
    ShoesNaiveProxyServer {
        username: String,
        password: String,
        sni: String,
        /// If true, use CA-signed certs installed to system trust store.
        /// Required for native naive client which doesn't support insecure mode.
        use_system_ca: bool,
        /// Optional fallback for probe resistance (file path for static serving)
        fallback: Option<String>,
    },
    ShoesNaiveProxyClient {
        upstream_ip: String,
        upstream_port: u16,
        username: String,
        password: String,
        sni: String,
    },
    SingboxNaiveServer {
        username: String,
        password: String,
        sni: String,
    },
    SingboxNaiveClient {
        upstream_ip: String,
        upstream_port: u16,
        username: String,
        password: String,
        sni: String,
    },

    // Native NaiveProxy binaries (naive client, caddy forwardproxy server)
    NaiveProxyCaddyServer {
        username: String,
        password: String,
        sni: String,
    },
    NaiveProxyClient {
        upstream_ip: String,
        upstream_port: u16,
        username: String,
        password: String,
        sni: String,
    },

    // Hysteria2 (QUIC-based)
    ShoesHysteria2Server {
        password: String,
    },
    SingboxHysteria2Client {
        upstream_ip: String,
        upstream_port: u16,
        password: String,
    },
    SingboxHysteria2Server {
        password: String,
    },

    // TUIC v5 (QUIC-based)
    ShoesTuicServer {
        password: String,
    },
    SingboxTuicClient {
        upstream_ip: String,
        upstream_port: u16,
        password: String,
    },
    SingboxTuicServer {
        password: String,
    },

    // TUN entry (uses TUN device + netstack-smoltcp as entry point)
    // Traffic flows: curl --interface tun0 -> TUN device -> netstack -> destination (or proxy chain)
    TunEntry {
        /// TUN device name
        tun_name: String,
        /// TUN device IP address (e.g., "10.200.100.1")
        tun_ip: String,
        /// Virtual server IP within TUN subnet (e.g., "10.200.100.2")
        virtual_server_ip: String,
    },

    // H2MUX (HTTP/2 multiplexing over VLESS+TLS)
    // Server side uses ShoesVlessTlsServer - h2mux is auto-detected
    SingboxH2muxVlessClient {
        upstream_ip: String,
        upstream_port: u16,
    },
    ShoesH2muxVlessClient {
        upstream_ip: String,
        upstream_port: u16,
    },
}

/// A proxy server in the test chain
#[derive(Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub ip: String,
    pub port: u16,
    pub role: ProxyRole,
}

/// Generate a REALITY keypair for testing
pub fn generate_reality_keypair() -> (String, String) {
    use aws_lc_rs::{
        agreement,
        rand::{SecureRandom, SystemRandom},
    };
    use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

    let rng = SystemRandom::new();

    // Generate raw private key bytes
    let mut private_bytes = [0u8; 32];
    rng.fill(&mut private_bytes)
        .expect("Failed to generate random bytes");

    // Create private key from bytes
    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_bytes)
        .expect("Failed to create private key");
    let public_key_bytes = private_key
        .compute_public_key()
        .expect("Failed to compute public key");

    let private_key_b64 = URL_SAFE_NO_PAD.encode(private_bytes);
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes.as_ref());

    (private_key_b64, public_key_b64)
}

/// Builder for constructing test fixtures
pub struct ProxyTestFixture {
    proxies: Vec<ProxyConfig>,
    certs: Vec<(tempfile::TempPath, tempfile::TempPath)>,
    local_server: Option<LocalServerConfig>,
    ports: super::port_helper::PortHelper,
}

/// Configuration for local test HTTP/HTTPS server
pub struct LocalServerConfig {
    pub ip: String,
    pub port: u16,
    pub protocol: LocalServerProtocol,
}

#[derive(Clone, Copy)]
pub enum LocalServerProtocol {
    Http,
    HttpsTls12,
    HttpsTls13,
}

/// Built test fixture ready for testing
pub struct BuiltFixture {
    _tun_route: Option<RouteGuard>,
    _guards: Vec<ProcessGuard>,
    _local_servers: Vec<test_servers::TestServer>,
    _config_files: Vec<tempfile::NamedTempFile>,
    _certs: Vec<(tempfile::TempPath, tempfile::TempPath)>,
    /// Handles for TUN background tasks (keep alive for duration of test)
    _tun_handles: Vec<tokio::task::JoinHandle<()>>,
    entry_ip: String,
    entry_port: u16,
    local_server_ip: Option<String>,
    local_server_port: Option<u16>,
    local_server_protocol: Option<LocalServerProtocol>,
    /// TUN interface name (if TUN entry is used)
    tun_interface: Option<String>,
    /// Virtual server IP within TUN subnet (if TUN entry is used)
    tun_virtual_server_ip: Option<String>,
}

impl ProxyTestFixture {
    /// Create a new test fixture builder
    pub fn new() -> Self {
        Self {
            proxies: Vec::new(),
            certs: Vec::new(),
            local_server: None,
            ports: super::port_helper::PortHelper::new(),
        }
    }

    /// Add a shoes VLESS+Vision server (TLS with vision flag on tls_targets)
    pub fn with_shoes_vision_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesTlsVisionServer,
            port,
            role,
        });
        self
    }

    /// Add a shoes VLESS+Vision client (connects to next proxy in chain automatically)
    pub fn with_shoes_vision_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesTlsVisionClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes VLESS server (no TLS, no Vision)
    pub fn with_shoes_vless_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVlessServer,
            port,
            role,
        });
        self
    }

    /// Add a shoes VLESS client (no TLS, no Vision)
    pub fn with_shoes_vless_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVlessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS server (no TLS, no Vision)
    pub fn with_singbox_vless_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVlessServer,
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS client (no TLS, no Vision)
    pub fn with_singbox_vless_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVlessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes VLESS+TLS server (TLS with sni_targets, no Vision)
    pub fn with_shoes_vless_tls_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVlessTlsServer,
            port,
            role,
        });
        self
    }

    /// Add a shoes VLESS+TLS client (TLS with sni_hostname, no Vision)
    pub fn with_shoes_vless_tls_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVlessTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS+TLS server (TLS without Vision)
    pub fn with_singbox_vless_tls_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVlessTlsServer,
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS+TLS client (TLS without Vision)
    pub fn with_singbox_vless_tls_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVlessTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS+TLS client with h2mux multiplexing enabled
    pub fn with_singbox_h2mux_vless_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxH2muxVlessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes VLESS+TLS client with h2mux multiplexing enabled
    pub fn with_shoes_h2mux_vless_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesH2muxVlessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes VMess server (no TLS)
    pub fn with_shoes_vmess_server(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVmessServer { cipher },
            port,
            role,
        });
        self
    }

    /// Add a shoes VMess+TLS server
    pub fn with_shoes_vmess_tls_server(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVmessTlsServer { cipher },
            port,
            role,
        });
        self
    }

    /// Add a shoes VMess client (no TLS)
    pub fn with_shoes_vmess_client(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVmessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes VMess+TLS client
    pub fn with_shoes_vmess_tls_client(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesVmessTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes SOCKS server
    pub fn with_shoes_socks_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesSocksServer,
            port,
            role,
        });
        self
    }

    /// Add a shoes SOCKS client
    pub fn with_shoes_socks_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesSocksClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a TUN entry point (uses TUN device + netstack-smoltcp).
    ///
    /// This creates a TUN network interface that captures all IP traffic.
    /// Traffic is processed by netstack-smoltcp and either forwarded directly
    /// to the destination or through subsequent proxies in the chain.
    ///
    /// **Requires root privileges** on Linux to create TUN devices.
    ///
    /// The TUN entry uses a unique subnet (10.200.X.0/24) where X is based on
    /// a counter to avoid conflicts with concurrent tests.
    pub fn with_tun_entry(mut self) -> Self {
        // Generate a unique subnet for this TUN device
        static TUN_COUNTER: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        let subnet_id = TUN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let tun_name = format!("shoes_tun{}", subnet_id);
        let tun_ip = format!("10.200.{}.1", subnet_id);
        let virtual_server_ip = format!("10.200.{}.2", subnet_id);

        // TUN entry is always the first entry point
        assert!(
            self.proxies.is_empty()
                || !matches!(self.proxies[0].proxy_type, ProxyType::TunEntry { .. }),
            "Only one TUN entry is allowed per fixture"
        );

        // Port is not used for TUN (it's a network interface, not a TCP listener)
        // but we still track it for consistency with the proxy chain
        self.proxies.insert(
            0,
            ProxyConfig {
                ip: tun_ip.clone(),
                proxy_type: ProxyType::TunEntry {
                    tun_name,
                    tun_ip,
                    virtual_server_ip,
                },
                port: 0, // Not applicable for TUN
                role: ProxyRole::Entry,
            },
        );

        self
    }

    /// Add a shoes HTTP proxy
    pub fn with_shoes_http_proxy(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesHttpProxy,
            port,
            role,
        });
        self
    }

    /// Add a shoes Shadowsocks server
    pub fn with_shoes_shadowsocks_server(
        mut self,
        cipher: ShadowsocksCipher,
        password: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesShadowsocksServer {
                cipher,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes Shadowsocks client
    pub fn with_shoes_shadowsocks_client(
        mut self,
        cipher: ShadowsocksCipher,
        password: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesShadowsocksClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Shadowsocks server
    pub fn with_singbox_shadowsocks_server(
        mut self,
        cipher: ShadowsocksCipher,
        password: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxShadowsocksServer {
                cipher,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Shadowsocks client
    pub fn with_singbox_shadowsocks_client(
        mut self,
        cipher: ShadowsocksCipher,
        password: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxShadowsocksClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Shadowsocks client with UDP-over-TCP enabled
    pub fn with_singbox_shadowsocks_uot_client(
        mut self,
        cipher: ShadowsocksCipher,
        password: &str,
        uot_version: u8,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxShadowsocksUotClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
                password: password.to_string(),
                uot_version,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes Snell server
    pub fn with_shoes_snell_server(mut self, cipher: ShadowsocksCipher, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesSnellServer {
                cipher,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes Snell client
    pub fn with_shoes_snell_client(mut self, cipher: ShadowsocksCipher, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesSnellClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes AnyTLS server
    pub fn with_shoes_anytls_server(self) -> Self {
        self.with_shoes_anytls_server_with_params("testpassword123", "test.anytls.local")
    }

    /// Add a shoes AnyTLS server with custom password and SNI
    pub fn with_shoes_anytls_server_with_params(mut self, password: &str, sni: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesAnyTlsServer {
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box AnyTLS client (connects to next proxy in chain automatically)
    pub fn with_singbox_anytls_client(self) -> Self {
        self.with_singbox_anytls_client_with_params("testpassword123", "test.anytls.local")
    }

    /// Add a sing-box AnyTLS client with custom password and SNI
    pub fn with_singbox_anytls_client_with_params(mut self, password: &str, sni: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxAnyTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes AnyTLS client (connects to next proxy in chain automatically)
    pub fn with_shoes_anytls_client(self) -> Self {
        self.with_shoes_anytls_client_with_params("testpassword123", "test.anytls.local")
    }

    /// Add a shoes AnyTLS client with custom password and SNI
    pub fn with_shoes_anytls_client_with_params(mut self, password: &str, sni: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesAnyTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box AnyTLS server with default password/sni (matches with_shoes_anytls_client)
    pub fn with_singbox_anytls_server(self) -> Self {
        self.with_singbox_anytls_server_with_params("testpassword123", "test.anytls.local")
    }

    /// Add a sing-box AnyTLS server with custom password/sni
    pub fn with_singbox_anytls_server_with_params(mut self, password: &str, sni: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxAnyTlsServer {
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    // ========================================================================
    // NaiveProxy methods
    // ========================================================================

    /// Add a shoes NaiveProxy server with default credentials
    pub fn with_shoes_naiveproxy_server(self) -> Self {
        self.with_shoes_naiveproxy_server_with_params(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
        )
    }

    /// Add a shoes NaiveProxy server with custom credentials
    pub fn with_shoes_naiveproxy_server_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesNaiveProxyServer {
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
                use_system_ca: false,
                fallback: None,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes NaiveProxy server with fallback for probe resistance
    ///
    /// The fallback must be an absolute path like "/var/www/html" for static file serving.
    /// URL-based fallback (HTTP reverse proxy) is not supported.
    pub fn with_shoes_naiveproxy_server_with_fallback(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
        fallback: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesNaiveProxyServer {
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
                use_system_ca: false,
                fallback: Some(fallback.to_string()),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes NaiveProxy server with system CA (for native naive client tests)
    ///
    /// This uses a CA certificate installed to the system trust store, which is
    /// required for the native naive client that doesn't support insecure mode.
    /// Must be run with sudo for the CA installation.
    pub fn with_shoes_naiveproxy_server_system_ca(self) -> Self {
        self.with_shoes_naiveproxy_server_system_ca_with_params(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
        )
    }

    /// Add a shoes NaiveProxy server with system CA and custom credentials
    pub fn with_shoes_naiveproxy_server_system_ca_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesNaiveProxyServer {
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
                use_system_ca: true,
                fallback: None,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes NaiveProxy client with default credentials
    pub fn with_shoes_naiveproxy_client(self) -> Self {
        self.with_shoes_naiveproxy_client_with_params(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
        )
    }

    /// Add a shoes NaiveProxy client with custom credentials
    pub fn with_shoes_naiveproxy_client_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesNaiveProxyClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Naive server with default credentials
    pub fn with_singbox_naive_server(self) -> Self {
        self.with_singbox_naive_server_with_params("naiveuser", "naivepass123", "test.naive.local")
    }

    /// Add a sing-box Naive server with custom credentials
    pub fn with_singbox_naive_server_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxNaiveServer {
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Naive client with default credentials
    pub fn with_singbox_naive_client(self) -> Self {
        self.with_singbox_naive_client_with_params("naiveuser", "naivepass123", "test.naive.local")
    }

    /// Add a sing-box Naive client with custom credentials
    pub fn with_singbox_naive_client_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxNaiveClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a native NaiveProxy caddy server (forwardproxy) with default credentials
    pub fn with_naive_caddy_server(self) -> Self {
        self.with_naive_caddy_server_with_params("naiveuser", "naivepass123", "test.naive.local")
    }

    /// Add a native NaiveProxy caddy server (forwardproxy) with custom credentials
    pub fn with_naive_caddy_server_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::NaiveProxyCaddyServer {
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a native NaiveProxy client with default credentials
    pub fn with_naive_client(self) -> Self {
        self.with_naive_client_with_params("naiveuser", "naivepass123", "test.naive.local")
    }

    /// Add a native NaiveProxy client with custom credentials
    pub fn with_naive_client_with_params(
        mut self,
        username: &str,
        password: &str,
        sni: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::NaiveProxyClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                username: username.to_string(),
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box HTTP proxy (routes to next proxy in chain automatically)
    pub fn with_singbox_http_proxy(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxHttpProxy {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS+Vision client (connects to next proxy in chain automatically)
    pub fn with_singbox_vision_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVisionClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VLESS+Vision server
    pub fn with_singbox_vision_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVisionServer,
            port,
            role,
        });
        self
    }

    /// Add a sing-box VMess server (no TLS)
    pub fn with_singbox_vmess_server(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVmessServer { cipher },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VMess+TLS server
    pub fn with_singbox_vmess_tls_server(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVmessTlsServer { cipher },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VMess client (no TLS)
    pub fn with_singbox_vmess_client(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVmessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box VMess+TLS client
    pub fn with_singbox_vmess_tls_client(mut self, cipher: VmessCipher) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxVmessTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                cipher,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box SOCKS server
    pub fn with_singbox_socks_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxSocksServer,
            port,
            role,
        });
        self
    }

    /// Add a sing-box SOCKS client
    pub fn with_singbox_socks_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxSocksClient {
                upstream_ip: String::new(),
                upstream_port: 0,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes REALITY+VLESS server
    pub fn with_shoes_reality_vless_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.cloudflare.com".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.cloudflare.com:443".to_string(),
            inner_protocol: RealityInnerProtocol::Vless,
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesRealityServer { config },
            port,
            role,
        });
        self
    }

    /// Add a shoes REALITY+VLESS server using a SEPARATE mode dest server
    ///
    /// Uses www.debian.org:443 which sends 4 encrypted records (first one <= 512 bytes)
    /// rather than 1 combined record. This tests the 512-byte heuristic for mode detection.
    pub fn with_shoes_reality_vless_server_separate_mode(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.debian.org".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.debian.org:443".to_string(),
            inner_protocol: RealityInnerProtocol::Vless,
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesRealityServer { config },
            port,
            role,
        });
        self
    }

    /// Add a shoes REALITY+Trojan server
    pub fn with_shoes_reality_trojan_server(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.google.com".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.google.com:443".to_string(),
            inner_protocol: RealityInnerProtocol::Trojan {
                password: password.to_string(),
            },
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesRealityServer { config },
            port,
            role,
        });
        self
    }

    /// Add a sing-box REALITY+VLESS client (connects to next proxy in chain automatically)
    pub fn with_singbox_reality_vless_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        // Placeholder config - will be populated during wire_proxy_chain
        let config = RealityConfig {
            private_key: String::new(),
            public_key: String::new(),
            server_name: String::new(),
            short_id: String::new(),
            dest: String::new(),
            inner_protocol: RealityInnerProtocol::Vless,
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxRealityVlessClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                config,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box REALITY+Trojan client (connects to next proxy in chain automatically)
    pub fn with_singbox_reality_trojan_client(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        // Placeholder config - will be populated during wire_proxy_chain
        let config = RealityConfig {
            private_key: String::new(),
            public_key: password.to_string(), // Store password temporarily in public_key field
            server_name: String::new(),
            short_id: String::new(),
            dest: String::new(),
            inner_protocol: RealityInnerProtocol::Trojan {
                password: password.to_string(),
            },
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxRealityTrojanClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                config,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box REALITY+VLESS server
    pub fn with_singbox_reality_vless_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.cloudflare.com".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.cloudflare.com:443".to_string(),
            inner_protocol: RealityInnerProtocol::Vless,
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxRealityVlessServer { config },
            port,
            role,
        });
        self
    }

    /// Add a sing-box REALITY+Trojan server
    pub fn with_singbox_reality_trojan_server(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.google.com".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.google.com:443".to_string(),
            inner_protocol: RealityInnerProtocol::Trojan {
                password: password.to_string(),
            },
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxRealityTrojanServer { config },
            port,
            role,
        });
        self
    }

    /// Add a shoes REALITY client (connects to next proxy in chain automatically)
    pub fn with_shoes_reality_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        // Placeholder config - will be populated during wire_proxy_chain
        let config = RealityConfig {
            private_key: String::new(),
            public_key: String::new(),
            server_name: String::new(),
            short_id: String::new(),
            dest: String::new(),
            inner_protocol: RealityInnerProtocol::Vless,
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesRealityClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                config,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes REALITY+Vision server
    pub fn with_shoes_reality_vision_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.cloudflare.com".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.cloudflare.com:443".to_string(),
            inner_protocol: RealityInnerProtocol::VlessVision,
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesRealityVisionServer { config },
            port,
            role,
        });
        self
    }

    /// Add a shoes REALITY+Vision client (connects to next proxy in chain automatically)
    pub fn with_shoes_reality_vision_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        // Placeholder config - will be populated during wire_proxy_chain
        let config = RealityConfig {
            private_key: String::new(),
            public_key: String::new(),
            server_name: String::new(),
            short_id: String::new(),
            dest: String::new(),
            inner_protocol: RealityInnerProtocol::VlessVision,
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesRealityVisionClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                config,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box REALITY+Vision server
    pub fn with_singbox_reality_vision_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let (private_key, public_key) = generate_reality_keypair();

        let config = RealityConfig {
            private_key,
            public_key,
            server_name: "www.cloudflare.com".to_string(),
            short_id: "0123456789abcdef".to_string(),
            dest: "www.cloudflare.com:443".to_string(),
            inner_protocol: RealityInnerProtocol::VlessVision,
        };

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxRealityVisionServer { config },
            port,
            role,
        });
        self
    }

    /// Add a sing-box REALITY+Vision client (connects to next proxy in chain automatically)
    pub fn with_singbox_reality_vision_client(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();

        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };

        // Placeholder config - will be populated during wire_proxy_chain
        let config = RealityConfig {
            private_key: String::new(),
            public_key: String::new(),
            server_name: String::new(),
            short_id: String::new(),
            dest: String::new(),
            inner_protocol: RealityInnerProtocol::VlessVision,
        };

        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxRealityVisionClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                config,
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes ShadowTLS server with local TLS handshake
    pub fn with_shoes_shadowtls_local_server(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesShadowTlsLocalServer {
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes ShadowTLS server with remote TLS handshake
    pub fn with_shoes_shadowtls_remote_server(
        mut self,
        password: &str,
        handshake_server: &str,
    ) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesShadowTlsRemoteServer {
                password: password.to_string(),
                handshake_server: handshake_server.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a shoes ShadowTLS client
    pub fn with_shoes_shadowtls_client(mut self, password: &str, sni: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesShadowTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                password: password.to_string(),
                sni: sni.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box ShadowTLS server (with VLESS inner protocol)
    pub fn with_singbox_shadowtls_server(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        // Use get_port() for inner port since it's sing-box internal (listens on 127.0.0.1)
        // and we don't need to wait for it - sing-box handles the internal routing
        let (_, inner_port) = self.ports.get_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxShadowTlsServer {
                password: password.to_string(),
                inner_port,
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box ShadowTLS client
    pub fn with_singbox_shadowtls_client(mut self, password: &str, server_name: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxShadowTlsClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                password: password.to_string(),
                server_name: server_name.to_string(),
            },
            port,
            role,
        });
        self
    }

    // ==================== Hysteria2 (QUIC-based) ====================

    /// Add a shoes Hysteria2 server with default password
    pub fn with_shoes_hysteria2_server(self) -> Self {
        self.with_shoes_hysteria2_server_with_password("test_hysteria2_password")
    }

    /// Add a shoes Hysteria2 server with custom password
    pub fn with_shoes_hysteria2_server_with_password(mut self, password: &str) -> Self {
        // Use get_quic_listener_port() for QUIC-based servers (UDP, not TCP)
        let (ip, port) = self.ports.get_quic_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesHysteria2Server {
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Hysteria2 client with default password
    pub fn with_singbox_hysteria2_client(self) -> Self {
        self.with_singbox_hysteria2_client_with_password("test_hysteria2_password")
    }

    /// Add a sing-box Hysteria2 client with custom password
    pub fn with_singbox_hysteria2_client_with_password(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxHysteria2Client {
                upstream_ip: String::new(),
                upstream_port: 0,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box Hysteria2 server with default password
    pub fn with_singbox_hysteria2_server(self) -> Self {
        self.with_singbox_hysteria2_server_with_password("test_hysteria2_password")
    }

    /// Add a sing-box Hysteria2 server with custom password
    pub fn with_singbox_hysteria2_server_with_password(mut self, password: &str) -> Self {
        // Use get_quic_listener_port() for QUIC-based servers (UDP, not TCP)
        let (ip, port) = self.ports.get_quic_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxHysteria2Server {
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    // ==================== TUIC v5 (QUIC-based) ====================

    /// Add a shoes TUIC v5 server with default password
    pub fn with_shoes_tuic_server(self) -> Self {
        self.with_shoes_tuic_server_with_password("test_tuic_password")
    }

    /// Add a shoes TUIC v5 server with custom password
    pub fn with_shoes_tuic_server_with_password(mut self, password: &str) -> Self {
        // Use get_quic_listener_port() for QUIC-based servers (UDP, not TCP)
        let (ip, port) = self.ports.get_quic_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::ShoesTuicServer {
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box TUIC v5 client with default password
    pub fn with_singbox_tuic_client(self) -> Self {
        self.with_singbox_tuic_client_with_password("test_tuic_password")
    }

    /// Add a sing-box TUIC v5 client with custom password
    pub fn with_singbox_tuic_client_with_password(mut self, password: &str) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxTuicClient {
                upstream_ip: String::new(),
                upstream_port: 0,
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    /// Add a sing-box TUIC v5 server with default password
    pub fn with_singbox_tuic_server(self) -> Self {
        self.with_singbox_tuic_server_with_password("test_tuic_password")
    }

    /// Add a sing-box TUIC v5 server with custom password
    pub fn with_singbox_tuic_server_with_password(mut self, password: &str) -> Self {
        // Use get_quic_listener_port() for QUIC-based servers (UDP, not TCP)
        let (ip, port) = self.ports.get_quic_listener_port();
        let role = if self.proxies.is_empty() {
            ProxyRole::Entry
        } else {
            ProxyRole::Intermediate
        };
        self.proxies.push(ProxyConfig {
            ip,
            proxy_type: ProxyType::SingboxTuicServer {
                password: password.to_string(),
            },
            port,
            role,
        });
        self
    }

    // ==================== Local Test Servers ====================

    /// Add a local HTTP test server as final destination
    pub fn with_local_http_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        self.local_server = Some(LocalServerConfig {
            ip,
            port,
            protocol: LocalServerProtocol::Http,
        });
        self
    }

    pub fn with_local_http_server_on_localhost(mut self) -> Self {
        let (ip, port) = self.ports.get_localhost_listener_port();
        self.local_server = Some(LocalServerConfig {
            ip,
            port,
            protocol: LocalServerProtocol::Http,
        });
        self
    }

    pub fn with_local_http_server_ipv6(mut self) -> Self {
        let (ip, port) = self.ports.get_ipv6_listener_port();
        self.local_server = Some(LocalServerConfig {
            ip,
            port,
            protocol: LocalServerProtocol::Http,
        });
        self
    }

    /// Add a local HTTPS/TLS1.3 test server as final destination
    pub fn with_local_https_tls13_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        self.local_server = Some(LocalServerConfig {
            ip,
            port,
            protocol: LocalServerProtocol::HttpsTls13,
        });
        self
    }

    /// Add a local HTTPS/TLS1.2 test server as final destination
    pub fn with_local_https_tls12_server(mut self) -> Self {
        let (ip, port) = self.ports.get_listener_port();
        self.local_server = Some(LocalServerConfig {
            ip,
            port,
            protocol: LocalServerProtocol::HttpsTls12,
        });
        self
    }

    pub async fn test_local_http(
        self,
        response_size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = self.with_local_http_server().build().await?;
        let body = fixture
            .test_local_server(&format!("/bytes/{response_size}"), false)
            .await?;
        if body != vec![b'X'; response_size] {
            return Err(format!(
                "local HTTP response did not match {response_size} expected bytes"
            )
            .into());
        }
        Ok(())
    }

    pub async fn test_local_http_hostname(
        self,
        response_size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = self.with_local_http_server_on_localhost().build().await?;
        let url = format!(
            "http://localhost:{}/bytes/{response_size}",
            fixture.local_server_port().unwrap()
        );
        let output = fixture
            .test_http_with_options(
                &url,
                super::curl::CurlOptions::new()
                    .timeout(30)
                    .fail_on_http_error(true),
            )
            .await?;
        if !output.status.success() {
            return Err(format!(
                "curl failed with exit code {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        if output.stdout != vec![b'X'; response_size] {
            return Err(format!(
                "local HTTP response did not match {response_size} expected bytes"
            )
            .into());
        }
        Ok(())
    }

    pub async fn test_local_https_tls13(
        self,
        response_size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = self.with_local_https_tls13_server().build().await?;
        let body = fixture
            .test_local_server(&format!("/bytes/{response_size}"), true)
            .await?;
        if body != vec![b'X'; response_size] {
            return Err(format!(
                "local HTTPS response did not match {response_size} expected bytes"
            )
            .into());
        }
        Ok(())
    }

    /// Wire up the proxy chain by setting upstream ports for client proxies
    fn wire_proxy_chain(&mut self) {
        for i in 0..self.proxies.len() {
            let needs_upstream = match &self.proxies[i].proxy_type {
                ProxyType::ShoesTlsVisionClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesVlessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesVlessTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesRealityClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesRealityVisionClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesVmessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesVmessTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesSocksClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxVisionClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxVlessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxVlessTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxH2muxVlessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesH2muxVlessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxRealityVlessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxRealityVisionClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxRealityTrojanClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxVmessClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxVmessTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxSocksClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxHttpProxy { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesShadowTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxShadowTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesShadowsocksClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxShadowsocksClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxShadowsocksUotClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxAnyTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesAnyTlsClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesSnellClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::ShoesNaiveProxyClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxNaiveClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::NaiveProxyClient { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxHysteria2Client { upstream_port, .. } => *upstream_port == 0,
                ProxyType::SingboxTuicClient { upstream_port, .. } => *upstream_port == 0,
                _ => false,
            };

            if needs_upstream && i + 1 < self.proxies.len() {
                let next_ip = self.proxies[i + 1].ip.clone();
                let next_port = self.proxies[i + 1].port;

                // For REALITY clients, we also need to copy the server's REALITY config
                if let ProxyType::SingboxRealityVlessClient { .. }
                | ProxyType::SingboxRealityVisionClient { .. }
                | ProxyType::SingboxRealityTrojanClient { .. }
                | ProxyType::ShoesRealityClient { .. }
                | ProxyType::ShoesRealityVisionClient { .. } = &self.proxies[i].proxy_type
                {
                    // Check if next proxy is a REALITY server (either shoes or sing-box)
                    let server_config = match &self.proxies[i + 1].proxy_type {
                        ProxyType::ShoesRealityServer { config } => Some(config.clone()),
                        ProxyType::ShoesRealityVisionServer { config } => Some(config.clone()),
                        ProxyType::SingboxRealityVlessServer { config } => Some(config.clone()),
                        ProxyType::SingboxRealityVisionServer { config } => Some(config.clone()),
                        ProxyType::SingboxRealityTrojanServer { config } => Some(config.clone()),
                        _ => None,
                    };

                    if let Some(server_config) = server_config {
                        match &mut self.proxies[i].proxy_type {
                            ProxyType::SingboxRealityVlessClient {
                                upstream_ip,
                                upstream_port,
                                config,
                            } => {
                                *upstream_ip = next_ip.clone();
                                *upstream_port = next_port;
                                *config = server_config;
                            }
                            ProxyType::SingboxRealityVisionClient {
                                upstream_ip,
                                upstream_port,
                                config,
                            } => {
                                *upstream_ip = next_ip.clone();
                                *upstream_port = next_port;
                                *config = server_config;
                            }
                            ProxyType::SingboxRealityTrojanClient {
                                upstream_ip,
                                upstream_port,
                                config,
                            } => {
                                *upstream_ip = next_ip.clone();
                                *upstream_port = next_port;
                                *config = server_config;
                            }
                            ProxyType::ShoesRealityClient {
                                upstream_ip,
                                upstream_port,
                                config,
                            } => {
                                *upstream_ip = next_ip.clone();
                                *upstream_port = next_port;
                                *config = server_config;
                            }
                            ProxyType::ShoesRealityVisionClient {
                                upstream_ip,
                                upstream_port,
                                config,
                            } => {
                                *upstream_ip = next_ip.clone();
                                *upstream_port = next_port;
                                *config = server_config;
                            }
                            _ => {}
                        }
                    }
                } else {
                    match &mut self.proxies[i].proxy_type {
                        ProxyType::ShoesTlsVisionClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesVlessClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesVlessTlsClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesVmessClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesVmessTlsClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesSocksClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxVisionClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxVlessClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxVlessTlsClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxH2muxVlessClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesH2muxVlessClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxVmessClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxVmessTlsClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxSocksClient {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxHttpProxy {
                            upstream_ip,
                            upstream_port,
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesShadowTlsClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxShadowTlsClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesShadowsocksClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxShadowsocksClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxShadowsocksUotClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxAnyTlsClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesAnyTlsClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesSnellClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::ShoesNaiveProxyClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxNaiveClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::NaiveProxyClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxHysteria2Client {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        ProxyType::SingboxTuicClient {
                            upstream_ip,
                            upstream_port,
                            ..
                        } => {
                            *upstream_ip = next_ip.clone();
                            *upstream_port = next_port
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Build the fixture and start all servers
    pub async fn build(mut self) -> Result<BuiltFixture, Box<dyn std::error::Error>> {
        // Wire up proxy chain
        self.wire_proxy_chain();

        let mut guards = Vec::new();
        let mut local_servers = Vec::new();
        let mut config_files = Vec::new();
        let tun_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut tun_route = None;
        let mut tun_interface: Option<String> = None;
        let mut tun_virtual_server_ip: Option<String> = None;

        // Start local server if configured
        if let Some(ref local_config) = self.local_server {
            match local_config.protocol {
                LocalServerProtocol::Http => {
                    local_servers.push(
                        test_servers::start_local_http_server(&local_config.ip, local_config.port)
                            .await?,
                    );
                }
                LocalServerProtocol::HttpsTls12 => {
                    let (cert, key) = generate_test_cert()?;
                    local_servers.push(
                        test_servers::start_local_https_server(
                            &local_config.ip,
                            local_config.port,
                            AsRef::<Path>::as_ref(&cert),
                            AsRef::<Path>::as_ref(&key),
                            TlsVersion::Tls12Only,
                        )
                        .await?,
                    );
                    self.certs.push((cert, key));
                }
                LocalServerProtocol::HttpsTls13 => {
                    let (cert, key) = generate_test_cert()?;
                    local_servers.push(
                        test_servers::start_local_https_server(
                            &local_config.ip,
                            local_config.port,
                            AsRef::<Path>::as_ref(&cert),
                            AsRef::<Path>::as_ref(&key),
                            TlsVersion::Tls13Only,
                        )
                        .await?,
                    );
                    self.certs.push((cert, key));
                }
            }
        }

        // Set up TUN entry if configured (must be done before starting proxies)
        // We start shoes with a TUN server config that handles the TUN device
        if let Some(tun_proxy) = self.proxies.first()
            && let ProxyType::TunEntry {
                tun_name,
                tun_ip,
                virtual_server_ip: vip,
            } = &tun_proxy.proxy_type
        {
            eprintln!(
                "[TUN] Setting up TUN via shoes: device={} ip={} vip={}",
                tun_name, tun_ip, vip
            );

            // Get local server info for forwarding
            let local_server_ip = self
                .local_server
                .as_ref()
                .map(|s| s.ip.clone())
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let local_server_port = self.local_server.as_ref().map(|s| s.port).unwrap_or(80);

            // Generate TUN server config for shoes
            // The TUN server will forward all traffic to the local HTTP server
            let tun_config = format!(
                r#"
# TUN server that forwards to local HTTP server
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
"#,
                tun_name, tun_ip, local_server_ip, local_server_port,
            );

            eprintln!("[TUN] Starting shoes with TUN config:\n{}", tun_config);

            // Start shoes with sudo for TUN device creation
            let (tun_guard, tun_config_file) = start_shoes_server_with_sudo(&tun_config)?;
            guards.push(tun_guard);
            config_files.push(tun_config_file);

            // Wait for TUN device to be created
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            // Add route for the virtual server IP through the TUN device
            let destination = format!("{vip}/32");
            tun_route = Some(add_route_via_device(&destination, tun_name)?);
            eprintln!("[TUN] Added route for {} via {}", vip, tun_name);

            tun_interface = Some(tun_name.clone());
            tun_virtual_server_ip = Some(vip.clone());

            // Give shoes TUN server time to fully initialize
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }

        // Generate shoes configs - each shoes proxy gets its own process
        let shoes_configs = self.generate_shoes_configs()?;
        let has_quic_servers = self.proxies.iter().any(|p| {
            matches!(
                p.proxy_type,
                ProxyType::ShoesHysteria2Server { .. } | ProxyType::ShoesTuicServer { .. }
            )
        });
        for config in shoes_configs {
            let (guard, config_file) = start_shoes_server(&config)?;
            guards.push(guard);
            config_files.push(config_file);
        }

        // Wait for QUIC servers to start (no TCP readiness check for UDP)
        if has_quic_servers {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Generate and start sing-box configs (each needs separate process)
        let proxies_clone = self.proxies.clone();
        for proxy in &proxies_clone {
            if let Some(config) = self.generate_singbox_config(proxy)? {
                let (guard, config_file) = start_singbox_server(&config)?;
                guards.push(guard);
                config_files.push(config_file);
            }
        }

        // Generate and start native naive client/caddy configs
        for proxy in &proxies_clone {
            if let Some(config) = self.generate_naive_config(proxy)? {
                match &proxy.proxy_type {
                    ProxyType::NaiveProxyClient { .. } => {
                        let (guard, config_file) = start_naive_client(&config)?;
                        guards.push(guard);
                        config_files.push(config_file);
                    }
                    ProxyType::NaiveProxyCaddyServer { .. } => {
                        let (guard, config_file) = start_naive_caddy_server(&config)?;
                        guards.push(guard);
                        config_files.push(config_file);
                    }
                    _ => {}
                }
            }
        }

        // Wait for all listener ports to be ready
        self.ports.wait_for_all_ports().await?;

        // Find entry IP and port (first proxy in chain)
        let first_proxy = self.proxies.first().ok_or("No proxies configured")?;
        let entry_ip = first_proxy.ip.clone();
        let entry_port = first_proxy.port;

        let local_server_ip = self.local_server.as_ref().map(|s| s.ip.clone());
        let local_server_port = self.local_server.as_ref().map(|s| s.port);
        let local_server_protocol = self.local_server.as_ref().map(|s| s.protocol);

        Ok(BuiltFixture {
            _tun_route: tun_route,
            _guards: guards,
            _local_servers: local_servers,
            _config_files: config_files,
            _certs: self.certs,
            _tun_handles: tun_handles,
            entry_ip,
            entry_port,
            local_server_ip,
            local_server_port,
            local_server_protocol,
            tun_interface,
            tun_virtual_server_ip,
        })
    }

    /// Generate shoes config for all shoes proxies
    fn generate_shoes_configs(&mut self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut configs = Vec::new();

        for proxy in &self.proxies {
            let config = match &proxy.proxy_type {
                ProxyType::ShoesTlsVisionServer => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
                        proxy.ip,
                        proxy.port,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        TEST_UUID
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesTlsVisionClient {
                    upstream_ip,
                    upstream_port,
                } => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: test.local
        verify: false
        vision: true
        protocol:
          type: vless
          user_id: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                        upstream_ip, upstream_port, TEST_UUID, proxy.ip, proxy.port
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesVlessServer => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: vless
    user_id: "{}""#,
                    proxy.ip, proxy.port, TEST_UUID
                )),
                ProxyType::ShoesVlessClient {
                    upstream_ip,
                    upstream_port,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: vless
        user_id: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip, upstream_port, TEST_UUID, proxy.ip, proxy.port
                )),
                ProxyType::ShoesVlessTlsServer => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    sni_targets:
      test.local:
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}""#,
                        proxy.ip,
                        proxy.port,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        TEST_UUID
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesVlessTlsClient {
                    upstream_ip,
                    upstream_port,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: "test.local"
        verify: false
        protocol:
          type: vless
          user_id: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip, upstream_port, TEST_UUID, proxy.ip, proxy.port
                )),
                ProxyType::ShoesH2muxVlessClient {
                    upstream_ip,
                    upstream_port,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: "test.local"
        verify: false
        protocol:
          type: vless
          user_id: "{}"
          h2mux:
            max_connections: 4
            min_streams: 1

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip, upstream_port, TEST_UUID, proxy.ip, proxy.port
                )),
                ProxyType::ShoesVmessServer { cipher } => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: vmess
    user_id: "{}"
    cipher: {}"#,
                    proxy.ip,
                    proxy.port,
                    TEST_UUID,
                    cipher.as_str()
                )),
                ProxyType::ShoesVmessTlsServer { cipher } => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    sni_targets:
      test.local:
        cert: {}
        key: {}
        protocol:
          type: vmess
          user_id: "{}"
          cipher: {}"#,
                        proxy.ip,
                        proxy.port,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        TEST_UUID,
                        cipher.as_str()
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesVmessClient {
                    upstream_ip,
                    upstream_port,
                    cipher,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: vmess
        user_id: "{}"
        cipher: {}

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip,
                    upstream_port,
                    TEST_UUID,
                    cipher.as_str(),
                    proxy.ip,
                    proxy.port
                )),
                ProxyType::ShoesVmessTlsClient {
                    upstream_ip,
                    upstream_port,
                    cipher,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: "test.local"
        verify: false
        protocol:
          type: vmess
          user_id: "{}"
          cipher: {}

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip,
                    upstream_port,
                    TEST_UUID,
                    cipher.as_str(),
                    proxy.ip,
                    proxy.port
                )),
                ProxyType::ShoesSocksServer => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: socks"#,
                    proxy.ip, proxy.port
                )),
                ProxyType::ShoesSocksClient {
                    upstream_ip,
                    upstream_port,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: socks

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip, upstream_port, proxy.ip, proxy.port
                )),
                ProxyType::ShoesHttpProxy => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: http"#,
                    proxy.ip, proxy.port
                )),
                ProxyType::ShoesRealityServer { config } => {
                    let protocol_config = match &config.inner_protocol {
                        RealityInnerProtocol::Vless => format!(
                            r#"protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
                            TEST_UUID
                        ),
                        RealityInnerProtocol::VlessVision => format!(
                            r#"protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
                            TEST_UUID
                        ),
                        RealityInnerProtocol::Trojan { password } => format!(
                            r#"protocol:
          type: trojan
          password: "{}""#,
                            password
                        ),
                    };

                    Some(format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        {}"#,
                        proxy.ip,
                        proxy.port,
                        config.server_name, // Use server_name (SNI) as the key
                        config.private_key,
                        config.short_id,
                        config.dest,
                        protocol_config
                    ))
                }
                ProxyType::ShoesRealityClient {
                    upstream_ip,
                    upstream_port,
                    config,
                } => {
                    // REALITY client with standalone protocol type
                    let inner_protocol_config = match &config.inner_protocol {
                        RealityInnerProtocol::Vless => format!(
                            r#"type: vless
          user_id: "{}""#,
                            TEST_UUID
                        ),
                        RealityInnerProtocol::VlessVision => format!(
                            r#"type: vless
          user_id: "{}""#,
                            TEST_UUID
                        ),
                        RealityInnerProtocol::Trojan { password } => format!(
                            r#"type: trojan
          password: "{}""#,
                            password
                        ),
                    };

                    Some(format!(
                        r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: reality
        public_key: "{}"
        short_id: "{}"
        sni_hostname: "{}"
        protocol:
          {}

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                        upstream_ip,
                        upstream_port,
                        config.public_key,
                        config.short_id,
                        config.server_name,
                        inner_protocol_config,
                        proxy.ip,
                        proxy.port
                    ))
                }
                ProxyType::ShoesRealityVisionServer { config } => {
                    // REALITY Vision server - always uses VlessVision
                    Some(format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
                        proxy.ip,
                        proxy.port,
                        config.server_name,
                        config.private_key,
                        config.short_id,
                        config.dest,
                        TEST_UUID
                    ))
                }
                ProxyType::ShoesRealityVisionClient {
                    upstream_ip,
                    upstream_port,
                    config,
                } => {
                    // REALITY Vision client - always uses VlessVision
                    Some(format!(
                        r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: reality
        public_key: "{}"
        short_id: "{}"
        sni_hostname: "{}"
        vision: true
        protocol:
          type: vless
          user_id: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                        upstream_ip,
                        upstream_port,
                        config.public_key,
                        config.short_id,
                        config.server_name,
                        TEST_UUID,
                        proxy.ip,
                        proxy.port
                    ))
                }
                ProxyType::ShoesShadowTlsLocalServer { password } => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    shadowtls_targets:
      "test.local":
        password: "{}"
        handshake:
          cert: {}
          key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
                        proxy.ip,
                        proxy.port,
                        password,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        TEST_UUID
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesShadowTlsRemoteServer {
                    password,
                    handshake_server,
                } => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: tls
    shadowtls_targets:
      "{}":
        password: "{}"
        handshake:
          address: "{}:443"
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
                    proxy.ip, proxy.port, handshake_server, password, handshake_server, TEST_UUID
                )),
                ProxyType::ShoesShadowTlsClient {
                    upstream_ip,
                    upstream_port,
                    password,
                    sni,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: shadowtls
        password: "{}"
        sni_hostname: "{}"
        protocol:
          type: vless
          user_id: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip, upstream_port, password, sni, TEST_UUID, proxy.ip, proxy.port
                )),
                ProxyType::ShoesShadowsocksServer { cipher, password } => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: shadowsocks
    cipher: {}
    password: "{}""#,
                    proxy.ip,
                    proxy.port,
                    cipher.as_str(),
                    password
                )),
                ProxyType::ShoesShadowsocksClient {
                    upstream_ip,
                    upstream_port,
                    cipher,
                    password,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: shadowsocks
        cipher: {}
        password: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip,
                    upstream_port,
                    cipher.as_str(),
                    password,
                    proxy.ip,
                    proxy.port
                )),
                ProxyType::ShoesSnellServer { cipher, password } => Some(format!(
                    r#"- address: "{}:{}"
  protocol:
    type: snell
    cipher: {}
    password: "{}""#,
                    proxy.ip,
                    proxy.port,
                    cipher.as_str(),
                    password
                )),
                ProxyType::ShoesSnellClient {
                    upstream_ip,
                    upstream_port,
                    cipher,
                    password,
                } => Some(format!(
                    r#"- client_group: default
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: snell
        cipher: {}
        password: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: default"#,
                    upstream_ip,
                    upstream_port,
                    cipher.as_str(),
                    password,
                    proxy.ip,
                    proxy.port
                )),
                ProxyType::ShoesAnyTlsServer { password, sni } => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "{}":
        cert: {}
        key: {}
        protocol:
          type: anytls
          users:
            - name: "testuser"
              password: "{}""#,
                        proxy.ip,
                        proxy.port,
                        sni,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        password,
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesAnyTlsClient {
                    upstream_ip,
                    upstream_port,
                    password,
                    sni,
                } => Some(format!(
                    r#"- client_group: anytls-client
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: tls
        verify: false
        sni_hostname: "{}"
        protocol:
          type: anytls
          password: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: anytls-client"#,
                    upstream_ip, upstream_port, sni, password, proxy.ip, proxy.port
                )),
                ProxyType::ShoesNaiveProxyServer {
                    username,
                    password,
                    sni,
                    use_system_ca,
                    fallback,
                } => {
                    let (cert, key) = if *use_system_ca {
                        // Use CA-signed cert for native naive client compatibility
                        super::certs::generate_ca_signed_cert_files(sni)?
                    } else {
                        generate_test_cert()?
                    };
                    let fallback_line = match fallback {
                        Some(fb) => format!("\n          fallback: \"{}\"", fb),
                        None => String::new(),
                    };
                    let cfg = format!(
                        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "{}":
        cert: {}
        key: {}
        alpn_protocols:
          - h2
        protocol:
          type: naiveproxy
          users:
            - name: "testuser"
              username: "{}"
              password: "{}"{}"#,
                        proxy.ip,
                        proxy.port,
                        sni,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        username,
                        password,
                        fallback_line,
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }
                ProxyType::ShoesNaiveProxyClient {
                    upstream_ip,
                    upstream_port,
                    username,
                    password,
                    sni,
                } => Some(format!(
                    r#"- client_group: naiveproxy-client
  client_proxy:
    - address: "{}:{}"
      protocol:
        type: tls
        verify: false
        sni_hostname: "{}"
        alpn_protocols:
          - h2
        protocol:
          type: naiveproxy
          username: "{}"
          password: "{}"

- address: "{}:{}"
  protocol:
    type: http
  rule:
    mask: "0.0.0.0/0"
    action: allow
    client_proxy: naiveproxy-client"#,
                    upstream_ip, upstream_port, sni, username, password, proxy.ip, proxy.port
                )),

                // Hysteria2 server (QUIC-based)
                ProxyType::ShoesHysteria2Server { password } => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  transport: quic
  quic_settings:
    cert: {}
    key: {}
    num_endpoints: 1
    alpn_protocols:
      - h3
  protocol:
    type: hysteria2
    password: "{}"
    udp_enabled: true"#,
                        proxy.ip,
                        proxy.port,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        password
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }

                // TUIC v5 server (QUIC-based)
                // Note: Using h3 ALPN to match sing-box client
                ProxyType::ShoesTuicServer { password } => {
                    let (cert, key) = generate_test_cert()?;
                    let cfg = format!(
                        r#"- address: "{}:{}"
  transport: quic
  quic_settings:
    cert: {}
    key: {}
    num_endpoints: 1
    alpn_protocols:
      - h3
  protocol:
    type: tuic
    uuid: "{}"
    password: "{}""#,
                        proxy.ip,
                        proxy.port,
                        AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                        AsRef::<Path>::as_ref(&key).to_str().unwrap(),
                        TEST_UUID,
                        password
                    );
                    self.certs.push((cert, key));
                    Some(cfg)
                }

                _ => None,
            };

            if let Some(cfg) = config {
                configs.push(cfg);
            }
        }

        Ok(configs)
    }

    /// Generate sing-box config for a single sing-box proxy
    fn generate_singbox_config(
        &mut self,
        proxy: &ProxyConfig,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let config = match &proxy.proxy_type {
            ProxyType::SingboxHttpProxy { .. } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct-out"
    }}
  ],
  "route": {{
    "final": "direct-out"
  }}
}}"#,
                proxy.ip, proxy.port
            )),
            ProxyType::SingboxVisionClient {
                upstream_ip,
                upstream_port,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, TEST_UUID
            )),
            ProxyType::SingboxVisionServer => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}",
          "flow": "xtls-rprx-vision"
        }}
      ],
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "certificate_path": "{}",
        "key_path": "{}"
      }}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct-out"
    }}
  ],
  "route": {{
    "final": "direct-out"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    TEST_UUID,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }
            ProxyType::SingboxVlessServer => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip, proxy.port, TEST_UUID
            )),
            ProxyType::SingboxVlessClient {
                upstream_ip,
                upstream_port,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, TEST_UUID
            )),
            ProxyType::SingboxVlessTlsServer => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ],
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "certificate_path": "{}",
        "key_path": "{}"
      }}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    TEST_UUID,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }
            ProxyType::SingboxVlessTlsClient {
                upstream_ip,
                upstream_port,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, TEST_UUID
            )),
            ProxyType::SingboxH2muxVlessClient {
                upstream_ip,
                upstream_port,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "warn"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "multiplex": {{
        "enabled": true,
        "protocol": "h2mux",
        "max_connections": 1,
        "min_streams": 4,
        "max_streams": 0
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, TEST_UUID
            )),
            ProxyType::SingboxVmessServer { .. } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip, proxy.port, TEST_UUID
            )),
            ProxyType::SingboxVmessTlsServer { .. } => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ],
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "certificate_path": "{}",
        "key_path": "{}"
      }}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    TEST_UUID,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }
            ProxyType::SingboxVmessClient {
                upstream_ip,
                upstream_port,
                cipher,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vmess",
      "tag": "vmess-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "security": "{}"
    }}
  ],
  "route": {{
    "final": "vmess-out"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                upstream_ip,
                upstream_port,
                TEST_UUID,
                cipher.as_str()
            )),
            ProxyType::SingboxVmessTlsClient {
                upstream_ip,
                upstream_port,
                cipher,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vmess",
      "tag": "vmess-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "security": "{}",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vmess-out"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                upstream_ip,
                upstream_port,
                TEST_UUID,
                cipher.as_str()
            )),
            ProxyType::SingboxSocksServer => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "socks",
      "tag": "socks-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip, proxy.port
            )),
            ProxyType::SingboxSocksClient {
                upstream_ip,
                upstream_port,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "socks",
      "tag": "socks-out",
      "server": "{}",
      "server_port": {},
      "version": "5"
    }}
  ],
  "route": {{
    "final": "socks-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port
            )),
            ProxyType::SingboxRealityVlessClient {
                upstream_ip,
                upstream_port,
                config,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "reality-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "",
      "packet_encoding": "",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "insecure": true,
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }}
    }}
  ],
  "route": {{
    "final": "reality-out"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                upstream_ip,
                upstream_port,
                TEST_UUID,
                config.server_name,
                config.public_key,
                config.short_id
            )),
            ProxyType::SingboxRealityTrojanClient {
                upstream_ip,
                upstream_port,
                config,
            } => {
                let password = match &config.inner_protocol {
                    RealityInnerProtocol::Trojan { password } => password,
                    _ => "",
                };

                Some(format!(
                    r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "trojan",
      "tag": "reality-trojan-out",
      "server": "{}",
      "server_port": {},
      "password": "{}",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "insecure": true,
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }}
    }}
  ],
  "route": {{
    "final": "reality-trojan-out"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    upstream_ip,
                    upstream_port,
                    password,
                    config.server_name,
                    config.public_key,
                    config.short_id
                ))
            }
            ProxyType::SingboxRealityVlessServer { config } => Some(format!(
                r#"{{
  "log": {{
    "level": "trace"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ],
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "reality": {{
          "enabled": true,
          "handshake": {{
            "server": "{}",
            "server_port": 443
          }},
          "private_key": "{}",
          "short_id": [
            "{}"
          ]
        }}
      }}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                TEST_UUID,
                config.server_name,
                config.dest.split(':').next().unwrap_or(&config.dest),
                config.private_key,
                config.short_id
            )),
            ProxyType::SingboxRealityTrojanServer { config } => {
                let password = match &config.inner_protocol {
                    RealityInnerProtocol::Trojan { password } => password,
                    _ => "",
                };

                Some(format!(
                    r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "password": "{}"
        }}
      ],
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "reality": {{
          "enabled": true,
          "handshake": {{
            "server": "{}",
            "server_port": 443
          }},
          "private_key": "{}",
          "short_id": [
            "{}"
          ]
        }}
      }}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    password,
                    config.server_name,
                    config.dest.split(':').next().unwrap_or(&config.dest),
                    config.private_key,
                    config.short_id
                ))
            }
            ProxyType::SingboxRealityVisionClient {
                upstream_ip,
                upstream_port,
                config,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "reality-vision-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "insecure": true,
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }}
    }}
  ],
  "route": {{
    "final": "reality-vision-out"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                upstream_ip,
                upstream_port,
                TEST_UUID,
                config.server_name,
                config.public_key,
                config.short_id
            )),
            ProxyType::SingboxRealityVisionServer { config } => Some(format!(
                r#"{{
  "log": {{
    "level": "trace"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-vision-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}",
          "flow": "xtls-rprx-vision"
        }}
      ],
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "reality": {{
          "enabled": true,
          "handshake": {{
            "server": "{}",
            "server_port": 443
          }},
          "private_key": "{}",
          "short_id": [
            "{}"
          ]
        }}
      }}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                TEST_UUID,
                config.server_name,
                config.dest.split(':').next().unwrap_or(&config.dest),
                config.private_key,
                config.short_id
            )),
            ProxyType::SingboxShadowTlsServer {
                password,
                inner_port,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "shadowtls",
      "tag": "shadowtls-in",
      "listen": "{}",
      "listen_port": {},
      "version": 3,
      "users": [
        {{
          "password": "{}"
        }}
      ],
      "handshake": {{
        "server": "www.cloudflare.com",
        "server_port": 443
      }},
      "detour": "vless-in"
    }},
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip, proxy.port, password, inner_port, TEST_UUID
            )),
            ProxyType::SingboxShadowTlsClient {
                upstream_ip,
                upstream_port,
                password,
                server_name,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "127.0.0.1",
      "server_port": 0,
      "uuid": "{}",
      "multiplex": {{
        "enabled": false
      }},
      "detour": "shadowtls-out"
    }},
    {{
      "type": "shadowtls",
      "tag": "shadowtls-out",
      "server": "{}",
      "server_port": {},
      "version": 3,
      "password": "{}",
      "tls": {{
        "enabled": true,
        "server_name": "{}"
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
                proxy.ip, proxy.port, TEST_UUID, upstream_ip, upstream_port, password, server_name
            )),
            ProxyType::SingboxShadowsocksServer { cipher, password } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "{}",
      "listen_port": {},
      "method": "{}",
      "password": "{}"
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "final": "direct"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                cipher.singbox_method(),
                password
            )),
            ProxyType::SingboxShadowsocksClient {
                upstream_ip,
                upstream_port,
                cipher,
                password,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "shadowsocks",
      "tag": "ss-out",
      "server": "{}",
      "server_port": {},
      "method": "{}",
      "password": "{}"
    }}
  ],
  "route": {{
    "final": "ss-out"
  }}
}}"#,
                proxy.ip,
                proxy.port,
                upstream_ip,
                upstream_port,
                cipher.singbox_method(),
                password
            )),
            ProxyType::SingboxShadowsocksUotClient {
                upstream_ip,
                upstream_port,
                cipher,
                password,
                uot_version,
            } => Some(format!(
                r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun-ss-uot-{}",
      "inet4_address": "172.19.{}.1/30",
      "auto_route": false,
      "stack": "system"
    }}
  ],
  "outbounds": [
    {{
      "type": "shadowsocks",
      "tag": "ss-out",
      "server": "{}",
      "server_port": {},
      "method": "{}",
      "password": "{}",
      "udp_over_tcp": {{
        "enabled": true,
        "version": {}
      }}
    }}
  ],
  "route": {{
    "final": "ss-out"
  }}
}}"#,
                proxy.port,
                proxy.port % 256,
                upstream_ip,
                upstream_port,
                cipher.singbox_method(),
                password,
                uot_version
            )),

            // AnyTLS client (sing-box)
            ProxyType::SingboxAnyTlsClient {
                upstream_ip,
                upstream_port,
                password,
                sni,
            } => Some(format!(
                r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "http",
    "tag": "http-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "anytls",
    "tag": "anytls-out",
    "server": "{}",
    "server_port": {},
    "password": "{}",
    "tls": {{
      "enabled": true,
      "insecure": true,
      "server_name": "{}"
    }}
  }}]
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, password, sni
            )),

            // AnyTLS server (sing-box)
            ProxyType::SingboxAnyTlsServer { password, sni } => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "anytls",
    "tag": "anytls-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{"name": "test", "password": "{}"}}],
    "tls": {{
      "enabled": true,
      "server_name": "{}",
      "certificate_path": "{}",
      "key_path": "{}"
    }}
  }}],
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}]
}}"#,
                    proxy.ip,
                    proxy.port,
                    password,
                    sni,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }

            // NaiveProxy server (sing-box)
            ProxyType::SingboxNaiveServer {
                username,
                password,
                sni,
            } => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "naive",
    "tag": "naive-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{"username": "{}", "password": "{}"}}],
    "tls": {{
      "enabled": true,
      "server_name": "{}",
      "alpn": ["h2"],
      "certificate_path": "{}",
      "key_path": "{}"
    }}
  }}],
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}]
}}"#,
                    proxy.ip,
                    proxy.port,
                    username,
                    password,
                    sni,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }

            // NaiveProxy client (sing-box) - note: requires libcronet
            // cronet uses system CA trust store, no insecure option available
            ProxyType::SingboxNaiveClient {
                upstream_ip,
                upstream_port,
                username,
                password,
                sni,
            } => Some(format!(
                r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "http",
    "tag": "http-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "naive",
    "tag": "naive-out",
    "server": "{}",
    "server_port": {},
    "username": "{}",
    "password": "{}",
    "tls": {{
      "enabled": true,
      "server_name": "{}"
    }}
  }}]
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, username, password, sni
            )),

            // Hysteria2 client (sing-box connects to shoes Hysteria2 server)
            ProxyType::SingboxHysteria2Client {
                upstream_ip,
                upstream_port,
                password,
            } => Some(format!(
                r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "http",
    "tag": "http-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "hysteria2",
    "tag": "hy2-out",
    "server": "{}",
    "server_port": {},
    "password": "{}",
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "insecure": true,
      "alpn": ["h3"]
    }}
  }}],
  "route": {{
    "final": "hy2-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, password
            )),

            // Hysteria2 server (sing-box)
            ProxyType::SingboxHysteria2Server { password } => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{
      "password": "{}"
    }}],
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "alpn": ["h3"],
      "certificate_path": "{}",
      "key_path": "{}"
    }}
  }}],
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}],
  "route": {{
    "final": "direct"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    password,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }

            // TUIC v5 client (sing-box connects to shoes TUIC server)
            ProxyType::SingboxTuicClient {
                upstream_ip,
                upstream_port,
                password,
            } => Some(format!(
                r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "http",
    "tag": "http-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "tuic",
    "tag": "tuic-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "password": "{}",
    "congestion_control": "cubic",
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "insecure": true,
      "alpn": ["h3"]
    }}
  }}],
  "route": {{
    "final": "tuic-out"
  }}
}}"#,
                proxy.ip, proxy.port, upstream_ip, upstream_port, TEST_UUID, password
            )),

            // TUIC v5 server (sing-box)
            ProxyType::SingboxTuicServer { password } => {
                let (cert, key) = generate_test_cert()?;
                let cfg = format!(
                    r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "tuic",
    "tag": "tuic-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{
      "uuid": "{}",
      "password": "{}"
    }}],
    "congestion_control": "cubic",
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "certificate_path": "{}",
      "key_path": "{}"
    }}
  }}],
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}],
  "route": {{
    "final": "direct"
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    TEST_UUID,
                    password,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }

            _ => None,
        };

        Ok(config)
    }

    /// Generate config for native naive client/caddy server
    fn generate_naive_config(
        &mut self,
        proxy: &ProxyConfig,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let config = match &proxy.proxy_type {
            // Native NaiveProxy client (naive binary)
            ProxyType::NaiveProxyClient {
                upstream_ip,
                upstream_port,
                username,
                password,
                sni,
            } => Some(format!(
                r#"{{
  "listen": "http://{}:{}",
  "proxy": "https://{}:{}@{}:{}",
  "host-resolver-rules": "MAP {} {}"
}}"#,
                proxy.ip, proxy.port, username, password, sni, upstream_port, sni, upstream_ip
            )),

            // Native NaiveProxy caddy server (forwardproxy)
            ProxyType::NaiveProxyCaddyServer {
                username,
                password,
                sni: _,
            } => {
                use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
                let (cert, key) = generate_test_cert()?;
                // The decoded JSON bytes must retain the Base64 Authorization payload, so the
                // credentials use base64(base64("user:pass")).
                let credentials = format!("{}:{}", username, password);
                let first_encode = BASE64.encode(&credentials);
                let encoded_creds = BASE64.encode(&first_encode);
                // NOTE: forwardproxy by default blocks private IP ranges (10.0.0.0/8,
                // 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) as SSRF protection.
                // We need to add an explicit ACL rule to allow all addresses for testing.
                let cfg = format!(
                    r#"{{
  "admin": {{"disabled": true}},
  "apps": {{
    "http": {{
      "servers": {{
        "naive": {{
          "listen": ["{}:{}"],
          "routes": [{{
            "handle": [{{
              "handler": "forward_proxy",
              "auth_credentials": ["{}"],
              "hide_ip": true,
              "hide_via": true,
              "acl": [{{"subjects": ["all"], "allow": true}}]
            }}]
          }}],
          "tls_connection_policies": [{{
            "certificate_selection": {{"any_tag": ["naive"]}},
            "alpn": ["h2"]
          }}]
        }}
      }}
    }},
    "tls": {{
      "certificates": {{
        "load_files": [{{
          "certificate": "{}",
          "key": "{}",
          "tags": ["naive"]
        }}]
      }}
    }}
  }}
}}"#,
                    proxy.ip,
                    proxy.port,
                    encoded_creds,
                    AsRef::<Path>::as_ref(&cert).to_str().unwrap(),
                    AsRef::<Path>::as_ref(&key).to_str().unwrap()
                );
                self.certs.push((cert, key));
                Some(cfg)
            }

            _ => None,
        };

        Ok(config)
    }
}

impl Default for ProxyTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl BuiltFixture {
    /// Test an HTTP request through the proxy chain to the internet
    pub async fn test_http(&self, url: &str) -> Result<(), Box<dyn std::error::Error>> {
        use super::curl::*;

        let output = run_curl(
            url,
            CurlOptions::new()
                .proxy(format!("http://{}:{}", self.entry_ip, self.entry_port))
                .timeout(10),
        )
        .await?;

        assert!(
            output.status.success(),
            "curl failed with exit code: {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }

    /// Test an HTTP request with custom curl options
    pub async fn test_http_with_options(
        &self,
        url: &str,
        mut options: super::curl::CurlOptions,
    ) -> Result<std::process::Output, Box<dyn std::error::Error>> {
        options = options.proxy(format!("http://{}:{}", self.entry_ip, self.entry_port));
        Ok(super::curl::run_curl(url, options).await?)
    }

    /// Test a request to the local HTTP/HTTPS server
    pub async fn test_local_server(
        &self,
        path: &str,
        insecure: bool,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let ip = self
            .local_server_ip
            .as_ref()
            .ok_or("No local server configured")?;
        let port = self.local_server_port.ok_or("No local server configured")?;

        let protocol = if insecure { "https" } else { "http" };
        let host = if ip.contains(':') {
            format!("[{ip}]")
        } else {
            ip.clone()
        };
        let url = format!("{protocol}://{host}:{port}{path}");

        let mut options = super::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", self.entry_ip, self.entry_port))
            .timeout(30);

        if insecure {
            options = options.insecure(true);

            // Force TLS 1.2 if using TLS 1.2 local server
            if let Some(LocalServerProtocol::HttpsTls12) = self.local_server_protocol {
                options = options.tls_version("1.2").tls_max_version("1.2");
            }

            // Force TLS 1.3 if using TLS 1.3 local server
            if let Some(LocalServerProtocol::HttpsTls13) = self.local_server_protocol {
                options = options.tls_version("1.3").tls_max_version("1.3");
            }
        }

        let output = super::curl::run_curl(&url, options).await?;

        assert!(
            output.status.success(),
            "curl failed with exit code: {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(output.stdout)
    }

    /// Get the entry IP for the proxy chain
    pub fn entry_ip(&self) -> &str {
        &self.entry_ip
    }

    /// Get the entry port for the proxy chain
    pub fn entry_port(&self) -> u16 {
        self.entry_port
    }

    /// Get the local server port if configured
    pub fn local_server_port(&self) -> Option<u16> {
        self.local_server_port
    }

    /// Get the local server IP if configured
    pub fn local_server_ip(&self) -> Option<&str> {
        self.local_server_ip.as_deref()
    }

    /// Get the TUN interface name if configured
    pub fn tun_interface(&self) -> Option<&str> {
        self.tun_interface.as_deref()
    }

    /// Get the TUN virtual server IP if configured
    pub fn tun_virtual_server_ip(&self) -> Option<&str> {
        self.tun_virtual_server_ip.as_deref()
    }

    /// Check if this fixture uses TUN as entry point
    pub fn is_tun_entry(&self) -> bool {
        self.tun_interface.is_some()
    }

    /// Test a request to the local HTTP server via TUN interface.
    ///
    /// This routes traffic through the TUN device instead of using an HTTP proxy.
    /// Requires TUN entry to be configured.
    pub async fn test_local_server_via_tun(
        &self,
        path: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let _tun_iface = self
            .tun_interface
            .as_ref()
            .ok_or("TUN entry not configured")?;
        let virtual_ip = self
            .tun_virtual_server_ip
            .as_ref()
            .ok_or("TUN virtual server IP not configured")?;
        let port = self.local_server_port.ok_or("No local server configured")?;

        // Traffic to virtual_ip goes through TUN, then netstack forwards to local server
        let url = format!("http://{}:{}{}", virtual_ip, port, path);

        let options = super::curl::CurlOptions::new().timeout(30);

        let output = super::curl::run_curl(&url, options).await?;

        assert!(
            output.status.success(),
            "curl via TUN failed with exit code: {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(output.stdout)
    }

    /// Test a streaming request to the local HTTP server via TUN (discards output).
    /// Returns the elapsed time.
    pub async fn test_local_server_streaming_via_tun(
        &self,
        path: &str,
        timeout_secs: u32,
    ) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
        let tun_iface = self
            .tun_interface
            .as_ref()
            .ok_or("TUN entry not configured")?;
        let virtual_ip = self
            .tun_virtual_server_ip
            .as_ref()
            .ok_or("TUN virtual server IP not configured")?;
        let port = self.local_server_port.ok_or("No local server configured")?;

        let url = format!("http://{}:{}{}", virtual_ip, port, path);

        let options = super::curl::CurlOptions::new()
            .timeout(timeout_secs)
            .discard_output(true)
            .interface(tun_iface);

        let start = std::time::Instant::now();
        let output = super::curl::run_curl(&url, options).await?;
        let elapsed = start.elapsed();

        assert!(
            output.status.success(),
            "curl via TUN failed with exit code: {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(elapsed)
    }

    /// Test a verified streaming request to the local HTTP server via TUN.
    ///
    /// Uses /bytes_verified/N endpoint which returns N bytes of data followed by
    /// 32-byte SHA256 digest. Verifies data integrity.
    pub async fn test_local_server_streaming_verified_via_tun(
        &self,
        data_size: u64,
        timeout_secs: u64,
    ) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
        use aws_lc_rs::digest::{Context, SHA256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let _tun_iface = self
            .tun_interface
            .as_ref()
            .ok_or("TUN entry not configured")?;
        let virtual_ip = self
            .tun_virtual_server_ip
            .as_ref()
            .ok_or("TUN virtual server IP not configured")?;
        let port = self.local_server_port.ok_or("No local server configured")?;

        let start = std::time::Instant::now();

        // Connect directly to the virtual IP (goes through TUN -> netstack -> local server)
        let addr = format!("{}:{}", virtual_ip, port);
        let mut stream = timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await??;

        // Send HTTP request
        let request = format!(
            "GET /bytes_verified/{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
            data_size, virtual_ip, port
        );
        stream.write_all(request.as_bytes()).await?;

        // Read headers
        let mut header_buf = Vec::with_capacity(1024);
        loop {
            let mut byte = [0u8; 1];
            timeout(
                std::time::Duration::from_secs(timeout_secs),
                stream.read_exact(&mut byte),
            )
            .await??;
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        // Parse Content-Length
        let header_str = String::from_utf8_lossy(&header_buf);
        let content_length: u64 = header_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse().ok())
            .ok_or("Missing Content-Length header")?;

        let expected_total = data_size + 32; // data + SHA256 digest
        if content_length != expected_total {
            return Err(format!(
                "Unexpected Content-Length: {} (expected {})",
                content_length, expected_total
            )
            .into());
        }

        // Stream body and compute digest
        let mut hasher = Context::new(&SHA256);
        let mut data_remaining = data_size;
        let mut buf = [0u8; 65536];

        while data_remaining > 0 {
            let to_read = std::cmp::min(data_remaining as usize, buf.len());
            let n = timeout(
                std::time::Duration::from_secs(timeout_secs),
                stream.read(&mut buf[..to_read]),
            )
            .await??;
            if n == 0 {
                return Err("Unexpected EOF while reading data".into());
            }
            hasher.update(&buf[..n]);
            data_remaining -= n as u64;
        }

        // Read server's digest
        let mut server_digest = [0u8; 32];
        timeout(
            std::time::Duration::from_secs(timeout_secs),
            stream.read_exact(&mut server_digest),
        )
        .await??;

        // Verify
        let computed = hasher.finish();
        if computed.as_ref() != server_digest {
            return Err("Digest mismatch! Data corruption detected".into());
        }

        Ok(start.elapsed())
    }

    /// Test a streaming request to the local HTTP/HTTPS server (discards output to /dev/null)
    /// This is useful for benchmarking large transfers without memory buffering.
    /// Returns the time taken in milliseconds.
    pub async fn test_local_server_streaming(
        &self,
        path: &str,
        insecure: bool,
        timeout_secs: u32,
    ) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
        let ip = self
            .local_server_ip
            .as_ref()
            .ok_or("No local server configured")?;
        let port = self.local_server_port.ok_or("No local server configured")?;

        let protocol = if insecure { "https" } else { "http" };
        let host = if ip.contains(':') {
            format!("[{ip}]")
        } else {
            ip.clone()
        };
        let url = format!("{protocol}://{host}:{port}{path}");

        let mut options = super::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", self.entry_ip, self.entry_port))
            .timeout(timeout_secs)
            .discard_output(true);

        if insecure {
            options = options.insecure(true);

            // Force TLS 1.2 if using TLS 1.2 local server
            if let Some(LocalServerProtocol::HttpsTls12) = self.local_server_protocol {
                options = options.tls_version("1.2").tls_max_version("1.2");
            }

            // Force TLS 1.3 if using TLS 1.3 local server
            if let Some(LocalServerProtocol::HttpsTls13) = self.local_server_protocol {
                options = options.tls_version("1.3").tls_max_version("1.3");
            }
        }

        let start = std::time::Instant::now();
        let output = super::curl::run_curl(&url, options).await?;
        let elapsed = start.elapsed();

        assert!(
            output.status.success(),
            "curl failed with exit code: {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(elapsed)
    }

    /// Test a verified streaming request to the local HTTP server.
    ///
    /// Uses /bytes_verified/N endpoint which returns N bytes of data followed by
    /// 32-byte SHA256 digest. Client computes digest while streaming and verifies
    /// it matches the server's digest at the end.
    ///
    /// Returns the elapsed time on success, or error if verification fails.
    pub async fn test_local_server_streaming_verified(
        &self,
        data_size: u64,
        timeout_secs: u64,
    ) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
        use aws_lc_rs::digest::{Context, SHA256};
        use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let ip = self
            .local_server_ip
            .as_ref()
            .ok_or("No local server configured")?;
        let port = self.local_server_port.ok_or("No local server configured")?;

        let is_https = matches!(
            self.local_server_protocol,
            Some(LocalServerProtocol::HttpsTls13) | Some(LocalServerProtocol::HttpsTls12)
        );

        let start = std::time::Instant::now();

        // Connect to proxy
        let proxy_addr = format!("{}:{}", self.entry_ip, self.entry_port);
        let stream = timeout(Duration::from_secs(10), TcpStream::connect(&proxy_addr)).await??;

        // Helper macro to read headers from any AsyncRead stream
        async fn read_headers<R: AsyncRead + Unpin>(
            stream: &mut R,
            timeout_secs: u64,
        ) -> Result<(String, Option<u64>), Box<dyn std::error::Error>> {
            let mut header_buf = Vec::with_capacity(1024);
            loop {
                let mut byte = [0u8; 1];
                tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    stream.read_exact(&mut byte),
                )
                .await??;
                header_buf.push(byte[0]);

                if header_buf.len() >= 4 {
                    let len = header_buf.len();
                    if &header_buf[len - 4..] == b"\r\n\r\n" {
                        break;
                    }
                }

                if header_buf.len() > 16384 {
                    return Err("HTTP headers too large".into());
                }
            }

            let headers_str = String::from_utf8_lossy(&header_buf).to_string();
            let mut content_length = None;
            for line in headers_str.lines() {
                if line.to_lowercase().starts_with("content-length:")
                    && let Some(v) = line.split(':').nth(1).map(str::trim)
                {
                    content_length = v.parse().ok();
                }
            }
            Ok((headers_str, content_length))
        }

        // Helper to stream and verify body from any AsyncRead stream
        async fn stream_and_verify<R: AsyncRead + Unpin>(
            stream: &mut R,
            data_size: u64,
            total_size: u64,
            timeout_secs: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut hasher = Context::new(&SHA256);
            let mut bytes_read = 0u64;
            let mut digest_buf = Vec::with_capacity(32);
            let mut read_buf = vec![0u8; 64 * 1024];

            while bytes_read < total_size {
                let to_read =
                    std::cmp::min(read_buf.len() as u64, total_size - bytes_read) as usize;
                let n = tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    stream.read(&mut read_buf[..to_read]),
                )
                .await??;

                if n == 0 {
                    return Err(format!(
                        "Unexpected EOF: read {} bytes, expected {}",
                        bytes_read, total_size
                    )
                    .into());
                }

                let chunk = &read_buf[..n];
                let chunk_start = bytes_read;
                let chunk_end = bytes_read + n as u64;

                if chunk_end <= data_size {
                    hasher.update(chunk);
                } else if chunk_start >= data_size {
                    digest_buf.extend_from_slice(chunk);
                } else {
                    let data_part = (data_size - chunk_start) as usize;
                    hasher.update(&chunk[..data_part]);
                    digest_buf.extend_from_slice(&chunk[data_part..]);
                }

                bytes_read = chunk_end;
            }

            if digest_buf.len() != 32 {
                return Err(format!(
                    "Digest buffer wrong size: expected 32, got {}",
                    digest_buf.len()
                )
                .into());
            }

            let computed = hasher.finish();
            let computed_hex: String = computed
                .as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            let received_hex: String = digest_buf.iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("[CLIENT] SHA256 computed: {}", computed_hex);
            eprintln!("[CLIENT] SHA256 received: {}", received_hex);
            if computed.as_ref() != &digest_buf[..] {
                return Err(format!(
                    "SHA256 digest mismatch!\n  Expected: {:02x?}\n  Computed: {:02x?}",
                    &digest_buf[..],
                    computed.as_ref()
                )
                .into());
            }
            Ok(())
        }

        if is_https {
            // For HTTPS: use CONNECT tunnel, then TLS, then HTTP request
            let mut stream = stream;

            // Send CONNECT request to establish tunnel
            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 \r\n",
                ip, port, ip, port
            );
            stream.write_all(connect_req.as_bytes()).await?;

            // Read CONNECT response
            let mut buf_reader = BufReader::new(stream);
            let mut response_line = String::new();
            buf_reader.read_line(&mut response_line).await?;
            if !response_line.starts_with("HTTP/1.1 200")
                && !response_line.starts_with("HTTP/1.0 200")
            {
                return Err(format!("CONNECT failed: {}", response_line.trim()).into());
            }
            // Read remaining headers until empty line
            loop {
                let mut line = String::new();
                buf_reader.read_line(&mut line).await?;
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            let stream = buf_reader.into_inner();

            // TLS handshake through the tunnel (skip cert verification for self-signed test certs)
            use rustls::client::danger::{
                HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
            };
            use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
            use rustls::{DigitallySignedStruct, SignatureScheme};

            #[derive(Debug)]
            struct InsecureCertVerifier;

            impl ServerCertVerifier for InsecureCertVerifier {
                fn verify_server_cert(
                    &self,
                    _end_entity: &CertificateDer<'_>,
                    _intermediates: &[CertificateDer<'_>],
                    _server_name: &ServerName<'_>,
                    _ocsp_response: &[u8],
                    _now: UnixTime,
                ) -> Result<ServerCertVerified, rustls::Error> {
                    Ok(ServerCertVerified::assertion())
                }

                fn verify_tls12_signature(
                    &self,
                    _message: &[u8],
                    _cert: &CertificateDer<'_>,
                    _dss: &DigitallySignedStruct,
                ) -> Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }

                fn verify_tls13_signature(
                    &self,
                    _message: &[u8],
                    _cert: &CertificateDer<'_>,
                    _dss: &DigitallySignedStruct,
                ) -> Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }

                fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                    vec![
                        SignatureScheme::RSA_PKCS1_SHA256,
                        SignatureScheme::RSA_PKCS1_SHA384,
                        SignatureScheme::RSA_PKCS1_SHA512,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ECDSA_NISTP384_SHA384,
                        SignatureScheme::ECDSA_NISTP521_SHA512,
                        SignatureScheme::RSA_PSS_SHA256,
                        SignatureScheme::RSA_PSS_SHA384,
                        SignatureScheme::RSA_PSS_SHA512,
                        SignatureScheme::ED25519,
                    ]
                }
            }

            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(InsecureCertVerifier))
                .with_no_client_auth();

            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
            let ip_owned = ip.clone();
            let server_name =
                rustls::pki_types::ServerName::try_from(ip_owned).unwrap_or_else(|_| {
                    rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap()
                });
            let mut tls_stream = connector.connect(server_name, stream).await?;

            // Send HTTP request over TLS (relative URL since we're tunneled)
            let request = format!(
                "GET /bytes_verified/{} HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 Connection: close\r\n\
                 \r\n",
                data_size, ip, port
            );
            tls_stream.write_all(request.as_bytes()).await?;

            // Read and verify response
            let (headers_str, content_length) = read_headers(&mut tls_stream, timeout_secs).await?;
            if !headers_str.starts_with("HTTP/1.1 200") && !headers_str.starts_with("HTTP/1.0 200")
            {
                return Err(format!(
                    "HTTP request failed: {}",
                    headers_str.lines().next().unwrap_or("")
                )
                .into());
            }

            let total_size = content_length.ok_or("No Content-Length header")?;
            let expected_total = data_size + 32;
            if total_size != expected_total {
                return Err(format!(
                    "Content-Length mismatch: expected {}, got {}",
                    expected_total, total_size
                )
                .into());
            }

            stream_and_verify(&mut tls_stream, data_size, total_size, timeout_secs).await?;

            let elapsed = start.elapsed();
            eprintln!(
                "[VERIFIED] {} bytes transferred and verified in {:.2}s ({:.2} MB/s)",
                data_size,
                elapsed.as_secs_f64(),
                data_size as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64()
            );
            Ok(elapsed)
        } else {
            // For HTTP: send GET with absolute URL directly
            let mut stream = stream;
            let request = format!(
                "GET http://{}:{}/bytes_verified/{} HTTP/1.1\r\n\
                 Host: {}:{}\r\n\
                 Connection: close\r\n\
                 \r\n",
                ip, port, data_size, ip, port
            );
            stream.write_all(request.as_bytes()).await?;

            let (headers_str, content_length) = read_headers(&mut stream, timeout_secs).await?;
            if !headers_str.starts_with("HTTP/1.1 200") && !headers_str.starts_with("HTTP/1.0 200")
            {
                return Err(format!(
                    "HTTP request failed: {}",
                    headers_str.lines().next().unwrap_or("")
                )
                .into());
            }

            let total_size = content_length.ok_or("No Content-Length header")?;
            let expected_total = data_size + 32;
            if total_size != expected_total {
                return Err(format!(
                    "Content-Length mismatch: expected {}, got {}",
                    expected_total, total_size
                )
                .into());
            }

            stream_and_verify(&mut stream, data_size, total_size, timeout_secs).await?;

            let elapsed = start.elapsed();
            eprintln!(
                "[VERIFIED] {} bytes transferred and verified in {:.2}s ({:.2} MB/s)",
                data_size,
                elapsed.as_secs_f64(),
                data_size as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64()
            );
            Ok(elapsed)
        }
    }
}
