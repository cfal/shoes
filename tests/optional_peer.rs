#[path = "cases/http_proxy_support.rs"]
mod http_proxy_support;

#[path = "cases/optional_peer/anytls_uot_mihomo.rs"]
mod anytls_uot_mihomo;

#[path = "cases/optional_peer/snell_mihomo.rs"]
mod snell_mihomo;

#[path = "cases/optional_peer/tls_hybrid.rs"]
mod tls_hybrid;

#[path = "cases/optional_peer/http2_proxy.rs"]
mod http2_proxy;

#[path = "cases/optional_peer/shadowsocks_identity.rs"]
mod shadowsocks_identity;

#[path = "cases/optional_peer/clash_api.rs"]
mod clash_api;
#[path = "cases/optional_peer/naive_transport.rs"]
mod naive_transport;
#[cfg(unix)]
#[path = "cases/optional_peer/wireguard_interop.rs"]
mod wireguard;
#[cfg(unix)]
#[path = "cases/wireguard_support.rs"]
mod wireguard_support;
