use base64::{Engine, engine::general_purpose::STANDARD};
use gotatun::x25519::{PublicKey, StaticSecret};
use serde_json::{Value, json};
use shoes_test_support::test_fixture::TEST_UUID;

pub fn vless_protocol() -> Value {
    json!({"type": "vless", "user_id": TEST_UUID, "udp_enabled": true})
}

pub fn key(n: u8) -> String {
    STANDARD.encode([n; 32])
}
pub fn public(n: u8) -> String {
    STANDARD.encode(PublicKey::from(&StaticSecret::from([n; 32])).as_bytes())
}
pub fn server(port: u16) -> Value {
    json!({
        "address": format!("0.0.0.0:{port}"),
        "protocol": {
            "type": "wireguard",
            "private_key": key(41),
            "addresses": ["10.77.0.1/32", "fd77::1/128"],
            "peers": [{
                "public_key": public(42),
                "pre_shared_key": key(43),
                "allowed_ips": ["10.77.0.2/32", "fd77::2/128"],
            }],
        },
        "rules": [
            {
                "masks": ["fd88::1/128", "::1/128"],
                "action": "allow",
                "override_address": "[::1]:0",
            },
            {
                "masks": ["0.0.0.0/0"],
                "action": "allow",
                "override_address": "127.0.0.1:0",
            },
        ],
    })
}
pub fn client(port: u16) -> Value {
    json!({
        "client_group": "wg",
        "client_proxies": [{
            "address": format!("127.0.0.1:{port}"),
            "protocol": {
                "type": "wireguard",
                "private_key": key(42),
                "addresses": ["10.77.0.2/32", "fd77::2/128"],
                "public_key": public(41),
                "pre_shared_key": key(43),
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            },
        }],
    })
}
pub fn socks(port: u16) -> Value {
    json!({
        "address": format!("0.0.0.0:{port}"),
        "protocol": {"type": "socks"},
        "rules": [{
            "masks": ["0.0.0.0/0", "::/0"],
            "action": "allow",
            "client_chain": ["wg"],
        }],
    })
}
