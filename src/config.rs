use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec::Vec;

use json::JsonValue;
use log::warn;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::address::{Location, LocationMask};
use crate::http_handler::{HttpTcpClientHandler, HttpTcpServerHandler};
use crate::protocol_handler::{TcpClientHandler, TcpServerHandler, UdpMessageHandler};
use crate::shadowsocks::{ShadowsocksTcpHandler, ShadowsocksUdpHandler};
use crate::socks_handler::{SocksTcpClientHandler, SocksTcpServerHandler};
use crate::trojan_handler::TrojanTcpHandler;
use crate::vless_handler::VlessTcpHandler;
use crate::vmess::{VmessTcpClientHandler, VmessTcpServerHandler};
use crate::websocket::{
    WebsocketClientTarget, WebsocketServerTarget, WebsocketTcpClientHandler,
    WebsocketTcpServerHandler,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerProtocol {
    Tcp,
    Udp,
}

impl TryFrom<&str> for ServerProtocol {
    type Error = String;

    fn try_from(name: &str) -> std::result::Result<Self, Self::Error> {
        match name.to_lowercase().as_str() {
            "tcp" => Ok(ServerProtocol::Tcp),
            "udp" => Ok(ServerProtocol::Udp),
            _ => Err(format!("Unknown protocol: {}", name)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
    pub server_protocols: Vec<ServerProtocol>,
    pub server_proxy_config: ServerProxyConfig,
    pub tls_config: Option<ServerTlsConfig>,
    pub proxies: Vec<ClientConfig>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct ServerTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub location: Location,
    pub secure: bool,
    pub client_proxy_config: ClientProxyConfig,
}

#[derive(Debug, Clone)]
pub enum ProxyConfig {
    HTTP {
        auth_credentials: Option<(String, String)>,
    },
    Socks {
        auth_credentials: Option<(String, String)>,
    },
    Shadowsocks(ShadowsocksConfig),
    Vless {
        user_id: String,
    },
    Trojan {
        password: String,
        shadowsocks_config: Option<ShadowsocksConfig>,
    },
}

#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    pub cipher_name: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum ServerProxyConfig {
    Generic(ProxyConfig),
    Vmess {
        cipher_name: String,
        user_id: String,
        force_aead: bool,
    },
    Websocket {
        configs: Vec<WebsocketServerConfig>,
    },
}

#[derive(Debug, Clone)]
pub struct WebsocketServerConfig {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub target_config: ServerProxyConfig,
    pub override_proxies: Option<Vec<ClientConfig>>,
    pub override_rules: Option<Vec<Rule>>,
}

#[derive(Debug, Clone)]
pub struct WebsocketClientConfig {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub target_config: ClientProxyConfig,
}

#[derive(Debug, Clone)]
pub enum ClientProxyConfig {
    Generic(ProxyConfig),
    Vmess {
        cipher_name: String,
        user_id: String,
        aead: bool,
    },
    // This needs to be a box due to indirection (ClientProxyConfig ->
    // WebsocketClientConfig -> ClientProxyConfig)
    Websocket(Box<WebsocketClientConfig>),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub masks: Vec<LocationMask>,
    pub action: RuleAction,
}

#[derive(Debug, Clone)]
pub enum RuleAction {
    Allow {
        replacement_location: Option<Location>,
        proxies: Vec<ClientConfig>,
    },
    Block,
}

fn get_default_server_port(server_proxy_config: &ServerProxyConfig, secure: bool) -> Option<u16> {
    match server_proxy_config {
        ServerProxyConfig::Vmess { .. } => None,
        ServerProxyConfig::Websocket { .. } => {
            if secure {
                Some(443)
            } else {
                Some(80)
            }
        }
        ServerProxyConfig::Generic(ref proxy_config) => get_default_port(proxy_config, secure),
    }
}

fn get_default_client_port(client_proxy_config: &ClientProxyConfig, secure: bool) -> Option<u16> {
    match client_proxy_config {
        ClientProxyConfig::Vmess { .. } => None,
        ClientProxyConfig::Websocket { .. } => {
            if secure {
                Some(443)
            } else {
                Some(80)
            }
        }
        ClientProxyConfig::Generic(ref proxy_config) => get_default_port(proxy_config, secure),
    }
}

fn get_default_port(proxy_config: &ProxyConfig, secure: bool) -> Option<u16> {
    match proxy_config {
        ProxyConfig::HTTP { .. } => {
            if secure {
                Some(443)
            } else {
                Some(80)
            }
        }
        ProxyConfig::Socks { .. } => Some(1080),
        ProxyConfig::Shadowsocks { .. } => None,
        ProxyConfig::Vless { .. } => None,
        ProxyConfig::Trojan { .. } => None,
    }
}

impl ServerConfig {
    pub fn from_args(mut args: Vec<String>) -> std::result::Result<Vec<Self>, String> {
        if args.is_empty() {
            println!("No config specified, assuming loading from file config.shoes.json");
            args.push("config.shoes.json".to_string())
        }

        let mut configs = vec![];
        for arg in args {
            if arg.ends_with(".json") {
                configs.append(&mut Self::from_file(&arg)?);
            } else {
                let json_value = convert_url_to_obj(&arg)?;
                configs.push(Self::from_json_value(json_value)?);
            }
        }
        Ok(configs)
    }

    fn from_file(config_filename: &str) -> std::result::Result<Vec<Self>, String> {
        println!("Reading server config {}..", config_filename);

        let config_bytes = match std::fs::read(config_filename) {
            Ok(b) => b,
            Err(e) => {
                return Err(format!(
                    "Could not read config file {}: {}",
                    config_filename, e
                ));
            }
        };
        let config_str = match String::from_utf8(config_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!(
                    "Could not parse config file {} as UTF8: {}",
                    config_filename, e
                ));
            }
        };

        let config_str = config_str
            .split('\n')
            .filter(|line| !line.trim_start().starts_with(r#"//"#))
            .collect::<Vec<&str>>()
            .join("\n");

        let mut config_obj =
            json::parse(&config_str).map_err(|e| format!("Failed to parse config: {}", e))?;

        if config_obj.is_array() {
            // List of servers.
            let mut ret = vec![];
            while !config_obj.is_empty() {
                ret.push(Self::from_json_value(config_obj.array_remove(0))?);
            }
            Ok(ret)
        } else {
            Ok(vec![Self::from_json_value(config_obj)?])
        }
    }

    fn from_json_value(value: JsonValue) -> std::result::Result<Self, String> {
        let config_obj = normalize_url_config_value(value)?;

        let ReadServerProxyConfigResult {
            implies_secure: proxy_implies_secure,
            server_proxy_config,
        } = read_server_proxy_config(&config_obj)?;

        let implies_secure = proxy_implies_secure || is_true_value(&config_obj["tls"], false);

        let server_protocols = read_server_protocols(&config_obj)?;

        let bind_location = read_address(
            &config_obj,
            get_default_server_port(&server_proxy_config, implies_secure),
        )?;
        let bind_address = bind_location
            .to_socket_addr()
            .map_err(|e| format!("Could not resolve bind address: {}", e))?;

        let mut obj = Self {
            bind_address,
            server_protocols,
            server_proxy_config,
            tls_config: None,
            proxies: vec![],
            rules: vec![],
        };

        let tls_config = read_tls_config(&config_obj)?;
        if tls_config.is_some() {
            obj.tls_config = tls_config;
        }

        if implies_secure && obj.tls_config.is_none() {
            return Err("Server requires TLS config, but none was provided".to_string());
        }

        if let Some(p) = read_proxies(&config_obj)? {
            obj.proxies.extend(p);
        }

        if let Some(r) = read_rules(&config_obj)? {
            obj.rules.extend(r);
        }

        Ok(obj)
    }
}

fn read_server_protocols(obj: &JsonValue) -> std::result::Result<Vec<ServerProtocol>, String> {
    let protocol_obj = if obj.has_key("protocol") {
        &obj["protocol"]
    } else {
        &obj["protocols"]
    };

    if protocol_obj.is_null() {
        Ok(vec![ServerProtocol::Tcp, ServerProtocol::Udp])
    } else if protocol_obj.is_string() {
        Ok(vec![ServerProtocol::try_from(
            protocol_obj.as_str().unwrap(),
        )?])
    } else if protocol_obj.is_array() {
        let ret: Vec<ServerProtocol> = protocol_obj
            .members()
            .map(|val| {
                if !val.is_string() {
                    Err(format!("Invalid server protocol: {}", val))
                } else {
                    ServerProtocol::try_from(val.as_str().unwrap())
                }
            })
            .collect::<Result<Vec<_>, String>>()?;
        if ret.is_empty() {
            Err("No server protocols specified".to_string())
        } else {
            Ok(ret)
        }
    } else {
        Err(format!("Invalid server protocols: {}", protocol_obj))
    }
}

fn read_address(
    obj: &JsonValue,
    default_port: Option<u16>,
) -> std::result::Result<Location, String> {
    let address = obj["address"].as_str().ok_or("Could not read address")?;

    Location::from_str(address, default_port).map_err(|e| format!("Could not read address: {}", e))
}

struct ReadServerProxyConfigResult {
    server_proxy_config: ServerProxyConfig,
    implies_secure: bool,
}

fn read_websocket_headers(
    obj: &JsonValue,
    force_lowercase: bool,
) -> std::result::Result<Option<HashMap<String, String>>, String> {
    match &obj["matching_headers"] {
        JsonValue::Null => Ok(None),
        JsonValue::Object(headers_obj) => {
            let mut header_map = HashMap::new();

            let header_keys = headers_obj
                .iter()
                .map(|(key, _)| key.to_string())
                .collect::<Vec<_>>();

            for header_key in header_keys.into_iter() {
                let lowercase_header_key = header_key.to_lowercase();
                if lowercase_header_key == "connection"
                    || lowercase_header_key == "upgrade"
                    || lowercase_header_key.starts_with("sec-")
                {
                    return Err(format!("Cannot specify header: {}", header_key));
                }

                let header_value = headers_obj.get(&header_key).unwrap();
                if !header_value.is_string() {
                    return Err(format!("Invalid header value for {}", &header_key));
                }

                let insert_header_key = if force_lowercase {
                    lowercase_header_key
                } else {
                    header_key
                };

                header_map.insert(
                    insert_header_key,
                    header_value.as_str().unwrap().to_string(),
                );
            }
            Ok(Some(header_map))
        }
        unknown_value => Err(format!("Invalid header map value: {}", unknown_value)),
    }
}

fn read_server_proxy_config(
    obj: &JsonValue,
) -> std::result::Result<ReadServerProxyConfigResult, String> {
    let proxy_scheme = obj["scheme"]
        .as_str()
        .ok_or("Could not read proxy scheme")?;
    match proxy_scheme {
        "vmess" => {
            let cipher_name = obj["cipher"].as_str().unwrap_or("any").to_string();
            let user_id = obj["user_id"]
                .as_str()
                .ok_or("Invalid vmess user id")?
                .to_string();
            let force_aead = is_true_value(&obj["force_aead"], false);

            Ok(ReadServerProxyConfigResult {
                implies_secure: false,
                server_proxy_config: ServerProxyConfig::Vmess {
                    cipher_name,
                    user_id,
                    force_aead,
                },
            })
        }
        "ws" | "wss" => {
            let mut targets = match &obj["targets"] {
                JsonValue::Array(v) => v.clone(),
                JsonValue::Null => vec![],
                unknown_value => {
                    return Err(format!("Invalid targets field: {}", unknown_value));
                }
            };

            if targets.len() == 0 {
                if !obj["target"].is_null() {
                    targets.push(obj["target"].clone());
                } else {
                    return Err("Websocket servers must specify at least one target.".to_string());
                }
            }

            let mut implies_secure = proxy_scheme == "wss";

            let mut configs: Vec<WebsocketServerConfig> = Vec::with_capacity(targets.len());
            for target in targets.into_iter() {
                let target = normalize_url_config_value(target)?;

                let ReadServerProxyConfigResult {
                    implies_secure: proxy_implies_secure,
                    server_proxy_config,
                } = read_server_proxy_config(&target)?;

                if proxy_implies_secure {
                    implies_secure = true;
                }

                let matching_path = target["matching_path"].as_str().map(ToString::to_string);

                // for servers, we'll be matching the headers so convert them to lowercase.
                // see ParsedHttpData.
                let matching_headers = read_websocket_headers(&target, true)?;

                let override_proxies = read_proxies(&target)?;
                let override_rules = read_rules(&target)?;

                configs.push(WebsocketServerConfig {
                    matching_path,
                    matching_headers,
                    target_config: server_proxy_config,
                    override_proxies,
                    override_rules,
                });
            }

            Ok(ReadServerProxyConfigResult {
                implies_secure,
                server_proxy_config: ServerProxyConfig::Websocket { configs },
            })
        }
        _ => read_generic_proxy_config(obj).map(|result| {
            let ReadProxyConfigResult {
                implies_secure,
                proxy_config,
            } = result;
            ReadServerProxyConfigResult {
                implies_secure,
                server_proxy_config: ServerProxyConfig::Generic(proxy_config),
            }
        }),
    }
}

struct ReadClientProxyConfigResult {
    client_proxy_config: ClientProxyConfig,
    implies_secure: bool,
}

fn read_client_proxy_config(
    obj: &JsonValue,
) -> std::result::Result<ReadClientProxyConfigResult, String> {
    let proxy_scheme = obj["scheme"]
        .as_str()
        .ok_or("Could not read proxy scheme")?;
    match proxy_scheme {
        "vmess" => {
            let cipher_name = obj["cipher"].as_str().unwrap_or("any").to_string();
            let user_id = obj["user_id"]
                .as_str()
                .ok_or("Invalid vmess user id")?
                .to_string();
            let aead = is_true_value(&obj["aead"], true);

            Ok(ReadClientProxyConfigResult {
                implies_secure: false,
                client_proxy_config: ClientProxyConfig::Vmess {
                    cipher_name,
                    user_id,
                    aead,
                },
            })
        }
        "ws" | "wss" => {
            let proxy_implies_secure = proxy_scheme == "wss";
            let target = normalize_url_config_value(obj["target"].clone())?;
            let matching_path = target["matching_path"].as_str().map(ToString::to_string);
            let matching_headers = read_websocket_headers(&target, false)?;
            let ReadClientProxyConfigResult {
                implies_secure: target_implies_secure,
                client_proxy_config,
            } = read_client_proxy_config(&target)?;
            Ok(ReadClientProxyConfigResult {
                implies_secure: proxy_implies_secure || target_implies_secure,
                client_proxy_config: ClientProxyConfig::Websocket(Box::new(
                    WebsocketClientConfig {
                        matching_path,
                        matching_headers,
                        target_config: client_proxy_config,
                    },
                )),
            })
        }
        _ => read_generic_proxy_config(obj).map(|result| {
            let ReadProxyConfigResult {
                implies_secure,
                proxy_config,
            } = result;
            ReadClientProxyConfigResult {
                implies_secure,
                client_proxy_config: ClientProxyConfig::Generic(proxy_config),
            }
        }),
    }
}

struct ReadProxyConfigResult {
    proxy_config: ProxyConfig,
    implies_secure: bool,
}

fn read_generic_proxy_config(
    obj: &JsonValue,
) -> std::result::Result<ReadProxyConfigResult, String> {
    let proxy_scheme = obj["scheme"]
        .as_str()
        .ok_or("Could not read proxy scheme")?;
    match proxy_scheme {
        "http" | "https" => {
            let auth_credentials = read_auth_credentials(obj)?;
            Ok(ReadProxyConfigResult {
                implies_secure: proxy_scheme == "https",
                proxy_config: ProxyConfig::HTTP { auth_credentials },
            })
        }
        "socks" | "socks5" => {
            let auth_credentials = read_auth_credentials(obj)?;
            Ok(ReadProxyConfigResult {
                implies_secure: false,
                proxy_config: ProxyConfig::Socks { auth_credentials },
            })
        }
        "shadowsocks" | "ss" => {
            let cipher_name = obj["cipher"]
                .as_str()
                .ok_or("Invalid shadowsocks cipher")?
                .to_string();
            let password = obj["password"]
                .as_str()
                .ok_or("Invalid shadowsocks password")?
                .to_string();

            Ok(ReadProxyConfigResult {
                implies_secure: false,
                proxy_config: ProxyConfig::Shadowsocks(ShadowsocksConfig {
                    cipher_name,
                    password,
                }),
            })
        }
        "vless" => {
            let user_id = obj["user_id"]
                .as_str()
                .ok_or("Invalid vless user id")?
                .to_string();

            Ok(ReadProxyConfigResult {
                implies_secure: false,
                proxy_config: ProxyConfig::Vless { user_id },
            })
        }
        "trojan" => {
            let password = obj["password"]
                .as_str()
                .ok_or("Invalid trojan password")?
                .to_string();

            let shadowsocks_val = &obj["shadowsocks"];
            let shadowsocks_config = if shadowsocks_val.is_object() {
                let cipher_name = shadowsocks_val["cipher"]
                    .as_str()
                    .ok_or("Invalid shadowsocks cipher")?
                    .to_string();
                let shadowsocks_password = shadowsocks_val["password"]
                    .as_str()
                    .ok_or("Invalid shadowsocks password")?
                    .to_string();
                Some(ShadowsocksConfig {
                    cipher_name,
                    password: shadowsocks_password,
                })
            } else {
                None
            };

            Ok(ReadProxyConfigResult {
                implies_secure: false,
                proxy_config: ProxyConfig::Trojan {
                    password,
                    shadowsocks_config,
                },
            })
        }
        _ => Err(format!("Invalid proxy scheme: {}", proxy_scheme)),
    }
}

fn read_tls_config(obj: &JsonValue) -> std::result::Result<Option<ServerTlsConfig>, String> {
    if obj["cert"].is_string() && obj["key"].is_string() {
        let cert_path = obj["cert"].as_str().ok_or("Invalid cert path")?.to_string();
        let key_path = obj["key"].as_str().ok_or("Invalid key path")?.to_string();
        Ok(Some(ServerTlsConfig {
            cert_path,
            key_path,
        }))
    } else if obj["cert"].is_null() && obj["key"].is_null() {
        Ok(None)
    } else {
        Err("Only one of cert or key was provided".to_string())
    }
}

fn read_proxies(obj: &JsonValue) -> std::result::Result<Option<Vec<ClientConfig>>, String> {
    let proxies_obj = &obj["proxies"];

    if proxies_obj.is_null() {
        return Ok(None);
    }

    let proxies_array = if proxies_obj.is_string() {
        vec![proxies_obj.clone()]
    } else if proxies_obj.is_array() {
        proxies_obj.members().map(|v| v.clone()).collect::<Vec<_>>()
    } else {
        return Err("Invalid proxies value".to_string());
    };

    let mut proxies = Vec::with_capacity(proxies_array.len());

    for proxy_value in proxies_array {
        let proxy_obj = normalize_url_config_value(proxy_value.clone())?;
        let ReadClientProxyConfigResult {
            implies_secure: proxy_implies_secure,
            client_proxy_config,
        } = read_client_proxy_config(&proxy_obj)?;

        let implies_secure = proxy_implies_secure || is_true_value(&proxy_obj["tls"], false);

        let location = read_address(
            &proxy_obj,
            get_default_client_port(&client_proxy_config, implies_secure),
        )?;

        proxies.push(ClientConfig {
            location,
            secure: implies_secure,
            client_proxy_config,
        });
    }

    Ok(Some(proxies))
}

fn is_true_value(value: &JsonValue, default_value: bool) -> bool {
    if value.is_string() {
        let value_str = value.as_str().unwrap();
        return value_str == "true" || value_str == "1" || value_str == "yes";
    }
    value.as_bool().unwrap_or(default_value)
}

fn read_rules(obj: &JsonValue) -> std::result::Result<Option<Vec<Rule>>, String> {
    let blocklist_obj = &obj["blocklist"];
    let rules_obj = &obj["rules"];
    if blocklist_obj.is_null() && rules_obj.is_null() {
        return Ok(None);
    }

    let mut rules = vec![];

    let mut blocklist = if blocklist_obj.is_null() || blocklist_obj.is_empty() {
        vec![]
    } else {
        read_location_masks(&obj, "blocklist")?
    };

    if !rules_obj.is_empty() {
        if !rules_obj.is_array() {
            return Err("Invalid rules value".to_string());
        }
        for rule_obj in rules_obj.members() {
            let mut masks = read_location_masks(&rule_obj, "hosts")?;

            let allow_proxies = match read_proxies(rule_obj)? {
                Some(p) => {
                    // Expect either "allow" or missing "action" key
                    let action_obj = &rules_obj["action"];
                    if action_obj.is_null() {
                        warn!("action was not specified for rule but proxies were provided, assuming allow.");
                        p
                    } else if action_obj.is_string() && action_obj.as_str().unwrap() == "allow" {
                        p
                    } else {
                        return Err("Invalid action value".to_string());
                    }
                }
                None => {
                    // "allow" or "block" must be explicitly set.
                    let action_obj = &rule_obj["action"];
                    match action_obj.as_str() {
                        Some("allow") => vec![],
                        Some("block") => {
                            // Just add it to the blocklist set.
                            blocklist.append(&mut masks);
                            continue;
                        }
                        Some(value) => {
                            return Err(format!("Invalid action value: {}", value));
                        }
                        None => {
                            return Err("No action value provided".to_string());
                        }
                    }
                }
            };

            let replacement_location_obj = &rule_obj["replacement_location"];
            let replacement_location = if replacement_location_obj.is_empty() {
                None
            } else {
                let location_str = replacement_location_obj
                    .as_str()
                    .expect("Invalid replacement address");

                // port of 0 means to copy the port from the specified remote location.
                let location = Location::from_str(location_str, Some(0))
                    .map_err(|e| format!("Invalid location: {}", e))?;

                Some(location)
            };

            rules.push(Rule {
                masks,
                action: RuleAction::Allow {
                    replacement_location,
                    proxies: allow_proxies,
                },
            });
        }
    }

    if !blocklist.is_empty() {
        rules.push(Rule {
            masks: blocklist,
            action: RuleAction::Block,
        });
    }

    Ok(Some(rules))
}

fn read_location_masks(
    obj: &JsonValue,
    key: &str,
) -> std::result::Result<Vec<LocationMask>, String> {
    let obj = &obj[key];

    if obj.is_string() {
        let location_mask = LocationMask::from(obj.as_str().unwrap())
            .map_err(|e| format!("Invalid location mask: {}", e))?;
        Ok(vec![location_mask])
    } else if obj.is_array() {
        // TODO: clean this up
        let mut ret = vec![];
        for subobj in obj.members() {
            if !subobj.is_string() {
                return Err("Invalid location mask".to_string());
            }
            let location_mask = LocationMask::from(subobj.as_str().unwrap())
                .map_err(|e| format!("Invalid location mask: {}", e))?;
            ret.push(location_mask);
        }
        Ok(ret)
    } else {
        Err("Invalid location masks value".to_string())
    }
}

fn read_auth_credentials(obj: &JsonValue) -> std::result::Result<Option<(String, String)>, String> {
    let username_obj = &obj["username"];
    let password_obj = &obj["password"];
    if username_obj.is_empty() {
        if !password_obj.is_empty() {
            return Err("Password provided without username".to_string());
        }
        Ok(None)
    } else {
        if password_obj.is_empty() {
            return Err("Username provided without password".to_string());
        }
        Ok(Some((
            username_obj.as_str().ok_or("Invalid username")?.to_string(),
            password_obj.as_str().ok_or("Invalid password")?.to_string(),
        )))
    }
}

fn normalize_url_config_value(mut value: JsonValue) -> std::result::Result<JsonValue, String> {
    if value.is_string() {
        convert_url_to_obj(value.as_str().unwrap())
    } else if value.is_object() {
        if value.has_key("url") {
            let mut sub_obj =
                convert_url_to_obj(value.remove("url").as_str().ok_or("Invalid url field")?)?;
            let sub_keys = sub_obj
                .entries()
                .map(|(key, _)| key.to_string())
                .collect::<Vec<_>>();
            for key in sub_keys.into_iter() {
                if value.has_key(&key) {
                    return Err(format!(
                        "Tried to convert URL but key '{}' already exists",
                        key
                    ));
                }
                value.insert(&key, sub_obj.remove(&key)).unwrap();
            }
        }
        Ok(value)
    } else {
        Err(format!("Invalid server JSON config: {}", value))
    }
}

fn convert_url_to_obj(url_str: &str) -> std::result::Result<JsonValue, String> {
    let url = Url::parse(url_str).map_err(|e| format!("Failed to parse url: {}", e))?;

    let mut json_obj = JsonValue::new_object();

    let proxy_scheme = url.scheme();

    json_obj.insert("scheme", proxy_scheme.to_string()).unwrap();

    let (username_label, password_label) = match proxy_scheme {
        "shadowsocks" | "ss" => ("cipher", "password"),
        "vmess" => ("user_id", "cipher"),
        "vless" => ("user_id", ""),
        "trojan" => ("password", ""),
        "socks" => ("password", ""),
        _ => ("username", "password"),
    };

    fn decode_auth_fields(username: &str, password: Option<&str>) -> (String, String) {
        let username = percent_decode_str(username)
            .decode_utf8()
            .unwrap()
            .to_string();
        match password {
            Some(password) => (
                username.to_string(),
                percent_decode_str(password)
                    .decode_utf8()
                    .unwrap()
                    .to_string(),
            ),
            None => {
                if username == "" {
                    return ("".to_string(), "".to_string());
                }
                // Check if it's base64.
                if let Ok(auth_bytes) = base64::decode(&username) {
                    if let Ok(auth_str) = String::from_utf8(auth_bytes) {
                        let tokens = auth_str.splitn(2, ':').collect::<Vec<_>>();
                        if tokens.len() == 2 {
                            return (tokens[0].to_string(), tokens[1].to_string());
                        } else {
                            return (username.to_string(), "".to_string());
                        }
                    }
                }
                (username.to_string(), "".to_string())
            }
        }
    }

    let (username, password) = decode_auth_fields(url.username(), url.password());

    if username != "" {
        json_obj.insert(username_label, username).unwrap();
    }

    if password != "" && password_label != "" {
        json_obj.insert(password_label, password).unwrap();
    }

    let host_str = match url.host_str() {
        Some(s) => s.to_string(),
        None => {
            return Err(format!("URL missing host: {}", url_str));
        }
    };

    let address = match url.port() {
        Some(port) => format!("{}:{}", host_str, port),
        None => host_str,
    };

    json_obj.insert("address", address).unwrap();

    for (query_key, query_value) in url.query_pairs().into_owned() {
        let new_value = JsonValue::String(
            percent_decode_str(&query_value)
                .decode_utf8()
                .unwrap()
                .into_owned(),
        );

        let mut key_parts = query_key.split('.').collect::<Vec<_>>();
        let final_part = key_parts.pop().unwrap();

        let mut current_obj = &mut json_obj;
        for key_part in key_parts.into_iter() {
            if !current_obj.has_key(&key_part) {
                current_obj[key_part] = JsonValue::new_object();
            }
            current_obj = &mut current_obj[key_part];
        }

        if current_obj.has_key(final_part) {
            let existing_value = &mut current_obj[final_part];
            if existing_value.is_array() {
                existing_value.push(new_value).unwrap();
            } else {
                let existing_value = current_obj.remove(final_part);
                current_obj
                    .insert(final_part, vec![existing_value, new_value])
                    .unwrap();
            }
        } else {
            current_obj.insert(final_part, new_value).unwrap();
        }
    }

    Ok(json_obj)
}

impl From<ServerProxyConfig> for Box<dyn TcpServerHandler> {
    fn from(server_proxy_config: ServerProxyConfig) -> Self {
        match server_proxy_config {
            ServerProxyConfig::Vmess {
                cipher_name,
                user_id,
                force_aead,
            } => Box::new(VmessTcpServerHandler::new(
                &cipher_name,
                &user_id,
                force_aead,
            )),
            ServerProxyConfig::Websocket { configs } => {
                assert!(configs.len() > 0);
                let server_targets: Vec<WebsocketServerTarget> =
                    configs.into_iter().map(Into::into).collect::<Vec<_>>();
                Box::new(WebsocketTcpServerHandler::new(server_targets))
            }
            ServerProxyConfig::Generic(proxy_config) => match proxy_config {
                ProxyConfig::HTTP { auth_credentials } => {
                    Box::new(HttpTcpServerHandler::new(auth_credentials))
                }
                ProxyConfig::Socks { auth_credentials } => {
                    Box::new(SocksTcpServerHandler::new(auth_credentials))
                }
                ProxyConfig::Shadowsocks(ShadowsocksConfig {
                    cipher_name,
                    password,
                }) => Box::new(ShadowsocksTcpHandler::new(&cipher_name, &password)),
                ProxyConfig::Vless { user_id } => Box::new(VlessTcpHandler::new(&user_id)),
                ProxyConfig::Trojan {
                    password,
                    shadowsocks_config,
                } => Box::new(TrojanTcpHandler::new(&password, &shadowsocks_config)),
            },
        }
    }
}

impl From<ClientProxyConfig> for Box<dyn TcpClientHandler> {
    fn from(client_proxy_config: ClientProxyConfig) -> Self {
        match client_proxy_config {
            ClientProxyConfig::Vmess {
                cipher_name,
                user_id,
                aead,
            } => Box::new(VmessTcpClientHandler::new(&cipher_name, &user_id, aead)),
            ClientProxyConfig::Websocket(websocket_client_config) => {
                let client_target: WebsocketClientTarget = websocket_client_config.into();
                Box::new(WebsocketTcpClientHandler::new(client_target))
            }
            ClientProxyConfig::Generic(proxy_config) => match proxy_config {
                ProxyConfig::HTTP { auth_credentials } => {
                    Box::new(HttpTcpClientHandler::new(auth_credentials))
                }
                ProxyConfig::Socks { auth_credentials } => {
                    Box::new(SocksTcpClientHandler::new(auth_credentials))
                }
                ProxyConfig::Shadowsocks(ShadowsocksConfig {
                    cipher_name,
                    password,
                }) => Box::new(ShadowsocksTcpHandler::new(&cipher_name, &password)),
                ProxyConfig::Vless { user_id } => Box::new(VlessTcpHandler::new(&user_id)),
                ProxyConfig::Trojan {
                    password,
                    shadowsocks_config,
                } => Box::new(TrojanTcpHandler::new(&password, &shadowsocks_config)),
            },
        }
    }
}

impl TryFrom<ServerProxyConfig> for Arc<dyn UdpMessageHandler> {
    type Error = std::io::Error;

    fn try_from(server_proxy_config: ServerProxyConfig) -> std::io::Result<Self> {
        match server_proxy_config {
            ServerProxyConfig::Generic(proxy_config) => match proxy_config {
                ProxyConfig::Shadowsocks(ShadowsocksConfig {
                    cipher_name,
                    password,
                }) => Ok(Arc::new(ShadowsocksUdpHandler::new(
                    &cipher_name,
                    &password,
                ))),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unsupported",
                )),
            },
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unsupported",
            )),
        }
    }
}
