# Configuration Guide

shoes uses a YAML-based configuration format. Each configuration file can contain multiple entries of different types.

## Configuration Types

There are three main configuration types:

1. Server configurations (`ServerConfig`)
2. Client proxy groups (`ClientConfigGroup`)
3. Rule groups (`RuleConfigGroup`)

## Server Configuration

A server configuration defines a proxy server instance:

```yaml
bind_location: address | path  # Network address or Unix socket path
protocol: ServerProxyConfig    # Server protocol configuration
transport: tcp | quic | udp    # Optional, defaults to tcp
tcp_settings:                  # Optional TCP settings
  no_delay: bool              # Default: true
quic_settings:                # Required if transport is quic
  cert: string               # TLS certificate path
  key: string                # TLS private key path
  alpn_protocols: [string]   # Optional ALPN protocols
  client_fingerprints: [string] # Optional allowed client cert fingerprints
rules: string | RuleConfig   # Optional, defaults to allow-all-direct
```

## Protocol Types

### Server Protocols

#### HTTP/SOCKS5 Proxy
```yaml
protocol:
  type: http | socks
  username: string?  # Optional
  password: string?  # Optional
```

#### Shadowsocks
```yaml
protocol:
  type: shadowsocks | ss
  cipher: string         # Encryption algorithm
  password: string
```

#### Snell
```yaml
protocol:
  type: snell
  cipher: string         # Encryption algorithm
  password: string
  udp_enabled: bool      # Optional, defaults to true
  udp_num_sockets: int   # Optional, defaults to 1
```

#### VLESS
```yaml
protocol:
  type: vless
  user_id: string  # UUID
```

#### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:      # Optional additional encryption
    cipher: string
    password: string
```

#### VMess
```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string   # UUID
  force_aead: bool  # Default: true
  udp_enabled: bool # Default: true
```

#### TLS Server
```yaml
protocol:
  type: tls
  sni_targets:                # Map of SNI hostnames to configs
    "example.com":
      cert: string           # Certificate path
      key: string            # Private key path
      alpn_protocols: [string]  # Optional ALPN protocols
      client_fingerprints: [string]  # Optional allowed client fingerprints
      protocol: ServerProxyConfig  # Inner protocol configuration
      override_rules: string | [RuleConfig]  # Optional override rules
  default_target:            # Optional default configuration
    cert: string
    key: string
    protocol: ServerProxyConfig
    override_rules: string | [RuleConfig]
```

#### WebSocket
```yaml
protocol:
  type: websocket | ws
  targets:
    - matching_path: string?     # Optional path to match
      matching_headers:          # Optional headers to match
        header_name: string
      protocol: ServerProxyConfig  # Inner protocol configuration
      ping_type: disabled | ping-frame | empty-frame  # Default: ping-frame
      override_rules: string | [RuleConfig]  # Optional override rules
```

#### Port Forward
```yaml
protocol:
  type: forward | port_forward
  targets: string | [string]  # Target address(es) to forward to
```

#### Hysteria2
```yaml
protocol:
  type: hysteria2
  password: string    # Proxy password
  udp_enabled: bool   # Optional, defaults to true
```

#### Tuic v5
```yaml
protocol:
  type: tuic | tuicv5
  uuid: string        # UUID for identification
  password: string
```

### Client Protocols

Client protocols (`ClientProxyConfig`) include all server protocols plus:

#### Direct Connection
```yaml
protocol:
  type: direct
```

#### TLS Client
```yaml
protocol:
  type: tls
  verify: bool               # Default: true
  server_fingerprints: [string]  # Optional allowed server fingerprints
  sni_hostname: string?     # Optional SNI hostname
  alpn_protocols: [string]  # Optional ALPN protocols
  key: string?             # Optional client key
  cert: string?            # Optional client cert
  protocol: ClientProxyConfig  # Inner protocol configuration
```

#### WebSocket Client
```yaml
protocol:
  type: websocket | ws
  matching_path: string?     # Optional path to match
  matching_headers:          # Optional headers to match
    header_name: string
  ping_type: disabled | ping-frame | empty-frame  # Default: ping-frame
  protocol: ClientProxyConfig  # Inner protocol configuration
```

## Client Configuration

A client configuration defines proxy client settings:

```yaml
bind_interface: string?     # Optional interface name (Linux/Android only)
address: string            # Optional target address
protocol: ClientProxyConfig  # Client protocol configuration
transport: tcp | quic | udp  # Optional, defaults to tcp
tcp_settings:               # Optional TCP settings
  no_delay: bool           # Default: true
quic_settings:             # Optional QUIC settings
  verify: bool            # Default: true
  server_fingerprints: [string]  # Optional allowed server fingerprints
  sni_hostname: string?   # Optional SNI hostname
  alpn_protocols: [string]  # Optional ALPN protocols
  key: string?           # Optional client key
  cert: string?          # Optional client cert
```

## Client Proxy Groups

Client proxy groups allow defining reusable proxy configurations:

```yaml
client_group: string
client_proxies: ClientConfig | [ClientConfig]
```

## Rule Groups

Rule groups define access control and routing rules:

```yaml
rule_group: string
rules: RuleConfig | [RuleConfig]
```

### Rule Configuration

```yaml
masks: string | [string]  # IP/CIDR masks to match
action: allow | block     # Action to take
override_address: string?  # Optional address override for allow action
client_proxies: string | ClientConfig | [string | ClientConfig]  # Required for allow action
```

## Built-in Defaults

The system includes these built-in defaults:

### Client Groups
- `direct`: Direct connections without proxy

### Rule Groups
- `allow-all-direct`: Allows all traffic directly
- `block-all`: Blocks all traffic

## Security Considerations

1. TLS/QUIC Security:
   - Use strong certificates and private keys
   - Consider enabling client certificate authentication
   - Use secure cipher suites
   - Verify certificate fingerprints when possible

2. Authentication:
   - Use strong passwords for all authentication methods
   - Consider using client certificates where supported
   - Rotate credentials regularly

3. Network Security:
   - Be cautious with 0.0.0.0 bind addresses
   - Use firewalls to restrict access
   - Consider binding to specific interfaces when possible
   - Monitor logs for suspicious activity

4. WebSocket Security:
   - Use path and header matching to restrict access
   - Consider using TLS for transport security
   - Implement rate limiting if needed

## Examples

### Basic HTTP Proxy Server
```yaml
bind_location: "127.0.0.1:8080"
protocol:
  type: http
  username: user
  password: pass
```

### SOCKS5 with TLS
```yaml
bind_location: "0.0.0.0:1080"
protocol:
  type: tls
  sni_targets:
    "proxy.example.com":
      cert: "cert.pem"
      key: "key.pem"
      protocol:
        type: socks
        username: user
        password: pass
```

### VMess over WebSocket
```yaml
bind_location: "0.0.0.0:443"
protocol:
  type: websocket
  targets:
    - matching_path: "/vmess"
      protocol:
        type: vmess
        cipher: auto
        user_id: "123e4567-e89b-12d3-a456-426614174000"
```

### Complex Routing Setup
```yaml
# Define client proxies
client_group: "proxies"
client_proxies:
  - protocol:
      type: shadowsocks
      cipher: chacha20-ietf-poly1305
      password: secret1
  - protocol:
      type: vmess
      cipher: auto
      user_id: "123e4567-e89b-12d3-a456-426614174000"

# Define routing rules
rule_group: "routing"
rules:
  - masks: "192.168.0.0/16"
    action: allow
    client_proxy: direct
  - masks: "0.0.0.0/0"
    action: allow
    client_proxy: proxies

# Main server config
bind_location: "0.0.0.0:8080"
protocol:
  type: http
rules: routing
```

### Hysteria2 Proxy Server
```yaml
bind_location: "0.0.0.0:4443"
protocol:
  type: hysteria2
  password: "hysteria_secret"
  udp_enabled: true
```

### Tuic v5 Proxy Server
```yaml
bind_location: "0.0.0.0:5555"
protocol:
  type: tuicv5
  uuid: "123e4567-e89b-12d3-a456-426614174000"
  password: "tuic_secret"
```
