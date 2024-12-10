# Configuration Guide

shoes uses a YAML-based configuration format for defining servers, proxies, and routing rules. Each configuration file can contain multiple entries of different types.

## Configuration Types

There are three main types of configuration entries:

1. Server configurations (`ServerConfig`)
2. Client proxy groups (`ClientConfigGroup`) 
3. Rule groups (`RuleConfigGroup`)

## Server Configuration

A server configuration defines a proxy server instance. Required fields:

- `bind_location`: Where the server listens for connections
  - `address`: Network address (e.g. "127.0.0.1:8080")
  - `path`: Unix domain socket path
- `protocol`: Server protocol configuration (see Protocol Types below)
- `transport`: Transport layer protocol (optional)
  - `tcp` (default)
  - `quic` 
  - `udp`
- `tcp_settings`: TCP-specific settings (optional)
  - `no_delay`: Boolean, default true
- `quic_settings`: QUIC-specific settings (required if transport is quic)
  - `cert`: TLS certificate path
  - `key`: TLS private key path
  - `alpn_protocols`: Optional list of ALPN protocols
  - `client_fingerprints`: Optional list of allowed client certificate fingerprints
- `rules`: Access control rules (optional, defaults to allow all direct)

Example:
```yaml
- bind_location: "127.0.0.1:8080"
  protocol:
    type: http
  transport: tcp
  tcp_settings:
    no_delay: true
  rules: "my-rules"  # Reference to a rule group
```

## Protocol Types

### Server Protocols

#### HTTP Proxy
```yaml
protocol:
  type: http
  username: string  # Optional
  password: string  # Optional
```

#### SOCKS5 Proxy
```yaml
protocol:
  type: socks  # or socks5
  username: string  # Optional
  password: string  # Optional
```

#### Shadowsocks
```yaml
protocol:
  type: shadowsocks  # or ss
  cipher: string     # Encryption algorithm
  password: string
```

#### Snell
```yaml
protocol:
  type: snell
  cipher: string  # Encryption algorithm
  password: string
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
  shadowsocks:     # Optional additional encryption
    cipher: string
    password: string
```

#### VMess
```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string  # UUID
  force_aead: bool   # Default: true
  udp_enabled: bool  # Default: true
```

#### TLS Server
```yaml
protocol:
  type: tls
  sni_targets:      # Map of SNI hostnames to configs
    "example.com":
      cert: string  # Certificate path
      key: string   # Private key path
      alpn_protocols: [string]  # Optional ALPN protocols
      client_fingerprints: [string]  # Optional allowed client cert fingerprints
      protocol:     # Inner protocol configuration
        type: ...   # Any other protocol type
      override_rules: [RuleConfig]  # Optional override rules
  default_target:   # Optional default configuration
    cert: string
    key: string
    protocol:
      type: ...
    override_rules: [RuleConfig]
```

#### WebSocket
```yaml
protocol:
  type: websocket  # or ws
  targets:
    - matching_path: string     # Optional path to match
      matching_headers:         # Optional headers to match
        header_name: string
      protocol:                # Inner protocol configuration
        type: ...
      ping_type: string        # "disabled", "ping-frame", or "empty-frame"
      override_rules: [RuleConfig]  # Optional override rules
```

#### Port Forward
```yaml
protocol:
  type: forward  # or port_forward
  targets: string | [string]  # Target address(es) to forward to
```

### Client Protocols

Client protocols are used in client proxy configurations and include all server protocols plus:

#### Direct Connection
```yaml
protocol:
  type: direct
```

## Client Proxy Groups

Client proxy groups allow defining reusable proxy configurations:

```yaml
- client_group: string
  client_proxies:
    - address: 1.2.3.4
      protocol:             # Client protocol configuration
        type: ...
      ...
    - address: 3.4.5.6
```

## Rule Groups

Rule groups define access control and routing rules:

```yaml
- rule_group: string
  rules:
    - masks: string | [string]  # IP/CIDR masks to match
      action: string           # "allow" or "block"
      override_address: string # Optional address override
      client_proxy: string | [string]  # Client proxy or group reference
```

## Built-in Defaults

The system includes these built-in defaults:

- Client Groups:
  - `direct`: Direct connections without proxy

- Rule Groups:
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
- bind_location: "127.0.0.1:8080"
  protocol:
    type: http
    username: user
    password: pass
```

### SOCKS5 with TLS
```yaml
- bind_location: "0.0.0.0:1080"
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
- bind_location: "0.0.0.0:443"
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
- client_group: "proxies"
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
- rule_group: "routing"
  rules:
    - masks: "192.168.0.0/16"
      action: allow
      client_proxy: direct
    - masks: "0.0.0.0/0"
      action: allow
      client_proxy: proxies

# Main server config
- bind_location: "0.0.0.0:8080"
  protocol:
    type: http
  rules: routing
```

