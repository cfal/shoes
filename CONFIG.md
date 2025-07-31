# Configuration Guide

shoes uses a YAML-based configuration format. Each configuration file can contain multiple entries of different types.

## Configuration Types

There are four main configuration types:

1. Server configurations (`ServerConfig`)
2. Client proxy groups (`ClientConfigGroup`)
3. Rule groups (`RuleConfigGroup`)
4. Named PEM files (`NamedPem`)

## Named PEM Files

You can define PEM files (containing certificates and/or private keys) once and reference them throughout your configuration. This is particularly useful when the same certificate/key pair is used in multiple places.

### Named PEM
```yaml
pem: string                 # Name identifier for the PEM data
path: string                # File path to PEM file
# OR
data: string                # Inline PEM-encoded data
```

**Note**: A single PEM file can contain:
- Just a certificate
- Just a private key
- Both certificate and private key
- Multiple certificates (chain)
- Any combination of the above

When referenced in a `cert` field, only the certificate portion is used. When referenced in a `key` field, only the private key portion is used.

## Server Configuration

A server configuration defines a proxy server instance:

```yaml
bind_location: address | path  # Network address or Unix socket path (use a file path for Unix sockets)
protocol: ServerProxyConfig    # Server protocol configuration (see available types below)
transport: tcp | quic | udp     # Optional, defaults to tcp; note: Unix socket binding is supported only with tcp
tcp_settings:                   # Optional TCP settings
  no_delay: bool               # Default: true
quic_settings:                 # Required if transport is quic
  cert: string                # TLS certificate (path, inline PEM data, or named PEM reference)
  key: string                 # TLS private key (path, inline PEM data, or named PEM reference)
  alpn_protocols: [string]    # Optional ALPN protocols (alias: alpn_protocol)
  client_fingerprints: [string] # Optional allowed client cert fingerprints (alias: client_fingerprint)
  client_ca_certs: [string]   # Optional client CA certificates (path, inline PEM, or named PEM reference)
  num_endpoints: int          # Optional; if set to 0, defaults to the number of available threads
rules: string | RuleConfig    # Optional; defaults to allow-all-direct if omitted
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
  sni_targets:                # Map of SNI hostnames to TLS configs
    "example.com":
      cert: string           # Certificate (path, inline PEM data, or named PEM reference)
      key: string            # Private key (path, inline PEM data, or named PEM reference)
      alpn_protocols: [string]  # Optional ALPN protocols
      client_fingerprints: [string]  # Optional allowed client fingerprints
      client_ca_certs: [string]  # Optional client CA certificates
      protocol: ServerProxyConfig  # Inner protocol configuration
      override_rules: string | [RuleConfig]  # Optional override rules
  default_target:            # Optional default configuration
    cert: string
    key: string
    client_ca_certs: [string]
    protocol: ServerProxyConfig
    override_rules: string | [RuleConfig]
  tls_buffer_size: int       # Optional TLS buffer size (minimum 16384)
```

#### ShadowTLS v3 (in-process handshake)
```yaml
protocol:
  type: shadowtls
  sni_targets:                # Map of SNI hostnames to ShadowTLS v3 configs
    "example.com":
      password: string        # ShadowTLS password
      handshake:              # TLS handshake configuration; can be defined in two ways:
        cert: string         # Local handshake: certificate (path, inline PEM, or named PEM reference)
        key: string          # Local handshake: private key (path, inline PEM, or named PEM reference)
        alpn_protocols: [string]  # Optional ALPN protocols
        client_fingerprints: [string]  # Optional allowed client fingerprints
      protocol: ServerProxyConfig  # Inner protocol configuration
      override_rules: string | [RuleConfig]  # Optional override rules
  default_target:            # Optional default configuration for ShadowTLS v3
    password: string
    handshake: { ... }        # Handshake configuration (local or remote)
    protocol: ServerProxyConfig
    override_rules: string | [RuleConfig]
```

#### ShadowTLS v3 (remote handshake server)
```yaml
protocol:
  type: shadowtls
  sni_targets:                # Map of SNI hostnames to ShadowTLS v3 configs
    "example.com":
      password: string        # ShadowTLS password
      handshake:              # TLS handshake configuration; can be defined in two ways:
        address: example.com:443  # Remote handshake: address of handshake server
        client_proxies: ClientConfig # Remote handshake: client proxy configuration for handshake server
      protocol: ServerProxyConfig  # Inner protocol configuration
      override_rules: string | [RuleConfig]  # Optional override rules
  default_target:            # Optional default configuration for ShadowTLS v3
    handshake: { ... }        # Handshake configuration (local or remote)
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
  key: string?             # Optional client key (path, inline PEM, or named PEM reference)
  cert: string?            # Optional client cert (path, inline PEM, or named PEM reference)
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
bind_interface: string?      # Optional interface name (available on Linux, Android, or Fuchsia)
address: string             # Target address; defaults to unspecified if omitted
protocol: ClientProxyConfig   # Client protocol configuration
transport: tcp | quic | udp   # Optional, defaults to tcp
tcp_settings:                # Optional TCP settings
  no_delay: bool            # Default: true
quic_settings:              # Optional QUIC settings (only applicable if transport is quic)
  verify: bool             # Default: true
  server_fingerprints: [string]  # Optional allowed server fingerprints (alias: server_fingerprint)
  sni_hostname: string?    # Optional SNI hostname
  alpn_protocols: [string]   # Optional ALPN protocols (alias: alpn_protocol)
  key: string?            # Optional client key (path, inline PEM, or named PEM reference; must be paired with cert)
  cert: string?           # Optional client cert (path, inline PEM, or named PEM reference; must be paired with key)
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
client_proxies: string | ClientConfig | [string | ClientConfig]  # Required for allow action (alias: client_proxy)
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

## Certificate and Key Specification

Certificates and keys can be specified in three ways:

1. **File Path**: Provide the path to a PEM-encoded file
   ```yaml
   cert: "/etc/certs/server.pem"
   key: "/etc/certs/server.pem"  # Can be the same file if it contains both
   ```

2. **Inline PEM Data**: Embed the PEM data directly in the configuration
   ```yaml
   cert: |
     -----BEGIN CERTIFICATE-----
     MIIDXTCCAkWgAwIBAgIJAKl...
     -----END CERTIFICATE-----
   key: |
     -----BEGIN PRIVATE KEY-----
     MIIEvQIBADANBgkqhkiG9w0...
     -----END PRIVATE KEY-----
   ```

3. **Named PEM Reference**: Reference a previously defined named PEM
   ```yaml
   cert: "my-server-pem"  # References a named PEM (certificate portion will be used)
   key: "my-server-pem"   # References a named PEM (private key portion will be used)
   ```

**Important**: When a PEM file contains both certificate and private key, you can reference it in both `cert` and `key` fields. The system will automatically extract the appropriate portion.

## Examples

### Using Named PEM Files

```yaml
# Define named PEM files
- pem: "server-pem"
  path: "/etc/certs/server.pem"  # Contains both cert and key

- pem: "ca-cert"
  data: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKl...
    -----END CERTIFICATE-----

# Use named PEM files in server configurations
- bind_location: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "server-pem"       # Reference named PEM (cert portion)
    key: "server-pem"        # Reference named PEM (key portion)
    client_ca_certs:
      - "ca-cert"            # Reference named CA certificate
  protocol:
    type: socks

- bind_location: "0.0.0.0:8443"
  protocol:
    type: tls
    sni_targets:
      "example.com":
        cert: "server-pem"   # Reuse the same PEM file
        key: "server-pem"    # Reuse the same PEM file
        protocol:
          type: http
```

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

## Advanced Configuration Details

- Multiple configuration blocks can be combined in a single YAML file.
- Fields support aliases (e.g., "alpn_protocol" and "alpn_protocols", "client_proxy" for "client_proxies").
- For QUIC transport, if "num_endpoints" is set to 0, it defaults to the number of available CPU threads.
- Unix domain socket binding is supported only when using TCP transport.
- Client configurations require both certificate and key to be specified together.
- UUIDs in Vless and Vmess protocols are validated for correct format.
