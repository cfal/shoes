# shoes

shoes is a multi-protocol proxy server written in Rust.

## Supported protocols

- **Vmess**
  - TCP and UDP-over-TCP
  - AEAD and Legacy modes
  - Supported ciphers:
    - aes-128-gcm
    - chacha20-poly1305
- **Snell** v3
  - TCP and UDP-over-TCP
  - Supported ciphers:
    - aes-128-gcm
    - chacha20-poly1305
- **Shadowsocks**
  - TCP only
  - Supported ciphers:
    - aes-128-gcm
    - aes-256-gcm
    - chacha20-ietf-poly1305
    - 2022-blake3-aes-256-gcm
    - 2022-blake3-chacha20-ietf-poly1305
- **HTTP/HTTPS**
- **SOCKS5**
  - TCP only
- **Vless**
- **Trojan**

## Features

All supported protocols can be combined with the following features:

- **TLS support** with SNI based forwarding
- **Websocket obfs** (Shadowsocks SIP003)
- **Upstream proxy support**: route connections through other proxy servers
- **Forwarding rules (allowlists/blocklists)**: Block or redirect connections based on IP or hostname
- **Hot reloading**: Updated configs are automatically reloaded
- **Unix domain socket**: Bind to an interface, or listen on a UNIX domain socket
- **Netmask and proxy groups**

## Examples

Here's an example of running a WSS vmess and shadowsocks server, with all requests routed through a SOCKS proxy:

```yaml
# Listen on all IPv4 interfaces, port 443 (HTTPS)
- address: 0.0.0.0:443
  transport: tcp
  # Use TLS as the first protocol layer
  protocol:
    type: tls
    # Set a default target, for any (or no) SNI
    default_target:
      cert: cert.pem
      key: key.pem
      # ..which goes to a websocket server
      protocol:
        type: ws
        # .. where we have different supported proxy protocols, based on HTTP request path and headers.
        targets:
          - matching_path: /vmess
            matching_headers:
              X-Secret-Key: "secret"
            protocol:
              type: vmess
              # allow any cipher, which means: none, aes-128-gcm, or chacha20-poly1305.
              cipher: any
              user_id: b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4
          - matching_path: /shadowsocks
            protocol:
              type: shadowsocks
              cipher: 2022-blake3-aes-256-gcm
              password: Hax8btYlNao5qcaN/l/NUl9JgbwapfqG5QyAtH+aKPg=
  rules:
    # Allow clients to connect to all IPs
    - mask: 0.0.0.0/0
      action: allow
      # Forward all requests through a local SOCKS server.
      client_proxy:
        address: 127.0.0.1:5000
        protocol:
          type: socks
          username: socksuser
          password: secretpass
```

For other YAML config examples, see the [examples](./examples) directory.

## Usage

```
shoes [OPTIONS] <YAML CONFIG PATH> [YAML CONFIG PATH] [..]

OPTIONS:

    -t, --threads NUM
        Set the number of worker threads. This usually defaults to the number of CPUs.

    -d, --dry-run
        Parse the config and exit.
```

## Config format

Sorry, formal documentation for the YAML config format have not yet been written. You can refer to the [examples](./examples), or open an issue if you need help.

## Roadmap

- Proxy client chaining
- SOCKS and Shadowsocks UDP support
