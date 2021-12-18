# shoes

shoes is a multi-protocol proxy server written in Rust.

- Supported TCP protocols
  - **HTTP/HTTPS**
  - **SOCKS5**
  - **Shadowsocks**
    - Supported ciphers: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  - **Vmess**
    - Supported ciphers: aes-128-gcm, chacha20-poly1305
    - AEAD mode support
  - **Trojan**
    - Optional Shadowsocks cipher support
- Supported UDP protocols
  - **Shadowsocks**

## Features

- **TLS support**: use TLS/SSL with any supported TCP proxy protocol
- **Websocket obfs (Shadowsocks SIP003)** for all supported TCP protocols
  - Multi-path support: for example, run a single websocket server on a single port that serves Vmess at one path, and Shadowsocks at another path.
- **Upstream proxy support**: route connections through other proxy servers in a round-robin fashion
- **Forwarding rules**: Block or redirect connections based on IP or hostname

## Usage

`shoes <JSON config file or URL> [JSON config file or URL] [..]`

## Configuration format

Single line comments starting with `//` are supported in JSON config files.

Configuration can be provided in URL or JSON format, or a combination of both. For example, the following configs are all equivalent:

```
"ss://chacha20-ietf-poly1305:hello@0.0.0.0:62813/?tls=true&cert=cert.pem&key=key.pem"
```

```js
{
  "scheme": "shadowsocks",
  "cipher": "chacha20-ietf-poly1305",
  "password": "hello",
  "address": "0.0.0.0:62813",
  "tls": "true",
  "cert": "cert.pem",
  "key": "key.pem"
}
```

```js
{
  "url": "ss://chacha20-ietf-poly1305:hello@0.0.0.0:62813",
  "tls": "true",
  "cert": "cert.pem",
  "key": "key.pem"
}
```

## Websocket obfs (SIP003) configuration

Websocket obfs configuration is different from other proxy servers. They are configured as websocket servers that can provide different proxy protocols. See some of the example configs below.

## Example configs

[Multiple servers with one process](#multiple-servers-with-one-process)

[SOCKS5 TLS server with upstream proxies](#socks5-tls-server-with-upstream-proxies)

[SOCKS5 server that connects using a Vmess proxy](#socks5-server-that-connects-using-a-vmess-proxy)

[Trojan server that connects using a Vmess proxy server over websocket obfs](#trojan-server-that-connects-using-a-vmess-proxy-server-over-websocket-obfs-sip003)

[Websocket (SIP033 obfs) server with Vmess and Shadowsocks](#websocket-sip033-obfs-server-with-vmess-and-shadowsocks)


### Multiple servers with one process

```js
[
  // run a shadowsocks server with aes-256-gcm encryption (password hello) on port 10000.
  {
    "url": "ss://aes-256-gcm:hello@0.0.0.0:10000"
  },
  // run a socks5 server with authentication on port 20000.
  {
    "url": "socks5://user:pass@0.0.0.0:20000"
  },
  // run a vmess server on port 30000.
  {
    "url": "vmess://c63425cc-3dca-439f-a323-832d03cd0658:chacha20-poly1305@0.0.0.0:30000"
  }
]
```

### SOCKS5 TLS server with upstream proxies

```js
{
  // Run a SOCKS5 server on port 5000.
  "url": "socks5://username:password@0.0.0.0:5000",

  // Note that the 'tls' field is optional. When 'cert' and 'key' are provided, it is
  // assumed that TLS needs to be enabled.
  "tls": true,

  "cert": "cert.pem",
  "key": "keyfile.pem",

  // Connections to the SOCKS5 server will be routed through these proxies, in
  // round-robin fashion.
  "proxies": [
    // Connect using a HTTP proxy
    "http://1.2.3.4:5555",
    // .. and a trojan proxy
    "trojan://password@5.6.7.8:9999",
    // .. and another SOCKS5 TLS proxy.
    "socks5://username:password@4.3.2.1:32145/?tls=true"
  ]
}
```

### SOCKS5 server that connects using a Vmess proxy

```js
{
  "url": "socks5://username:password@0.0.0.0:5000",
  "proxies": [
    "vmess://c63425cc-3dca-439f-a323-832d03cd0658:chacha20-poly1305@0.0.0.0:30000"
  ]
}
```

### Trojan server that connects using a Vmess proxy server over websocket obfs (SIP003)

```js
{
  // Run a trojan server on port 6000 with password 'abcd1234'.
  "url": "trojan://abcd1234@0.0.0.0:6000",
  "proxies": [
    {
      // Connect using a websocket server that provides vmess support, which can be
      // accessed using path '/ws', with host header 'example.com'
      //
      // in other words: 'vmess server with websocket obfs, obfs path /ws and obfs host example.com'
      "url": "wss://2.3.4.5:443",
      "target": {
        "matching_headers": {
          "host": "example.com"
        },
        "matching_path": "/ws",
        "scheme": "vmess",
        "user_id": "e05b95db-a229-4f64-b2b3-b6073b4eb6c4",
        "cipher": "chacha20-poly1305"
      }
    }
  ]
}
```

### Websocket (SIP033 obfs) server with Vmess and Shadowsocks

```js
{
  // Run a websocket server over TLS (wss) on port 443.
  "url": "wss://0.0.0.0:443",

  // TLS configuration
  "cert": "cert.pem",
  "key": "keyfile.pem",

  "targets": [
    // Serve shadowsocks at obfs path /ss, obfs host example.com
    {
      "matching_path": "/ss",
      "matching_headers": {
        "host": "example.com"
      },
      "scheme": "shadowsocks",
      "cipher": "aes-256-gcm",
      "password": "hello",
    },

    // Serve shadowsocks at obfs path /ss2, where requests are routed through a HTTPS proxy.
    // Any obfs host can be provided, since we do not specify it.
    {
      // Targets can also be specified using URL format, but note that the address is unused.
      "matching_path": "/ss2",
      "url": "shadowsocks://aes-256-gcm:hello@unused-address.com",
      "proxies": [
        "https://username:password@1.2.3.4:8080"
      ]
    },

    // Serve vmess at obfs path /vmess, obfs host 'hello.com', when the user-agent is 'secret-client-v1.0'
    {
      "matching_path": "/vmess",
      "matching_headers": {
        "host": "hello.com",
        "user-agent": "secret-client-v1.0"
      },
      "url": "vmess://3f4c7cb7-54fa-4965-b4f7-255047554831:chacha20-poly1305@unused-address.com"
    }
  ]
}
```
