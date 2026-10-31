---
title: "HTTP"
description: Shoes http configuration.
---

**Complete example:** [http_proxy_basic.yaml](/examples/http_proxy_basic/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: http
  username: string?            # Optional authentication
  password: string?
```

Accepts HTTP/1.0 and HTTP/1.1 CONNECT and absolute-form forwarding, plus
multiplexed TCP CONNECT over HTTP/2. H2 is detected from its connection preface;
cleartext H2 requires prior knowledge, not HTTP Upgrade. Authentication applies
independently to every H2 stream. A successful CONNECT response is sent only
after the destination connects.

H2 connections with no active tunnels close after 60 seconds; PINGs and rejected
authentication attempts do not extend that interval. Missing credentials receive
a 407 challenge. Incorrect credentials also begin connection shutdown, preventing
repeated password guesses on one carrier.

For HTTPS proxying, wrap HTTP in a TLS server and explicitly configure
`alpn_protocols: [h2, http/1.1]` on its TLS target. HTTP does not change the
parent layer's ALPN defaults. H2 GET/POST forwarding, extended CONNECT,
CONNECT-UDP, and HTTP/3 are not supported. This is standard HTTP proxying, not
NaiveProxy or XHTTP.


## Client

```yaml
protocol:
  type: http
  username: string?
  password: string?
  http_version: h1             # h1 (default) or h2
  resolve_hostname: false      # Resolve destinations locally before CONNECT
```

Both versions establish TCP CONNECT tunnels. When the H2 proxy is the first and
only hop, eligible routes reuse a connection for multiple concurrent tunnels.
Chained H2 hops use the carrier established through the selected prefix rather
than sharing tunnels across routes. H1 retains its existing one-tunnel-per-connection behavior.
There is no automatic version fallback or replay after a failed CONNECT.

For H2 over TLS, set `http_version: h2` here and `alpn_protocols: [h2]` on
the enclosing TLS client. The handshake must negotiate `h2`. Omitted or explicit
`http_version: h1` preserves legacy behavior: it sends HTTP/1.1 without checking
the negotiated ALPN. Set `alpn_protocols: [http/1.1]` on the enclosing TLS client
when the peer requires ALPN to match the HTTP version. Cleartext H2 uses prior
knowledge. See [examples/http2-proxy.yaml](/examples/http2-proxy/).
