---
title: "Certificate Sources"
description: shoes certificate sources configuration.
---

Ordinary TLS targets and QUIC listeners can share a named certificate source.
Use `certificate_source` instead of `cert` and `key`; combining them is an error.
Existing inline certificates, file paths, and named PEMs remain supported.

```yaml
- certificate_source: public
  type: files
  cert: /etc/shoes/certs/fullchain.pem
  key: /etc/shoes/certs/privkey.pem

- address: "0.0.0.0:443"
  protocol:
    type: tls
    tls_targets:
      proxy.example.com:
        certificate_source: public
        protocol: {type: trojan, password: change-me}

- address: "0.0.0.0:443"
  transport: quic
  quic_settings:
    certificate_source: public
  protocol: {type: hysteria2, password: change-me}
```

There is one runtime worker per source, not per listener. File sources use the
same filesystem watcher machinery as configuration files, with a 250 ms quiet
period after the last relevant event. They support atomic rename and symlink
replacement. Both the full certificate chain and its matching private key must
validate before publication. Separate file writes, missing files, malformed
data, key mismatches, and invalid validity
periods leave the last good pair in place. Failed updates retry every second;
a 60-second internal reconciliation also recovers missed events or unavailable
watches. Neither interval is a configuration setting. Errors are rate-limited
and never include private material. An expired source fails new handshakes
rather than serving a substitute certificate. Existing connections continue
uninterrupted.

Initial file-source loading (including legacy paths) rejects expired or not-yet-valid
chains, malformed or misordered chains, and PEM files larger than 1 MiB. A rejected
configuration reload leaves the current listeners running and watches the candidate's
file paths so repairing the pair retries the reload. After activation, identity-only
changes use live rotation, not a full reload.

**Upgrade warning:** These checks also apply to existing `cert`/`key` file paths
and file-backed named PEMs, even without a configuration change. Previously accepted
expired or not-yet-valid certificates and misordered bundles now reject at startup;
running file sources stop serving at expiry, including when clients disable
verification or pin a fingerprint. Renew expired certificates, put bundles in
leaf-to-issuer order, remove expired cross-signs and certificates outside that chain,
and synchronize the system clock before starting shoes. Child-to-issuer signatures
must use algorithms supported by the TLS provider: no SHA-1, and RSA issuer keys
must be at least 2048 bits. Reissue certificates with unsupported signatures.
Inline-only pairs retain their previous static behavior.

Legacy `cert`/`key` paths, including paths referenced through named PEMs, also
rotate live through these watches. Inline-only pairs stay static. This applies
to ordinary inbound TLS and QUIC, including Hysteria2, TUIC and XHTTP. Outbound
client certificates, trust roots, and local ShadowTLS handshake certificates
instead trigger a full CLI configuration reload when their referenced files
change, including named PEM references. If a file serves both roles, a full
reload is still necessary. REALITY's handshake behavior is unchanged.

New handshakes use the current certificate without replacing TCP listeners or
QUIC endpoints. TLS session state is scoped to the certificate generation and
the listener's security policy: sessions resume within a generation, but not
across rotation or expiration. Existing TCP and QUIC sessions are not retired.

### Built-in ACME

ACME uses `instant-acme` and explicitly configured domains. Start with your CA's
staging directory. No certificate is issued during `--dry-run`.

```yaml
- certificate_source: public
  type: acme
  domains: [proxy.example.com]
  directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
  state_dir: /var/lib/shoes/acme/public
  contacts: [mailto:operator@example.com]
  # Read the CA's terms, then set this to its exact meta.termsOfService URL.
  terms_of_service: https://example.invalid/replace-with-accepted-ca-terms-url
  challenge:
    type: http01
    listen: ["0.0.0.0:8080"]
```

Reference `public` from TLS or QUIC as in the file-source example. Domains must
be unique lowercase ASCII DNS names (use punycode for internationalized names).
Every named TLS target using an ACME source must be covered by its domains.
There is no issuance based on incoming SNI.

`terms_of_service` is explicit acceptance of that exact URL, not blanket
acceptance of future terms. shoes checks the directory's `meta.termsOfService`
before account operations and refuses a changed URL. Review new terms and
update the configuration to accept them. If a private CA publishes no terms,
omit this field; a subsequently advertised terms URL still requires explicit
acceptance. Accounts requiring external account
binding are not supported in this version.

HTTP-01 requirements:

- The CA must reach public TCP port 80 for every domain, forwarded to one of the
  explicit `listen` addresses. shoes never implicitly binds port 80.
- The challenge listener is independent of proxy listeners, so UDP-only QUIC
  deployments can use HTTP-01. A reverse proxy/CDN must forward the exact
  `/.well-known/acme-challenge/` path and original Host header.
- Listen addresses must not overlap another HTTP-01 source or a TCP proxy
  listener. Use a single multi-domain source when sharing the challenge address.
  Dry-run checks literal addresses and port ranges; a hostname-bound TCP
  listener on the same port is conservatively treated as a conflict.
- Only exact, pending, unexpired GET challenges are answered. Unknown tokens
  return 404. Headers are limited to 8 KiB / 32 fields, with at most 64 concurrent
  connections per address and a 10-second request lifetime.

For TLS-ALPN-01, replace the `challenge` mapping with:

```yaml
  challenge: {type: tls_alpn01}
```

The CA must reach public TCP port 443, forwarded to an existing outermost shoes
TLS listener covering every configured domain. This is not QUIC, ShadowTLS or
REALITY validation. An intermediate TLS terminator must pass the handshake
through, including SNI and ALPN. shoes only answers the sole offered protocol
`acme-tls/1` for a pending configured SNI. The short-lived challenge response
uses the RFC 8737 critical `acmeIdentifier` extension and never enters the proxy
handler or replaces the ordinary certificate. Normal ALPN, client authentication,
fallback routing and QUIC policy are unchanged.

At first start, proxy and challenge listeners bind before issuance begins.
Normal handshakes for a source without a certificate fail until issuance
succeeds; `Servers ready` means listeners are bound, not that ACME has finished.
A valid cached certificate allows immediate startup during a CA outage.

shoes persists the account key before registration, account credentials,
in-progress orders and CSR keys, and the certificate/key pair in one atomically
replaced, synced state file. Do not edit it or share it between sources. On Unix,
the state directory must be owned by the running user with mode 0700, and files
use 0600. Other platforms use their inherited filesystem access controls; place
the directory in private application storage. An exclusive OS file lock prevents
multiple processes or embedded lifecycles from owning the same directory.
Back up the whole directory securely. Changing the CA or domain list requires a
distinct state directory; staging and production must never share one.

Renewal normally begins with one third of the certificate's lifetime remaining.
ARI is checked while idle and can request earlier renewal when the CA and
certificate support it. Its Retry-After applies only to ARI; optional checks,
including account setup, cannot delay due renewal. The source worker alone
schedules requests and durable deadlines. Pending orders use a five-second
polling interval unless the CA requests a longer wait. Transient
failures preserve valid material and use jittered exponential backoff from 60
seconds to 6 hours, honoring longer CA Retry-After values. Retry-After waits over
100 years or outside the platform clock range are rejected. Each worker step is
bounded to 10 minutes. Pending and processing orders are polled until the CA
completes, invalidates, or removes them. A completed pair is persisted before
it becomes live. Storage errors do not publish an unpersisted replacement.
Order retry deadlines, including successful finalization and resumed orders,
survive restart; startup logs an inherited delay rather than bypassing it.
The failure backoff resets after installation or healthy idle, not after a
deferred wake or a successful intermediate order step. Its exponent is kept
in memory; the selected deadline survives restart.
ARI retry deadlines also survive restart, including failed ARI responses.
Missing or invalid orders are discarded so a later attempt can create a new one.
Certificate failures and inherited retry delays are visible with the default
error-only logging; successful issuance and rotation use the info level.
During deferred polling, pending challenge responses remain
available until their 10-minute lease expires, the order leaves the pending
state, or the source is stopped.

CA traffic goes directly through the OS resolver and shoes' protected TCP socket
helper, not through proxy rules or the certificate being issued. HTTPS verifies
the CA hostname and public roots. Optional `ca_cert: /path/to/test-ca.crt`
replaces those roots for a private CA. Requests have a 30-second total timeout,
32 KiB response header limit and 1 MiB response body limit; redirects are not
followed. Plain HTTP directories/endpoints are accepted only on numeric loopback
addresses for local testing. Never disable verification for a public CA.

Configuration reload reuses unchanged sources and their workers, accounts and
pending challenges. Changed sources hand off storage and challenge listeners
when a validated reload commits. Retired challenge ports are released before
new proxy listeners bind; failed preparation does not mutate live sources.
When an existing proxy address moves to HTTP-01, its challenge bind is deferred
until the old proxy has stopped. Narrowing a proxy wildcard within the same IP
family is also supported. Other challenge addresses are still bound during
preparation: widening bindings, changing IP families, or replacing a challenge
wildcard binding may require a restart or two separate reloads to avoid conflicts.
Removed sources are canceled. CLI and mobile/FFI use the same
manager, with no process-global certificate registry. Mobile deployments still
need externally reachable challenge ports and persistent application storage.

`--dry-run` validates configuration, references, domain coverage, challenge
compatibility, certificate material and declared address conflicts without
contacting a CA, binding ports, or creating ACME state. An unissued ACME source
is a valid configuration, not a self-signed placeholder. Existing readable state
is checked for CA/domain identity mismatches without locking or modifying it;
the check need not run as the service user.
Actual OS port conflicts,
storage ownership and permissions are checked during runtime preparation.

There is no built-in DNS-01, wildcard ACME issuance, DNS vendor API, shell hook,
Tailscale provider, or Cloudflare Origin CA provider. For wildcard certificates
or DNS-01, run an external client such as acme.sh, lego or Certbot and use a file
source. Manually supplied wildcard certificates remain supported.

Examples: [file rotation and reuse](/examples/certificates_files/) and
[ACME with shared TCP/QUIC consumers](/examples/certificates_acme/).
