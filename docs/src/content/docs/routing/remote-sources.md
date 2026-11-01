---
title: Remote rule sources
description: Download, cache, refresh, and validate remote rule data.
---

Remote sources are optional. [Local sources](/routing/rules/#local-rule-sources)
continue to work without network access. The example below uses placeholder
URLs and is illustrative, not a ready-to-run configuration.

Use `url` to load a remote source. Persistent caching is optional. The same
source object works in `rule_source_group.rules`, under `masks` (including
`all`/`any`/`not`), or flat alongside `action` in a policy group's rules, a server's
`rules`, or supported `override_rules`. A flat source cannot also specify `masks`.

```yaml
- global_settings:
    rule_cache_dir: ./cache

- rule_source_group: regional
  rules:
    - url: https://example.net/geoip-cn.srs
      update_interval: 7d
      download:
        client_chain: direct
        bootstrap_url: system

- address: "0.0.0.0:1080"
  protocol: {type: socks}
  rules:
    - masks: {rule_source_group: regional}
      action: block
    - url: https://example.net/blocked.json
      download:
        client_chain:
          address: "proxy.example.net:1080"
          protocol: {type: socks}
        bootstrap_url: system
      action: block
    - masks: {any_destination: true}
      action: allow
```

Replace `proxy.example.net:1080` with your proxy address. `download.client_chain` accepts
the existing chain, pool, inline-client, and group syntax. It is independent of
the outer policy's `client_chain`, which routes matched traffic. Both
`download.client_chain` and `download.bootstrap_url` are required. Bootstrap may
be `system`, an IP-based DNS URL, or a named DNS group. Target and proxy hostnames
use this resolver; failed refresh routing never falls back to direct. Automatic
refresh uses the active generation's DNS, proxy clients, and selector choices.

All runtime remote sources use compiled rules retained in memory, including when
disk caching is enabled. Reloads reuse sources whose URL and decoding options
are unchanged; runtime compilation never falls back to cache files.
Omit `global_settings.rule_cache_dir` to disable persistence. shoes downloads required sources
before starting listeners. Periodic refresh still applies;
failed downloads or rejected candidates leave the active rules unchanged. No
cache, lock, staging, or temporary files are created. Download buffers are released
after validation and optional cache saving; byte-identical refreshes do not recompile the rules.
A cold start requires network access; a remote outage prevents startup when
there is no persistent cache. `check` and `--dry-run` remain offline and cannot
validate memory-only remote sources. Local file sources still require `path`.

`global_settings.rule_cache_dir` enables best-effort persistence in one private managed directory
across all config files. Valid downloads remain usable even when saving fails.
Cache-save failures are logged; the next successful download retries saving,
including byte-identical downloads. Until a save succeeds, a restart may restore
older cached rules or require network access.
Use persistent caching on routers that must restart while the origin is unavailable.
Its value is relative to the declaring file and fixed for the process lifetime:
adding, changing, or removing it requires a restart, even without remote sources.
Remote `path` is optional: when omitted, shoes generates a stable filename from
the URL and decoding options. Explicit remote paths require `rule_cache_dir` and
must be direct children of that directory. Configuration, local
rule sources (including aliases), PEMs, sockets, and other state must be outside
it. ACME state directories cannot contain or be contained by the cache directory.
On Linux, `/run/shoes` is reserved for managed-TUN ownership and recovery files;
use a separate cache directory, such as `/run/shoes/rule-cache`, instead.
The directory must be owned by the running user and not group- or world-writable
(for example, create it with `install -d -m 700 cache`). Cache files must be owned,
regular, singly linked, not group- or world-writable, and have no setuid, setgid,
or sticky mode bits. Symlinks in any path component
and `..` traversal are rejected. `owner.lock`, `.shoes-update.lock`, and
`.shoes-update.tmp` sidecars are reserved. The daemon holds an exclusive directory
lease; another daemon cannot use the same directory concurrently.
Replacing the directory or `owner.lock` invalidates the lease; subsequent runtime
cache reads and writes are rejected until restart, without acquiring a replacement
lease. Retained rules, downloads, and configuration reloads can continue in memory.
Identical declarations sharing a cache are deduplicated;
conflicting declarations are rejected. Local-only file sources are unchanged.

`format` remains optional: explicit override, recognized SRS/MRS signature, URL
pathname extension (ignoring query), then cache-path extension. All local decoders
are supported; DAT still needs explicit format/code, and Mihomo YAML/text needs
behavior. Invalid decoding never retries a different format.

`update_interval` defaults to `24h`; use a positive integer with `s`, `m`, `h`, or
`d`, from `1s` through `365d`. Daemon startup restores valid cached sources into
memory. Missing, unreadable, invalid, or empty cached sources are fetched through
their configured download routes before preparing candidate listeners. Unsafe
files are never read or replaced; a fresh download may still run in memory.
Initial directory creation and exclusive lease acquisition must succeed when
`rule_cache_dir` is configured. Reloads prefer retained rules, so removing or editing
a cache does not force a refetch. Changing a retained source's URL or decoding
options fetches a new source instead of reusing its old cache.
`check` and `--dry-run` stay strictly offline: no fetching, directory
creation, leases, or installation. They fail for missing or invalid caches; run
the daemon to populate missing files.

Bootstrap downloads support built-in `direct`, inline TCP proxy chains and
pools, and normal outbound TLS settings with inline, named, or file-backed PEMs.
Its `bootstrap_url` must be `system` or a literal-IP `udp://`, `tcp://`, `tls://`,
or `https://` DNS URL. Target and proxy hostnames use that resolver. Every pool
member must be supported. User-defined named client groups (including ordinary
round-robin groups), selectors, URL-test groups, named DNS groups, WireGuard,
QUIC proxy transports, and H3 DNS are unsupported for bootstrap. A DNS group
named `system` is still a named group, not the built-in resolver. No failed or
unsupported route falls back to direct TCP or system DNS. Literal bootstrap DNS
URLs keep their existing direct routing semantics; OS VPN/TUN routing still applies.

These restrictions apply whenever a source must be downloaded during startup or
reload, including every memory-only source on a cold start. With usable caches or
retained in-memory sources, preparation accepts the normal refresh routes,
including dynamic client and named DNS
groups. Populate such caches externally, or bootstrap with a supported route
before switching to a runtime-dependent route. Bootstrap must not depend on this
instance's own listeners; indirect dependencies can fail at the download deadline.
Candidate and retained Fake-IP ranges remain excluded from download destinations,
proxy hops, and bootstrap DNS.

When configured, startup creates the final cache directory if missing, then acquires its lease.
The parent directory must already exist. Creation respects the process umask and
never repairs permissions. If owner access is missing, create the directory with
`install -d -m 700 cache` before starting. Reload reuses the lease and does not
recreate a removed root.

Declarations and all required bootstrap routes are preflighted before fetching.
Sources are downloaded and decoder-validated serially, retained in memory, and
optionally saved to disk, then the complete configuration is compiled normally.
A failed startup exits before serving; a failed reload retains the active generation.
Earlier completed saves remain if a later download, configuration check, or activation fails. This is a
per-file repair, not a multi-file disk transaction or a promise of activation.

The process refreshes due sources serially, with 10% jitter and capped exponential
failure backoff. Downloaded sources pass shoes' actual decoders, compilation budgets,
and validation against the active configuration snapshot before replacing retained
rules. Persistent and nonpersistent sources use this same validation path.
The initial due time is based on a restored cache's mtime or the initial download
time; future mtimes are treated as due.
Successful check times are remembered only in memory. On a cold start, an explicit
cache path does not record the URL it came from; use a new cache name when changing
the URL between process lifetimes if immediate replacement is required.
Download or validation failures retain the last-good rules and cache.
Identical downloads reuse compiled rules and do not reload; identical cached bytes
preserve inode/mtime. Each file replacement is atomic, not a multi-file transaction.
A post-rename directory-sync failure reports uncertain durability without rejecting
the update. New flows use the reloaded rules; existing flows retain
their previous configuration. Reload/removal/shutdown cancels in-flight refreshes.
`--no-reload` disables filesystem-triggered reloads, not configured remote refresh.
Managed caches are excluded from generic filesystem watching. An automatic changed
source requests one immediate reload; external cache edits are read only after restart,
not on SIGHUP. Use local file sources for externally managed live rule updates.
Reload reads the configuration files, including any unrelated edits. If activation
fails, the validated replacement remains available in memory while old rules remain
active. Correct the configuration and reload explicitly; a later byte-identical fetch does not retry
activation. Atomic installation does not provide a disk/activation or power-loss
transaction.
Bulk file reads, writes, and synchronization run off the forwarding executor.
Filesystem work already submitted may finish after cancellation, holding its
update lock until cleanup; it cannot publish an abandoned pre-rename update.
The final ownership check and atomic rename remain one synchronous publication step.

HTTPS verifies certificates. An explicit `http://` URL permits cleartext. Redirects,
URL credentials/fragments, HTTP content compression, and trailers are rejected.
Chunked and close-delimited bodies are accepted within the same limits: 64 MiB
download, 64 headers/32 KiB, 10-second connect/DNS/TLS and header/body-idle deadlines,
and a 120-second total download deadline. Decoder-specific decompression limits
still apply. A truncated close-delimited cleartext response can be indistinguishable
from a shorter valid rule list; prefer HTTPS. Logs report
actual updated/unchanged/failed results without URL query values or downloaded data.

Remote refresh currently requires the Unix process runtime. FFI startup and
WireGuard-dependent download/bootstrap routes reject it explicitly. It does not
add proxy subscriptions, dynamic provider groups, or provider API endpoints.
