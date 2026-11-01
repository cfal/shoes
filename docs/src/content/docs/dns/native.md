---
title: "Native DNS Freshness"
description: shoes native dns freshness configuration.
---

Without `global_settings.default_dns`, omitting a listener's `dns` uses native
OS/NSS resolution. An explicit `dns` object with empty `servers` always selects
this underlying system resolver, even when a global default is set. It provides
hostname resolution with a **60-second application memoization window**. The
same default resolver serves controller probes. The window starts when a
successful lookup finishes; an entry expires at the window boundary. All returned
usable addresses and their original order are retained.
Errors and empty results are not cached, and expired answers are not served on
failure. Each cache has a lazy, bounded 10,000-entry LRU keyed by exact hostname;
results are shared across ports, with each caller receiving its requested port.
Eviction can cause earlier refresh. Concurrent misses share a lookup, up to
1,024 participating callers per resolver. Excess callers look up independently;
this is not an OS lookup concurrency cap. Cancelling the owner makes surviving
callers retry within their remaining deadlines. No background refresh is added,
and already-running OS calls cannot be stopped.

Explicit `dns: {servers: system}` continues to use OS/NSS lookup **without
application memoization or concurrent lookup sharing**. To select a different
fixed window, use a system server options object, inline or in a named DNS group:

```yaml
dns:
  servers:
    url: system
    native_cache_secs: 15
```

`native_cache_secs` accepts an integer from 0 to 4294967295 seconds. Omitted or
`0` disables memoization for this explicit system entry. It is rejected on
non-system upstreams, including when set to `0`; unknown options and invalid
values are rejected. The option belongs to the server options object, not the
outer `dns` object. Existing `timeout_secs` remains a lookup deadline, not cache
freshness; `connect_timeout_secs` and `attempts` do not control native caching.

This is a load/freshness trade-off, **not DNS TTL compliance**: the OS lookup API
does not provide record TTLs. Shorter windows increase OS lookups; disabling the
shoes cache cannot bypass caches in the OS, NSS modules, or upstream resolvers.
Native hosts-file/NSS behavior is preserved. New flows can see updated answers
after expiry; established flows retain their pinned destination. This setting
controls native hostname lookup caching, not every DNS-related cache. Hickory
caches and Fake-IP mappings/TTLs are unchanged.

See [the DNS tuning example](/examples/dns_tuning/).
