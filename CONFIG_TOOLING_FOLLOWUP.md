# Configuration Tooling Follow-Ups

Status: optional, not implemented. Native Shoes types and the existing
load/PEM/compile/resource-validation pipeline remain authoritative. No alternate
runtime configuration model, permissive compatibility mode, or DIRECT fallback
is proposed.

## Typed Reference and Editor Support

Start with a small reference generated from configuration types, defaults, and
deserialization attributes, checked into documentation only if it demonstrably
reduces drift. Preserve hand-written explanations of transport composition, group graph
validation, resource limits, selector identities, and deployment prerequisites.
Custom deserializers, flattened/tagged protocols, aliases, and one-or-many fields
need explicit tests; deriving a schema alone does not describe their behavior.

A JSON Schema may later provide editor completion and basic shape checking.
Label it advisory: it cannot replace native semantic validation, local rule and
certificate loading, or platform-specific checks. Do not add a schema dependency
until a concrete editor workflow and maintenance owner justify it. Test generated
examples through Shoes rather than only through a schema validator.

## Strict Subset Converter

A standalone converter could support a documented subset of external proxy/group
configuration formats. It must reject unsupported fields, protocols, policies,
ambiguous defaults, and lossy mappings, with source location and a nonzero exit code. Never
silently skip nodes, drop policy, or substitute DIRECT. Output must pass the same
native Shoes validation path before publication; keep selector identities stable
and report unsupported composition rather than guessing.

Keep fetching/subscriptions and provider lifecycle work separate. Do not implement
the converter concurrently with provider work without an agreed ownership and
capability contract. Future acceptance includes unsupported policy rejection,
secret-safe errors, deterministic identity, invalid graph rejection, and unchanged
last-good configuration after conversion failure.

## Normalized Configuration Output

Not shipped. Existing Debug and Serialize implementations are not a comprehensive
export-redaction contract. An audit must cover every protocol credential, user ID,
controller token, WireGuard/Reality/VLESS key, pre-shared key, PEM body, URL userinfo,
and credentials in nested transport/DNS/rule settings. Prefer an allowlisted public
view over a credential-name denylist. Tests must cover every secret-bearing field,
including malformed input and future additions, before adding an output flag.

## Diagnostic Limits

Continue improving paths at custom deserialization boundaries without duplicating
the runtime model. Untagged alternatives and custom parsers can hide the innermost
field. For `config[N]` decoding errors, a trailing line/column (if any) marks the
start of the file's top-level list, not entry N or the failing field; use the
`config[N]` and `rules[N]` paths for that context. YAML syntax and duplicate-key
errors retain the parser's original locations when available.
Exact semantic source attribution across multiple files requires provenance that
survives group expansion and composition. Do not claim one input file caused a
cross-file error without that provenance.

Named PEMs and TCP settings reject unknown fields. Some other configuration
types (for example TLS server settings and DNS server options)
lack `deny_unknown_fields`. Audit those separately with their owners rather than
adding blanket attributes to flattened/untagged types without compatibility and
composition tests. A whole-model strictness audit remains deferred.

Parser errors are not a general-purpose redacted export. In particular, arbitrary
values placed in non-secret fields and user-controlled names can appear in errors.
A broader structured diagnostic/redaction contract needs its own audit; do not
promise that existing free-form semantic errors are safe to publish unreviewed.
