---
title: "Command Line"
description: shoes command line configuration.
---

```bash
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
  -t, --threads NUM    Worker threads (default: CPU count)
  -l, --log-file PATH  Log to a file; repeatable ("-" means stderr)
  -d, --dry-run        Validate config and certificates without starting listeners
  --no-reload          Disable automatic reloads on file changes
  -V, --version        Print version information

COMMANDS:
  check <config.yaml>                            Alias for --dry-run
  version                                        Alias for --version
  cleanup-tun                                    Recover managed-TUN state (Linux only)
  generate-reality-keypair                       Generate Reality X25519 keypair
  generate-reality-mldsa65-keypair                Generate optional Reality ML-DSA-65 keys
  generate-shadowsocks-2022-password <cipher>    Generate Shadowsocks 2022 password
  generate-vless-user-id                         Generate a VLESS/VMess UUID v4
  generate-vless-encryption [options]            Generate matched VLESS encryption credentials
  generate-tendns-txt [options]                  Generate an encrypted tendns TXT value
```

`generate-vless-encryption` accepts repeated `--auth x25519|mlkem768`,
`--mode native|xorpub|random`, `--rtt 0rtt|1rtt`, and
`--lifetime 600s|N-Ms|0s`. See [VLESS encryption](/protocols/vless-encryption/).
SIGHUP reloads configuration even with `--no-reload`; SIGINT/SIGTERM stop
listeners without waiting for the TCP reload drain.

`check` and `--dry-run` exit with status 0 for valid configuration and 1 for errors. They do not open listeners, create a file watcher, or perform DNS bootstrap networking. Runtime failures such as unavailable bind addresses remain possible after a successful check.

### Tendns TXT Generation

`generate-tendns-txt` creates an encrypted TXT publication offline, without a
Shoes configuration file or DNS-provider access. Supply an existing 32-byte
unpadded base64url discovery key through `TENDNS_KEY`, not a command-line option.

```bash
read -r -s -p 'Tendns key: ' TENDNS_KEY
export TENDNS_KEY
shoes generate-tendns-txt \
  --name example.com \
  --entry nas:A:192.0.2.10 \
  --entry nas:AAAA:2001:db8::10 \
  --entry web:CNAME:service.example.net \
  --valid-for-secs 86400
unset TENDNS_KEY
```

`--name` is the public TXT owner. Each repeatable `--entry LABEL:TYPE:VALUE`
adds an A, AAAA, or CNAME entry; use `@` for the owner itself or a single label
such as `nas` for `nas.example.com`. A CNAME must be the only entry for its name.
The default validity is 86,400 seconds from generation, independent of DNS TTL.
Regenerate the publication before it expires.

Standard output contains only the encrypted `td1.` value. Publish that value as
TXT at the specified owner using your DNS provider. Values longer than 255 bytes
must be split into adjacent strings within **one TXT record**, without adding
spaces to the data or creating separate records for the fragments.

The value represents a whole publication, not an update to an existing one.
Replace or remove the old `td1.` value when updating; merely adding the new value
alongside it leaves both active. An invalid or expired value makes the lookup
fail even when another value at the same owner is valid. Generation does not
enable tendns resolution in Shoes; runtime activation is not available yet.

### Configuration Diagnostics

Check the same set of files that will be used at startup:

```bash
shoes check groups.yaml listeners.yaml
```

Configuration decoding failures identify the input file and the entry's
zero-based `config[N]` index. Rule-group decoding also identifies `rules[N]`
(or `rules` for a single object). For example, an unsupported field in the second
rule source of the third entry reports `config[2]`, `rules[1]`, and the unknown
field. YAML syntax and duplicate-key errors retain the parser's original
diagnostic and line/column information when available, rather than adding an
entry prefix. For `config[N]` decoding errors, a trailing line/column (if any)
marks the start of the file's top-level list, not entry N or the failing field;
use the `config[N]` and `rules[N]` paths for that context.

Errors during certificate loading and semantic validation name the input file
set, not an inferred single culprit: group references can span files. Checks use
the native validation path, including graph and transport-composition checks.
Named PEM entries accept only `pem` and exactly one of `path` or `data`; unknown
fields are rejected rather than ignored. TCP settings likewise reject unknown
fields; their only current field is `no_delay` (default `true`).

Diagnostics do not include full YAML excerpts. They are not a redacted config
export: user-defined names, paths, and some invalid values can appear in errors.
Review diagnostics before sharing them. No normalized-config output is provided.

Offline regression coverage runs native preparation checks for a curated subset
of examples listed in `src/config/tests.rs`. Other examples may need
deployment-specific certificates, keys, files, or platform support; parsing an
example alone does not establish runtime validity.

Editor schema generation is not part of this reference. The native parser and
validator remain authoritative for accepted configuration.
