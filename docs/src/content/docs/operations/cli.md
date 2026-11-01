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
```

`generate-vless-encryption` accepts repeated `--auth x25519|mlkem768`,
`--mode native|xorpub|random`, `--rtt 0rtt|1rtt`, and
`--lifetime 600s|N-Ms|0s`. See [VLESS encryption](/protocols/vless-encryption/).
SIGHUP reloads configuration even with `--no-reload`; SIGINT/SIGTERM stop
listeners without waiting for the TCP reload drain.

`check` and `--dry-run` exit with status 0 for valid configuration and 1 for errors. They do not open listeners, create a file watcher, or perform DNS bootstrap networking. Runtime failures such as unavailable bind addresses remain possible after a successful check.

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
