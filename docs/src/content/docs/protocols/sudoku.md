---
title: "Sudoku TCP Mask"
description: Shoes sudoku tcp mask configuration.
---

`sudoku_mask` is an outer protocol wrapper for both TCP clients and servers. It
implements Xray FinalMask Sudoku, not the standalone Sudoku tunnel protocol.
It transforms the TCP carrier bytes without changing the inner proxy protocol.
Masks must form a consecutive outermost prefix of each client hop or server
listener. Masks beneath any non-mask protocol are rejected during configuration
validation. Native UDP and QUIC hops reject masks anywhere in their
protocol tree, including inside XHTTP. UDP/XUDP forwarded inside a supported
TCP proxy stream remains supported.

```yaml
# Outbound example: wire -> Sudoku -> TLS -> VLESS
address: proxy.example:443
transport: tcp
protocol:
  type: sudoku_mask
  password: "shared-mask-password"  # Default: empty; exact bytes, not trimmed
  ascii: prefer_entropy             # Default; also entropy, prefer_ascii, ascii
  padding_min: 0                    # Default: 0 percent
  padding_max: 0                    # Default: 0 percent
  protocol:
    type: tls
    protocol:
      type: vless
      user_id: "550e8400-e29b-41d4-a716-446655440000"
```

For an inbound, use the same mask options around the usual server protocol
configuration, for example `sudoku_mask -> tls` with a TLS `default_target`
containing VLESS. Default TLS/REALITY SNI still comes from the outbound address.
The client writes classic encoding and reads packed encoding; the server uses
the inverse. There is no negotiation, header, symmetric mode, or automatic
password/layout mismatch detection. Configure both peers together.

Options are the same in both roles:

| Field | Behavior |
| --- | --- |
| `ascii` | Case-insensitive, trimmed mode name. ASCII mode ignores custom tables, even invalid ones. |
| `custom_table` | Optional eight-character layout containing two `x`, two `p`, and four `v`, e.g. `xpxvvpvv`. Empty means the entropy layout. |
| `custom_tables` | Nonempty list overrides `custom_table`; normalized duplicates are removed in first-seen order. Layouts rotate per classic byte or packed six-bit group, including across writes. |
| `padding_min`, `padding_max` | Unsigned 32-bit percentages, clamped to 100; maximum is raised to minimum if needed. Each direction chooses one inclusive probability for its lifetime. |

Custom patterns are lowercased, trimmed, and have spaces removed. An empty
entry in `custom_tables` selects entropy. Camel-case aliases `customTable`,
`customTables`, `paddingMin`, and `paddingMax` are accepted. Unknown fields fail
validation.

Placement matches Xray, with the root closest to the wire:

- `mask -> TLS/REALITY -> VLESS`, `mask -> WebSocket -> VLESS`, and
  `mask -> TLS/REALITY -> XHTTP -> VLESS` match Xray's wire-outside placement.
- `TLS -> mask -> VLESS`, `TLS -> mask -> XHTTP`, and
  `XHTTP -> mask -> VLESS` are rejected. Masks cannot be inserted inside TLS,
  WebSocket, or an XHTTP logical session.
- XHTTP masks wrap each TCP carrier before TLS/REALITY, if configured. Mask state
  persists for the carrier's lifetime across pooled requests; new carriers start
  with fresh state.
- Consecutive outer masks compose in nesting order, including at later chain
  hops and in pools. Xray's public mask list `[A, B]` corresponds to Shoes root `B`
  containing `A`. Use distinct matching options for each stage.

Existing Vision and NaiveProxy immediate-child constraints still apply inside
the outer masks. A mask remains active during Vision
DIRECT and disables raw TCP splice. A mask outside REALITY also prevents
unmasked probes from reaching its usual camouflage fallback. Masked TLS listeners
cannot serve unmasked ACME TLS-ALPN-01 challenges.

**Security and cost:** this is obfuscation, not encryption or authentication.
Packed downlink is not password-keyed; classic's Go-compatible shuffle has a
reduced seed space. Retain actual transport security. Classic uplink expands
data 4x without padding, approximately 4.5x at 10%, and up to 9x plus one byte
per write. Packed downlink approaches 4/3x without padding; small writes incur
extra termination bytes. Each mask retains 32 KiB read and 32 KiB write buffers,
plus codec state. Stacking compounds expansion and memory. No speedup or traffic
classification resistance is promised.
