# Rule-set interoperability fixtures

`singbox.json` is an original destination-only example. `singbox-v2.srs` was
generated from it with the sing-box CLI at revision
`43a3beb98851ad5e27e60042ea353b63c7d77448`:

```sh
sing-box rule-set compile tests/fixtures/rule_sets/singbox.json \
  --output tests/fixtures/rule_sets/singbox-v2.srs
```

The compiler downgrades this subset to version 2. Tests also exercise that same
payload with version 3, 4 and 5 headers, whose supported item encodings are
unchanged. Those header variants are not claimed to be separate upstream outputs.
Tests construct empty and malformed containers independently in memory.

`mihomo-domain.txt` and `mihomo-ip.txt` are original provider inputs. The adjacent
MRS fixtures were produced by MetaCubeX/mihomo
`88dcbf7f1614a67c3b36b848ee3592dfa92ada36` built with `GOMAXPROCS=1 go build -p 1`:

```sh
mihomo convert-ruleset domain text tests/fixtures/rule_sets/mihomo-domain.txt \
  tests/fixtures/rule_sets/mihomo-domain.mrs
mihomo convert-ruleset ipcidr text tests/fixtures/rule_sets/mihomo-ip.txt \
  tests/fixtures/rule_sets/mihomo-ip.mrs
```

Tests compare each binary against the corresponding text adapter and construct
small original raw zstd frames for malformed headers, ranges and window bounds.
No upstream matcher implementation or subscription data is copied into Shoes.
