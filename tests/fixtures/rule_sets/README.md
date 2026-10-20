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
