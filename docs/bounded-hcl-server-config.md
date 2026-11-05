# Bounded HCL deployment configuration

The server accepts JSON and a static HCL subset through the same `--config`
and optional `--ha-config` flags. Files retain the existing absolute-path,
bounded-regular-file and 65,536-byte admission. JSON keeps its original strict
serde schema and defaults.

HCL supports literal strings, booleans, null, numbers, arrays, objects and
unlabelled native blocks. Attributes require a newline (or a closing brace or
end of file); collections also allow commas. Strings support documented escapes
and escaped template markers. Duplicate keys, expressions, functions,
interpolation, heredocs, non-UTF8 input, more than 32 nesting levels or 4,096
structural values are rejected. Errors never include input credentials.

One `listener "tcp"` block maps `address` to `listen` and maps existing TLS,
PQC named-group and consistency fields. Its address defaults to
`127.0.0.1:8200`. `tls_disable = true` is rejected. The three documented listener
boolean aliases accept exact boolean literals or quoted `"true"`/`"false"`;
native typed fields retain their exact types. Explicit client-certificate
verification requires the existing deployment-owned CA. Explicit false plus a
CA selects optional authentication, which still validates every presented
chain. Omitted verification preserves HeptaBao's stronger existing mandatory
default when a CA is configured. No system trust or peer discovery is added.

```hcl
data_dir = "/data/heptabao/state"
audit_file = "/data/heptabao-audit/events"
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_cert_file = "/data/heptabao-tls/server.pem"
  tls_key_file = "/data/heptabao-tls/server.key"
  tls_min_version = "tls13"
  tls_key_exchange_preferences = ["X25519MLKEM768", "X25519"]
}
```

Other native configuration fields retain their existing names, types and
deployment authority. The separate HA file uses the existing explicit node,
peer, certificate pin, replication-key and timeout schema. HCL decoding does
not enroll peers or change runtime admission.

Remaining OpenBao 2.7 configuration gaps are explicit errors: multiple
listeners, directory merging, storage blocks (including PebbleDB and Raft),
declarative audit blocks, telemetry, seal blocks, API/cluster advertisement
aliases, proxy headers, ACME, certificate reload and unmapped HTTP timeouts.
A storage block is never accepted as an alias for a different backend or file
format. The native `data_dir` and mandatory `audit_file` remain explicit;
a PebbleDB directory cannot be opened or migrated through this adapter.

Sources: [OpenBao 2.7 configuration](https://github.com/openbao/openbao/blob/v2.7.0/website/content/docs/configuration/index.mdx),
[TCP fields](https://github.com/openbao/openbao/blob/v2.7.0/website/content/docs/configuration/listener/tcp.mdx),
[PebbleDB owner](https://github.com/openbao/openbao/blob/v2.7.0/website/content/docs/configuration/storage/pebbledb.mdx),
and [HCL native syntax](https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md).
This describes the source implementation; compilation and runtime verification
must be performed independently.
