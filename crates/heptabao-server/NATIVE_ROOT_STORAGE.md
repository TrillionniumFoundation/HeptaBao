# Explicit native root storage

This implementation adds normal configuration and lifecycle entry points for
the bounded native V6 root profile. It is a candidate for qualification, not a
claim that the complete OpenBao compatibility or production rollout gates have
passed. Run the tests and machine qualification on the exact resulting commit.

## Selection and custody

The default server compiles `native-v6-storage` and `native-v6-ha`. Compilation
does not select either profile. Existing storage configuration keeps its current
consumer. The fixture and fault features remain separate from normal startup.

A standalone configuration explicitly selects the actual local file owner:

```json
{
  "listen": "127.0.0.1:8200",
  "data_dir": "/absolute/native-data",
  "audit_file": "/absolute/audit/server.jsonl",
  "tls_cert_file": "/absolute/tls/server.pem",
  "tls_key_file": "/absolute/tls/server-key.pem",
  "storage": {"native_v6_file": {"path": "/absolute/native-data"}}
}
```

Start it with the ordinary `heptabao-server --config /absolute/server.json`
entry point. Use the normal authenticated initialization and unseal protocol.
Initialization generates the real Shamir seal; configuration supplies no key,
token, seed, synthetic provider or deadline. If initialization used response
recovery, acknowledge that response through the existing root-authorized
`POST /v1/sys/init/ack` protocol before later HA enrollment.

Selecting the profile leaves an existing V5 store in V5. After unseal, a current
root actor explicitly activates migration with an empty JSON object at
`POST /v1/sys/storage/native-v6/activate`. The original migration validates the
actual source graph, actor, seal, owner, original request deadline, and atomic
publication. Configuration does not grant that operation. Once V6 is active,
ordinary KV requests use the same runtime owner. An unconfigured server cannot
load the authenticated V6 root through a V5 fallback.

The profile admits root-namespace KV and the existing local token, AppRole,
certificate, policy and rate-limit paths. Activation and restore reject live
owners that those paths cannot continue to serve, including other engines,
provider or namespace custody, unsupported authentication mounts, token-private
cubbyhole data, wrapped replies, control groups and nondefault Raft autopilot
configuration or pending promotion policy. No rejected owner is deleted
or silently converted. This is a bounded migration scope, not full-feature
OpenBao compatibility.

## Restart and restore

Restart with the same selected profile and use the actual Shamir shares. Cold
opening rechecks the authenticated root, retained migration source, publication
cursor, object graph and current physical owner. A successful prior operation
does not replace those checks.

The ordinary binary snapshot endpoint at `/v1/sys/storage/raft/snapshot` exports
and restores the authenticated V6 object pack. Download and upload keep the
original actor, live seal and request deadline. A historical restore derives a
new generation and replay epoch; it does not reuse an archived authority. An
active V6 store refuses a V5-only snapshot, and a different seal cannot use the
archive as a key or bypass checksum authentication. Plain JSON copying and a
running directory copy are not supported backup procedures.

A rollback to the V5 server requires a retained, independently verified V5
backup and an explicit traffic/credential recovery plan. Merely changing the
storage selector cannot roll V6 back. Preserve the original source and backups
until the complete per-client migration and restart/rollback gates pass.

## Existing-seed Raft admission

`native_v6_raft` selects the enrolled native Raft runtime. Its configuration has
the same `path`, optional `node_id`, `cluster_addr` and optional `api_addr`
bindings as the existing `raft` selector; `data_dir` must equal `path/state` and
the enrolled Raft directory must equal `path/raft`. Start through the ordinary
`--config ... --ha-config ...` entry point. Strict peer pins, actual TLS leaf,
replication-key custody, original ReadIndex and durability checks remain in
force. Legacy-peer and overlapping-pin transitions are refused by this profile.

Before opening Raft workers or a peer listener, this entry point requires an
existing private Shamir file seed, a real sealed checkpoint, and completed
initialization recovery. It refuses an empty directory, Wrapper/legacy seal,
provider marker, missing checkpoint, and symlink checkpoint. The preliminary
metadata check is startup eligibility only; real unseal and consensus admission
still authenticate the selected state and cohort.

Fresh ordinary HA initialization is **not implemented by this slice**. The
existing HA initialization guard is unchanged. A separate provisioning and
migration step must establish the actual same Shamir cohort from a stopped,
owned, ordinary-file initialization before this profile can be qualified on
new nodes. Do not use a fixture key, copy a running owner, or label startup
refusal as proof of HA provisioning or failover.

## Required qualification

The new focused tests are selected by `native_storage` under the normal server
default features. They cover actual Shamir file activation and cold reopen,
binary historical restore, V5/cross-seal refusal, unsupported live owners,
original root-actor requirements, exact configured ownership, and seed refusal.
Configuration-only tests use inert paths and pin strings and perform no I/O.

Before admission, also run the original unmodified 108 native tests and full
workspace gates, build the default binary without fixture features, and verify
that binary over real TLS on Mac/Linux and the intended LAN cohort. Large
OpenBao KV2 import, process death/restart, quorum loss/re-election, ReadIndex,
durability, real client credentials and rollback remain mandatory. Evidence
must identify the exact source commit/tree, binary hashes, feature set, machines,
commands and terminal outcomes; partial or earlier-commit results do not compose
into a complete release proof.
