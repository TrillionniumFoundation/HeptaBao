# HeptaBao single-node black-box acceptance

## Scope and evidence boundary

`qa/openbao-acceptance/acceptance.py` performs real HTTPS requests against an
already initialized, unsealed candidate and optionally an independently deployed
OpenBao **2.6.2**. It tests a deliberately bounded KV-v2, token and Transit profile.
It does not certify all OpenBao APIs, authentication methods, secret engines,
CLI/agent/proxy behavior, restart safety, HA, migration, security qualification or
production operation. Every report sets `full_openbao_compatibility=false` and
`production_qualified=false`, including a successful differential run.

API selection was checked against OpenBao's primary Version 2.6.x documentation:
[KV-v2](https://openbao.org/docs/api/secret/kv/kv-v2/),
[token](https://openbao.org/docs/api/auth/token/),
[Transit](https://openbao.org/docs/api/secret/transit/),
[mount administration](https://openbao.org/docs/api/system/mounts/) and
[health](https://openbao.org/docs/api/system/health/). Live Oracle responses supply
the actual comparison for the pinned 2.6.2 deployment; documentation examples or
candidate-generated fixtures cannot substitute for that execution.

## Required deployment and identity inputs

Configure each endpoint through environment variables. `HB_CANDIDATE_ADDR` and
`HB_ORACLE_ADDR` must be HTTPS origins with no path, query, fragment or URL user
information. Configure a CA file through the corresponding `_CACERT` variable.
Exactly one of `_TOKEN_FILE` and `_TOKEN` must be present. Tokens are never
accepted as argument values. Token files must be regular, effective-user-owned,
owner-only files; symlinks are rejected. The client requires TLS 1.2 or later,
validates server certificates and hostnames, disables implicit proxies and
rejects redirects instead of forwarding credentials to an unverified leader.

An optional `_NAMESPACE` selects an existing isolated namespace. Each test run
creates unpredictable `hbqa-<run-id>-kv`, `hbqa-<run-id>-transit` mounts and one
`hbqa-<run-id>-reader` policy. All stored data and Transit plaintext are synthetic.
The supplied token must have the explicit administrative capabilities required
for these test resources. Production key names and values are not inputs.

Differential mode rejects the same normalized endpoint or the same live
`cluster_id` on both sides. It requires an owner-only Oracle identity JSON file:

```json
{
  "product": "OpenBao",
  "version": "2.6.2",
  "artifact_sha256": "ACTUAL_64_CHARACTER_LOWERCASE_ARTIFACT_SHA256",
  "provenance_url": "https://github.com/openbao/openbao/releases/tag/v2.6.2",
  "endpoint": "https://oracle.example:8200",
  "cluster_id": "ACTUAL_CLUSTER_ID_FROM_THE_ORACLE_DEPLOYMENT"
}
```

This is a deployment operator's artifact attestation checked against live health,
not remote binary attestation. The tool reports
`independent_binary_attestation=false`. Verify the downloaded Oracle artifact
against the official release's checksums/signatures, retain its provenance and
independent deployment record, and record the actual artifact digest. A version
string or a fabricated receipt does not establish independent origin. The
all-zero digest and the illustrative placeholders above are rejected.

```sh
export HB_CANDIDATE_ADDR=https://candidate.example:8200
export HB_CANDIDATE_CACERT=/secure/qa/candidate-ca.pem
export HB_CANDIDATE_TOKEN_FILE=/secure/qa/candidate.token
export HB_ORACLE_ADDR=https://oracle.example:8200
export HB_ORACLE_CACERT=/secure/qa/oracle-ca.pem
export HB_ORACLE_TOKEN_FILE=/secure/qa/oracle.token
python qa/openbao-acceptance/acceptance.py --compare \
  --oracle-identity-file /secure/qa/oracle-identity.json \
  --allow-test-writes --output /secure/qa/acceptance.json
```

The output directory must already be owned by the effective user and have no
group/other permissions, normally `0700`. The report is published as `0600`.
Without `--allow-test-writes`, the tool performs identity/health preflight and
reports the mutation cases `not_run`, exiting nonzero. `--candidate-only` runs the
same cases as local smoke coverage; it never records an Oracle or a compatibility
match. `--modules kv`, `--modules kv,token`, or `--modules transit` narrows the
profile; token tests depend on a successful KV fixture.

## Executable case matrix

All paths below are relative to `/v1`. The implementation report records each
individual method/path template, expected and observed status, and semantic
assertions. The generated mount name substitutes for `<kv>` or `<transit>`.

| Module | Requests | Assertions and observable side effects |
|---|---|---|
| KV-v2 setup | `POST sys/mounts/<kv>` | New isolated `kv` mount with `options.version=2`, acknowledged before ownership is recorded |
| KV-v2 versions | `POST <kv>/data/item`, `GET ...?version=1` | CAS=0 creates version1; CAS=1 creates version2; typed nested JSON and old-version values read back exactly |
| KV-v2 rejected CAS | A stale CAS write followed by current read | HTTP400 with an error array; current value and version remain unchanged |
| KV-v2 listing | `LIST <kv>/metadata/` | Exactly the synthetic key appears |
| KV-v2 delete/restore | `DELETE <kv>/data/item`, `POST <kv>/undelete/item` | Deleted reads return404; metadata records deletion without destruction; undelete restores the exact value |
| KV-v2 destroy | `POST <kv>/destroy/item` for version1 | Old version returns404 and metadata records `destroyed=true` |
| KV-v2 metadata | `POST/GET <kv>/metadata/item` | Custom metadata, CAS-required policy and max-version limit survive readback |
| Token/ACL | `POST sys/policies/acl/<policy>`, `POST auth/token/create` | Child token gets the requested read-only policy and no root policy |
| Token enforcement | Read and denied write with the child token | Read200, write403, then administrative read proves unchanged data/version |
| Token revocation | `POST auth/token/revoke`, then child read | Revoke204; revoked and random-invalid tokens return403 |
| Token expiry | Create nonrenewable token with2-second explicit max TTL; wait; read | A positive bounded TTL is observed; subsequent access returns403 |
| Transit | Create/read key, encrypt/decrypt, rotate, encrypt/decrypt again | `aes256-gcm96`, exact roundtrip, `vault:v1:` then `vault:v2:` format, latest key generation1→2, old ciphertext remains decryptable after rotation |

The actual OpenBao2.6.2 Oracle returns HTTP200 with key metadata for Transit key
creation and rotation. These two cases require200 and verify returned generation;
the harness does not accept a200/204 union that would conceal a candidate mismatch.

The corpus comprises18 KV,10 token and10 Transit cases. Random ciphertext bytes,
request IDs, creation timestamps and token strings are not compared. The selected
HTTP statuses and explicit semantic/side-effect assertions are compared exactly.
Error text and the full error-precedence matrix are outside this initial profile.
No raw server error body is written to a report.

## Failure, cleanup and interpretation

Requests are bounded to16 MiB responses and a15-second timeout. A network error
after a mutation is classified `transport_outcome_unknown`; no mutation is
automatically retried. The failed case and dependent cases cannot pass. Unknown
after-entry results require operator inspection of the generated test-resource
prefix, rather than assuming no side effect occurred.

Known issued test tokens are revoked during cleanup even when their returned
policy/TTL semantics fail validation. Acknowledged test policies are deleted.
Before deleting an owned test mount, cleanup checks that its description still
matches the unpredictable run marker. Cleanup failure makes the run fail. A
creation that committed but never returned an acknowledgement can leave a test
resource requiring operator reconciliation; the tool does not silently claim
ownership of an unrelated resource or destroy it.

`passed_scoped_cases` means all selected live cases and cleanup succeeded. In
differential mode, the independent Oracle and candidate must both pass and their
case records must match. Missing functionality is `failed` or `not_run`, never a
pass. Candidate smoke, formal differential execution, unit tests and external
qualification are separate evidence classes.

## Real HA observation and failover

`ha_acceptance.py` is a separate external-cluster harness, using the primary
[leader API](https://openbao.org/docs/api/system/leader/). It requires at least
three distinct HTTPS node origins in one live cluster, one namespace, HA enabled,
consistent leader identity and exactly one node reporting itself leader. A
single-node server returning `ha_enabled=false` fails this prerequisite.

Configure `HB_HA_1_*`, `HB_HA_2_*`, `HB_HA_3_*` using the same CA/token input rules.
Choose a previously enabled dedicated KV-v2 mount. A baseline writes a synthetic
CAS-protected key to the current leader and reads it through every node:

```sh
python qa/openbao-acceptance/ha_acceptance.py \
  --node-prefix HB_HA_1 --node-prefix HB_HA_2 --node-prefix HB_HA_3 \
  --phase baseline --mount ha-test --allow-test-writes \
  --receipt /secure/qa/ha-baseline.json
```

The baseline receipt records the exact leader and cluster. Through the actual
deployment controller, stop only that test-cluster leader, observe another node
becoming leader, restart the stopped node and wait for it to rejoin as a follower.
The script does not accept arbitrary PIDs or shell commands and does not kill any
process. Preserve the controller's independent evidence and an owner-only JSON
fault receipt with `action=controlled_leader_stop_restart`, the baseline
`cluster_id`, `stopped_node` equal to the baseline leader origin, and numeric Unix
`stopped_at`, `restarted_at`, `rejoined_at` timestamps in that strict order.

```sh
python qa/openbao-acceptance/ha_acceptance.py \
  --node-prefix HB_HA_1 --node-prefix HB_HA_2 --node-prefix HB_HA_3 \
  --phase verify --mount ha-test --allow-test-writes \
  --receipt /secure/qa/ha-baseline.json \
  --fault-receipt /secure/qa/ha-fault.json
```

Verification requires a different live leader, every original node reachable,
the pre-fault acknowledged value readable through every node, a new CAS write
readable through every rejoined node, and synthetic cleanup readback. The fault
receipt remains an operator attestation, reported explicitly as such. A baseline
or health observation alone reports failover `not_run`; missing nodes also produce
`not_run` and a nonzero exit. Even verified failover sets `ha_qualified=false`:
quorum loss, split brain, partitions, membership changes, snapshot recovery,
power loss and a linearizability campaign still require separate real evidence.
