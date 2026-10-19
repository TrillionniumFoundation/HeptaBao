# OpenBao 2.7.1 lossless KV2 to native V6 controller

The executable is `qa/openbao-acceptance/kv2_271_lossless_native_live.py`.
It owns two fresh local TLS services, invokes the checked-in raw exporter and
atomic importer once each, and verifies retained history, deletion state,
metadata, cold recovery and snapshot restore. It never accepts an existing
service address or token. All source data are synthetic.

This revision was reconstructed on 2026-10-19 after the earlier uncommitted
controller and memory-backed overlay disappeared. It has new source hashes;
it is not a byte recovery of the former e07a7c overlay. The regression receipt
records a new execution against the exact files in this commit.

## Evidence scope

The original seven controller regressions cover exact Decimal, large integer and
Unicode serialization; profile sizes; cleartext rejection; one real 2 MiB TLS
exchange with a generated pinned certificate; termination of one real
timed-out child without retry; cleanup of a second owner after the first
cleanup fails; and redaction of a failed report. The oracle-split revision adds
six regressions for the observed API/storage distinction, raw precision,
canonical cross-language hashes, native witness semantics and qualification
requiring all three storage stages. Its real TLS regression also captures and
rehashes the same GET response bytes that it decodes. All 13 tests passed in
the separately retained local regression receipt.

Those tests do not execute OpenBao or HeptaBao. They do not qualify Mac,
X230, HA, production or a migration. The real command below must produce its
own complete summary and exact source/binary identity. Corresponding flags
in the controller regression receipt remain false.

## Run on the actual Mac or X230

Use a complete checkout, an already built candidate with its retained build
receipt, and an already downloaded official OpenBao 2.7.1 binary/archive pair.
The launcher checks its platform-specific archive and binary pins, archive
membership and the actual server version. It performs no download or version
fallback and does not use development mode.

Set these variables to verified existing files and an operator-owned parent
directory outside the source checkout:

* `HB_ORACLE_BINARY`: official OpenBao 2.7.1 executable for this machine.
* `HB_ORACLE_ARCHIVE`: its matching pinned release archive.
* `HB_CANDIDATE_BINARY`: exact candidate executable in the build receipt.
* `HB_MIGRATION_WORK_PARENT`: an absolute, current-user-owned directory with
  no group or other write permission. Every invocation needs a new child.

The Mac parent can be in the existing T5 continuation directory. Select the
X230 parent after checking its real identity, disk and toolchain. Do not use
a production service root or infer machine readiness from an older receipt.

From the complete checkout, first diagnose the dedicated native graph writer:

```sh
python3 -B qa/openbao-acceptance/kv2_271_lossless_native_live.py \
  --binary "$HB_CANDIDATE_BINARY" \
  --private-work-root "$HB_MIGRATION_WORK_PARENT/kv2-native-small-r1" \
  --profile native-small
```

After the concrete large-record and transport blockers are fixed, run the
full profile under a different new root:

```sh
python3 -B qa/openbao-acceptance/kv2_271_lossless_native_live.py \
  --binary "$HB_CANDIDATE_BINARY" \
  --private-work-root "$HB_MIGRATION_WORK_PARENT/kv2-full34-r1" \
  --profile full34 \
  --migration-lane native-large
```

The script prints only status, profile, summary path and full34 qualification.
Private roots hold synthetic credential custody, source bundle, archive and
phase receipts. Preserve those for interrupted-run reconciliation; share
only the credential-free summary. Failed or interrupted imports are never
automatically repeated.

Controller-only regressions:

```sh
python3 -B -m unittest discover \
  -s qa/openbao-acceptance/tests \
  -p test_kv2_271_lossless_native_live.py -v
```

## Profiles and existing bounds

All profiles use the KV2 mount `secret` and key `history`. Version 1 has a
1 KiB payload and is soft deleted. Version 2 has a 1 KiB payload and is
destroyed. They precede the live versions below. Payloads also contain an
ordinal, integer `9007199254740993`, exact decimal
`0.123456789012345678901234567890`, Unicode and a nested JSON value.

| Profile | Live versions | Payload per live version | Live payload total | V6 activation |
| --- | ---: | ---: | ---: | --- |
| native-small | 2 | 4096 bytes | 8192 bytes | Before import |
| full34 | 17 | 2 MiB | 34 MiB | Before import |
| raw2 | 1 | 2 MiB | 2 MiB | Before import |
| bundle34 | 68 | 512 KiB | 34 MiB | Before import |
| legacy8 | 17 | 512 KiB | 8.5 MiB | After import |
| legacy-small | 2 | 4096 bytes | 8192 bytes | After import |

The controller never shrinks full34. Only a complete successful full34 run
can set `full34_qualified` true. Small import success leaves the large
migration gate unresolved.

At the reviewed 5ea baseline the decoder accepts at most 1 MiB per raw
record and 64 MiB of raw aggregate. The migration CLI permits at most
16 MiB of bundle/request JSON. Its original HTTP helper also bounds input,
body and response. The saved boundary probe exercises the actual decoder;
its old native 501 finding is explicitly a source guard, not a live HTTP
receipt.

This controller does not increase or bypass those bounds. It calls
`tools/migration/openbao270_kv2_migrate.py --_owned-worker` with the existing
argument framing and original 360-second deadline. It directly owns that
worker's process group and the worker's one-shot HTTP children. Nesting
another CLI supervisor would create a separate session and undermine
cleanup after an unknown outcome.

Until a dedicated large migration transport exists, full34 is expected to
expose the original raw/response bound before import. The bundle34 profile
isolates the separate 16 MiB bundle bound using sub-1 MiB raw payloads.
The legacy8 profile diagnoses the old aggregate owner boundary. Repeating
a known-blocked profile needs a concrete implementation change first.

## Real migration and recovery checks

The pinned official fixture is stopped and restarted with
`raw_storage_endpoint: true` only in its new private configuration.
The candidate starts with `--config <private/server.json>` and
`--fixture-native-v6-service`. Existing service roots are not admitted.

The controller requires all 31 fixed named checks in its source:

1. Official 2.7.1 artifact and live identity.
2. Two distinct owned server processes.
3. Each live official API response captured before deletion or destruction.
4. Exact live, soft-deleted and destroyed source API history.
5. Required metadata CAS and a real incremented metadata counter.
6. The same source after a real restart.
7. A pristine target mount.
8. One completed source raw export.
9. All source raw historical payloads retain the original precise numeric tokens.
10. Soft-deleted payload retained; destroyed payload absent in the bundle.
11. Source unchanged after export.
12. One completed native import.
13. Actual V6 storage/reader format and logical payload bytes.
14. Exact target API history and metadata compared with the official source API.
15. Independent precise native storage witnesses for every historical version.
16. Exact target API history after SIGKILL, restart and original-key unseal.
17. Independent precise storage witnesses after that cold restart.
18. A downloaded native snapshot.
19. One actual post-snapshot version append.
20. One actual snapshot restore with the native route's HTTP 200.
21. Exact restored API history after another cold restart.
22. Independent precise storage witnesses after snapshot restore and cold restart.
23. The observed source API payload recovered by undeleting version 1.
24. Destroyed version 2 remains absent after undelete.
25. Stale data CAS rejected without effect.
26. Stale metadata CAS rejected without effect.
27. Correct metadata CAS increments the original counter exactly once.
28. The official source remains unchanged after target mutations.
29. Source files and candidate binary retain their exact identities.
30. Both owned servers stop, even if one cleanup fails.
31. The public report excludes captured runtime credentials.

Exact comparisons include timestamps, custom metadata, indices, flags,
payloads and counters. A loop of ordinary KV writes does not establish a
historical import.

## The observed API and raw-storage oracles

The first actual Mac native-small run reached all twelve planned seed mutations
and then failed its source payload assertion before export/import. A read-only
diagnosis of a separately rebound clone established that deletion, destruction
and version predicates passed. The two live API payload comparisons failed
only on the numeric fields:

| Layer actually observed on official OpenBao 2.7.1 | Wide integer | Decimal |
| --- | --- | --- |
| Public `GET secret/data/history?version=3` and version 4 | `9007199254740992` | `0.12345678901234568` |
| Raw/protobuf historical payload | `9007199254740993` | `0.123456789012345678901234567890` |

The retained projection receipt has SHA-256
`9d46e5113eff82506ab1bc410ca86290410317b9786cdf76c5aec5a5c3e4d825`.
Its original decoder read nine records and produced a 10,794-byte bundle with
SHA-256 `deb90c25de15fabc2203b0cf329c6dd7cf6ab84e07c64149196366589c43d89c`.
The companion controller receipt records zero source writes, a stopped clone,
and nineteen original fixture files unchanged. The original failed controller
had not captured its source history baseline; repository/binary identity
success alone did not establish a source history comparison.

This revision does not change or round the generated fixture. Each source write
is followed by an actual GET whose original response bytes are saved under
`source-api-oracle/` with their SHA-256 and decoded identity in the receipt.
This includes version 1 before soft deletion. Non-numeric fixture fields must
still match exactly. Subsequent source and target API comparisons use the
same observed source API values. Canonical comparisons retain decimal token
representation rather than equating a differently serialized decimal with an
integer solely through Python numeric equality.

The raw bundle is independently compared with the original exact fixture,
including retained deleted history. Target storage must then prove the same
precise data through the dedicated witness, not through its public KV2 API,
logical byte count or an opaque encrypted archive hash.

### Native per-version storage witness

At each of import, cold restart, and snapshot restore plus cold restart, the
controller sends one actual request per version:

```json
{"mount":"secret","path":"history","version":3}
```

The route is `POST /v1/sys/internal/storage/kv2-version-witness`. It is a
root-namespace sudo-authorized precise native read. A POST transport failure is
never retried by the controller. An absent route, HTTP 501, a malformed witness,
wrong metadata, or a rounded payload hash fails the stage.

HTTP 200 must contain `data.schema=heptabao-native-kv2-storage-witness-v1`,
`canonical_profile=heptabao-lossless-json-v1`, the exact mount/path/explicit
version, creation and deletion times, destroyed flag, payload-present flag,
canonical payload byte count, and canonical SHA-256. A soft-deleted version
retains its precise payload witness. A destroyed version requires no payload,
zero bytes and a null hash. Additional source-binding fields do not replace
these comparisons.

Canonical payloads use compact UTF-8 JSON, recursively sorted object keys,
original array order, standard JSON string escaping, and stored lossless
numeric tokens without a float conversion. The shared cross-language vector
is 134 bytes with SHA-256
`8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395`:

```json
{"a":0.123456789012345678901234567890,"nested":[null,true,{"zero":"\\u0000"}],"unicode":"凭证迁移试验🧪","z":9007199254740993}
```

The receipt separates `api_history_qualified` from
`target_storage_precision_qualified`. All three named target storage stages
are required for complete controller success and `full34_qualified`.

### Independent numeric boundary diagnosis

`kv2_271_numeric_boundaries.py` is a separate diagnostic for an operator-started
new official clone. It writes each of `1.0`, `-0`, `1e-6`, `1e-7`, `1e20`,
`1e21`, and `1e400` once to its own new key with CAS 0, captures the exact GET
response or error status, and performs two identical read-only raw acquisitions.
It extracts the original numeric lexeme directly from protobuf payload JSON,
so the observer does not itself normalize negative zero or exponent notation.
The fixed overall budget is 120 seconds; mutations are not retried. The
operator owns clone startup, cleanup, and proof that the original fixture
remained unchanged. A completed diagnostic is not a migration qualification.

Each controller HTTP operation has a private one-shot child, literal
`https://127.0.0.1`, generated CA verification, no proxy or redirect, an
original 15-second absolute budget, a 4 MiB JSON response/body bound and a
separate 128 MiB archive bound. Mutations have begin/outcome receipts and
no retry. A timeout stops the owned child and records uncertainty; it
cannot establish that the target had no effect.

## Native implementation boundary

The dedicated Rust writer is maintained separately. Its small route must
publish a complete typed graph using the existing scope-bound objects,
bounded locator batches and root/cursor CAS. It must retain the original
actor, authorization clock, incarnation, pristine-target witness and root
preconditions across physical writes. Lost acknowledgement requires a
fenced result and recovery through the existing commit protocol.

Full34 additionally needs a bounded transfer/staging protocol that validates
actual raw records and the complete historical projection, then uses the
same publication protocol. Increasing global JSON or legacy aggregate
owner limits is not that implementation. Controller readiness, small
native import and full34 migration require separate evidence; none alone
grants HA, production cutover or old-service cleanup authority.


## Dedicated native-large lane (2026-10-19)

`--migration-lane native-large` explicitly selects
`tools/migration/openbao271_kv2_native_large_migrate.py` for both raw export
and import. The default remains `legacy`, preserving the original boundary
profiles and their exact limits. The new lane requires V6 activation before
import; combining it with either legacy activation profile is rejected
before fixture allocation.

The new client retains the original worker argument contract, 360-second
original worker deadline and 5-second original per-request deadline. No
failure resets either budget. The controller still supervises the actual
worker process group and never retries an uncertain mutation.

| Boundary | Legacy default | Native-large explicit lane |
| --- | ---: | ---: |
| Raw record | 1 MiB | 4 MiB |
| Aggregate raw records | 64 MiB | 64 MiB |
| Closed bundle | 16 MiB | 64 MiB |
| Raw HTTP response | 2 MiB | 8 MiB |
| Private HTTP child input | 32 MiB | 96 MiB |

The shared decoder now accepts an immutable `Bounds` argument. Every nested
protobuf and lossless JSON decode receives that same selected object;
legacy callers retain the original default. The old CLI and old HTTP leaf
are untouched. The new transport uses its separate fixed `Limits` object
and separate `kv2_native_large_http_once.py`; it never monkeypatches old
module constants.

The import request is exactly:

- `POST /v1/sys/migration/openbao/kv2/native-large?mount=secret`
- HTTP/1.1 with one positive exact `Content-Length`.
- `Content-Type: application/vnd.heptabao.kv2-lossless+json`.
- Root namespace; one canonical mount query.
- Raw `openbao270-kv2-lossless-v1` closed bundle, without a mount/bundle envelope.

The fixed leaf cannot add `Expect`, `Transfer-Encoding`, duplicated lengths,
redirects or proxy behavior. Its input, body and response are bounded. The
Rust route must separately admit the authenticated actor, original clock,
root namespace, single-node active V6 state and pristine target before body
consumption, and carry that admission to final graph publication. The
transport tests cannot substitute for the Rust route's admission or native
persistence tests.

The new regression file is `tests/test_kv2_native_large_migration.py`. Its
synthetic raw fixture contains one soft-deleted payload, one destroyed
version, seventeen 2 MiB live payloads, exact wide integer and decimal
values, custom metadata, and an actual metadata counter. Tests exercise
both consistent source acquisitions, changed-source refusal, retained and
destroyed payload invariants, raw/bundle limits, root/TLS admission,
expired deadlines, one unknown child timeout, a real HTTP 503 without
provider body leakage, a real TLS raw response above the old 2 MiB bound,
and the complete greater-than-34-MiB bundle over actual TLS to a synthetic
acknowledgement server. That server does not implement Bao. Accordingly,
the receipt reports no official OpenBao execution, native graph import,
physical-host qualification or full replacement authority.
