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

The seven controller regressions cover exact Decimal, large integer and
Unicode serialization; profile sizes; cleartext rejection; one real 2 MiB TLS
exchange with a generated pinned certificate; termination of one real
timed-out child without retry; cleanup of a second owner after the first
cleanup fails; and redaction of a failed report.

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
  --profile full34
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

The controller requires all 26 fixed named checks in its source:

1. Official 2.7.1 artifact and live identity.
2. Two distinct owned server processes.
3. Exact live, soft-deleted and destroyed source history.
4. Required metadata CAS and a real incremented metadata counter.
5. The same source after a real restart.
6. A pristine target mount.
7. One completed source raw export.
8. Soft-deleted payload retained; destroyed payload absent in the bundle.
9. Source unchanged after export.
10. One completed native import.
11. Actual V6 storage/reader format and logical payload bytes.
12. Exact target history and metadata compared with the official source.
13. Exact target history after SIGKILL, restart and original-key unseal.
14. A downloaded native snapshot.
15. One actual post-snapshot version append.
16. One actual snapshot restore with the native route's HTTP 200.
17. Exact restored history after another cold restart.
18. Original payload recovered by undeleting version 1.
19. Destroyed version 2 remains absent after undelete.
20. Stale data CAS rejected without effect.
21. Stale metadata CAS rejected without effect.
22. Correct metadata CAS increments the original counter exactly once.
23. The official source remains unchanged after target mutations.
24. Source files and candidate binary retain their exact identities.
25. Both owned servers stop, even if one cleanup fails.
26. The public report excludes captured runtime credentials.

Exact comparisons include timestamps, custom metadata, indices, flags,
payloads and counters. A loop of ordinary KV writes does not establish a
historical import.

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
