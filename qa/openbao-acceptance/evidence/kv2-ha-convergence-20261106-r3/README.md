# Native KV2 convergence: Mac 107 passed; first fresh-directory run failed

This checkpoint binds the first complete Mac ordinary-build qualification to
source `4bde9aee03fcd27c59e13607e529b1cee594b249`, tree
`f08493a23f8ea0637073651231865ea9607b790e`, and retains the subsequent failed
full34-to-DR25 execution. **Formal KV2, physical HA, AuthBus migration, real
client cutover, resource comparison, and full replacement remain unqualified.**
No production traffic was switched and no old service, binary, or retained
attempt was removed by this work.

The required order remains formal KV2 migration and recovery, actual physical
Mac/ROG/Pocket4 HA, trusted AuthBus credentials without J3160, host-by-host
client and backup migration, and only then legacy cleanup. A passing component
suite or isolated SDK rehearsal does not satisfy a later gate.

## Actual execution results

| Host and attempt | Fixed source | Executed cases | Pass / fail / ignored | Authoritative terminal |
| --- | --- | ---: | --- | --- |
| Mac ordinary build, 09c14 r1 | `09c14eae` | 103 of 107 | 102 / 1 / 0 | Failed, exit 1 |
| ROG ordinary build, r8 | `09c14eae` | 103 of 107 | 102 / 1 / 0 | Failed, exit 1 |
| Mac ordinary build, 4bde9 r1 | `4bde9aee` | 107 of 107 | 107 / 0 / 0 | Succeeded, exit 0 |
| ROG source preparation, r9 | `4bde9aee` | No product tests | Source preparation only | Succeeded, exit 0 |
| ROG ordinary-build launcher, r9 | `4bde9aee` intended | 0 | Controller not installed; compiler not started | Failed, exit 1 |
| Mac DR source staging | `4bde9aee` | No product tests | Fresh QA source only | Succeeded, exit 0 |
| Mac DR prepare-only | `4bde9aee` | No product tests | Actual source/build/storage admission | Succeeded, exit 0 |
| Mac actual full34-to-DR25, r1 | `4bde9aee` | Original baseline incomplete; 5 DR observations | 4 DR checks passed; no recovery qualification | Failed, exit 1 |

The two 09c14 executions each completed the first 88 cases and then failed one
case in the 15-case JWT group. Four TLS cases were never executed. Their 102
individual passes do not constitute an accepted 107-case receipt. Both complete
failure packages retain the original assertion, outputs, source bindings, and
authoritative terminal records.

### Why the last JWT fixture changed

The role retained both `native-jwt` and the automatically added `default`
policy. The old helper issued the manager with `no_default_policy=true`, so
the manager lacked part of the role's effective policy set. Its TTL-only POST
was therefore rejected before the later DELETE assertion.

Commit 4bde9 changes only the JWT test file. It checks the actual role, token
issue response, and lookup-self policy sets; uses an eligible manager; retains
the old missing-default actor as an explicit denial control; and keeps the
missing-native-policy and no-sudo controls. The original successful POST,
DELETE, and subsequent GET behavior remains required. No product permission
logic changed, no named case was removed, and no execution budget increased.
This preserves the existing legacy ACL contract; it is not independent
OpenBao 2.7.1 role-administration protocol parity.

The actual pinned Mac formatter run and its original inputs, output, diff,
controller, and Runtime terminal are retained separately in
`mac/default-policy-fixture-formatter-r1`.

## Mac's accepted ordinary build

Runtime job `1a1b116ba98-fc05-75a6` completed with exit 0, without timeout or
cancellation. The exact 181,226-byte result has SHA-256
`90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6`.

All 107 unique names were reconciled against the complete newly built libtest
listings and the 30 actual test stdout files: 90 server cases and 17 HA-service
cases, across 16 groups. There are no ignored, failed, missing, or unexecuted
selected cases. The four retained artifacts each have exactly one matching
Cargo compiler-artifact event with the correct package, absolute source entry,
features, normal profile, and `fresh=false`, plus an independent native full-file
hash. All registered owned groups retired; five previous source roots and
17 previous artifacts remained unchanged. A separate post-terminal read-only
job confirmed the same clean source HEAD and tree.

| Actual artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Server | 92359328 | `5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c` |
| Seed tool | 86355760 | `203c7af52c0f9aa4ca71e591c1428acac9382f3c4105036a494631b0e1cae8e7` |
| Server libtest | 154608832 | `823b6590c23d736d61d03ec6f27e44f258b0766096737bdc26e73fa0113a5b1b` |
| HA-service libtest | 17068112 | `3c5fd3113ff107db07c833c4d7c80070f29e3bbd1937928af670f1bb6bd2e6f0` |

The complete package has 206 files, including 184 original safe step streams.
Four whole-host process streams are explicitly withheld; their bounded
metadata does not authorize publication of their contents. The original
critical 50-file package was not rewritten when the complete package was made.

## First actual Mac full34-to-DR25 attempt

The source-stage job `1a1b1311acc-fc05-76cc` created a separate clean QA checkout
without shared Git-object inodes or alternates and preserved the old checkout.
The prepare-only job `1a1b132edcf-fc05-76de` actually validated the completed
107-case receipt, selection, artifacts, official OpenBao 2.7.1 binary/archive,
and distinct APFS devices for the external work root and internal backup root.
The canonical prepared binding is
`0709194a4dcecee3d91274ebc7185487623ec00e1910306be0928a641b1bae19`.
Prepare-only did not start a product process or grant storage acceptance.

The single actual run was job `1a1b137be71-fc05-76fa`. Its authoritative terminal
is **failed / exit 1**, with no timeout or cancellation. The wrapper observed
50.712132 seconds; its original work deadline did not fire or renew, and signal
and timer handlers were restored. The original HTTP 15-second, migration
360-second, work 1,740-second, and Runtime 1,800-second budgets stayed intact.

The wrapper result is 2,142 bytes, SHA-256
`5513b8ba10c7b79547b9a9d284b9ad352d8710e26fb5b3c71798c92d57635f88`,
and reports `actual_dr_controller_failed`, controller exit 1, five observed
DR checks, and four passing DR checks. The original full34 31-case requirement
did not qualify. The failure is not reclassified as a successful backup,
fresh-directory recovery, or production storage migration. Its work, output,
backup, key-custody, and failed-attempt directories remain retained. No automatic
rerun or same-operation replay was performed.

The separate read-only diagnosis identifies the failed predicate as
`complete_v6_archive_seal_binding`. Both independently inspected archives
report 9,009,418 physical `state.bin` bytes, generation 4, the expected object
snapshot format, and equal existing seal identities. The predicate demanded
at least 35,651,584 physical bytes. The final baseline summary records 21
passing checks, including final custody and credential-reporting checks;
the 31-case baseline did not qualify.

Independent source inspection explains why that lower bound is invalid:
`PayloadDescriptor::encode` in `engines/kv2_native_paged.rs` stores each keyed
256 KiB block once while keeping every reference in the logical descriptor.
Its reader follows all references and verifies the complete logical length
and digest. This fixture's large values contain repeated single-character
payloads. `v6_object_backup.rs` computes the pack length from the encrypted
core, unique registered ciphertext slots, framing, and footer; the server
writes that physical length into snapshot `state_bytes`. It is not the sum of
all logical historical payload lengths.

This diagnoses a QA measurement error, not successful recovery. A subsequent
source-bound correction must retain the 34 MiB logical-capacity requirement,
all 19 API/raw history observations, complete archive checks and seal binding,
the original 31 plus 25 obligations, and the full cold/fresh-directory restore.
No corrected execution result is implied by this diagnosis.

The read-only projection job `1a1b141a2cd-fc05-774a` completed successfully;
its exact 180,368-byte safe stdout is retained. All 277 original child records
were independently reconciled: one completed original wait each, no live
members before reaping, no custody gaps, and top-level custody finished and
passed without interruption. This proves controlled process retirement for
the failed attempt, not successful storage recovery. The projection suppresses
labels outside its grammar; its null `state_format` fields cannot be interpreted
as missing or invalid fields in the private originals. The derived note's
correction is recorded explicitly without altering the original projection.

Private controller output, private summaries and their credential-dependent
fingerprints, keys, and source payloads are excluded from this public package.
The original safe terminal, complete Runtime streams, request, start record,
and wrapper result are present in `mac/dr25-execution-4bde9-r1`.

## ROG launch boundary

The r9 source preparation completed at the same 4bde9 HEAD/tree and preserved
the previous failed attempt. Its build launcher then failed at a create-only
directory operation: `build-test-r9` already contained another candidate's
preparation. The actual launch ran no controller, compiler, or tests. The
collision and both preparations were retained without overwriting either.

The separate read-only observation found source `6d4562e7` in that preparation,
and active compiler processes outside the convergence root. A unique
`build-test-4bde9-r10` output was prepared for a later attempt. Admission still
requires natural compiler idleness under the original resource rule. This
checkpoint does not claim that a waiting attempt has run or that ROG's 107
cases have passed. The other candidate's test and diagnostic changes
were not silently merged into the accepted Mac source.

## Formal source audit and remaining gates

`formal-source-audit/AUDIT.public.json` is the independently reviewed allowlist
projection of 28 actual read-only jobs. The raw receipts, account-bearing
paths, business values, and credential-dependent fingerprints remain private.
Its observations are bounded to the checked hosts and paths, not a claim of
an exhaustive fleet inventory.

The production-named Mac, ROG, and Pocket roots observed by that audit were
staged older native profiles with empty data/state/raft directories and no
started current service. Existing application SQLite stores and historical
encrypted backup captures are real source material, but they do not themselves
provide OpenBao KV2 historical versions, tombstones, or mount identity. Earlier
current-profile and private-SDK rehearsals covered limited profiles and do not
establish all-account or production gateway migration.

The next qualification must preserve these separate obligations:

1. Complete the actual synthetic migration and fresh-directory recovery, then
   qualify current business-data capture, real writer and synchronization
   boundaries, independent backup, cold recovery, and rollback.
2. Exercise leader failure, election, ReadIndex, durable commit, restart, and
   failure recovery on the real Mac/ROG/Pocket4 machines.
3. Establish a trusted credential source without J3160 and verify actual
   AppRole, TLS, Policy, KV, renewal, revocation, and key protection.
4. Verify each host's real credentials, dependency clients, backup paths, and
   rollback before switching its traffic.
5. Obtain independent evidence for every migrated client and backup path
   before deleting old OpenBao services, old HeptaBao binaries, or regenerable
   intermediate assets.

Comparable OpenBao 2.7.1 correctness, HA, and resource workloads still require
their own observations. Compiler elapsed times, compile RSS, and available-disk
admission measurements are not product resource comparisons. CI and
single-machine component tests do not replace the physical production gates.

## Evidence custody

Input-package manifests retain their original bytes and are listed separately.
The checkpoint manifest covers every public file except itself. Original log
whitespace and empty streams are preserved. Later results require a new
source-bound addendum; this checkpoint and the previous r2 historical record
are not edited into success.
