# Native KV2 convergence: retained failures and the next candidate

This checkpoint retains original cross-platform failure evidence and the inputs
for candidate `09c14eae7a3b52dee8ce3af3175dad5900ac59ec` (tree
`dfb0df97a2c74b1c0154f45342f3debb0ce438ab`). It contains **no successful 107-case
receipt for that candidate**, no fresh-directory DR execution, and no production
migration authority. Later results must be bound to their own source, build,
selection, executable hashes and authoritative Runtime terminal records.

The required order remains formal KV2 migration and recovery, physical HA,
trusted AuthBus credentials without J3160, host-by-host real-client cutover, and
only then legacy cleanup. None of those production gates is accepted by this
checkpoint. No production traffic or old service/binary cleanup was performed.

## What actually ran

The fixed selection has 107 unique names: 90 server cases and 17 HA-service
cases. The latter explicitly build with `native-v6-peer-ingress`. The selection
is 61 retained cases, 27 snapshot cases, 15 JWT cases and 4 TLS-close cases.
Every name is reconciled with the newly built executable's complete `--list`
output before execution. A missing, ignored, failed or unexecuted required case
does not pass.

| Host and attempt | Source | Actual executed | Passed | Failed | Unexecuted | Authoritative result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| ROG r4 | `2b38f091` | 88 | 85 | 3 | 19 | Failed; snapshot-audit group |
| Mac 2b38 r2 | `2b38f091` | 0 | 0 | 0 | 107 | Controlled cancellation during libtest compilation |
| Mac f301 r1 | `f301a0f3` | 103 | 94 | 9 | 4 | Failed; JWT group |
| ROG r5 | `f301a0f3` | 103 | 94 | 9 | 4 | Failed; JWT group |
| ROG r6 | `868439e6` candidate, source not admitted | 0 | 0 | 0 | 107 | Failed before compilation; existing coordination lock |
| Mac 868 r1 | `868439e6` | 103 | 100 | 3 | 4 | Failed; JWT group |
| ROG r7 | `868439e6` | 103 | 100 | 3 | 4 | Failed; same three JWT cases |

All executed cases in this table had zero ignored cases. The Mac and ROG
`868439e6` runs each completed the first 88 cases, then reported 12 passed and
3 failed within JWT15. Their completed-group count is therefore 88, and 19
cases remain unqualified under the whole-group admission rule. The 100 actual
passes must not be rewritten as a complete 107-case pass. The four TLS cases
were enumerated but were never executed in these failed runs.

The normal release binaries and both libtest executables were actually built
for each of the f301 and 868 completed attempts. A built server binary is not
enough to admit DR when the matching build/test receipt failed.

The Mac 2b38 cancellation retains its original controller result and a separate
authoritative Runtime reconciliation. It is not reclassified as a Rust compiler
diagnostic failure. The ROG r6 coordination lock and its original checkout were
preserved; the r7 attempt used a separate verified clone with no hardlinks.

### Source-bound terminal receipts

| Attempt | Runtime job | Original result SHA-256 |
| --- | --- | --- |
| ROG r4 | `1a1b0722961-fc05-7091` | `3e7ff56be3e36f32aabf77ff67f84678d4f13e597e3ef40490b1bbc4e3547902` |
| Mac f301 r1 | `1a1b092715c-fc05-716d` | `31b60348a98aef69c57381637cc59d7c69ba3f6729ba63f89c2b7ff76e5ea155` |
| ROG r5 | `1a1b0918213-fc05-716a` | `3c5b97830c373d8366fabfb4f8362fd0710d72d366975609a1baa2cde6bce3e9` |
| ROG r6 | `1a1b0b787ab-fc05-7256` | `c08e70f085cfcc1657e01ad4f9c9e9b7bb910e63ce89f1018cbe03b7cc9e8b8f` |
| Mac 868 r1 | `1a1b0bb5170-fc05-726c` | `8f8ecf43e2fbca843d0c0635b19a774a61f8fb0e17d87c019ade20f8a738a419` |
| ROG r7 | `1a1b0bf6f25-fc05-7292` | `423799fbc2e69b08e8bc2f29f9813b1365f017765f9292394a48ce1b7d068a9e` |

## Why the test repairs were necessary

Each failure remains in its original receipt and logs. Repairs below are
reviewed changes with a new source identity; no failed receipt was edited into
a pass, no case was dropped, and no runtime budget was increased.

### Snapshot operation versus terminal-clock successor

ROG r4's three audit failures compared a historical restore operation digest
with the later durable terminal-clock successor. The failed assertions occurred
before the cold reopen assertions. `f301a0f3` binds the original operation and
its legal successor separately while retaining the exact warm and cold selected
root checks. The four snapshot-audit cases subsequently passed on both real
hosts at f301 and 868. This evidence does not establish physical multi-node HA.

### The f301 JWT observer and orphan expectation

Eight f301 JWT tests tried to observe Identity through the legacy inline JSON
serialization of the complete Engines owner. Their fixture already mounted
real native KV2, whose native read view intentionally refuses that legacy
representation. The observer failed with `Identity projection` before reaching
the negative-path assertions.

`868439e6` reads the actual complete root Identity through a test-only accessor,
retains complete Auth observation, and binds the real native KV1/KV2 references
and reader floor. It does not make production native KV2 serializable through
the legacy path. The Identity disabled/enabled positive control verifies that
the observer can detect a real state change.

The ninth f301 failure expected an orphaned Token API child to be revoked when
its original JWT mount was disabled. The existing Token API contract retains
the detached child's own issuer. The corrected test creates a separate still
dependent parent/child control, proves both controls are live after role removal
and cold reopen, and then proves mount removal revokes that dependent tree.
The real orphan continues lookup, exact KV read and renewal through cold
reopen, then explicit self-revocation removes it. This complete test passed in
both 868 attempts.

Official OpenBao 2.7.1 source at
`a5db72cef75c24b920ade02065b18dd8eb666bac` was inspected for Token API parent/path
creation, `revokeOrphan`, mount retirement and expiration-prefix behavior. That
is source-level corroboration, not a claim that this exact protocol sequence
has already been executed against an official 2.7.1 server in this checkpoint.

### The three failures reproduced at 868

Candidate `09c14eae` changes only
`crates/heptabao-server/src/service_native_jwt_tests.rs` and the bodies of the
three affected named tests, plus a fixture helper. All 15 names and all 107
selected cases remain unchanged.

1. **Mount token type.** `default_batch` is malformed wire input and correctly
   receives 400 before the native-owner support check. The test now separately
   exercises valid `default-batch` with the original expected unsupported-profile
   response, 501, and retains the malformed 400 case. Both require unchanged
   complete state, no returned credential and no pending auth delivery.
2. **Role policy assignment.** Updating the existing role retains its
   `native-jwt` policy. The original manager fixture lacked that policy, so the
   pre-existing non-root policy-assignment check rejected its POST before the
   DELETE assertion. The successful manager and no-sudo actor now carry the
   retained role policy. A manager without assignment eligibility remains an
   explicit 403 negative control, and the independent no-sudo 403 control stays.
   Product authorization is unchanged. This establishes the existing HeptaBao
   contract; it is not a claim of complete OpenBao role-administration parity.
3. **Display path and actual issuer.** For the actual unroled Token API child,
   a syntactically valid public `creation_path` is a response fact. It is not a
   replacement for real provenance or the parent graph. Six original missing
   owner/grant/parent-graph negative probes stay unchanged, and the seventh
   now uses the invalid string `auth//token/create`. The original JWT-looking
   display path is retained as a detached positive control with real issuer and
   parent intact; removing provenance from that same value must still fail.
   The real fixture remains unchanged and its actual API lookup still reports
   `auth/token/create`. This is explicitly scoped to the unroled, non-SDK
   fixture; named roles have their own immutable path binding, and public
   origin also participates in SDK instance fingerprints elsewhere.

The exact repaired file is 42,377 bytes with SHA-256
`d36bd868975958093c50218ad1e06b20a58b5156a37cd58718dfdc1654c1f156`.
Independent review checked both the semantic boundary and the unchanged case
selection. Actual pinned Mac rustfmt job `1a1b0dff6e5-fc05-7384` completed with
exit 0 and an empty formatter-only diff. Formatting is not compilation or a
product test result.

## Evidence custody and exclusions

The original result files are preserved byte-for-byte. Small logs retain
native read metadata; larger files were recovered using version-bound chunks,
independent chunk hashes and full-file hashes. The Mac f301 full log collection
contains its three Cargo JSON streams and full libtest listing. The separate
Mac 868 complete-log manifest contains 148 safe original step logs and an
independent reconciliation of all 103 executed names against the 107 selection.
The ROG 868 complete-log manifest similarly preserves all 94 original step
logs, full Cargo output and listings, and its separate reconciliation of the
same 103 executed names and four unexecuted TLS names.

Post-failure native file-info reads independently match all four new artifacts
on both 868 hosts. Original retained binaries were checked before and after the
attempts. Runtime records distinguish failed, cancelled, timed out, still
running and never executed states. These classifications cannot be inferred
from a controller's success-looking progress line alone.

Raw global process listings, private recovery transport wrappers, credential
values, private key contents and production business data are not published.
Withheld raw process logs remain on their originating host and are identified
by bounded path/size/hash metadata in the applicable manifests. A pattern scan
is supplementary; the reviewed source and capture scope determine the public
allowlist.

`FILES.sha256.json` covers this checkpoint's public files. The input manifests
remain separate so their original byte identities are not changed when this
checkpoint copies their allowlisted files. Empty stdout/stderr files are
retained as actual zero-byte artifacts.
Original log whitespace and final blank lines are also retained; normalizing
them would invalidate the independently recorded byte hashes.

## Next execution and production gates

The 09c14 Mac and ROG jobs were submitted separately with fresh source/output
directories and the original per-host budgets: Mac outer 8,280 seconds, ROG
outer 12,000 seconds, original build caps, 30-second listings and 600-second
whole runtime groups. Mac job `1a1b0e9a401-fc05-73ec` and ROG job
`1a1b0e79889-fc05-73db` have no completed result in this checkpoint. ROG's new
controller differs only in seven source/input binding constants; its full
module AST after masking those values is identical to the r7 controller. Its
selection retains the original 13 artifacts and adds the four actual 868
artifacts for a total of 17 protected artifacts.

The [fresh-directory DR25 contract](../../KV2_FRESH_DIRECTORY_DR25.md) still
requires a fully accepted 107-case build receipt, the matching normal server
and seed tool, the exact QA source and selection, the original full34 workload,
and the additional fresh-directory recovery obligations. Unit tests of process
custody or the wrapper do not execute DR or grant production authority. Failed
f301 and 868 receipts cannot be admitted merely because their normal release
binaries exist.

The actual Mac wrapper guard job `1a1b0b212fb-fc05-7239` ran six guards with stub
DR and short owned Python children, and passed in 0.127 seconds. The recovered
manifest distinguishes byte-exact original files from two parsed Runtime
objects whose transport serialization was not reconstructed. The 09 wrapper
only changes eight fixed bindings from that version; full masked-module AST
comparison preserves all execution and cleanup logic. A separate local check
uses the unchanged DR validator on the actual failed Mac f301 and 868 receipts,
under both their own and the new candidate source bindings. All four are
rejected at `completed_bound_build_receipt_required`, with no subprocess,
network, product or DR execution. These are admission checks, not recovery
results.

Even a successful synthetic full34 plus DR25 execution will not by itself
establish a formal production storage service, the real source-writer boundary,
actual credential migration, physical Mac/ROG/Pocket4 HA, provider validity,
client and backup migration, rollback readiness or safe legacy removal. Those
remain separate required gates. Earlier 61-case, 31-case and 69-case passes are
bounded historical evidence and are not reused as acceptance of this candidate.

Compiler elapsed times, build-process RSS and disk-space admission observations
are not matched product-resource benchmarks. A comparable OpenBao 2.7.1
correctness, HA and resource workload still needs its own execution evidence.
