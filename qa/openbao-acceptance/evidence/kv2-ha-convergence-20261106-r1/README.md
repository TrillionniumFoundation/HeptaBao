# HeptaBao replacement continuation — 2026-11-06

## Decision and required order

The retained evidence does **not yet qualify replacement of the real OpenBao
2.7.1 duties**. The required order remains:

1. Formal native V6 KV2 migration, complete backup and fresh-directory recovery.
2. Physical Mac / ROG / Pocket4 HA, including leader loss, election, ReadIndex,
   durable publication, restart and recovery.
3. A trustworthy AuthBus credential source independent of J3160, with real
   AppRole, TLS, policy, KV, renewal, revocation and key-custody evidence.
4. Each host's actual clients, credential read/write, backup, rollback and
   synchronization boundary, followed by that host's qualified traffic cutover.
5. Cleanup only after every client and backup path has migrated with independent
   evidence.

No real traffic has been switched and no old OpenBao service, old HeptaBao
binary, original evidence or backup has been removed by this continuation.
The machine-readable decision is [qualification.public.json](qualification.public.json).

## One candidate lineage

The current product candidate is `2b38f091c2903eac74b4ed9dc32b1f1f00fd8a8a`, tree
`e2da9354cf482a8d3ebd67898812e2fcb026832a`. Its parent is
`1d63ec98ce0fc5cbc7d74a37f6307be148dd5aeb`, tree
`cae7f371ee07d90f7ac9d50d1c205ca77bfd3902`. The latter descends directly from
`4be17241395952b01890d30545b537a28ac2c06c`, which directly retains snapshot/JWT
source `2379d02ba1ee3e88989815d5a978f998822bac4f`. That source retains the
`4e808d0ecb1bcded22870a7ec960dfb2491cf6ec` same-root A→B→A repair.

The divergent `23b689d3617db758657b87b66129d60cbd076f95` Pocket4 result is not
added to this candidate's pass counts. GitHub publication through the connected
API reproduced the reviewed local source tree exactly; the public commit is
the execution identity, rather than the unpublished local commit alias.

The candidate includes four strict real-TCP TLS-close regressions and explicit
pinned official CLI version selection, including OpenBao 2.7.1. The historical
CLI default remains unchanged. That existing CLI workload is a KV1/file or
PostgreSQL workload; selecting 2.7.1 does not turn it into formal V6 KV2 recovery.

## Newly executed failure and repair

The first normal ROG build of `4be1724` genuinely failed before any selected
Rust test executed. Cargo exited **101** after **63.699666 seconds**, with 13
compiler diagnostics. The durable controller job was
`1a1b04e8b40-fc05-6fa1`; its authoritative final state is failed/exit 1, complete
and durable, with terminal publication confirmed and no timeout.

- Nine `E0599` diagnostics came from calling the HA-control-only `HaLock`
  method on the `Service` mutex.
- Two `E0061` diagnostics came from PKI/SSH dispatch calls missing the new
  optional native JWT lifetime output parameter.
- Two `E0277` diagnostics followed the unresolved snapshot completion type.

The repair uses existing `lock_until(service, original_deadline)` at the nine
Service-writer acquisitions. The helper keeps the minimum of that deadline and
the thread-local outer deadline, checks expiry before and after `try_lock`, and
has no unbounded fallback. PKI/SSH retain their existing route, engine and Actor
checks and pass no JWT lifetime output slot. The repair does not add a replay,
leader chase, response retry or fresh deadline.

Both the first formatter failure/recheck and the later fixed-source formatting
run used the pinned actual ROG Rust 1.98 executable. They are retained under
[rog/format](rog/format) and [rog/compile-fix-format-r1](rog/compile-fix-format-r1).
The original build failure and compiler diagnostics are under
[rog/build-test-r1](rog/build-test-r1). All three separately retained old binary
artifacts remained byte-identical before and after that failed build; its owned
process group was empty at completion.

The next real ROG run, `1a1b05cba7c-fc05-6ff7` under `build-test-r2`, passed
the normal optimized server/seed build in **588.484568 seconds**. The server
libtest compilation then failed with cargo exit 101 after **50.183763 seconds**:
two legacy HA constructors omitted the new feature-gated snapshot fields, and
two assertions used unstable `ExactSizeIterator::is_empty`. The durable job is
authoritatively failed/exit 1, non-timeout; **zero selected cases executed**.
The original result and compiler errors are retained under
[rog/build-test-r2](rog/build-test-r2).

`2b38f091` repairs only those three test-source files: the legacy constructors
initialize the optional handler and empty server-pin map under the original
feature guard, and the assertions use stable `len() == 0`. An independent
review checked their meaning and the unchanged test names. The pinned actual
ROG 1.98 formatter and check passed in job `1a1b06ecedf-fc05-7080`; the exact
formatted patch and receipt are under [rog/libtest-fix-format-r1](rog/libtest-fix-format-r1).

ROG `build-test-r3`, job `1a1b0705d8b-fc05-708b`, failed before any compiler
because the bootstrap packaged `canonical.bundle` while the controller required
`candidate.bundle`. Its final receipt remains retained. The corrected package
uses a new `build-test-r4` directory, job `1a1b0722961-fc05-7091`, with the
same candidate and unchanged original budgets. Its normal release step passed
in **0.399612 seconds**, reusing the unchanged product build; server libtest
compilation is in progress at this evidence checkpoint. No final 107-case pass
is claimed. Mac independently prepares the same source on T5. Its first source
fetch timed out under the original 240-second budget before any compiler; a
verified bundle with the old `4e808d0` as its sole prerequisite supplies the
same source without changing the network timeout or test budgets.

## Actual Mac controller prerequisites

The new DR process-custody helper encountered two real Darwin failures before
qualification: the first numeric `ps` parser rejected a system UID rendered as
`-2`, and the next run exposed Darwin returning `ESRCH` for `getsid`/`getpgid`
after `waitid(WNOWAIT)` had retained the exited original child. Both original
failures and the focused OS observations remain retained. The narrow fixes
normalize signed UID presentation and accept the retained zombie only through
the original unreaped child, its admitted session-leader identity and matching
numeric PID/PPID/PGID/UID/Z-state observations. Generic missing processes or
live identity mismatches remain failures.

The fixed helper's real Mac run `1a1b07481b6-fc05-70a0` passed **15/15** in
**0.906 seconds**, with authoritative success/exit 0 and no timeout. Linux
passed the same 15 cases separately. This qualifies only the declared process
lifecycle checks; it is not a product, recovery, physical HA or cutover result.
[mac/preparation](mac/preparation) preserves original failed/failed/passed
inputs and results. Its explicit [publication allowlist](mac/PUBLICATION_ALLOWLIST.public.json)
excludes the raw Git HTTP trace and the complete private recovery-input bundle.

The first Mac 107 build controller, `1a1b07a9013-fc05-70c1`, failed before
compilation because its `diskutil info` call supplied the T5 child directory
instead of the mounted volume. Its correction queries `/Volumes/T5` and binds
the actual root's filesystem identity. An external compiler observed afterward
is outside this controller's ownership; it is not stopped or treated as a
completed build. The next owned attempt must recheck resources and cache
ownership under the original budgets before compiling.

## Test denominator is explicit

| Selection | Required named tests | Evidence rule |
| --- | ---: | --- |
| Original base groups | 44 | Same six original groups and names |
| Original ingress observations | 7 | Exact cases share one original 600-second group budget |
| Original cold/HTTP2 regressions | 9 | Exact cases share one original 600-second group budget |
| Original same-root publication | 1 | Original exact case |
| New snapshot forwarding | 27 | 10 body + 7 peer + 2 Actor + 4 wire + 4 actual-Service audit |
| New native JWT | 15 | Independent additional group |
| New HTTP/1 TLS close | 4 | Verified TLS EOF, abrupt EOF rejection, writer errors and expired original deadline |
| **Total** | **107** | **90 server + 17 HA-service; no duplicate names** |

The HA-service tests require the explicit `native-v6-peer-ingress` feature.
Its default feature set alone would not enumerate the required 17 tests. Each
new executable must enumerate the exact selected names before execution; zero,
missing, extra selected, ignored or failed cases cannot satisfy a group.

[selection-r4.public.json](rog/controllers/selection-r4.public.json) retains
the exact names, original 61-case source receipts, original profile and budgets,
and independent additional groups. [build-test-r4.py](rog/controllers/build-test-r4.py)
is the exact executed controller. Its functions/classes are unchanged from the
independently reviewed first controller; only source/tree/patch/bundle/output
bindings changed for the repaired attempt. These component tests alone do not
qualify production storage or physical HA.

## Recovered earlier results remain attached to their own source

| Earlier observation | Actual scope | Limit for the current candidate |
| --- | --- | --- |
| Mac and ROG normal 61 | Source `4e808d0`, tree `eba5e650` | Recovered original component results, not execution of `2b38f091` |
| Mac and X230 full34, 31/31 | Official OpenBao 2.7.1 history migrated into the ordinary native V6 file profile | Synthetic 34 MiB history; same-directory restart/rollback; not whole-directory-loss recovery or real credential migration |
| X230 69/69 candidate and 69/69 oracle | Same bounded protocol corpus against real official 2.7.1 | Does not cover all OpenBao routes, authentication methods, upgrade, physical HA, backup or client migration |
| Pocket4 197 | Separate `23b689d` source line | Excluded from this candidate's total |
| Latest three physical post-recovery node roots | Node artifacts were found on all three hosts | Overall controller result and complete denominator were not recovered; no HA PASS inferred |

The full34 profile uses the ordinary binary and explicit `native_v6_file`
storage selection. Its synthetic workload and same-directory recovery boundary
must remain visible. A complete fresh-directory recovery needs a separately
verified backup/key package, stopped original processes, an isolated original
closure and actual restored history on a new directory.

The previous PR160 full CI run `42164486987`, bound to old source `8f3dd835`,
has now reached **completed / failure** for both its head and prospective merge.
It passed the complete locked Rust workspace, strict Clippy, documentation and
the bounded official 2.7.1 corpus, while several HA, runtime/ACL, RADIUS, online
authentication, OpenAPI and cleanup steps failed; the Agent/Proxy comparison
was skipped. The source-control and workflow-trust runs passed separately.
The recovered API results are under [recovered/ci-old-8f3](recovered/ci-old-8f3).
This is an explicit old-source failure, neither a stale running job nor a
current-candidate result. It was not automatically rerun or represented as full
qualification.

## Current real client boundary

Four new metadata collectors executed on the actual hosts on 2026-11-06. All
four jobs reached authoritative successful terminal states with complete,
durable output. They imported no SDK, resolved no credentials, called no
provider or J3160, and changed no production state.

| Host | Observed default AuthBus configuration | Observed agents / direct entrypoints | Meaning |
| --- | --- | ---: | --- |
| Mac | Enabled; address still references J3160 | 5 / 13 | Actual client migration is outstanding |
| ROG | Disabled; configured address still references J3160 | 6 / 14 | A retained address is not active traffic or a completed migration |
| Pocket4 | Enabled; address still references J3160 | 2 / 11 | Actual client migration is outstanding |
| X230 | Default config file absent | 0 / 0 in the bounded locations | This does not establish that the machine has no clients |

All three observed AppRole ID/SecretID files have mode `0600`. Pocket4's CA
file is `0644`; a public CA certificate is not a private key. This metadata does
not verify credential validity, lease ownership, recovery or revocation.

[current-summary.public.json](inventory/current-summary.public.json) links the
actual input receipts by exact file hash, version, host and path. The collector
source commit identifies the metadata collector, not the deployed service.
Raw configuration hashes, credential/profile fingerprints and private capsule
contents are omitted from this published projection; exact originals remain
on their original machines.

Pocket4's earlier persistent hold reconciliation proves the installed hold
files match their originals, while credential-reader classification, unique
refresh ownership, manager conditions and complete process absence remain
unqualified. The original cache/source profile counts and generation mismatch
also remain relevant. The registered systemd/cron inventory does not exhaust
manual, offline, PaperRAID or off-host backups. See
[boundaries-summary.public.json](recovered/pocket4/boundaries-summary.public.json).

The latest recovered Mac AuthBus owner-bind task is an actual failure, not a
pass: its launchd manager rejected integer parsing after bootstrap returned
zero. The result has no completed business checks, and service registration /
lineage closure remain unknown. The exact rejected field/value was not retained
in the safe result and is not guessed here. See
[owner-bind-failure-summary.public.json](recovered/mac/owner-bind-failure-summary.public.json).
The original task was not retried or used to authorize a client cutover.

## Verification and publication boundary

Original retrieved receipts are copied byte-for-byte where safe; their hashes
are checked. Derived projections explicitly identify their source and omitted
private fields. [FILES.sha256.json](FILES.sha256.json) inventories the published
files. Real service data, keys, credential fingerprints and private capture
capsules are not part of this public evidence directory.

The release decision remains closed until the ordered production gates have
their own complete results. An old pass, a new component pass, a successful
bootstrap, a node directory, or a metadata inventory cannot replace those
missing results.

## Subsequent evidence checkpoint

The [r2 checkpoint](../kv2-ha-convergence-20261106-r2/README.md) preserves the later Mac and ROG failures, full safe logs, source repairs, and next-candidate inputs. This earlier checkpoint remains historical and does not qualify the later source or any production migration.
