# R4 publication diagnostic - original assertion still failed

This diagnostic explains the remaining R3 failure without replacing that
failure or claiming a passing candidate.

* Source commit: `d784a7cb75643bde9d9224d90427dbcddda60a4b`
* Source tree: `c5a4df63dd04c0fa0b39e07f73014796affce752`
* Parent: `6b16a9292d046bbc42aec65045fa105aaa1ac5de`
* Scope: one instrumented test, normal release libtest, isolated synthetic
  state on the actual Mac/T5.
* Result: **failed, 0/1**, exit 101 after 13.6159555418 seconds. No timeout.
* Production change and full replacement qualification: **false**.

The diagnostic only added read-only stage probes. It retained every original
source line in order, including the original failed complete-root equality.
The original 120-second case cap and 15-second application deadlines were
unchanged. No production source path or clock behavior was changed.

## Direct observations

All rows below came from the same actual diagnostic execution. The first row
was captured immediately after the successful actual 204 restore.

| Observed stage | Epoch | Published generation | Publication log index | Auth clock floor |
| --- | ---: | ---: | ---: | --- |
| Installed after 204 | 1 | 38 | 89 | 1793864651.381606958 |
| One history v1 GET | 1 | 41 | 95 | 1793864652.060325750 |
| One history v2 GET, 404 | 1 | 44 | 101 | 1793864652.775628167 |
| One POST PendingInspect | 1 | 46 | 105 | 1793864653.287891000 |

The three later requests contributed 3, 3, and 2 published generations;
each generation corresponded to two additional log entries here. Epoch stayed
1. The original assertion then failed with the same 46/105 versus 38/89
values seen in both R3 platform runs. The later PUT was not reached in this
diagnostic and is not claimed as observed.

These stage measurements establish when the publications occur. Attributing
them to permitted authentication-clock persistence also requires the
implementation contract, not the stage table alone:

* The ordinary read path with precise token-clock state performs admission,
  candidate, and terminal observations. A 404 does not eliminate the observed
  candidate time.
* The snapshot PendingInspect path performs admission and terminal
  observations.
* The native clock-only writer validates the complete derived state against
  a clone of the prior state after observing the permitted time.
* The existing native-file clock oracle compares complete Auth serialization
  after applying only that time observation, and complete encoded native root
  state after normalizing only its Auth owner reference.

Those contracts are in the unchanged parent source, particularly
`service_native_v6_writer.rs`,
`service_native_file_clock_profile_actual_tests.rs`,
`auth_token_precision.rs`,
`service_ordinary_kv_delivery.rs`, and
`service_snapshot_v6_ha.rs`.

A full published-root equality across these later requests is therefore not
an adequate no-replay oracle by itself. It also rejects expected durable
clock publications. The diagnostic did not remove that assertion: it kept
failing, as the raw stderr shows.

The separately frozen R5 candidate
`1f188df0f2affebb92702222e9fe5dfb4712194c` changes that oracle explicitly:
baseline remains immediately after the successful 204; complete Auth bytes
must equal the baseline after only the known clock observation; all native
root bytes other than the uniquely identified Auth reference must remain
equal; full epoch-transition records, including retained roots, must remain
equal. R5 requires its own complete Mac and Linux regression and later live
gates. This R4 evidence does not supply those passes.

## Build and terminal evidence

The diagnostic's normal libtest build completed in 474.841516 seconds within
its 1800-second build cap. The actual retained libtest was 153,745,728 bytes,
SHA-256
`5baeaf3472f394944de29816cc56e9199094802fc00ce484e80a4fc0a9052b53`.

The test used the original exact test name, `--exact --nocapture
--test-threads=1`. Compiler, inventory, and test direct children were reaped;
their owned groups were empty. Source and retained executable were unchanged
at completion.

| Runtime job | Authoritative terminal |
| --- | --- |
| mac/1a1aaa16504-fc05-455e - source preparation | succeeded, exit 0 |
| mac/1a1aaa2d835-fc05-4571 - build and diagnostic | failed, exit 1 |
| mac/1a1aac78a1a-fc05-472b - package | succeeded, exit 0 |
| mac/1a1aac8a275-fc05-4737 - independent readback/export | succeeded, exit 0 |

Confirmed terminal publication and complete, durable, untruncated output
were checked independently. Successful packaging or export is not a passing
diagnostic. The original terminal JSON is retained in the archive, and the
package/export terminals are in `independent-export-terminals.public.json`.

The reported 12,133,875,712-byte RUSAGE_CHILDREN high-water mark includes the
compiler. It is not service RSS and must not be used as a matched runtime
memory benchmark.

## Evidence files and verification

| File | SHA-256 |
| --- | --- |
| r4-publication-diagnostic-evidence.tar.gz | 719fbbab68292b81cd70cf53a1aecdc517fb058cbfc128e8504d057436bdcd54 |
| Embedded MANIFEST.public.json | e49ade1c3b09df59bc4cf6047be21d477ed375a6aa7949bbe63ec73ed4ca6efa |
| diagnostic-result.public.json | ad71d706b1f7afec4d93e0a75fbabbecb1cca80401247e04f99ade8e93aa54eb |
| source.diff | 7985a1457a79c429bbd2fe2e6c7bc66c5fd19823297480ec8b3f33b98bf381e2 |
| Original test stderr, inside archive | de5fa55d0a8866e49082e6738bb6c8178ecc8a12807e1b1a2e7a10bc9fab382c |
| Original diagnostic controller, inside archive | 949376a1dca146f04327b584066d7e6d54a90017b42b93138870a2ddd45b0a11 |

The archive is 129,580 bytes and contains 18 evidence entries plus the
manifest, all regular files. It includes the complete build and test logs,
inventory, receipts, additive source diff, exact modified source file, raw
local Git commit object, original runtime terminals, and package script.
It excludes binaries, secret stores, credentials, and private fixture files.

The package script verified the source commit/tree, clean checkout, all
pinned original hashes, no removed source lines, exact raw commit-object
hash, and deterministic repeat output. A separate readback reopened the
archive, verified all 19 members and every manifest SHA-256, rehashed the raw
commit to its stated Git identity, and compared the result with the untouched
original. Four scoped secret-pattern positive controls passed; no allowlisted
file matched those patterns. The scanner's scope is explicitly limited.

The diagnostic commit is a local commit. Its raw commit object and modified
file are archived for reproduction; the public parent repository provides all
unchanged source. Applying `source.diff` to that parent must produce the
stated tree. Hashing the archived raw commit with Git's commit-object framing
must produce the stated diagnostic commit. Do not relabel another tree or a
later candidate as this execution.

This directory is separate from the complete R3 180/181 failure evidence and
from any later candidate results. No production traffic or old installation
was changed or removed.
