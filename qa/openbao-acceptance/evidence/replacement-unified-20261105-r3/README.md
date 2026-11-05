# R3 Mac complete regression evidence - failed 180/181

This is the preserved complete Mac regression result for source commit
`6b16a9292d046bbc42aec65045fa105aaa1ac5de`, tree
`0de9c516e94a47cb89e2e0f5ac2146e60913cfef`.

**Result: failed.** All 181 required tests were inventoried and attempted once.
The server suite passed 171/172 and the HA library suite passed 9/9.
The original 176-test set passed 175/176; the original 60-test acceptance
subset passed 60/60. The five added protocol-projection cases passed.
The complete denominator was retained. No test failure was converted to a
pass, removed, or hidden by a retry.

## Qualification boundary

These are isolated tests built from the normal product source on a real Mac
using its external T5 filesystem. They do not certify production credentials,
a completed client or backup migration, three-host physical HA, independent
AuthBus trust, or a production cutover. No production configuration, service,
credentials, traffic, backups, or old binaries were changed or deleted.
`full_replacement_qualified` and `production_changed` remain false.

The separate 34 MiB normal-backend migration/restore run, real Mac/ROG/Pocket4
HA, equivalent official OpenBao 2.7.1 HA/resource comparison, independent
AuthBus trust, and per-host migration gates remained outstanding for this
candidate. Passing SDK or library tests cannot replace those gates.

## Retained failure

The only failure was:

```text
service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor
```

This is case 0128. It exited 101 after 13.749309 seconds within its original
120-second case budget. It did not time out or get cancelled. Its actual
child was reaped and the owned process group was empty.

The original test compared the complete installed published root against a
later selected published root. At the failed assertion both epochs were 1
and both object counts were 9, but generation/publication-index changed from
38/89 to 46/105. The actual TLS restore response was 204; the earlier response,
history, 404, actor, and marker checks in this case had passed before that
assertion failed. That observation alone does not establish why the root
changed, or qualify a candidate. Subsequent diagnostics and any corrected
assertion belong to separately identified revisions; they are not substituted
for this preserved R3 failure.

Raw files are retained as `regression-server-r1/test-0128.*`:

| File role | SHA-256 |
| --- | --- |
| Intent | 5339205f090f7de268f60b76c3536dd341404124204c04161286ee83248d1b4b |
| Process result | 9d4e88f43015655ed849573182e19a813045591a3c2653c888009b94bd4cafdd |
| stdout | 4b736fb714f5fe4c7953feb60844a7c4ef5185d0add2d76e78601bccc64e33ab |
| stderr | fbc749e040426681f53a050395d72ad4d84f52384fe121c40bd6de43aa333918 |

## Source, executable, and manifest identity

The source checkout was the actual published commit, not a local commit
merely described as equivalent. Source and retained executable hashes were
checked before and after the test runs.

| Item | SHA-256 |
| --- | --- |
| Actual normal server | 8b42f0a6bc2de0647e558c065f517b52736c208b619902943663fe4a768f44d0 |
| Server libtest | f789e25f88880693aca01896676191e0f8b1c12c93a23d6ad8727f0c6c1e1eef |
| HA libtest | aad04c6fb205be71473779749fff21f5f315edd0f3e7f2681954019c14c07bc5 |
| Build result | a17913754a19a0434651b585d93bc08bdb07a1c0351904467c9248ed88f2aafb |
| Server 172-test manifest | ee44d8dc29f0762b532d13af3ecf2417638855e9464ca0bb052ae3f2dd35ba9e |
| HA 9-test manifest | 132ae0404e4d40ac9adc159533176b0e54d4ab1b32928aabf8b9b977c2e15287 |
| Preparation result | 0592a1684da73695f7bf3f00c311f087b5e3ff7db6d622819160942e776a603d |
| Unchanged regression runner | b5b936d1c75c2b7ef880aa0f60ca446bab479b30ddf0ccda9e0d095087e806f1 |
| Full aggregate | d0b4ac8ff03392517e102df4b2a2c9167f2b377474809da64d91d92b1db78975 |

## Independent terminal observations

`mac-runtime-terminals.public.json` contains independently read authoritative
runtime terminal states, separate from the test controllers' own results.

| Job | Runtime outcome |
| --- | --- |
| mac/1a1aa7d25bc-fc05-439e - build | succeeded, exit 0 |
| mac/1a1aa8c30a4-fc05-443d - server suite | failed, exit 1 |
| mac/1a1aa944888-fc05-44a6 - HA suite | succeeded, exit 0 |
| mac/1a1aa9663b8-fc05-44cc - aggregate | failed, exit 1 |
| mac/1a1aaae1513-fc05-45fd - independent archive readback/export | succeeded, exit 0 |

All five observations have confirmed terminal publication, complete and durable
output, no log truncation, no runtime timeout, and no automatic retry.
End-of-file from a log stream was not used as a substitute for terminal state.
The export succeeding does not change the regression's failed status.

## Archive and reproducibility

`r3-mac-regression-evidence.tar.gz` is 522,096 bytes.

* Archive SHA-256:
  `9ba5b8407a2878f37843a948b29e1b0031deb9f67b3619dbe9e44746070b46f8`
* Embedded manifest SHA-256:
  `b8d6a160659165fcf81a06415c54b9eeaf165d115cd79c675a2ee7f6d782dabe`
* 798 original evidence entries plus the embedded manifest: 799 regular USTAR
  members, totaling 3,425,239 uncompressed bytes.
* Git blob identity of the archive:
  `f66c1a51180e769eefc239e518dbca31fd8d3875`.

The explicit allowlist contains original per-test intent/process/stdout/stderr,
inventories, source and build receipts/logs, executable identities, the exact
manifests, preparation and aggregate, control scripts, and executor receipts.
Additional strict-204 control QA and full34 EOF-scope records are explicitly
control-only evidence; they are not a product HA or full34 run.

It excludes symlinks, private-run content, credentials, secret values,
snapshots, executable binaries, and Git bundles. Four sensitive-data scanner
positive controls passed and the allowlisted files produced no findings.
This scanner result is a scoped check, not a universal guarantee about data
outside the allowlist.

UID/GID/mtime and gzip filename/time were normalized for deterministic output.
A repeat package matched byte for byte. The primary reviewer independently
reopened the archive, checked its exact member names and count, verified every
one of the 798 member SHA-256 values, checked the manifest and archive hashes,
and matched the aggregate to the standalone JSON in this directory. Original
source evidence files remained unchanged.

After downloading, verify the archive hash before extracting:

```sh
shasum -a 256 r3-mac-regression-evidence.tar.gz
tar -tzf r3-mac-regression-evidence.tar.gz
```

Read the embedded manifest for exact member paths, lengths, and hashes, then
compare each extracted file. The standalone aggregate permits review of all
181 results without treating this README as the authoritative test result.

## Prior and later revisions

The prior R1 complete Mac and Linux failures remain in the adjacent
`replacement-unified-20261105-r1` directory and its immutable history.
This evidence commit only adds files; it neither rewrites those results nor
updates the repository's main branch. Later candidates must carry their own
source, build, full regression, and live-test evidence.
