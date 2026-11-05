# R5 Mac complete regressions - passed 181/181, replacement not qualified

The actual Mac/T5 execution of source commit
`1f188df0f2affebb92702222e9fe5dfb4712194c`, tree
`74bcb2b2af2fc9d349f007cd847fc2f16c08c01a`, passed the complete 181-test plan.

| Cohort | Actual result |
| --- | ---: |
| Server exact cases | 172/172 |
| HA library exact cases | 9/9 |
| Combined unique cases | 181/181 |
| Original 176-case plan | 176/176 |
| Original 60-case subset | 60/60 |
| Added protocol-projection cases | 5/5 |

All required cases were retained and executed once under the original case,
group, and shared-pool budgets. This result was not obtained by rerunning a
failed case until it passed or by dropping cases. The exact manifests, all
original intents/process receipts/stdout/stderr, inventories, group results,
build records, and aggregate are in the archive.

**The acceptance status is `regressions_passed_only`.** The archive does not
claim successful Linux R5 regression, the two-host gate, the separate 31-check
formal full34 live migration/restore, physical three-host HA, independent
AuthBus trust, actual production credentials, per-client migration, production
cutover, or retirement of old installations. No production services, traffic,
credentials, backups, or old binaries were changed or deleted.

## Explicit semantic change from the failed R3 candidate

R3 failed 180/181 on both Mac and Linux. The remaining failure was the
non-root snapshot ACL/historical-restore case:

```text
service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor
```

The R4 diagnostic retained every original test line and the failed equality.
It observed published generation/log-index advances of 38/89 -> 41/95 ->
44/101 -> 46/105 while epoch stayed 1 and authentication clock observations
advanced. That diagnostic remained failed 0/1; it is not converted into a pass.

R5 explicitly replaces that invalid complete-published-root equality across
later authenticated requests. It does not move the baseline, stop clock
persistence, remove the case, or extend its deadline:

* Baseline remains immediately after the actual successful 204 restore.
* After each subsequent v1 read, v2 404, pending inspect, and cancel, complete
  Auth serialization must equal the baseline after applying only the known
  permitted precise time observation.
* The complete encoded native root must match after normalizing only its
  uniquely identified Auth owner reference. All other owner references and
  root fields remain compared.
* Complete epoch-transition records remain equal, including retained roots.
  A read-only borrowed epoch view derives equality so the private retained
  roots participate in that comparison.
* Enrollment, schema, state identity, epoch, migration-source, object count,
  original update actor, ACL denials, restore protocol, historical values,
  tombstones, and reconciliation markers remain checked.

The original assertion text is therefore **not** completely unchanged.
`regression-semantic-change-scope.public.json` states that fact directly and
binds the new source/support hashes to this exact candidate. Original exact
test names and budgets are retained. This Mac run executes the changed case
as part of the whole plan, not as a stand-alone substitute.

R5 changes exactly two source files from its R3 parent:

| File | SHA-256 |
| --- | --- |
| crates/heptabao-server/src/service_native_v6_ha_snapshot_acl_tests.rs | 101642298107bcce8bc657adf3a1335df43bcf70740ea6f38efdefede27d704a |
| crates/heptabao-raft-runtime/src/v6_epoch_restore.rs | 4fb7e6bf6a14d4d46516f7ebfdc05c4f331c74da81fa13d24c5820aeaca447c3 |

Parent commit: `6b16a9292d046bbc42aec65045fa105aaa1ac5de`.
The published R5 source branch is
`codex/heptabao-unified-replacement-20261105-r5`.

## Actual build and identity chain

The clean source checkout was the actual published R5 commit/tree. The build
used Rust 1.98.0 for aarch64-apple-darwin, locked/offline Cargo, the normal
default/native-v6-ha/native-v6-storage features, and the recorded release
profile. The normal service executable and both libtests were retained and
checked before and after the regression.

| Evidence | SHA-256 |
| --- | --- |
| Final source freeze | 57b91c763fac2f9300a2d3ff30fd739b6fa84089889befd8083f74a91d6bcf5a |
| Normal build result | 8e6fae0298c1b643b70d18e383e8ec64113f8b6b1d55e046daf30a1200c53528 |
| Normal server executable | 8b42f0a6bc2de0647e558c065f517b52736c208b619902943663fe4a768f44d0 |
| Server libtest | 46a2bf0e6a0d01993ad154d4f80fa5082fdc66f3b23fa789c558bbdec20e1ab5 |
| HA libtest | aad04c6fb205be71473779749fff21f5f315edd0f3e7f2681954019c14c07bc5 |
| Server manifest | 0f41bc4c6137a778a922baf99eff3772c5cae2cb5d3bf30417afd84b5dc9cf99 |
| HA manifest | 06d3a44e334537b166150f841cf7d41cd3fa35a316ddaeb065fb29d673cb4b6d |
| Preparation | 7780c7ae0dcbaf571d2ff9748a1268f0b4d1cd5ff22011ec9de9000faede9f99 |
| Server result | 38fe026443a05e9fd501bd79918868fff7208fa96e40a04e23b7913396908681 |
| HA result | 9b06ff1bc814e196138a34929da12ad0d6e8ba470883106b7f5e39b14c0f8b47 |
| Full aggregate | 6917e6d2426f53f88c9a7f2e51cba18cdba002ec7d33f5a5be954c8aa4e5510c |
| Semantic change scope | 4120d973733695ef0de18dc0f08c1b614a732cdbe7f15f8974db565baed4d46b |

The normal server hash equals the preceding R3 normal server hash. That is
consistent with the limited test/read-only comparison change. It is still
bound to the actual R5 Cargo/source receipt and the new R5 execution; no R3
test qualification is borrowed. The server libtest changed and was compiled
and executed for R5.

Compiler RUSAGE_CHILDREN maxima in build/test receipts are not a matched
per-service runtime memory comparison. This package does not provide the
requested OpenBao-versus-HeptaBao resource benchmark.

## Independent runtime terminals

`mac-runtime-terminals.public.json` contains primary-reviewer observations
of the authoritative runtime states:

| Job | Actual outcome |
| --- | --- |
| mac/1a1aababc1e-fc05-4692 - final source admission | succeeded, exit 0 |
| mac/1a1aabbb9c8-fc05-469a - normal build and libtests | succeeded, exit 0 |
| mac/1a1aac9f39d-fc05-4748 - server 172 | succeeded, exit 0 |
| mac/1a1aad2f49e-fc05-47bc - HA 9 | succeeded, exit 0 |
| mac/1a1aad472cf-fc05-47cd - aggregate | succeeded, exit 0 |
| mac/1a1aae28ee2-fc05-4870 - archive | succeeded, exit 0 |
| mac/1a1aaef6981-fc05-48d5 - independent archive readback/export | succeeded, exit 0 |

Each has confirmed terminal publication, complete/durable/untruncated output,
no timeout, and no automatic retry. A temporary observer RPC failure was
reconciled against the same existing job and byte offsets; neither the
packager nor the regression was rerun for that transport issue.

Normal successful build cleanup is recorded. Cancellation/parent-death
qualification of the build controller is not claimed by this package.

## Complete archive and independent verification

`r5-mac-regression-evidence.tar.gz` is 745,655 bytes.

* SHA-256:
  `f7ac8f53ad3e47f4dad6b6e8e4d80bf6923549e97fe40f148067add412a314d2`
* Embedded `MANIFEST.public.json`: 376,218 bytes, SHA-256
  `4e93b0812959f6454bed46d26c01279f76880da2b38f75828a25992f424587fb`
* 871 evidence entries plus that manifest: **872 regular USTAR members**.
* The original evidence entries total 4,846,174 bytes before the manifest.
* Archive Git blob: `7f674af74bd9e7f17569fccc5f37456e9a195e99`.

The package uses an explicit allowlist, deterministic USTAR metadata and
gzip timestamp/filename, and preserves original selected bytes. Two package
constructions were identical. All selected source files were checked for
unchanged identity and bytes after packaging.

The primary reviewer separately reopened the archive, checked every member
name/count/length/SHA-256, compared the embedded manifest with its pinned
stand-alone bytes, and compared the archived aggregate with the untouched
original. The exported stdout was fetched by exact non-overlapping byte
offsets and reassembled with its full recorded byte length before publication.

The archive includes the full R5 execution and preserved R3 comparison/failure
chains. The R3 Mac original aggregate, child results, failing case files,
executor records, and prior manifest/receipt remain available. The R3 Linux
selected failing-case/build/aggregate chain is also included; it is not
misrepresented as this Mac package containing every R3 Linux per-test log.

Pure cross-host admission QA is separately recorded as initial 3/27 failed,
then 29/29 and 32/32. The prior strict-204 29-case control QA remains labeled
as its R3 control scope. None of those control-only results supplies a full34,
physical-HA, or production pass.

Four declared sensitive-pattern positive controls matched their controls;
the selected evidence had no matches. The scoped scanner is not a universal
claim about files outside the allowlist. No production secrets, private data
stores, snapshots, or executable binaries are in this public package.

## Prior immutable evidence

The prior complete Mac R3 failure is preserved under
`replacement-unified-20261105-r3` at commit
`08d70687490561145c994b62818c2b23d4075b17`.
The unchanged-assertion R4 diagnostic is preserved under
`replacement-unified-20261105-r4-diagnostic` at commit
`7380f9c36ea5a8889fa7df481973b74f3f75419e`.
Earlier R1 complete Mac/Linux failures remain in their original directory and
history. This commit only adds R5 evidence and does not update main.

The next acceptance gates remain independent and ordered: completed
same-candidate Linux evidence; normal-backend full34 migration/restore and
matched protocol/resource comparison; actual Mac/ROG/Pocket4 HA; independent
AuthBus trust; real-credential/client/backup/rollback proof per host; cutover;
and only then old-service/binary/intermediate retirement.
