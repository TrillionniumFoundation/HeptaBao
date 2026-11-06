# Native V6 full34 recovery into a fresh directory

`kv2_native_fresh_directory_dr_live.py` defines a new, fixed **DR25** controller.
No earlier DR25 specification or passing DR25 receipt was found in this source
tree. This file specifies work to execute; it is not a live recovery receipt.

The controller retains the original `kv2_271_lossless_native_live.py` full34
profile and all **31** original cases. A small subclass captures two additional
artifacts without replacing any original case. The complete original 31-case
receipt must pass before the independent recovery phase begins. The final DR
receipt has **25 additional named obligations**, each with its actual observations.
Missing, duplicated, false, empty-evidence or skipped obligations cannot pass.

## Recovery inputs and boundary

The original target uses the ordinary `heptabao-server --config` entry point,
with `storage.native_v6_file.path` explicitly selecting its own private data
directory. Initialization, unseal, KV2 mount and public V6 activation remain
explicit API operations. No fixture option or existing service address is
accepted. The independent source is the checked, official OpenBao **2.7.1**
release, serving the original 19 versions: 17 retained 2 MiB live payloads, one
soft-deleted payload and one destroyed payload. API numeric projection and raw
storage precision remain separate comparisons.

Before V6 activation or import, the candidate is stopped and the ordinary
`heptabao-seed export` command exports exactly `state.hbs`, `journal.hbj`,
`ledger.hbl` and `seal.json`. Its original writer fence, receipt, complete
artifact hashes and destination inode are checked. This seed provides the same
seal and startup authorization. It does not contain the later 34 MiB history.

After full34 has reached active V6 and verified its history, the actual pinned
2.7.1 `bao operator raft snapshot save` saves a **V6** archive onto the separate
backup filesystem. The controller verifies canonical archive headers, every
outer checksum, complete gzip framing, `HBV6PK01`, the V6 metadata and seal
binding. This structural inspection makes no standalone AEAD claim; the real
service must authenticate and restore the complete archive later.

The backup kit contains the encrypted four-file seed, the native archive, the
seed export receipt, a closed manifest and a verification witness containing
metadata and hashes. It contains no original raw source bundle or plaintext
business payloads. The unseal key and root token stay in a different private
key directory. The separate original full34 directory does retain synthetic
source material for auditing, and is quarantined before recovery.

Once the original 31 cases and cleanup have passed, the entire original private
root is hashed, with every file and directory inode recorded, and renamed into
quarantine. Its original path must be absent. The complete manifests before
rename, after rename and after recovery must agree. The new recovery process
has a new TLS identity and an initially absent data directory. Only the checked
`heptabao-seed stage` command creates that directory. Hard links and symlinks
cannot substitute for a backup or a new closure.

The complete manifests and their aggregate SHA-256 remain in `0600` private
evidence because they include fingerprints of synthetic credential files.
The public receipt exposes directory identities, counts and the exact equality
result, without publishing credential-dependent file or aggregate hashes.
Utility stdout/stderr and their full pins likewise stay private; public command
observations retain outcome, status, length, custody and the private evidence
location. Known credential plaintext and direct SHA-256 variants are also
rejected and redacted at the final publication boundary.

Recovery never calls the KV2 source-bundle importer. Before archive restore,
19 actual API reads return no history, the corresponding native raw-witness
requests reject the inactive store, and there are no native external objects.
These are the old-bootstrap negative control. A legal historical rollback is
not treated as a failure case.

The controller then proves wrong-key refusal, a structurally valid archive with
corrupted sealed checksums being rejected without publication, and the same
rejection result after a cold restart. It restores the valid V6 archive once
through the actual official CLI, observes every API and raw historical version,
reopens cold, verifies undelete and destroy behavior, checks both CAS boundaries,
and commits version 20 followed by another cold reopen.

## DR25 obligations

| # | Required case | Retained evidence |
| --- | --- | --- |
| 1 | `input_source_and_binaries_pinned` | Actual controller/source identity; completed pinned build receipt; actual server and seed hashes/lengths; toolchain and official CLI pins. |
| 2 | `official_271_live_identity_verified` | Actual official server identity and its original full34 identity check. |
| 3 | `official_full34_api_and_raw_history_bound` | Full original 31-case receipt; all 19 official API wire observations; exact raw oracle and three original storage-witness stages. |
| 4 | `normal_native_v6_file_profile` | Ordinary argv/config digest, explicit native file owner and actual V6 capacity. |
| 5 | `preactivation_seed_export_pinned` | Stopped original writer; real export command; four file hashes; physical custody receipt. |
| 6 | `independent_backup_filesystem_verified` | Actual private work, backup and key directory identities; different work/backup `st_dev`. |
| 7 | `official_cli_v6_save_complete` | Actual pinned 2.7.1 CLI command result, archive length/hash and completed child wait. |
| 8 | `complete_v6_archive_seal_binding` | Full canonical gzip/tar contract, V6 magic/metadata, state length, checksums and matching seal binding. |
| 9 | `backup_manifest_and_separate_key_custody` | Every backup leaf's hash/identity, manifest pin, private key-file modes and key-material exclusion. |
| 10 | `original_processes_stopped` | Original service cleanup plus owned session/process retirement evidence before quarantine. |
| 11 | `original_directories_quarantined` | Original path absence; private full unchanged SHA/inode manifests; two parent FD observations and closed tracked stdio before rename. |
| 12 | `fresh_recovery_directory_and_tls_identity` | New root identity, absent data directory before staging, new TLS certificate, ordinary argv/config. |
| 13 | `exact_seed_stage_verified` | Actual stage result and receipt; exact four copied files; fresh destination inode. |
| 14 | `old_closure_negative_cannot_read_history` | 19 missing API reads, 19 inactive raw-witness rejections, pre-restore capacity and zero native object files. |
| 15 | `wrong_unseal_key_denied` | Wrong-key HTTP refusal, still-sealed health and unchanged seal bytes/inode. |
| 16 | `tampered_archive_denied_without_commit` | Actual CLI HTTP rejection, unchanged generation/format/history/seal, followed by independent cold-reopen observations. |
| 17 | `official_cli_v6_restore_once` | One valid CLI restore attempt, same archive pin, actual native V6 capacity, no source-bundle import. |
| 18 | `restored_api_19_versions_exact` | All 19 actual API response hashes and exact source history/config/metadata comparison. |
| 19 | `restored_raw_19_versions_exact` | All 19 actual precise storage witnesses bound to the original raw source. |
| 20 | `restored_cold_reopen_history_exact` | Old/new process identities, successful original-key unseal, full 19-version API and raw checks again. |
| 21 | `soft_deleted_payload_undelete_exact` | Actual undelete/read status, original live API payload hash and cleared deletion time. |
| 22 | `destroyed_payload_not_resurrected` | Undelete attempt, continued API absence/destroyed marker and raw payload absence. |
| 23 | `data_and_metadata_cas_guards_exact` | Separate data-CAS and metadata-CAS rejection/status/before/after observations; successful metadata CAS and exact counter increment. |
| 24 | `new_write_survives_cold_reopen` | Actual version-20 CAS write, full before/after cold history, latest read and precise raw witness. |
| 25 | `final_custody_cleanup_and_redaction` | Retired owned processes; unchanged source/binaries/build receipt/backup; unchanged quarantine; protected key files; credential-free public receipt. |

## Execution prerequisites

`kv2_dr_process_custody.py` instruments every original subprocess in this
synchronous controller, including existing helper launches. Each target remains
behind an exec gate until its new PID, process group, session and owner have
been observed. An exited leader stays unreaped through `waitid(WNOWAIT)` until
the owned group has been inspected. Unexpected living descendants fail the
run; cleanup signals only a group still anchored by its original unreaped
child. Original handles are waited once and both process retirement and known
parent log-handle closure are required before quarantine.

Before rename, two independent current-parent FD enumerations use
`/proc/self/fd` on Linux or `/dev/fd` on Darwin and `fstat` each descriptor.
Neither may match any file or directory device/inode in the complete original
manifest. Tracked stdin/stdout/stderr objects must also be closed. A descriptor
closed during enumeration is recorded as `EBADF`; other observation errors
fail the gate. This is evidence for the manifest-covered closure in the
synchronous parent, not a system-wide claim about every historically unlinked
inode or a hostile concurrent process.

The implementation supports Linux process observations and Darwin numeric
`ps` fields plus `getsid`. It does not confuse Darwin's `ps sess` kernel pointer
with a session ID, or depend on second-resolution timestamps as the sole signal
authority. Use an interpreter exposing the required `waitid`, `WNOWAIT` and
session APIs; capability admission fails if these are missing. Actual Mac
qualification requires running the process regressions and the full profile on
that Mac. Linux tests and a Darwin parser fixture do not establish it.

Darwin can return `ESRCH` from `getsid` for an already exited, still waitable
original child. The only admitted fallback requires the original `WNOWAIT`
exit observation, the original live `PID = PGID = SID` identity, and a unique
current zombie row whose PID, parent, group and UID all match. The receipt labels
its SID as the retained immutable session-leader identity; it does not claim a
successful post-exit `getsid`, or use `waitid.si_uid` as UID authority. A missing
original child, a changed identity, or an unexplained live `ESRCH` still fails.

For the resumed Mac, select the already capability-checked Homebrew Python
3.14 interpreter at `/opt/homebrew/bin/python3`. Its system Python 3.9 does not
provide `os.waitid` and is not an admitted substitute. Retain the actual
interpreter hash and capability receipt with that machine's execution. On ROG
or X230, select and record that machine's existing admitted interpreter.

SIGTERM, SIGINT and SIGHUP enter failure cleanup and preserve failure receipts.
Historical process receipts are independent snapshots, so later recovery
processes cannot rewrite the earlier source-retirement evidence. This lifecycle
mechanism does not claim containment of a hostile program deliberately escaping
its session; the product and helper executables still require their fixed build
and release bindings.

Run only after a real completed build receipt is retained. The current receipt
contract is `heptabao.convergence-normal-build-tests.v1`. Its `status` must be
`passed`, `source_and_artifacts_unchanged` must be true, and both
`artifacts.heptabao-server` and `artifacts.heptabao-seed` must match the actual
executables' SHA-256 and byte count. Both artifact entries must bind the same
commit/tree and assert verified normal features/profile/source. Cargo, rustc
and rustfmt pins must be present. The operator separately supplies the expected
SHA-256 of this completed build receipt. A running receipt, server-only build,
different seed executable or arbitrary log file cannot satisfy this gate.

Retain `test-selection.public.json` beside the build receipt. Its bytes must
match the receipt's `selection_sha256`, and its commit, tree and denominators
must match the build. The gate requires exactly 107 unique tests, including
90 server and 17 HA service tests: `passed_cases` and `executed_passed_cases`
must both be 107, and `not_qualified_cases` must be zero. Every actual group,
enumerated test name and libtest result must agree with the pinned selection;
no failed, ignored or measured case can count as passing. The same build
receipt and selection pins are checked again after recovery.

The build tree must exist in the controller checkout. Product files outside
`qa/` and `docs/` must not differ between the build commit and the controller
HEAD. The full controller checkout must be clean. This allows the additional
QA controller to be committed after the already built product candidate while
preserving the product source binding. Retain the real build output alongside
the structured receipt; neither is replaced by this document.

Provide three current-user-owned `0700` parents outside the checkout. The work
root must be a new child. The backup filesystem must have a different `st_dev`
from the work/recovery filesystem. The key directory must be disjoint from both
the original work root and the backup kit. All created private files use `0600`.
The controller preserves every directory and failure record; it does not clean
up evidence by deleting it.

The backup and key parents must also be disjoint. Work, backup and key directory
ownership, `0700` mode and inode identities are rechecked at the final gate;
private files alone do not excuse a newly exposed key directory.

`st_dev` is a filesystem boundary. It does not, by itself, prove a separate
physical disk, power domain or machine. On a Mac with internal storage and an
external T5, record the real device mapping separately before executing. A RAM
filesystem must not be described as a second physical backup disk.

Set `HB_ORACLE_BINARY` and `HB_ORACLE_ARCHIVE` to the already retained official
2.7.1 artifact pair. The existing launcher validates the selected platform's
pins without downloads, version fallback, development mode or insecure TLS.
Set `HB_DR_PYTHON` to the selected, verified absolute interpreter path. On the
resumed Mac this is `/opt/homebrew/bin/python3`; do not rely on ambient `python3`.

```sh
"$HB_DR_PYTHON" -B qa/openbao-acceptance/kv2_native_fresh_directory_dr_live.py \
  --binary "$HB_CANDIDATE_BINARY" \
  --seed-binary "$HB_SEED_BINARY" \
  --build-source-commit "$HB_BUILD_SOURCE_COMMIT" \
  --build-log "$HB_BUILD_LOG" \
  --build-receipt "$HB_BUILD_RECEIPT" \
  --build-receipt-sha256 "$HB_BUILD_RECEIPT_SHA256" \
  --private-work-root "$HB_WORK_PARENT/full34-dr25-r1" \
  --backup-parent "$HB_BACKUP_PARENT" \
  --key-parent "$HB_KEY_PARENT"
```

There are no profile-size, existing-endpoint, production-credential, force
restore, timeout-extension or automatic-retry options. HTTP and CLI operations
retain a 15-second original budget; the unchanged migration operations retain
their original 360-second budget. Cleanup time cannot convert an expired
operation into a success. Interrupted or unknown mutations preserve their
original receipt and are not retried.

## Controller verification and remaining qualification

Controller regressions run without either product server:

```sh
"$HB_DR_PYTHON" -B -m unittest discover \
  -s qa/openbao-acceptance/tests \
  -p 'test_kv2*dr*.py' -v
```

The archive fixtures in these regressions are explicitly synthetic structural
fixtures. They do not authenticate an encrypted graph or prove successful
product recovery. Process tests use short-lived Python utilities, not product
services. Actual DR25 needs its own complete fresh run and independently
reviewed receipt.

A successful run proves the declared synthetic full34, single-node,
same-seal, fresh-directory recovery profile. It does not prove recovery from a
snapshot alone without the held seed/key package, automatic backup rotation,
post-rekey compatibility of an older kit, physical power-loss survival, HA,
AuthBus migration, client cutover or permission to delete old assets. The
production, replacement, HA and independent-qualification authority flags stay
false. Those later gates must retain their own evidence in the user's required
order.
