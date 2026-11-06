# KV2 → HA → AuthBus continuation: evidence checkpoint r5

## Decision

**HOLD. HeptaBao has not been qualified to replace the actual responsibilities of OpenBao 2.7.1.** This checkpoint closes several preparatory observations, records a successful ROG diagnostic run, and preserves two actual CI failures. It grants no production KV2, physical HA, AuthBus, per-host cutover, rollback or cleanup qualification.

The required order remains **formal KV2 → physical Mac/ROG/Pocket4 HA → trusted AuthBus independent of J3160 → individual host cutovers → old-service and binary cleanup**. At this checkpoint no current business database has been captured by the new workflow, no business traffic has been switched, and no old service or binary has been removed. No J3160 operation was performed.

This is an additive successor to [r4](../kv2-ha-convergence-20261106-r4/README.md), committed at `7f0e87292552521a56204acd44b895591662f1dc`. Earlier evidence and failures remain unchanged. The previous publication was independently fetched and verified against all 156 published files, including 155 files covered by its SHA256/size index. Those publication checks are under `previous-publication/`; they concern evidence storage, not product disaster recovery.

## Actual outcomes

| Work | Actual result | Qualified scope |
| --- | --- | --- |
| ROG source preparation | Job `1a1b192ffdb-fc05-79a9`, exit 0; all 15 Git commands and 30 original streams retained | New source for a diagnostic run only |
| ROG diagnostic build and tests | Job `1a1b196c999-fc05-79b6`, exit 0; 107 exact selected cases passed, 0 failed/ignored; 50 original steps and 100 original streams | `diagnostic_passed_legacy_hold`; machine acceptance remains HOLD |
| Mac offline environment r2 | Job `1a1b1a60246-fc05-7a15`, exit 1 before any venv, install or child | Permanent failed attempt retained |
| Mac metadata comparison controls | Job `1a1b1b98ccf-fc05-7a7c`, 10 passed, 0 failed/error/skip | Strict semantic metadata comparison, with raw bytes pinned |
| Mac isolated environment r3 | Job `1a1b1c05955-fc05-7aa0`, exit 0, 5.615668 s; all three original children retired | Fixed Python and offline dependency environment only |
| Actual Darwin capture controls | Job `1a1b1c4c600-fc05-7abc`, exit 0, 0.417375 s; 18 exact cases passed | Synthetic fixtures, one actual owned WAL writer, two actual filesystems |
| Current Mac source metadata admission | Job `1a1b1b702cb-fc05-7a6d`, exit 0, 0.325181 s | Current complete configuration and metadata only; no database contents read |
| Full CI, prospective merge | Run `42229582001`, job `127931720502`: 3751 server tests passed, 1 failed, 8 ignored | Actual unresolved publication-path failure |
| Full CI, exact head | Same run, job `127931720823`: 3752 server tests passed, 0 failed, 8 ignored; strict Clippy then failed | Actual lint failure; head test success does not erase merge-job failure |

All test counts in this table are bounded to their original enumerations. They are not sums of interchangeable test suites or evidence for migrated clients.

## 1. ROG: 107 diagnostic cases, with the original preservation failure retained

The exact source commit is `4bde9aee03fcd27c59e13607e529b1cee594b249`, tree `f08493a23f8ea0637073651231865ea9607b790e`. The selected set is 90 server cases and 17 HA-service cases. Independent reconciliation compared all 107 unique names against the original frozen selection, all 30 actual test stdout streams, and complete enumerations of 3760 server and 119 HA-service entries. It also reconciled the four actual Cargo artifacts to their Cargo events and independent native file information.

Every one of the 50 original run-step receipts reports one attempt, exit 0, and retired owned process groups. The original 21 retained-asset denominator remains intact: 18 files matched before and after, and the same three files were absent before and after. Their absence has not been explained, and replacement builds were not substituted for those original files. The earlier r10 failed with zero builds and zero tests; its failure remains in r4.

Accordingly the new result uses a different schema and the status **`diagnostic_passed_legacy_hold`**, with normal machine acceptance, rollback, DR and cutover all false. The pinned formal fresh-directory DR consumer requires the normal receipt schema AND `status == passed`; this diagnostic receipt cannot satisfy that first gate. That statement is limited to the inspected exact consumer, not all future code.

The diagnostic used a cold target directory. Its 947.371086 s release build and 1122.481444 s server-libtest build are observations of this run, not an OpenBao/HeptaBao performance comparison. No physical three-machine HA event occurred.

Files: `rog/preparation/`, `rog/inputs/`, `rog/diagnostic-r11/`, and `independent-reviews/root-rog-r11-recount.public.json`.

## 2. Mac: offline dependency provenance and actual capture controls

The original online Mac environment attempt timed out within its unchanged 20-second first-download limit and remains a failure in r4. A separate ROG job downloaded the four fixed public wheels. Version-locked, create-only transfers then delivered the exact wheels to the Mac. The complete transfer ledger is split between `mac/public-wheel-transfers/` and the cryptography ledger in `mac/environment-and-controls/`; the separate original download receipt and terminal are under `mac/rog-wheel-download/`.

The four wheel files total 6,165,482 bytes: pip 26.3, cryptography 50.0.2, cffi 2.0.0 and pycparser 2.23. ROG downloaded those bytes; it did not establish Darwin compatibility or install them. Actual Mac verification subsequently did that for the fixed environment.

Offline r2 rejected a raw wheel/PyPI metadata representation difference before venv creation. The wheel bytes, distribution names and versions all matched. The cryptography `Requires-Python` specifiers had a different order/spacing, and three `Requires-Dist` strings differed in marker spacing or quote style. The raw original metadata and r2 failure were retained rather than edited into a successful attempt.

The r3 correction first pins both raw metadata forms and all four wheel hashes, then uses the pinned pip wheel's `packaging` parser. It checks full specifier and requirement semantics, including inactive markers, exact counts and duplicate/URL/extra refusals. It does not merely check that both expressions happen to accept the running Python. The actual ten negative/positive controls include weakened Python constraints that still admit the current interpreter, missing or extra inactive dependencies, duplicate entries, URL and extras changes, markers, name and version changes.

Actual r3 ran in 5.615668 s within the original 150-second work / 180-second Runtime bounds. The original three child caps remained 15 / 35 / 10 seconds. Venv creation, offline install and environment verification each exited 0, were waited exactly once, and had no live members before reap. The environment verification included 1412 actual interpreter tags, complete dependency closure, Fernet round-trip, wrong-key and tamper rejection. No global or repository dependency environment was modified.

The actual 18 Darwin controls used unchanged capture source SHA256 `9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972` and unchanged test source SHA256 `0b93d597b9fd525470951cb7b49cdb6707c11fc38b5e42f0d06bcedc7e0395f6`. Only the driver bindings to the successful r3 environment changed. The controls ran on internal Data and external T5 filesystems and included one actual synthetic WAL writer, once waited and retired. All 18 exact unique names passed with zero failures, errors or skips. Inputs remained unchanged and synthetic fixtures were retired.

These are controls for the capture mechanism. They do not prove a real current business capture, a provider credential's validity, a production KV2 service, source-device-loss recovery, or an OpenBao migration.

Files: `mac/environment-and-controls/`, `mac/public-wheel-transfers/`, `mac/rog-wheel-download/`, and `independent-reviews/root-current-results.public.json`.

## 3. Current source: five configured agents and nine database families

The new bounded Mac admission read the current configuration privately and inspected the complete resulting metadata set. It found **five** configured default-directory agents, not the six or seven in older observations. The complete database-family denominator is nine: five agent databases, shared, quarantine, and two transport families.

Six main databases were present, totaling **3,278,327,808 bytes**. The shared WAL was **5,969,912 bytes**. Quarantine and both transport families were absent. Seven safety paths were included, of which three were present. Two observations reported the same family and safety metadata; no unsafe member or security writer lock was observed. This metadata stability is not a writer fence and does not establish a cross-database atomic snapshot.

The original fixed proposal was 3,087,007,744 bytes per database and 4,227,858,432 bytes total, with 12,079,595,520 bytes of capture headroom, 16,844,324,864 bytes for the conservative internal-disk capture/candidate/fresh-restore lifecycle, and 6,208,968,022 bytes for the external archive. Observed free space was 260,161,556,480 bytes on Data and 118,456,868,864 bytes on T5. These were physical metadata estimates with the fixed growth margin. Actual capture must still enforce transaction-level logical page-count/size limits.

All four proposed parent directories were absent at this admission; it created none of them. No database header, SQL row, sidecar body, safety-file body, key or credential value was read. The only two native metadata children were original `diskutil` invocations; both exited 0 and were once waited and retired.

### Historical private-binding limitation

The original admission public result and native terminal are independently pinned. **The old private input file did not have an independently captured original file identity or content hash.** Its current agreement with the old public result, and a later before/after read, would establish only later stability. They cannot establish that the private file remained unchanged since the original admission.

The next directory/plan stage must therefore reconstruct its baseline from the current complete configuration, identities and metadata. Its newly written private plan and binding must receive a non-content file-identity anchor in that stage's original public receipt and terminal. Private configuration/credential-dependent hashes must stay private. No historical pin may be synthesized retroactively. At the r5 boundary that corrected stage has not yet executed.

Files: `mac/current-source-admission/` and `independent-reviews/root-current-results.public.json`. The original private input and business configuration are not included.

## 4. Full CI: same source tree, two different actual failures

Run [42229582001](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42229582001) tested exact head `4bde9aee03fcd27c59e13607e529b1cee594b249` and prospective merge `6ed25e0d1f229483050a25f18750b7ceb14ee1c5`. **Both actual source trees were `f08493a23f8ea0637073651231865ea9607b790e`.** Both jobs used `--test-threads=1`.

The merge job failed this exact case:

```
service::native_v6_ha_pipeline_tests::native_large_import_tests::published_plan_tests::native_ha_published_local_plan_changed_cipher_after_actual_commit_is_unknown
```

The original log reports native-large finalization HTTP 503, `native V6 HA Service publication rejected`, followed by `actual install observer absent`. The expected observation is after the actual import commit. The existing generic rejection does not retain enough detail to distinguish the earlier rejection branches. The observed interval from the preceding sequential case finishing to this case failing was approximately 1.824 seconds; the logs do not establish exhaustion of the original 15-second budget.

This case is in the full 3760-entry server enumeration and **outside the selected 107-case set**. Consequently neither the ROG diagnostic pass nor the earlier Mac 107-case pass closes this failure. The same-tree head job's full server pass does not close it either. No root cause or protocol repair has been established at this checkpoint.

The head job later failed strict first-party Clippy on `clippy::manual_contains` in `crates/heptabao-ha-service/src/native_snapshot_peer.rs:54`. The prepared equivalent `contains(&[0; 32])` correction is not a claimed lint pass. A separate test-only observation patch is being reviewed to preserve the same request, fault, deadline and assertions while exposing bounded static phase/refusal classification. It is diagnostic work, not proof of a repaired publication protocol. No blind rerun or increased deadline is used as an acceptance substitute.

The complete original decoded logs, not only excerpts, are retained:

| Original log | Bytes | SHA256 |
| --- | ---: | --- |
| `ci-42229582001/merge.job.original.log` | 2,927,514 | `f3dbe04d1ed51a14b415dae8a7a6d4f441b854ea07fffae61ff4390a455fd0e0` |
| `ci-42229582001/head.job.original.log` | 2,983,636 | `0361631c3e3c1b208a8247ade437141b83e8fd5eb8937e83722bacdb59c62993` |

Both complete files were read back locally with exact byte/SHA256 checks and created as immutable Git blobs matching independently computed Git object identities. Their bindings and shorter derived excerpts are in `ci-42229582001/`.

## 5. What remains before moving to the next phase

The earlier 31 baseline + 25 fresh-directory DR synthetic KV2 checks and their independent 26 checks remain useful evidence in r4. Their logical 34 MiB fixture and same-seal recovery are not real business storage or a completed host migration.

The current whole-application SQLite workflow must first capture all configured families, preserve complete databases and safety state, make a separate encrypted archive, and restore into a new directory using authenticated inputs and independent readback. Each database's read transaction can be consistent without the group being globally atomic. Writer/client/backup/sync boundaries remain to be inventoried and controlled. Recovery-key protection and needed redundancy remain to be established; keeping the source, capture and key on the same internal device does not prove recovery after losing that device.

Application SQLite records also do not establish an original OpenBao KV2 mount UUID, version history, tombstone or destroyed-version history. A migration must use authentic original history when it exists. It may not invent such history or relabel a new version-1 document as preservation of an unobserved old KV2 history.

A separate ordinary persistent native KV2 service, its actual current credentials and dependent clients, cold restart, backup restore, rollback and ongoing synchronization must be demonstrated before formal KV2 acceptance. Existing empty `native_v6_raft` staging templates are not that service. Later physical Mac/ROG/Pocket4 HA, AuthBus and per-host traffic steps remain gated. Only after all dependent clients and backup paths have independent completed migration evidence may old OpenBao services, old HeptaBao binaries and regenerable intermediate assets be removed.

## Evidence layout and verification

`INPUT_MANIFESTS.public.json` binds every imported immutable package tree and exact original package manifest. `FILES.public.json` covers every other file in this checkpoint with size, SHA256 and Git blob identity. Package indexes remain original bytes; newly written summaries are explicitly derived. Original failure receipts are retained in their actual attempts. No private receipt, business database, credential value, wheel payload or private configuration fingerprint is included.

Root independently checked the terminal/result bindings and exact test/custody denominators noted above. Publication additionally requires canonical tree verification and an independent public Git fetch with a complete path/size/SHA256/blob recount. Publication verification is recorded as a separate later observation; this README does not predeclare that future check successful.
