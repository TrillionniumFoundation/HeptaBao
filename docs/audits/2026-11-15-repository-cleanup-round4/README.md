# Repository cleanup — fourth pass, 2026-11-15

Baseline: [`d35a7b72a95441ac9cf0908077ec9a979d36b81c`](https://github.com/TrillionniumFoundation/HeptaBao/tree/d35a7b72a95441ac9cf0908077ec9a979d36b81c).
This pass follows the remaining candidates through their callers, build targets,
source staging, historical replay and tests. All reviewed candidates have a
recorded disposition; no confirmed removable candidate remains open.

This conclusion is bounded by the recorded scans and observed consumers. It is
not a proof that arbitrary dynamic programs have no possible future refactoring.
Similar syntax across distinct state owners, protocol versions, independently
executed fixtures or immutable replay inputs is not sufficient deletion evidence.

## What changed

| Area | Cleanup and preserved behavior |
| --- | --- |
| Rust runtime | Shared descriptor-relative durable writes and parallel existing-file synchronization; common quoting, retention projection, root guards, request parameter checks, staging checks and SDK restored-graph validation. Caller-owned counters, error mapping, publication uncertainty, worker joining, secret drop order and state ownership remain explicit. |
| Rust tests | Shared fixtures only where callers have compatible concrete types and execution semantics. Local clocks, error adapters, fault owners and thread-local state remain local. All 544 original test names, attributes, assertions and execution tokens in the changed Rust files remain. |
| Python | Removed 139 initially flagged unused imports and five unused top-level definitions. Consolidated 16 AST-normalized duplicate groups and shared YAML 1.2 resolver configuration, the YAML 1.1 mapping constructor, migration checkpoint locks/state, trace operations, workflow CLI setup and repository test fixtures. Loader-specific errors, YAML version semantics, checkpoint schemas and each original descriptor lifecycle remain intact. |
| PostgreSQL | Removed 12 earlier function definitions that were overwritten later during fresh installation. The fresh provider now defines each of its 31 final functions once. All versioned upgrade files remain; current and historical upgrade tests observe the appropriate source. |
| OpenRaft probes | Shared private CLI seed/argument helpers and node construction within the existing recursively staged probe package. The probe's dependency profile and lockfile remain independent from the server. |
| Go / JavaScript | Removed the uncalled Darwin group-members helper and its sole C helper/import, an unused JavaScript function and an unused import. Remaining Go function bodies are byte-identical. |

The five removed Python definitions are `render_plan_v1_4_7.readme_source`,
`acceptance_case_ids`, `radius_bounded.encode_pap_value`, the unused parent-process
`NoRedirect`, and `postgres_generation_live.row`. The actual isolated HTTP worker
continues to own its redirect policy.

No test was deleted or newly skipped. New tests exercise shared checkpoint
behavior, PostgreSQL final-definition contracts and the actual descriptor helper
selected by Rust module declarations.

### Source size, including new checks and tests

| Language | Changed or added files | Net lines | Net bytes |
| --- | ---: | ---: | ---: |
| Rust | 92 | -864 | -32,628 |
| Python | 141 | +117 | +12,144 |
| SQL | 1 | -852 | -44,482 |
| Go | 1 | -21 | -839 |
| JavaScript | 2 | -1 | -110 |
| **Total source** | **237** | **-1,621** | **-65,915** |

Python grows slightly after adding the shared-contract checks and negative tests,
despite removing unused imports, definitions and repeated implementations.
The 11 added source files provide six Rust modules, three Python helpers and two
Python test modules. This pass removes definitions inside existing files; it
does not retire another whole source file. Audit records and documentation are
counted separately from the source figures above.

## Coverage and retained candidates

The starting tree contains 7,694 tracked files. The final source scan covers all
945 Python files, 1,256 Rust files, 57 JavaScript files, 21 Go files, 29 Java files
and 10 SQL files. Cargo/module analysis reaches all 1,199 first-party Rust files
through declared targets, modules and includes. The 53-member workspace remains
unchanged; metadata also contains the local template dependency.

The candidate register covers every initial Python duplicate/import/definition
candidate, every reviewed Rust function group, the JavaScript/Go/Java and SQL
groups, and all 62 whole-file duplicate groups. It also records final rescans and
newly introduced helper consumers. Overlapping token and normalized scans are
separate observations and are not added together as independent duplicates.

| Retained category | Concrete reason |
| --- | --- |
| Python client, CLI and migration tools | Declared user entry points and actual imports; the Rust server does not replace these clients. |
| Chromium and Android code | Browser/Android platform entry points and separate application packages. |
| Go SDK bridges and fixture modules | Distinct protocol executables, native process boundaries and independent pinned module graphs. |
| PostgreSQL upgrades | Existing installations still require their ordered transformations and old protocol comparisons. |
| Versioned phone/controller sources | Closed staging packages, exact source pins and replay consumers require their original source identities and globals. |
| Independent test oracles and typed adapters | They exercise different owners, formats or failure boundaries; sharing them would change the tested independence or API. |
| Vendored code, licenses, protobuf schemas and platform headers | Build inputs, attribution, explicit wire-field references or native includes remain consumed. |
| Original receipts and logs | They record distinct campaign observations, including empty output and failure; identical bytes are not counted as separate successful runs. |

All 38 workflows and 68 jobs were reviewed; no complete duplicate job was found.
All inspected direct dependencies have a source or explicit feature/version-pin
purpose. No dependency version, lockfile, workflow permission or acceptance scope
was changed in this pass.

## Validation and discovered regressions

| Check | Observed result |
| --- | --- |
| Repository / security regression | 305 / 81 passed. |
| Full plan discovery after integration repair | 333 passed, 27 existing skips; 360 total, no failures. |
| Current repository/documentation/identity/module/workflow/gate-owner/release-denominator validators | All seven passed on the staged working tree. |
| Linux Rust affected library packages | 572 passed, one existing ignored disk trial; strict all-target Clippy passed. Child-process test footers are not counted twice. |
| Native Mac server | All 560 selected tests passed: 529 with the default stack, 31 with a baseline-matched 32 MiB stack. Strict all-target Clippy and workspace formatting passed. The target contains 3,615 compiled tests; 111 of the 671 selected source tests are cfg-filtered on this target. |
| PostgreSQL 17.11 | 77 installation/catalog/behavior comparisons passed across old fresh install, cleaned fresh install and the v2-to-v6 upgrade chain; all 31 final functions, ACLs and schema objects agree. 59 contract tests passed. |
| OpenRaft probe | Locked all-target build, 30 original tests, strict Clippy and formatting passed; 135 parser comparisons agree. |
| Python behavior checks | Targeted parser, CLI, migration, trace, checkpoint and local transport checks passed. Full SDK discovery has baseline-equivalent environmental failures; full QA discovery additionally records one transient process-lifetime failure, with baseline/current targeted reruns passing. Exact results and log hashes are recorded in validation.json. |
| JavaScript contracts | 52 refresh and 11 trusted-control checks passed with local synthetic provider fixtures. Original tracked receipts were preserved. |
| Go native validation | Not run: the required Go 1.27.1 toolchain could not be provisioned on the Mac within the bounded attempts. Static deletion/AST proof passed for all 21 files and 192 remaining function bodies. |

Four issues were found before publication and corrected:

1. The old V1.4/V1.4.1 source validators still looked for durable-write statements
   inside caller files. They now use the existing descriptor contract guard to
   follow the shared implementation. Original error/order assertions and negative
   cases remain, with ten additional mutation subcases through those old entries.
2. Independent review showed that a Rust `#[path]`/conditional declaration could
   redirect the helper while the guard inspected the default file. The guard now
   requires the actual unconditional module/import/export/counter bindings.
   Eleven independent attribute mutations and eight historical fallback
   challenges reject. Exact historical inline replay remains gated by four
   original source hashes and absence of the shared helper.
3. Two shared test fixtures initially received same-type string arguments in
   different orders. Native tests exposed 15 assertion failures. The affected
   callers now have small adapters preserving their original signatures and
   explicitly mapping each argument. The complete alias/wrapper binding audit
   and corrected native results are recorded; initial failures are retained.
4. A shared native test initializer initially returned a large `Service` by value
   inside a tuple, adding stack use. An exact default-stack comparison found one
   case passing at d35 and aborting in that candidate. The callers now retain
   their original `Root`/`Service` ownership and pass `&mut Service` to the shared
   initializer. The corrected case passes with the original default stack; it
   is never classified as a baseline limit or rescued by a larger stack.

The first native test supervisor also double-escaped its result-parser regex.
An independent observer re-read the unchanged child logs and exit codes. This
correction fixes reporting only; actual assertion failures and stack aborts
remain recorded as failures of that initial candidate.

Native tests used an explicitly recorded `opt-level=0` profile with debug
assertions and overflow checks enabled. Each of the 560 selected tests ran in its
own subprocess. For every default-stack abort, the exact d35 baseline was checked
first; a larger stack was permitted only for the same baseline abort. All 31
such cases passed on both versions with 32 MiB. The other 529 passed with the
default stack, including the introduced stack regression after its repair.
No selected test was ignored. Source and binary hashes were verified after the
699-second final run. The build emitted one nonfatal compact-unwind size warning;
strict Clippy emitted no diagnostics. These results cover the selected affected
tests and their direct consumers, not all 3,615 compiled server tests.

The legacy `scripts/validate_plan_v2.py` scanner still reports the pre-existing
synthetic private-key-delimiter fixture in
`crates/heptabao-server/src/service_external_key_native_tests.rs`. Its output is
byte-identical to the baseline. Neither the fixture nor the scanner was weakened.
Python SDK/QA environment limitations and the observed transient process-lifetime
race are likewise retained alongside their exact baseline comparisons.

These are source cleanup and bounded regression results. External provider,
phone, destructive multi-host and production migration campaigns were not rerun.

## Evidence, records and recovery

All **4,531 evidence files / 91,754,542 bytes** retain their original bytes and
Git modes. The broader preservation check also covers historical audits,
out-of-evidence receipts/logs and the frozen passkey r9 package: 4,646 unique
paths, zero differences. The root README remains empty under the current policy.

- [Validation and source bindings](validation.json) record commands, results,
  log hashes, environmental limits and corrected failures.
- [Source changes](source-changes.json) identify every changed source file,
  original/final hash, mode, byte count and line delta.
- [Complete candidate register](candidates.json.gz) contains the compact indexed
  Python ledger and complete Rust/other-language/whole-file dispositions. It is
  deterministic gzip data, not executable source; repeated reference excerpts
  are indexed once instead of copying the full scan output into the repository.
- [Native test records](native-tests.json.gz) retain every exact test result,
  baseline comparison, build/source binding and the original failed candidate.

To inspect the candidate register without executing any repository source:

```sh
gzip -dc docs/audits/2026-11-15-repository-cleanup-round4/candidates.json.gz | python3 -m json.tool
```

The baseline commit retains every previous implementation. For exact historical
inspection, including the original dependency graph and receipts, create a new
detached worktree at the baseline commit. Earlier retirement manifests and their
restoration commands are unchanged. No Git history was rewritten.
