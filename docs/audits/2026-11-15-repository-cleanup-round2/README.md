# Repository cleanup follow-up — 2026-11-15

This pass starts at
[`dd38ea55476813fb4b5d6d9a9e73211249536a73`](https://github.com/TrillionniumFoundation/HeptaBao/tree/dd38ea55476813fb4b5d6d9a9e73211249536a73).
It removes unused generators and historical patch captures, consolidates exact
copies of maintained test/validation logic, and retires fully superseded CI
entries while carrying forward their remaining checks.

## Maintained implementation deduplication

### Native HA fixture

Five native HA test suites each contained the same formal three-node startup and
process-owner helpers. They now use
[`service_native_formal_ha_fixture.rs`](../../../crates/heptabao-server/src/service_native_formal_ha_fixture.rs).
The parent module declares the test-only fixture; userpass, missing-route,
Raft-observation, TOTP and PKI suites retain their own test bodies and aliases.

The two original methods were byte-identical across all five copies. The shared
type preserves the `inner: Pipeline` and `servers: Vec<crate::http::Config>` field
order, `Deref`/`DerefMut`, per-test fresh resources and original `Pipeline::drop`
cleanup. Raft-specific token/read helpers remain in their original suite.
All **34 primary and nested test definitions remain byte-identical** to the
baseline. The extraction removes **986 lines / 37,551 bytes net** across seven
Rust files. Production modules and protocol assertions are not changed.

### Strict YAML loader

The V1.4, V1.4.1, V1.4.2 and V1.4.3 validators duplicated one strict mapping
constructor and loader. They now import `UniqueKeyYaml12Loader` from the existing
[`yaml12_loader.py`](../../../scripts/yaml12_loader.py), removing **105 lines
net**. Duplicate and unhashable keys still raise the same `ConstructorError`;
YAML 1.2 boolean/string resolution and safe-tag restrictions are preserved.

The ordinary permissive `safe_load_yaml12` entry point and global PyYAML defaults
are unchanged. All four validators continue to work as scripts, modules and
dynamic imports. Independent AST comparison found no other executable logic
change in the validators. Forty differential parser cases match the original
implementation; the four existing test suites produce the same 33 passes and
eight pre-existing historical skips before and after the extraction.

## Removed files

| Category | Files | Bytes | Reason |
| --- | ---: | ---: | --- |
| Unused Python emitter and dossier initializer | 2 | 14,429 | No current code, test, workflow, schema or documented invocation uses them. Current metadata collection, source inventory, curated dossiers and validators remain. |
| Encoded V1.1 bootstrap fragments | 5 | 68,260 | No decoder or current caller; four compressed parts encode the original one-shot repository generator, while `part-00` repeats a truncated prefix. |
| Historical `.diff` / `.patch` captures | 125 | 1,446,885 | Frozen source variants under acceptance evidence; no current build, tool or test path consumes them. |
| Superseded workflow entries | 3 | 9,415 | Current qualification or export entries retain their checks and outputs; unique schema assertions migrated before removal. |
| **Total** | **135** | **1,538,989** | Complete file bindings are in the retirement manifest. |

The unused emitter was `scripts/emit_exact_head_receipt.py`; its private receipt
schema had no consumer. `scripts/generate_module_closure_docs.py` was an eager
one-shot initializer that rewrote all dossiers and their registry at import.
Current documentation validation reads retained dossiers, actual Git source and
named test anchors directly and does not invoke this initializer.

The bootstrap fragments decode to an old 129,712-byte generator that writes
README, SECURITY, Cargo manifests, dependency requirements, validators and old
planning/workflow files. The decoded source was inspected without executing it.
The now-obsolete bootstrap exclusion is also removed from the secret-hygiene
scanner. Historical source and original outputs remain accessible in Git.

The only Markdown link to a retired patch now points to its immutable original
at the baseline commit. No receipt JSON, log or archive container is removed or
rewritten. Required current clients, bridges, vendored source, license notices,
independent-module lockfiles and named historical replay tools remain.

## Workflow coverage and upload permissions

| Retired workflow | Retained owner |
| --- | --- |
| `v2-4-authoritative-repository-closure.yml` | Current replacement PR exact-head/prospective-merge matrix plus nightly workspace qualification. |
| `v2-5-external-evidence-admission.yml` | `tests/repository` discovery in current PR and nightly qualification. Its unique trust-store schema checks now live in `test_external_evidence_v2_5_schema.py`. |
| `export-exact-audit-source-macos.yml` | Existing `export-exact-audit-source.yml`, with the same Git tar format/prefix, digest, source binding and seven-day retention. The removed entry did not compile or exercise macOS product code. |

The current PR, nightly, native recovery and actual macOS qualification workflows
remain. The distinct platform/oracle/plan tests in `v2-continuous-assurance.yml`
also remain. The first-party Clippy scope in the PR gate and all-workspace Clippy
in nightly qualification are preserved. The retired V2.4 manual merge constructor
also assumed a different candidate branch; on the sole `main` branch it attempted
a self-merge and then required a `MERGE_HEAD` that Git does not create.

Upload permission records now correspond to **28 actual upload invocations**.
Four stale grants were removed: two for an already absent V2.1 workflow, one for
an old workflow-trust upload step, and one for the retired macOS source export.
The registry loader retains exact closed cardinality. Tests now compare the full
installed invocation-to-path mapping, and a new negative check rejects an added
obsolete grant. Existing path and native recovery restrictions remain.

The detailed per-step replacement mapping is included in
[`validation.json`](validation.json). The workflow set is reduced from 41 to 38.

## Remaining language ownership

The current tree contains 1,249 Rust files and 940 Python files, counted by
extension rather than GitHub Linguist's byte-based language proportions. Of the
Rust files, 1,194 belong to `crates/`; the rest are probes or maintained third-party
dependencies. The remaining Python files have the following owners:

| Directory | Python files | Purpose |
| --- | ---: | --- |
| `qa/` | 698 | Acceptance and hostile-input tests, HA/migration runners, credential/device qualification and named historical replay packages. |
| `tests/` | 100 | Repository, plan, platform, oracle and security tests. |
| `scripts/` | 92 | Validation, evidence collection, maintenance and archive recovery. |
| `clients/python/` | 35 | Installable SDK, CLI, Agent, Proxy, SSH helper, OIDC client and their tests. |
| `tools/` | 14 | AuthBus, signing, migration and other documented tools and tests. |
| `verification/` | 1 | Concurrency verification. |

Some frozen credential evidence and operator packages remain bound to explicit
integrity manifests or documented replay contracts. An absent automatic caller
alone does not make a documented manual tool or replay input redundant. Go SDK
bridges, Android Java, browser/Node JavaScript and SQL migrations also retain
their actual integration roles.

## Validation

The complete machine-readable result, including commands, unchanged test-body
hashes and historical baseline comparisons, is in
[`validation.json`](validation.json).

| Check | Observed result |
| --- | --- |
| Current repository regression tests | 305 passed. |
| Security regression tests | 81 passed. |
| Complete historical plan test discovery | 313 passed, 27 existing skips, 2 existing failures out of 342. |
| Four affected YAML-validator suites | 33 passed and 8 existing skips, identical before and after consolidation. |
| YAML parser differential and entry-point checks | 40 differential cases and 8 script/module entry points passed. |
| Current repository, documentation, identity, module, workflow, gate-owner and release-denominator validators | Passed. |
| Rust formatting and patch whitespace | Passed. |
| Native HA compilation and execution | Complete server library test target compiled on macOS arm64; all 34 affected tests passed, 0 failed, 0 ignored, all five test processes exited 0. |
| Retirement recovery | All 135 removed files restored with their original bytes and modes; all 4,440 retained non-Markdown evidence files are byte-identical to the baseline. |

The two historical plan failures are
`PlanV145HostileTests.test_current_tree_passes` and
`PlanV146HostileTests.test_current_tree_passes`. Both demand obsolete README
tokens despite the current empty-homepage policy. They reproduce at the exact
baseline, and their tests, validators and README are unchanged. The old V1.1
scanner (`validate_plan_v2.py`) also reproduces its existing private-key-delimiter
finding in a synthetic Rust test fixture. The scanner's only change removes the
retired bootstrap-directory exclusion. These results remain failures; no test is
deleted or newly skipped and no guard is weakened to obtain a green result.

### Native execution scope and evidence

The complete `heptabao-server` library test target compiled with Rust 1.98.0 on
macOS arm64 using `--offline --locked` and unchanged default features. All 34
affected tests actually ran: userpass 8, missing-route 7, Raft-observation 7,
TOTP 3 and PKI 9. The binary contains 3,615 registered tests; the other tests
were filtered out. This is targeted regression validation, not complete workspace
or multiplatform qualification.

The isolated native input was a verified sparse snapshot of 1,376 baseline files,
including all server library test sources and native build inputs, with the exact
seven-file Rust overlay applied (1,377 resulting files). It was not a full Git
checkout. After all tests, the complete path set, Git executable modes, sizes and
SHA256 values were unchanged. The 86 missing original registry archives were
verified against the unchanged Cargo.lock before being cached.

The build used one compiler job, disabled incremental compilation and debug
information, and set the server package's test optimization level to zero.
Debug assertions and overflow checks stayed enabled. Earlier local Linux build
and check attempts did not complete: two exited 137 and one explicitly recorded
rustc SIGKILL. A kernel OOM cause was not independently established. Those
attempts are retained as incomplete and are not reported as passing.

The original outer collector reported `FAIL / exit 1` because its single-line
regular expression missed `ok` statuses separated from test names by concurrent
HA diagnostics. Its original result is preserved. All five actual Rust test
processes exited 0 and their complete summary lines reported the expected
passes. An independent read-only observer then matched all 34 test names and
terminal statuses against the original listings, logs, process exits and totals;
that observer exited 0. No test was rerun or changed to make this correction.
The machine-readable record includes both observer outcomes, per-test results,
log hashes, platform verification and final source-integrity results.

## Recovery and future maintenance

The first cleanup manifest remains unchanged and remains the restoration tool's
default. This pass has a separate
[`retired-sources.json`](retired-sources.json), bound to the baseline above.

```sh
python3 scripts/archived_qa_sources.py --manifest docs/audits/2026-11-15-repository-cleanup-round2/retired-sources.json --verify
python3 scripts/archived_qa_sources.py --manifest docs/audits/2026-11-15-repository-cleanup-round2/retired-sources.json --restore-to /tmp/heptabao-cleanup-followup
```

The selector reuses the original commit/tree/path/blob/SHA256 validation and
new-directory requirement. Recovery never executes archived source. Full replay
of historical scripts should use the original complete tree, including its
relative imports and evidence. A shallow clone may need to fetch the baseline
commit first.

The ignore policy now also excludes ordinary staging of `.diff` and `.patch`
source captures inside acceptance evidence. Maintained patches outside that
directory remain available. The layout guide and current documentation entry
point describe the consolidated implementations; the stale “46 guides” count in
the current source-binding guide is replaced with a reference to current guides.

This cleanup preserves the public product surface. The remaining matching source
fragments often belong to different security-owner types, independent packages,
or explicitly frozen replay contracts; textual similarity alone is insufficient
reason to merge those boundaries.
