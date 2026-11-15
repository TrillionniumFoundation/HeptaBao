# Repository source and redundancy audit — 2026-11-15

HeptaBao's server and its first-party workspace are Rust. The repository also
ships real Python clients, Android Java clients, a JavaScript browser extension,
Go protocol bridges, SQL migrations and Python acceptance tooling. Removing those
components by file extension would remove functionality or validation.

The avoidable bulk was a second collection of executable source under historical
acceptance evidence. This cleanup retires **1,301 inactive source snapshots** and
**one unreachable workflow**, removing **26,931,646 bytes** from the current tree
before the smaller recovery manifest and documentation are added. Every removed
file remains recoverable from the original Git commit.

| Current-tree inventory | Before | After |
| --- | ---: | ---: |
| Tracked files | 9,115 | 7,821 |
| Tracked bytes, decimal MB | 171.16 | 144.81 |
| Python files | 1,885 | 942 |
| JavaScript files (`.js`) | 203 | 7 |
| MJS files | 200 | 50 |
| Rust files | 1,259 | 1,248 |
| GitHub Actions workflows | 42 | 41 |

Eight small documentation, manifest and recovery files are added alongside the
1,302 deletions, for a net reduction of 1,294 tracked files and approximately
26.36 MB. The 11 removed Rust files were historical reference copies; maintained
Rust packages are unchanged.

## Audited source and method

The baseline is
[`6faf7957bb0b9390141a9f3680567ef96295eba6`](https://github.com/TrillionniumFoundation/HeptaBao/tree/6faf7957bb0b9390141a9f3680567ef96295eba6),
the consolidated `main` observed before this cleanup. The inventory covered all
**9,115 tracked files / 171,161,708 bytes**, all 53 first-party workspace packages,
42 workflows, local Cargo dependencies, Python entry points and imports, local
JavaScript module references, client manifests, evidence consumers, Markdown
links and byte-identical file groups.

Deletion candidates were checked against current build inputs, Python AST
constants and dynamic loading patterns, non-evidence source/configuration
references, local JavaScript imports and current test execution. A dated filename
alone was not a deletion criterion. Complete-file duplicate groups outside
historical evidence were also reviewed: the frozen passkey driver is bound by an
R9 hash contract; repeated `go.sum` files belong to separate Go modules; repeated
license texts carry separate component notices. These remain required.

The [layout guide](../../REPOSITORY_LAYOUT.md) documents the resulting ownership
and dependency boundaries. This audit concerns repository structure, redundancy
and cleanup regressions; it does not replace a cryptographic, production or
full compatibility qualification.

## Removed current-tree copies

| Kind | Files | Bytes | Finding |
| --- | ---: | ---: | --- |
| Python snapshots | 944 | 21,558,691 | Frozen campaign controllers, host probes, source captures and earlier SDK helpers under acceptance evidence. |
| JavaScript snapshots | 196 | 2,944,635 | Copied SDK/plugin source and historical transport captures. |
| MJS snapshots | 150 | 1,901,779 | Frozen campaign launchers, probes and plugin controllers. |
| Rust snapshots | 11 | 524,885 | Copied Codex auth/config reference source outside the Cargo workspace. |
| Dead workflow | 1 | 1,656 | An exact-head workflow with only deleted branch triggers and no manual dispatch. |
| **Total** | **1,302** | **26,931,646** | Every path, Git blob, mode, size and SHA-256 is recorded in the retirement manifest. |

The 944 retired Python files represented **63.93% of tracked Python bytes** at
the baseline. This is a source-byte inventory, not a claim about GitHub's computed
Linguist percentages. Of the original 1,885 Python files, 941 remain; the small
archive verification/recovery tool adds one maintained Python file, for 942.

The largest concentration was
`qa/openbao-acceptance/evidence/authbus-fleet-closure-20261106-r2/`, which alone
contained 736 Python source snapshots. Some controllers had been copied up to
20 times. The audit found 50 byte-identical Python groups with 193 extra copies;
retiring the inactive historical collection also removes distinct old versions
that simple exact-byte deduplication would miss.

## Retained functions and evidence

- The 53 first-party Rust package manifests, runtime source, Cargo lockfile,
  tests, fixtures and required vendor inputs are unchanged. Cargo metadata is
  byte-identical before and after the cleanup.
- Python's installed `heptabao`, `heptabao-agent`, `heptabao-proxy`,
  `heptabao-ssh-helper` and `heptabao-oidc-login` entry points remain intact.
  The Python package provides actual HTTPS consumers and lifecycle owners.
- Browser JavaScript, Android Java, Go SDK/plugin bridges and PostgreSQL SQL
  migrations remain intact. The vendor and third-party directories remain direct
  Cargo inputs with their original attribution and licenses.
- Current Python QA programs and unit tests remain intact. They execute native
  binaries, compare official OpenBao behavior and check workflow, documentation,
  custody, restoration and compatibility contracts.
- **4,565 retained non-Markdown acceptance/personal-credential evidence files**
  were independently compared to the original Git blobs and are byte-identical.
  Original successes, failures, logs, manifests, mixed archives and Git bundles
  are preserved. These records retain their original candidate identity.
- The 17 Python snapshots in the personal-credentials archive remain because
  its verifier binds an exact 256-file set, sizes and hashes. That original
  **28,189,714-byte archive** passes its unchanged integrity check.
- Active AppRole fixtures, historical upgrade inputs, native build receipts and
  x230 source/ABI receipts are retained. They are current test dependencies.

Six Markdown links pointing to retired snapshots now target immutable GitHub
blob URLs at the baseline commit. Historical JSON inventories keep their original
paths and bytes. The [evidence directory guide](../../../qa/openbao-acceptance/evidence/README.md)
explains how to interpret those paths after retirement.

## Workflow cleanup and future placement

The removed workflow is
`.github/workflows/heptabao-official-private-owner-root-exact-head.yml`. Its only
automatic triggers named branches that no longer exist, and it offered no
`workflow_dispatch`. No current caller or ownership gate depends on it.

Three retained workflows (`clean-room-provenance`, `evidence-semantics` and
`repository-identity-integrity`) now list only `main` in their push selectors.
`native-historical-restore-recovery` retains its manual dispatch and all jobs,
without push selectors for deleted branches. Structural YAML comparison confirms
that all retained jobs and other fields are unchanged. The 41 remaining workflows
pass the existing trust validator; historical manual replay entries remain.

The repository ignore rules now prevent ordinary staging of executable captures
under acceptance evidence. Reusable code belongs alongside its current tests;
new campaign receipts should bind a source commit and hashes. `.gitattributes`
classifies historical evidence as documentation and required third-party inputs
as vendored code. Active QA, clients and bridges remain visible in language
statistics. No source language is relabeled as Rust.

The root README remains intentionally empty under the existing repository
contract. Current navigation is extended through
[`docs/CURRENT_DOCUMENTATION.md`](../../CURRENT_DOCUMENTATION.md).

## Verification and observed limitations

The final Python runs used Python 3.12.14, PyYAML 6.0.2, jsonschema 4.23.0 and
cryptography 50.0.0, matching the declared QA dependency pins. Rust metadata and
formatting used Rust/Cargo 1.98.0.

| Check | Observed result |
| --- | --- |
| Current repository and documentation validators | PASS; 53 first-party packages |
| Repository regression suite | 304 / 304 PASS |
| Security regression suite | 80 / 80 PASS |
| Retained personal-credentials guards | 26 commands PASS, including 217 unittest cases and 409 JSON self-test checks across overlapping historical profiles |
| Personal-credentials evidence integrity | 256 indexed files, 28,189,714 bytes PASS |
| Workflow trust and delivery-gate ownership | PASS; 41 retained workflows |
| Cargo metadata and formatting | PASS; metadata unchanged; workspace format check passes |
| Archived-source recovery | All 1,302 files / 26,931,646 bytes recovered and independently verified |
| Acceptance suite after cleanup | 1,768 tests: 1,763 passed, 3 skipped, 2 errors |
| Python client suite after cleanup | 224 tests: 216 passed, 4 skipped, 1 failure and 3 errors |

Both acceptance errors also occur on the unmodified baseline: the host refuses
AF_UNIX socket creation, and its system ELF loader fails the test's root-owner
requirement. One additional baseline invocation encountered an unhandled
`ProcessLookupError` while observing a short-lived process in
`test_actual_native_argv_and_wrong_identity_never_signal_another_child`. That
case passed in the cleanup run; its earlier failed observation is retained in
the validation record and is not treated as a fixed defect.

All four client failures reproduce in targeted runs against the untouched
baseline. Two require `fcntl` seal constants absent from this Python build; two
require AF_UNIX socket creation denied by the host. The affected source and tests
are byte-identical to the baseline. The tests and their admission assertions have
not been relaxed or skipped to obtain a passing result.

No new failing case was observed after cleanup, but the suites are **not wholly
green in this host**. Full native Rust runtime tests, physical Android/browser
qualification and production operations are not reissued by this structural
cleanup. No Rust build input was changed. See [validation.json](validation.json)
for structured commands, counts and original failure identities.

## Recovery

[`retired-sources.json`](retired-sources.json) binds every removed file to its
original commit, tree, path, mode, Git blob, byte count and SHA-256.

```sh
python3 scripts/archived_qa_sources.py --verify
python3 scripts/archived_qa_sources.py --restore-to /tmp/heptabao-archived-sources
```

Recovery requires a new directory outside the current checkout, verifies all
selected bytes before creating it, and executes no archived program. Use
`--prefix qa/openbao-acceptance/evidence/<campaign>/` for a smaller selection.
For a full historical replay with original relative imports and receipts:

```sh
git worktree add --detach /tmp/heptabao-historical 6faf7957bb0b9390141a9f3680567ef96295eba6
```

A shallow clone may first need
`git fetch origin 6faf7957bb0b9390141a9f3680567ef96295eba6`.
This cleanup changes the current tree without rewriting Git history; it therefore
reduces checkout contents, not necessarily the size of an existing `.git` object
database or a full-history clone.
