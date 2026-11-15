# Repository cleanup — third pass, 2026-11-15

Baseline: [`2b6cf2c68`](https://github.com/TrillionniumFoundation/HeptaBao/tree/2b6cf2c68dd953fd935a3fd94780aba6ae62c6d1).
The [validation record](validation.json) contains source bindings, commands,
results, log hashes and limits. Earlier audits retain their original results.

## Code cleanup

| Change | Result |
| --- | --- |
| Two unused top-level Android r4 Python copies | 13,592 bytes removed; identical versioned evidence originals and their manifest remain. |
| P0 library/binary response formatting | One private source for JSON escaping, protocol detail codes and status mapping; 55 lines / 3,336 bytes removed net. |
| Four strict JSON parsers and two YAML 1.1 loaders | One implementation of each policy; original hooks and exception boundaries retained. Net reduction: 6 lines / 357 bytes. YAML 1.2 and global PyYAML behavior are unchanged. |
| AuthBus SDK candidate copy | A 4-line compatibility entry replaces the duplicate: 142 lines / 8,147 bytes removed. Canonical implementation and runner are unchanged. |

Including new guard tests, source files decrease by **307 lines / 22,079 bytes
net**. Documentation is counted separately. Python remains at 940 files: two
old copies were removed and two shared helpers added. Rust increases from 1,249
to 1,250 files because the P0 targets now share a private source module.

The retired files are `qa/personal_credentials/passkey_phone_profile.py` and
`qa/personal_credentials/passkey_restore_autofill_bridge.py`. No current import,
workflow, documented command or dynamic staging consumer selects those paths.
Their versioned r4 originals remain byte-identical under evidence. Current
drivers and the frozen r9 package remain. The [retirement manifest](retired-sources.json)
records both original Git bindings and retained matching evidence paths.

Standalone JavaScript deployment still uses two files: copy the canonical
`authbus/` implementation and the runner into one directory with their basenames.
The compatibility entry is for an intact checkout. The [deployment guide](../../../qa/openbao-acceptance/patches/openclaw-sdk-explicit-deny.README.md)
now states the correct source paths.

## Reconciled documentation guards

The V1.4.5/V1.4.6 validators demanded old headings inside the empty root README.
Commit `7b4a59bdd72218c1e779eb32754a682cf465af7a` deliberately cleared that homepage;
`fdc802e2e933a65f298ff449ce00f1c0a454b682` moved technical requirements to the
current documentation portal. The current repository validator enforces this policy.

Only the obsolete README tails were replaced: the homepage must exist and have
zero bytes, and the technical portal must exist. All Rust semantic, recovery,
permission, workflow, authority, blocker, module and inherited portal-marker
checks remain. Both original current-tree assertions and all 22 original tests
remain; no test was deleted or newly skipped.

Previously, the permanently failing README baseline could make any mutation
appear rejected. Mutation helpers now require the unmodified candidate to pass
first. Eight new negative cases check nonempty/missing README, missing portal
and removed historical markers, including the relevant diagnostic. The original
two failures were reproduced at the exact baseline before repair.

## Validation

| Check | Observed result |
| --- | --- |
| Repository / security regression | 305 / 81 passed. |
| Full plan discovery | 323 passed, 27 existing skips, 0 failed; 350 total. |
| Linux x86_64 native P0 library / binary / protocol | 17 / 7 / 13 passed; no failures or ignores. |
| Affected Rust all-target Clippy, warnings denied; workspace formatting | Passed. |
| Parser differential / entry checks | 252 identical outcomes and exception chains; 18 entry points passed. |
| Six existing parser suites | Baseline and candidate both 75 passed + 9 existing skips. |
| JavaScript differential | 20 cases; 12 real runner subprocesses across three deployment layouts. |
| Current repository/documentation/identity/module/workflow/gate-owner/release-denominator validators | Passed. |
| Credential archive and host guards | Archive integrity passed; 24 verifier cases, 1 path test, 25 + 13 + 14 host guard cases passed. |
| Retirement and evidence preservation | Both removed files restored exactly; all 4,531 evidence files retain original bytes and executable modes. |

The legacy V1.1 scanner (`scripts/validate_plan_v2.py`) still returns 1 for the
existing synthetic private-key-delimiter fixture in
`crates/heptabao-server/src/service_external_key_native_tests.rs`. Its output is
byte-identical to the baseline. The scanner and fixture remain unchanged.

Native execution covers the affected P0/protocol targets, not the full workspace.
No external OpenClaw SDK campaign or phone qualification was rerun. Credential
checks used no phone, ADB or external network action and do not revise prior outcomes.

## Remaining scope and recovery

All 940 baseline Python files were parsed; module/path relationships in 1,194
existing first-party Rust files were reviewed. Other Rust duplicates cross
security-owner or package boundaries. All 52 schemas have references; 670
inspected relative file links resolve. The remaining ten patches and 48 original
stdout/stderr records have documented or integrity-bound roles. Dependency
versions, workflow coverage, permissions, vendored licenses and frozen replay
inputs are unchanged.

```sh
python3 scripts/archived_qa_sources.py --manifest docs/audits/2026-11-15-repository-cleanup-round3/retired-sources.json --verify
python3 scripts/archived_qa_sources.py --manifest docs/audits/2026-11-15-repository-cleanup-round3/retired-sources.json --restore-to /tmp/heptabao-retired-round3
```

Recovery requires a new destination, verifies commit/tree/blob/mode/size/SHA256,
and never executes archived source.
