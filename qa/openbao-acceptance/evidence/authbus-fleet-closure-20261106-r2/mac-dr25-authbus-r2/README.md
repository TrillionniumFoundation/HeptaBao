# Mac full34 baseline and fresh-directory DR25: completed actual run

The actual Mac job `1a1b16bbf10-fc05-788f` completed with exit 0, complete durable
output, no timeout, and no automatic retry. It passed all **31 original full34
baseline checks and all 25 original fresh-directory recovery checks** in
127.33642774960026 seconds. All 700 original controlled children were reaped
once, with no live members before reap and no recorded custody gaps.

This is synthetic normal-artifact evidence. AuthBus, physical HA, production
cutover and full OpenBao replacement remain unqualified by this run.

## Exact source and runtime bindings

| Binding | Actual value |
| --- | --- |
| Normal product source | `4bde9aee03fcd27c59e13607e529b1cee594b249` |
| Product tree | `f08493a23f8ea0637073651231865ea9607b790e` |
| Clean QA source | `5ded017e1c858b8602a73678acc29df75386a84d` |
| QA tree | `9d1d040a063504ede67559fadb556897591642f2` |
| Normal server SHA-256 | `5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c` |
| Normal seed SHA-256 | `203c7af52c0f9aa4ca71e591c1428acac9382f3c4105036a494631b0e1cae8e7` |
| Admitted Mac 107/107 build receipt SHA-256 | `90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6` |
| Read-only preparation digest | `685253afc398a084a93aa9aeaf44f1c44bf09aeb7c951f2cededece29cdec4dc` |
| Original work / outer caps | 1740 / 1800 seconds |
| Original HTTP, CLI and seed caps | 15 seconds |
| Original migration cap | 360 seconds |

All product files outside `qa/` and `docs/` in the QA checkpoint match the
canonical product commit. The QA change fixes the incorrect comparison between
encoded archive length and logical history volume. In this actual run the
archive has 9,009,239 encoded state bytes and the capacity observation reports
35,655,894 logical payload bytes. The full34 fixture retains 17 large live
versions containing 34 MiB, within a 19-version history. CLI and HTTP archive
metadata agree exactly, including generation and seal identity.

The earlier attempt remains failed in
[mac-dr25-4bde9-failed](../mac-dr25-4bde9-failed/). Its outcome is not changed by
this new run. No product deadline, history denominator, restore requirement,
negative control or custody requirement was relaxed.

## What the completed run proved

The OpenBao 2.7.1 oracle, API history, raw storage history, metadata, CAS behavior,
soft-deleted payload and destroyed version were captured and compared. The
baseline also performed cold restart and snapshot restore checks. The recovery
phase stopped and quarantined the original closure, released its handles,
created a fresh recovery directory and TLS identity, and used the staged seed
plus the actual V6 backup to recover the history.

The wrong unseal key was rejected. A tampered archive failed without a commit,
including a subsequent cold check. Exactly one valid CLI restore succeeded;
there were zero source-bundle imports after quarantine. All 19 historical
versions passed API and raw-storage comparisons, and another cold reopen
preserved them. A new version 20 then survived its own cold reopen. The final
source, key custody, backup manifest, process cleanup and redaction checks passed.

The backup and work directories have distinct observed filesystem device IDs.
The key directory is separate from the backup, and key material is absent from
the backup. This is not evidence of physical power-loss survival, off-host
backup custody, cross-seal restore or physical disk independence; those original
flags remain false.

## Complete original receipts and reproducible verification

- [run.result.public.json](run.result.public.json),
  [run.terminal.original.json](run.terminal.original.json), and
  [run.stdout.original](run.stdout.original) preserve the original wrapper and
  authoritative runtime outcome.
- [dr25-summary.original.json.gz](dr25-summary.original.json.gz) decompresses to
  the complete 2,148,370-byte original summary, SHA-256
  `0c6ac1f18fc2b00a8abf138226742b27e0f5149516bf5060a406e76a844331af`.
- [baseline31-summary.original.json.gz](baseline31-summary.original.json.gz)
  decompresses to the complete 92,097-byte original baseline summary, SHA-256
  `89448bf85f01828b05c4ad5f310502bd116d57ea2bb29b0f368577420b79603d`.
- [archive.original.py](archive.original.py) and its original stdout/terminal
  record the create-only, lossless compression after the actual test completed.
  It performed no service action and opened no private credential file.
- The source-stage, wrapper, read-only prepare, and actual Mac 34/34 controller
  guard receipts are retained here. The guard tests are separate from the
  31+25 actual product checks.

Run `python3 verify_evidence.py` in this directory. The verifier hashes and
decompresses both full original receipts, checks every exact case name and
denominator, verifies source and binary bindings, original terminal and budget
evidence, actual negative/positive restore outcomes, all 700 original children,
and the limits of the claims. Its captured result is
[verification.public.json](verification.public.json). It does not rerun the
product or freshly inspect remote disks.

The first bundle-write RPC had an unknown result. Its original record remains
here. Independent observations found the target absent; a separately recorded
conditional publication then installed the exact public bundle using a
no-replace link and verified it. This reconciles file publication without
relabeling the unknown RPC or replaying a product operation.
