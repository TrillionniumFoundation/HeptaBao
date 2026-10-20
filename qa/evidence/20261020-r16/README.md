# R16 native quota routing evidence — 2026-10-20

## Verdict

R16 is **not qualified for full OpenBao 2.7.1 replacement**. Mac supplemental passed 37 of 38 cases; Linux Main passed 38 of 39. Both failed the unchanged quota lifecycle case at `sys/step-down`: the native route guard returned HTTP 501 before the existing Service handoff handler could run. The later leader handoff, cold restart and seal/unseal assertions in that case were therefore not reached.

The original denominators remain separate. Independent HA2, quota refusal custody guard1 and native administration CRUD1 each passed on both hosts. These results do not turn either supplemental run into PASS and are not transferred to any later source candidate.

## Exact candidate

- Commit: `289a7c80771ae39095be7aaae4e0f42cf009a726`
- Tree: `ec902ac1a61cf86476518f65e1fc40032f2fcebc`
- Parent: `47b96f44edf51c2b68f22ed83495bc70e84ae24d`
- Manifest SHA256: `f87fc98fec5cac723abbd909bc65f65fa2e721e2077251557830043acb3cc54d`
- Actual raw commit SHA256: `048bb4a35904efe837da743e32cffd6e9c15c2ab09b0439703e01bfd31ff8bec`
- Source: 3556 files, two existing files changed, no added source files.

R16 routes the three Auth-owned quota administration paths through the existing native Auth writer and appends one independent native administration regression. Source and actual Git materialization receipts for both hosts are included. The original R15 source and input bytes remained unchanged; each executed runner verified the complete R16 source before and after execution.

## Observed results

| Gate | Mac | Linux Main |
|---|---|---|
| Supplemental total | FAIL, 37/38 | FAIL, 38/39 |
| AppRole135 | PASS, 11/11 | PASS, 11/11 |
| Quota definition catch-up and live buckets | PASS, 1/1 | PASS, 1/1 |
| Quota lifecycle / actual handoff / cold restart | FAIL, 0/1 | FAIL, 0/1 |
| Historical CIDR | PASS, 3/3 | PASS, 3/3 |
| Historical batch token | PASS, 22/22 | PASS, 22/22 |
| Linux historical defaults | Not selected on Darwin by the original runner | PASS, 1/1 |
| Independent HA publication and readback fences | PASS, 2/2 | PASS, 2/2 |
| Independent quota preauth refusal custody | PASS, 1/1 | PASS, 1/1 |
| Independent native quota administration | PASS, 1/1 | PASS, 1/1 |

The supplemental runner is unchanged, SHA256 `c614eb25a774cb06bc11b56bc95eaf32f0d3ba311cc3e0b335d6e9436154b50e`. The original native58 runner is unchanged, SHA256 `1a610b080e3f29e6daa19fe788eaf90f2c8d9d3c5e4daa2aea2fc6249e846e06`, and was **not executed for R16**.

All listed runs used the original locked/offline Cargo commands, default debug profile, 1800-second per-command limit, original target locks and host build job counts (Mac 2, Linux 8). No request deadline or test assertion was relaxed. A multi-request case's total elapsed time is not the per-request budget.

## Failure and follow-up

The retained logs end with:

- `sys/step-down` status 501;
- `quota-actual-leader-handoff`: expected HTTP 204, observed 501.

The pre-handoff quota writes, catch-up and live bucket assertions proceeded successfully. They do not prove the unexecuted remainder of the lifecycle case.

The next candidate R17 adds one exact `sys/step-down` exception to the native Service route gate. It must retain the existing real Principal and sudo checks, terminal clock publication, mandatory response audit, original deadline and observed leader-transfer completion. R17 must run the original lifecycle case and all further required gates afresh.

## Scope still unproved

R16 did not execute original58, focused20, current-candidate 34MiB official 2.7.1 migration/recovery, X230 artifact58, LAN98 fault validation, the official AppRole live differential, or the real-credential six-phase canaries. No production host was switched and no OpenBao service, binary or backup was removed.

Historical R11 write13 and R12 write15 are retained as completed publication followed by final HTTP 503. They must not be replayed. The R12 LAN failure remains a failure; its previous successes do not qualify R16 or R17.

## Evidence layout

`INDEX.json` records every original source path, exact size and SHA256 for the 33 raw files. Summaries retain exact command arguments, selected tests, exit states, toolchain/resource profiles and source-before/source-after identities. Test logs are unedited; large logs were retrieved with version-pinned bounded reads and verified against both chunk digests and the whole-file SHA recorded by the runner. The raw files include both lifecycle failures, all supplemental test groups, HA2, guard1, CRUD1 and both forms of source materialization.

Related prior evidence: R15 commit `2c35ad823748b4d6bb2430b60b6ba0ea12c1d861`, R14 commit `afcc2c3338b692170478c8cd6a478f8465e99424`, R12 commit `f623a039f21502ebaaf33c16c5cc22c26c197cc0`.
