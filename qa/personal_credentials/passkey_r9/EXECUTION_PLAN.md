# Fresh r9 Passkey phone profile

This is a new execution of the fixed eighteen-case profile. It reuses the exact
r7 provider and permissioned r8 fixtures, and changes only the QA controllers.
No old r8 case outcome or independent supplemental case contributes to its counts.
The product, build receipts, RP source, fixture certificates, encrypted seed, and
core driver remain pinned to the original artifacts named by `profile.public.json`.

## Admission and ownership

Host ingress copies only the explicitly checked artifacts and this run's synthetic
master from the previous private host directory into a new private r9 directory.
It does not use ADB, install packages, select a provider, or decrypt a vault.
The phone remains unavailable to this run until root explicitly transfers the
latest independently released phone window. A source or host-control review is
not a phone result. Preflight refuses previously installed or retained owned
packages and saves original settings before any installation or Settings action.

Every stage is dispatched once through the fixed `execute-workflow.py`. It first
creates and fsyncs a stage intent. An uncertain or failed dispatch is not reissued.
Read-only reconciliation may preserve already observed results; it never changes
the original terminal status or manufactures a successful attempt. A stopped flow
requires a separately reviewed limited cleanup if the complete-run cleanup's
eight-file preconditions have not all become true.

## Actual execution order

| Stage | Action and evidence boundary |
| --- | --- |
| RP | Fresh loopback RP on 38491, fixed certificate and 180-second challenges. Its process ceiling is 10,800 seconds; that ceiling does not extend any ceremony window. |
| SETUP | Exact owned preflight, installation, reverse, durable joint Settings intent, ordinary system picker. Ordinary nonsecure wake/swipe only after fresh platform state checks. No password. |
| DOCUMENTS | Four initially absent owned directories and four fixed encrypted-seed markers. One copy per marker, then exact size/hash and media-index checks. This is QA staging. |
| M01 | Complete ordinary SAF seed selection, real password EditText, explicit fresh-store import. |
| M02, M03 | Real CredentialManager create and get, each independently verified by the fixed RP. |
| M04 | Ordinary SAF backup export; unchanged RP bytes before/after, actual destination readback and a private host copy. |
| M05_OBSERVE | Read-only live checkpoint and provenance after M04. Peer must review this actual frozen checkpoint before any reset. |
| M05_RESET | Fixed helper, exactly one admitted reset; original launch audit flag, result and durable completion witness retained. Unknown result is fenced. |
| M05_RESTORE, M06 | Fresh process and ordinary SAF restoration, then real get with the same credential/public key and strictly increasing RP counter. Same physical phone, not cross-device migration. |
| G11_RECOVERY_EXPORT | Immediately after M06 count 2, export an independent current recovery backup through ordinary SAF. Keep M04 count-1 backup as the stale input. No positive guard is run before this export/checkpoint. |
| G11_OBSERVE, G11_RESET | Separate actual checkpoint review, then the only permitted second reset. Latest and stale roles are exact paths/digests. |
| G11_STALE | Ordinary SAF restores the old M04 file; real get must produce the RP's actual `counter_rollback_or_replay` rejection. Counters are not edited or advanced by QA. |
| G02_G06 | Five separate identity/authorization cases, each with a fresh successful CM control and a single actual negative request. Unique control filenames prevent the old report collision. |
| G07 | Fresh positive control and one new CM request. One ordinary Back from Operation, then at most one Back from the same request's system chooser. Actual fixture cancellation and final RP snapshot must remain within the original 180/300-second origins. |
| SAF_GUARDS | G01 and G09 retain their precise refusal checks. G08 and G10 each select a new valid SAF target that has not been consumed by any product Write. QA verifies it is empty, copies the fixed 615-byte encrypted seed once, and rechecks its digest. G08 starts a new picker and cancels before testing `choose_backup_destination_first`; G10 uses a wrong password and requires `wrong_key_or_corrupt`. Both require the nonempty destination and RP to remain unchanged. |
| M07_RESTORE | Core exact compare-and-restore for original settings, owned packages, and reverse. Unknown joint setting state is preserved. |
| RP stop | Cancel only this run's original RP job. Preserve its actual terminal state and exact stopped stdout before document cleanup. Closed-port observation alone is insufficient. |
| M07_CLEANUP | Require all eight files/four directories to match owned intents and actual digests. Preserve both private host backup captures; remove only exact files, empty directories, and their exact media rows. Recheck all settings/packages/reverse. |
| RELEASE | Independent read-only absence recheck and original terminal/stream binding for all prior stages. Root verifies this result before handing the phone to another task. |

The profile retains seven main cases and eleven guards, in the original ID order.
Setup, observers, reset steps, and export preparations are supporting evidence,
not extra passing cases. Every fresh case is missing until its actual behavior
has been observed. Any failures remain in the same eighteen-row ledger.

## Inputs and clocks

Passwords enter the product through its normal EditText. The authorized synthetic
QA input method briefly puts the synthetic value in an inner adb/input child argv;
this is explicitly not production end-to-end no-argv evidence. No real credentials
are used. Secrets and recovery ciphertext remain in owned private host directories.

CM ticket and index bounds remain 180 and 300 seconds from the original event.
The cancellation controller rejects late successful observations before accepting
the screen, and records the already verified final RP snapshot rather than doing
another unbounded observation before writing PASS. Individual observations are
bounded; unknown input outcomes are never repeated. The usual stage Runtime limit
is 1,200 seconds (guard groups 1,800); per-ceremony bounds are unchanged.

## Original Runtime records

For each stage, persist the exact requested argument object, original launch and
terminal tool response containers, and full bounded stdout/stderr in
`runtime-observations/<stage>/`. `capture-runtime.py` verifies matching job identity,
the actual fixed dispatcher argv, terminal durability/completeness, and byte counts.
It preserves `audit_recorded` as observed, including false or absent; it does not
upgrade a launch's audit state. M05_RESET and M05_RESTORE are reported separately.
Only host metadata capture uses stdin, never a product password argument.

M05/G11 observers consume those exact export records before generating their
checkpoint index. Reset and restore digest arguments are populated from actual
new-run files after peer review, never copied from r8. Result/witness failure is a
global fence; there is no third reset or ID substitution.

## Scope

Even an eighteen-case pass applies only to this fixed synthetic native RP, fixture
identity, APK/SDK/device combination, same-phone fresh-store restoration, and the
observed time period. P4 as a whole, production adoption, cross-device Passkey
migration, general websites, arbitrary document providers, and independent security
review remain unqualified. Original r8 16/18 and its three independent passing
supplements remain separate evidence with their original failures and limitations.
