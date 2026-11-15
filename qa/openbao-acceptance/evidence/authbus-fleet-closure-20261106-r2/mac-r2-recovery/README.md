# Mac R2 QA registration recovery — closed with independent evidence

This directory closes the failed QA registration `gui/501/org.heptabao.qa.mac-authbus-4e808-home-r2.server`. It does not qualify an AuthBus business cycle, a production cutover, or OpenBao removal. The original R2 business result remains failed.

## Outcome

The final cleanup job **1a1b134587a-fc05-76e5** succeeded with exit 0, complete durable output, no timeout, and confirmed terminal publication. It used a new independent 60-second cleanup budget. It observed the unchanged owned process for **20.053712790831923 seconds**, then dispatched exactly one label-scoped SIGKILL and one bootout. Total helper elapsed time was **20.214106917381287 seconds**.

The final helper never dispatched TERM. It bound the earlier recovery's single completed TERM receipt, five original journal files, authoritative failed runtime terminal, and the exact 10,650-byte previous stdout before acting. The previous failed operation was not relabelled or resumed.

The actual retirement record was `last terminating signal = Killed: 9`. Native libproc returned ESRCH for PID 32527, with no related PID, process-group, or direct-child rows. The helper then confirmed exact GUI-label absence twice.

Independent read-only job **1a1b13ae3a0-fc05-771f** also succeeded. Both of its rounds queried the exact **gui/501** domain, received exit 113 with the exact missing-service response, observed native PID absence (zero bytes, errno 3), and found no rows related by PID/PPID/PGID among 708 process metadata rows. It did not signal any process.

The generic `service_status` result checked only the system domain and explicitly reported `observation_complete=false`. That result is preserved and **was not used as GUI absence evidence**.

## Preserved sequence

| Stage | Durable job | Result and effects |
|---|---|---|
| Original registration reconciliation | 1a1b101ed2a-fc05-74d6 | Read-only success; original bootstrap-only ledger; no admission or recorded original wrapper birth |
| Recovery r1 | 1a1b11278be-fc05-7587 | Failed before journal creation or any mutation because a foreign ps UID displayed `-2` |
| UID diagnostic | 1a1b11635c5-fc05-75a3 | Read-only success; UID `-2` observed on unrelated PID 97472; target remained UID 501 |
| r2 preparation | 1a1b11b2289-fc05-75d3 | 15 synthetic gates and an actual no-signal preflight passed |
| Recovery r2 | 1a1b11e72f9-fc05-75ee | Failed after one known completed TERM; no KILL or bootout; later ps parser failure's offending row was not recorded |
| Post-TERM reconciliation | 1a1b124606d-fc05-7635 | Read-only success; same complete birth identity and argv; all five journals unchanged; 20 samples did not reproduce the later parser failure |
| r3 preparation | 1a1b13059c6-fc05-76c3 | 24 synthetic gates and an actual no-signal preflight passed |
| Recovery r3 | 1a1b134587a-fc05-76e5 | Succeeded; new own 20-second observation; KILL once, bootout once, no TERM |
| Independent absence | 1a1b13ae3a0-fc05-771f | Succeeded; exact GUI label, original PID, group, and direct-child selectors absent in both rounds |

The later r2 parser failure's exact literal remains unknown; the report does not infer it from later samples. The r3 observer strictly parses all PID/PPID/PGID selectors, then applies the full UID 501 and STAT requirements to related rows. Rejected selector or related-row fields are retained safely before refusal. Full libproc birth/executable checks remain mandatory for a live target.

## Source and byte bindings

- Executed r3 helper: `recover_r2_qa_once.r3.py`, 39,986 bytes, SHA256 `a54a12b1b7efd12c16f6720b6fe6a63fd197016b675068fb4d95da8ea891fde9`.
- Reviewed loader SHA256: `e6e57a0210cf691347b1c79b03c538b67b5e688115f69f755502168e39ce73d4`.
- Reviewed plan SHA256: `f73e8cb302cc2a6382d76c0e50ad942eb274ef73c09dd6703695cc2116d453a2`.
- Preparation gates SHA256: `589d6acae39cd3625ea76c32291cb33fceea06ce6088d835a2b8467b20c4229e`.
- Exact old identity: PID/PGID 32527, PPID 1, UID 501, birth 1793969379.298893, pinned Python 3.14 kernel executable.
- Eight r3 journal files were independently read back. The final candidate receipt SHA256 is `fa8acbaee7287281b9dae9021bcf3e603eaae80ab6f3594713b1f1ffedd3126e`.
- Both original stdout pages' hex bytes, text, offsets, EOF, and the authoritative 31,194-byte total were checked. The final candidate matches stdout after removing only the documented post-publication close/hash/elapsed fields.

Use `closure-verification.public.json`, the runtime terminal, both original read pages, the complete journal-file read, and the independent absence receipts together. A candidate journal file alone is not a terminal-success certificate.

All earlier failed results and original QA data files are retained. No credentials or credential digests are published here, no business phase was replayed, and no J3160 request or production-service operation was performed. This proves closure of the known owned QA registration and process group; it does not claim containment of arbitrary hostile descendants. The old wrapper's failure to reach ready remains a separate fresh HOME/T5/launchd qualification task.
