# R11 physical evidence, 2026-10-20

This is an evidence branch. The tested product is commit `d1879d97aac65ac064f70b6408ab6dc61975a08f`, tree `072be70722f3117118683403975a57fba9cfdbb4`. Adding these receipts does not create a newly tested product candidate.

## Completed scoped gates

- The unchanged native 58-case runner passed on Mac and Main. The same Main-built binaries and test executables then passed all 58 original cases on physical X230 Linux; X230 did not compile those artifacts.
- Mac and physical X230 each passed all 31 original full34 checks against a pinned, running OpenBao 2.7.1 process. The 17 retained 2 MiB versions total 34 MiB. The checks include official export, native import, exact API/storage history, cold restart, snapshot mutation/restore, undelete, destroyed-payload absence, and CAS denials without effects. These are single-node migration/recovery results.
- The Mac focused peer/runtime selection passed its 18 exact cases.
- Generic comparison executed 69 observations per endpoint: all 68 required cases plus the exact `totp.mount` extra. The first outer wrapper rejected the 69-versus-68 set; a separate read-only review verified the immutable original result and the exact extra case. The original result was not changed or re-executed.
- Original quota81 and AppRole25 comparisons passed on Mac. AppRole uses natural SecretID expiry and checks JSON/form requests and restart. Quota81 does not qualify HA/global/namespace quota behavior.

## Gates still failed or incomplete

Physical Mac/ROG/Pocket4 LAN98 stopped at 51 passed out of 98 required checks (52 observations). Write 13 returned HTTP 503 after publication and local installation had completed. The exact existing diagnostic reports a final `ha_sync` veto: remaining budget before sync 914,368 us, sync elapsed 914,664 us, original deadline expired. The failed mutation was not replayed. All owned fixture processes were retired. Failure, re-election, ReadIndex and cold-restart phases had not yet been reached.

ControlGroups passed the candidate's 132 control-semantic checks but retained 12 strict runtime differences against official 2.7.1. The separate original replay probe remains HOLD: official execution versions [1, 2, 3], candidate [1, 1, 1]. Neither result is converted to a strict pass.

The attached receipts do not prove full OpenBao 2.7.1 replacement, completed fleet migration, production cutover, or authority to delete existing OpenBao assets. R10 and failed R11 runs remain independent evidence. Original per-request limits, fixture budgets and denominators have not been increased or reduced to obtain a pass.

See `INDEX.json` for original paths and SHA256 values. JSON receipts retain their original bytes.
