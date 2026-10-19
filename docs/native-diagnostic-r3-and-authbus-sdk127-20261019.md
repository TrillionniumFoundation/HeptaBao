# Native restore diagnosis and actual SDK refresh checkpoint

This checkpoint preserves failures and adds a narrow diagnostic. It is not a full replacement qualification or authority to remove OpenBao.

## Actual physical candidate 0f1c

Mac ran all 55 selected tests at commit `0f1c996136aae94e99c2b709a5797ffea479f6cd`, tree `8befd5cedfb7ccafee5f707e5985d49eeb78fb60`. Source verification covered all 2,882 files before and after execution. The outcome was 53 passed and 2 failed. Both server tests and the native ARM64 server binary compiled successfully. The original summary and both failing group logs are included byte for byte.

The historical restore group passed 6/6, snapshot service 7/7, native large KV2 15/15, and the 34 MiB archive case 1/1. These are native fixture results, not proof of an actual official OpenBao process migration.

The import codec failure retained an obsolete exact-number expectation on the public API. The reviewed correction binds that expectation to the observed binary64 API response while adding direct cold descriptor checks of precise stored bytes and hashes, retained soft deletion, and destroyed payload absence.

The new witness recovery case passed import, initial and cold storage witnesses, and negative-zero reads, then received HTTP 400 when completing a snapshot restore. The candidate retains the same operation and success assertion and adds its synthetic response body to the diagnostic. No claim is made that this recovery failure is fixed; live token clock floor protection is a source-review hypothesis pending the actual response. No fixture values or deadlines were removed.

## X230 and prior CI evidence

The previous 22cd low-memory X230 run completed. Server test compilation exceeded the original 1,800-second build budget; two peer tests passed and 41 server tests were blocked. The subsequent native Linux binary build succeeded in 783.315 seconds with SHA-256 `cb384062a3732519fdc1a6d4e620fecbdd79c77ecef536b13921258064e33835`. This is not a passing 43-test run. The exact summary and compiler/build logs are retained.

Both completed 22cd CI jobs passed 42/43, failing the historical source-root expectation at line 310. Their complete original logs are retained. The new Mac candidate's 6/6 historical result is separate evidence for that correction.

## Actual AuthBus SDK owner R5

Owner R5 ran the real installed OpenClaw SDK 2026.7.1-2, its real SQLite persistence, OAuth manager, and a controlled HTTPS provider on the main host. It completed all 11 scenarios and 127/127 checks. The provider sent once only after durable UNKNOWN, failed or uncertain paths did not retry it, old wire and missing-scope successor attempts were denied, and the SQLite failure used real abort triggers.

The R4 scope fix is included together with its original final-boundary failure. R5 corrects fixture package discovery using the actual SDK package's verified bin entry and root as argv/cwd, preserves all filesystem guards, and records their restoration and source identity. It produced zero external network/process attempts, zero outside-fixture writes, and zero home read attempts. The installed SDK and all 13 source files were unchanged after execution.

The R5 source packet SHA-256 is `f8dc48896872d72ceda6c348234c7f2695391a91976bd1dda5a398482a9e3c11`; the actual public receipt SHA-256 is `067961e9851cee9e09deb2beaee5a63a02c38f98e9086eae7344f0a8b15289b9`. This run used synthetic OAuth credentials and a TLS KV emulator. Actual native HeptaBao control storage, an independent cold SDK process, the dynamic OpenAI facade, real provider refresh, per-host production cutover, and old-service removal remain unqualified.

All deployment, migration, cleanup, and full replacement authority flags remain false until their own required evidence is complete.
