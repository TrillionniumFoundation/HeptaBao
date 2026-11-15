# Legacy AuthBus inbox pagination — X230 evidence, 2026-11-03

Source commit: abdb586943137cd7dc5b6406437689c15e9087b4.
Base: ee851bd11e1a9d261be1acbd291d1599ffbf8f88.
Coordinator SHA-256: cc46822439dfd33c86d1068c886941a92c5581871474cef846d2aee14ce80fe0.
Actual Linux binary SHA-256: 187bcc477f3620c32d9ba549dc71e6c560417868a97faa8800d9fb14ffab1055, from unified source 4e2a6d7e5931eb72577f9bbd428fce5bb705027e.

The legacy coordinator now uses the existing exclusive-after KV2 LIST pagination contract and owner-bound, fsynced scan cursors. Each successful cycle scans at most 32 events in total, including deferred or already-recorded items. Source hosts rotate, exhausted pages wrap, and lower-UUID late arrivals are revisited. Pending unknown mutations are recovered before scanning. Immutable remote receipts remain the only completion evidence; scan cursors do not authorize a mutation or establish a commit.

## Verified scope

The 38 contract tests passed on X230 with synthetic transport and real private state files. They exercise 1,057 events, cold coordinator reopens, deferred/revoked grants, late lower UUIDs, host fairness, bad pagination responses, cursor ownership validation and recovery of unknown outcomes.

The actual formal V6, loopback TLS/AppRole fixture ended with 94/94 assertions and 1,058 exact report receipt identities. The successful continuation retained 555 receipt identities from interrupted runs and added 503 without clearing state. It ran 20 new coordinator processes, never scanned more than 32 events per cycle, preserved the original deferred credential event, and committed it exactly once only after explicit reauthorization. Real renewal, writer delete denial, bearer revocation, SecretID revocation, and their persistence through a SIGKILL/cold server restart passed. No inbox was deleted. Synthetic credentials stayed inside the private fixture.

The coordinator lease due clock was forced to exercise actual renewal; this fixture did not wait for a real lease to expire. The separate production-transport lifecycle fixture covers actual expiration.

## Failed observations remain failed

The first setup lacked formal V6 activation and failed before inbox seeding. The corrected initial run exceeded its original 900 second runtime budget. A first continuation exceeded its 60 second per-cycle observation budget. These outcomes are retained here and are not relabeled as passing.

The final continuation used the same original TLS/server storage/owner/event/receipt identities with a 300 second aggregate cycle observation limit and completed in 1,182.211 seconds. The coordinator's per-request deadlines, policy, rejection behavior and page bounds were not relaxed. This evidence qualifies resumable bounded work, not throughput within the original budget.

## Remaining limits

Immutable inbox and receipt retention still grows. This change does not add garbage collection, DELETE permission, distributed owner fencing or scheduler supervision. The newer production fixed-slot transport is a separate path. This fixture does not qualify real provider credentials, actual SDK cutover, all clients or backups, production traffic migration, cleanup, or full OpenBao replacement.

See summary.public.json, the byte-for-byte public live/failure results, runtime-status.public.json and contract.public.txt. Private fixture root: /home/qian/heptabao-authbus-inbox-20261103-r1-live-r2. Private keys, tokens, credential payloads and journals are deliberately outside this Git evidence.

## Reproduction

Run the contract suite:

    python3 qa/openbao-acceptance/authbus_coordinator_contract_test.py

For a fresh isolated actual server fixture, use qa/openbao-acceptance/authbus_inbox_pagination_live.py with an unused --work-dir, the pinned --binary, --binary-sha256, --central-sha256 and --events 1057. For recovery after an observed interruption, authbus_inbox_resume_live.py requires the original owned private fixture and refuses a still-running listener. It never reinitializes the server, substitutes receipt identities or treats the cursor as completion evidence.
