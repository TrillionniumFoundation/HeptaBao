# Durable AuthBus production transport

This directory makes the existing fixed-slot AuthBus transport adapter available
as versioned source. Import `ProductionTransportClient` from
`plugin/production-client.js`. The four modules originated in the r11
qualification package. The state journal and lifecycle changes are described
below; `provenance.json` records the original hashes and source generation.

## State journal change

The private state database uses SQLite WAL mode with `synchronous=FULL`.
Every existing CAS is still committed before its caller can proceed, including
every bearer wall-clock high-water update. Prepared and dispatched intents,
confirmed receipts, authentication renewal, revocation, and unknown-outcome
handling retain their existing transaction boundaries. The constructor verifies
that WAL and FULL were actually selected and fails if SQLite cannot provide them.

The separate operation database still uses DELETE/FULL. Its `BEGIN IMMEDIATE`
transaction excludes another local process for the duration of network work and
the operating system releases that lock when a process dies. No process-ID lock
files or time-based lock stealing are introduced.

WAL removes the repeated rollback-journal creation/deletion work from state
commits. Automatic checkpointing runs every 256 pages; the normal retained WAL
limit is 2 MiB. This is a checkpoint target, not a hard file-size bound: an open
reader can retain older WAL frames. Both database files and all existing sidecars
remain subject to the original private-owner, mode, inode and hard-link checks.

## Local deployment and backup requirements

The state and operation databases belong on a local filesystem on the client
host. WAL does not support distributing these database files across hosts or
using a network filesystem. Each host keeps its own existing private state.
The server KV2 data remains independent of this client SQLite implementation.

Stop every client using a state directory before upgrading from a DELETE-mode
adapter. Then replace the adapter for all of those local clients. The first
open converts the state journal without changing records, revisions or bindings.
Opening an old DELETE-mode adapter concurrently with a WAL-mode connection can
fail; mixed-version journal switching is not an accepted rollout.

Back up a **complete quiescent state directory**, including `state.sqlite-wal`
and `state.sqlite-shm` whenever present, or use SQLite's consistent backup API.
Never copy only `state.sqlite`. A process killed without closing SQLite can
leave its most recent durable intents and acknowledgments in WAL. Existing
complete-directory AuthBus checkpoint/restore code includes these sidecars.
Restoration must preserve directory/file ownership and private modes.

## Expired bearer recovery and operation deadlines

A restarted client can authenticate again when its previously active bearer has
certainly expired. The strict client first validates the persisted deployment
binding, lease fields, and wall-clock high-water mark. It retains the expired
record until the replacement AppRole attempt has a verified TLS socket and its
own durable login intent. An unresolved or rejected login, renewal, or revocation
is never cleared or retried by this recovery path. New AppRole constraints and
Secret ID consumption still apply on the server.

Each production read, publication, and reconciliation captures one absolute
operation deadline before renewal or reauthentication. That same deadline follows
renewal/login, control admission, KV reads, and outbox dispatch. Expiry prevents a
new request; a request already sent when its reply becomes late stays unknown.
`readSecret`, `writeInbox`, and `reconcile` accept `{ deadlineMs }` as their final
optional argument. The default whole-operation budget is 30 seconds and the
strict client's per-request maximum remains 15 seconds.

## Verification

Run `node --test tests/durability.test.mjs` with Node.js 22 or newer. Tests use
real child processes and real SQLite storage, with synthetic credential-free
remote state. They exercise DELETE migration, SIGKILL at four publication
boundaries, exact readback, no replay of uncertain mutations, two-process local
CAS conflicts, process-death lock release, known remote conflicts, and complete
WAL backup/restore after a crash. These tests do not claim real provider validity
or production cutover.

Run `node --test tests/lifecycle.test.mjs` for the persisted-bearer and operation
deadline regressions. This suite uses an actual loopback TLS server and private
SQLite state with synthetic credentials. It covers expired-lease startup,
unchanged active leases, unresolved/rejected authentication attempts, malformed
leases, backward-clock refusal, and renewal replies beyond the caller deadline.
Its HTTPS fixture is not an OpenBao/HeptaBao server or an external provider.

From the repository root, run
`python3 qa/openbao-acceptance/authbus_lifecycle_live.py --binary /absolute/path/to/heptabao-server --work-dir /new/private/fixture`
for the real-server lifecycle test. This starts an isolated loopback HTTPS service
using ordinary `--config` and formal `native_v6_file` activation. It waits for an
actual 10-second AppRole bearer lease to expire, cold-restarts the server twice,
opens new client processes, verifies persisted KV and ACL denial, renews the same
bearer, and confirms self-revocation before and after restart. It also drops one
real successful renewal response before client observation: the reopened strict
client and production wrapper retain the unknown intent without another request.
No server responses are fabricated in this test. All identities and payloads are
new fixture data; provider credentials and production cutover remain unverified.

`qualification/lifecycle-20261103.json` records the old-code regression failures
and the 21 passing SQLite/TLS tests on X230 and Mac T5. The real X230 HeptaBao
result and exact source/binary hashes are in
`qualification/lifecycle-live-x230-20261103.json`.

Run `node tests/benchmark.mjs /absolute/path/to/original/private-outbox-store.js`
to compare the exact original adapter against WAL/FULL on the same filesystem.
The baseline file must match the original hash in `provenance.json`. The benchmark
retains all six synchronous commits per synthetic report and verifies reopening.
It measures local state-storage cost, not whole AuthBus or network throughput.
