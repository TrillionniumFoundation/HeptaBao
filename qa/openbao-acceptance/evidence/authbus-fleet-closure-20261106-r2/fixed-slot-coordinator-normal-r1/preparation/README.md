# Fixed-slot coordinator — normal HeptaBao qualification preparation

This is a new, bounded Mac fixture for the frozen coordinator implementation
`248057b53a13708cc0650b73c83bc86729a7572e0d1bf24768ea94b8d3fd8265`.
Its nine runtime files, including all four original production transport files,
are unchanged. The coordinator's 22 local synthetic tests are separate evidence;
this preparation does not claim a Mac or normal HeptaBao pass.

The parent creates one new private HOME client root and one new T5 server root.
It reads the existing canonical normal executable as a public, whole-file pinned
artifact; it does not open the existing permanent service's data. Two original
Rust processes use the same new fixture data, with an explicit stop and cold
unseal between generations. Two new Node processes use the same private client
SQLite databases and operation journal.

The CA and server key are newly generated. The leaf includes Basic Constraints,
Key Usage, server Extended Key Usage, SAN localhost/127.0.0.1, SKI, and AKI. Native
Python's default strict TLS, hostname and whole-leaf checks must return the
uninitialized health response before the single init request. New root/unseal,
AppRole IDs, tokens, full response bytes and any failure diagnostics remain in
private 0600 files under 0700 fixture directories. Public reports contain checks,
counts, public code/certificate pins and original resource closure only.

The initial Node generation tests a wrong leaf before HTTP, exact operator
authorization, revoked authorization, a pending unauthorized event, single-slot
backpressure, credential rotation, health observations and a bounded report. It
then injects one **local receipt interruption after the original ack HTTP call
has returned successfully**. It retains the original dispatched plan. This is
not a network-loss claim. After the server and client process restart, the second
generation must confirm that exact original ack with readback and no write,
reconcile the producer slot, rotate again under a new exact grant, prove policy
denials, renew the original coordinator bearer, revoke the known bearers, and
destroy both synthetic Secret IDs. An unplanned failure prevents cold-phase
admission; no unknown preimage permits a replay.

The kernel policy admits the one tested local TCP port. Its actual scope is
local addresses at that port, not IPv4-only. The unchanged StrictBaoClient binds
each request to an already verified 127.0.0.1 socket, CA, hostname and leaf. The
worker separately observes the original request-to-socket association, complete
HTTP bodies and socket closure. It also performs real kernel denial probes on
two synthetic protected files and another loopback port. No current AuthBus
profile, OpenClaw SDK, provider endpoint, J3160, Keychain or live service
registration is accessed.

## Deadlines and closure

The parent has 600 seconds and the supervisor 630. Each API/Node phase is capped
at the original 120 seconds. Python requests retain their 10-second bound and
readiness its 15-second bound; the unchanged client uses 15-second requests and
30-second coordinator operations. Node receives the parent's original monotonic
absolute deadline as a decimal nanosecond string. A clock mismatch refuses the
run instead of starting a new budget.

Original `Commands` and retained direct-child custody are reused. Every crypto,
Node and Rust dispatch has an fsynced private intent; original outcomes and
streams are retained before interpreting a result. Rust cleanup remains the
qualified single-attempt ownership path. Successful admission requires all
original processes, groups, pipes, SQLite handles, explicit JavaScript file
descriptors, explicit parent descriptors and T5 anchors to close. Resource
failure or business unknown remains a failure. Log-size checks are bounded
post-stop reads, not claims of OS-enforced output quotas.

The complete source manifest, source derivation program and narrow root/CA-path
diffs make the Python and Node composition reviewable. No remote execution has
been performed by the preparation program.
