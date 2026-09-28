# Raft RPC queue and transport deadlines

The canonical process RPC adapter uses one absolute monotonic deadline from
`RaftPeerRpc::exchange` construction through admission, blocking-worker queueing,
TCP connect, TLS/frame I/O, response decoding and final response admission.
The configured peer timeout can shorten this budget but cannot restart it.
Application forwarding retains its independently configured timeout.

A private drop guard aborts a blocking task that has not started when its caller
is cancelled or times out. Tokio cannot abort an already running blocking task:
that task retains the semaphore permit until its deadline-bounded transport
ends. A timeout is not evidence that a submitted consensus mutation had no
effect. No mutation replay, quorum bypass, election change or state-format
migration is introduced.

## Regressions

`ha_rpc_deadline_tests.rs` exercises the production adapter with actual loopback
TCP and a controlled single blocking-worker queue. Three tests reject network
connections from work whose budget elapsed before first poll, from timed-out
queued work, and from explicitly cancelled queued work. The endpoint is silent
and deliberately cannot complete TLS; these tests do not establish mTLS identity
or consensus correctness. The pre-fix source fails all three assertions.

## Forwarding and consensus listener capacity

The listener has a bounded 4–16 worker pool selected by `max_inflight`.
`PeerWorkerBudget` reserves two workers from application-forward admission and
permits the remaining workers to forward. Requests still serialize at the
existing product state owner; no second writer or application retry is added.
A saturated forward pool rejects immediately rather than accumulating an
unbounded queue. Peer handshakes and consensus processing retain their existing
bounds; the reservation is not a claim of adversarial scheduling fairness.

The prior single forward slot rejected simultaneous traffic from two ordinary
standbys even when the rest of the listener pool was idle. The first bounded
physical-host load attempt at source `6eb7e275` failed during healthy concurrent
writes with `ha_leader_forwarding_failed`; its 21 completed base checks, failure
report and all three verified process stops are retained. Two production-budget
regressions fail under the old policy and assert both concurrent standby
admission and the unchanged consensus reservation after correction.

## Physical-host load profile

`qa/openbao-acceptance/ha_multihost_load_live.py` composes, rather than replaces,
the existing private three-host lifecycle. Its exact denominator is the original
54 checks plus 11 load checks. It submits 18 CAS-create writes using three
concurrent workers, 16 with the old leader stopped and two voters remaining,
and 18 after quorum recovery. Every mutation is attempted once. Each acknowledged
value must have version one and must survive snapshot catch-up and leader
recovery. Final convergence checks all 52 values on all three hosts; cleanup
only removes this fixture's unique synthetic prefix. Mutation retry is forbidden
also on transport failure or HTTP 503. Timing summaries describe only this
bounded sample; they are not sustained throughput or latency guarantees.

The profile accepts the same binary/source hashes, node declarations, private
new roots and explicit tailnet permission as `ha_multihost_live.py`. It retains
failed reports, checksums and stop events and never publishes fixture secrets.
Controller unit tests are explicitly not physical execution receipts.

A passing run does not explain the earlier two-voter ReadIndex availability
counterexample by itself. Disk-full, torn writes, WAN partitions, long-horizon
linearizability, all-asset OpenBao migration and independent security admission
remain separate acceptance work; this patch does not claim full replacement.
