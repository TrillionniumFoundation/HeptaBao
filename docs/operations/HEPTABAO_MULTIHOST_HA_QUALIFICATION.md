# Private multi-host HA qualification

Status: `IMPLEMENTED_SCOPED_LAB_PROFILE`

These profiles run one exact HeptaBao binary on separately authorized Linux
hosts joined only by a private tailnet. The three-host profile proves a bounded,
same-version, pre-enrolled voter lifecycle. The four-host profile exercises the
persisted Autopilot dead-server grace, safe contraction to three voters and
explicit readmission of the removed host. Neither grants OpenBao compatibility,
independent admission, production authority, key custody approval, or permission
to use arbitrary remote machines.

The executable owners are `qa/openbao-acceptance/ha_multihost_live.py` and
`qa/openbao-acceptance/ha_multihost_autopilot_live.py`. The surface inventory
names them `ha_multihost` and `ha_multihost_autopilot`. They are deliberately
**not** part of the default GitHub-hosted PR workflow: public runners cannot
reach the private hosts, and untrusted pull requests must never be routed to
persistent LAN runners merely to make these gates automatic.

## Prerequisites and trust boundary

Use exactly three Linux hosts for the general lifecycle or exactly four for
Autopilot cleanup, all explicitly authorized by the operator. Every host must be
reachable through a preconfigured noninteractive SSH alias and a unique address
inside `100.64.0.0/10`. The runners reject public, loopback, LAN, VPN-routed
non-tailnet, duplicate, or noncanonical addresses. Remote fixture roots and the
source binary must be new canonical paths below `/home/`.

The controller work-root parent must already exist, be owned by the invoking
user, resolve without a symlink, and be unwritable by group or others. The runner
creates the final work root with mode `0700`; it refuses an existing destination.
It never installs packages, edits a firewall, modifies a system service, or
opens a public listener.

Build the candidate from a clean exact source, then record the exact commit,
tree and executable SHA-256. A representative invocation is:

```bash
run_id=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
head=$(git rev-parse HEAD)
tree=$(git rev-parse 'HEAD^{tree}')
binary=/home/builder/heptabao-target/debug/heptabao-server
digest=$(sha256sum "$binary" | cut -d ' ' -f 1)

python3 qa/openbao-acceptance/ha_multihost_live.py \
  --binary-source local:/home/controller/heptabao-target/debug/heptabao-server \
  --expected-binary-sha256 "$digest" \
  --source-commit "$head" --source-tree "$tree" \
  --node host-a,100.64.0.11,/home/operator/heptabao-multihost-$run_id \
  --node host-b,100.64.0.12,/home/operator/heptabao-multihost-$run_id \
  --node host-c,100.64.0.13,/home/operator/heptabao-multihost-$run_id \
  --api-port 46230 --raft-port 46231 \
  --work-root /home/controller/heptabao-multihost-control-$run_id \
  --allow-private-tailnet
```

The source may be an SSH alias or `local:/home/...`. A local source must be a
canonical regular executable owned by the controller user and unwritable by
group or others. An SSH source alias may be one of the three nodes. In either
case the candidate is copied and its digest is checked independently on every
host. The profile creates one
fixture-only CA, one distinct client/server certificate per node, and a private
replication key. HTTP and Raft bind only the declared tailnet addresses.

## Fixed 54-check lifecycle

`REQUIRED_CHECKS` is a fixed denominator. A report can pass only when every name
appears exactly once, every row passes, the runner and all four candidate copies
(controller plus three hosts) remain byte-identical, and the recursive report
redaction check finds neither a forbidden secret key nor the runtime root token
or unseal key.

The lifecycle performs these stages without retrying a mutation:

1. Start one fresh node, initialize once, unseal, stop it, and copy only its
   encrypted durable state to the two new hosts.
2. Start three mutually authenticated Raft voters and require exactly one active
   authority before and after all nodes unseal.
3. Commit a baseline CAS=0 value, read it through every physical host, then send
   another one-shot mutation to a standby and verify forwarding and exact readback.
4. Stop one follower, use read-only leader probes and a stable window of
   exact protected reads of an already acknowledged KV value to observe a
   two-voter majority through the same ReadIndex/application-sync path used by
   normal requests. Only then commit enough entries, trigger a native snapshot,
   add a successor entry, restart the follower and require snapshot catch-up.
   After rejoin, leadership is observed again because snapshot installation may
   legitimately move authority. The recovered host then gets a bounded 90-second
   read window; each individual physical-host request may use the configured
   12-second service deadline. Readiness observations may repeat; none of the
   later writes is replayed to manufacture availability. Failure reports retain
   only a whitelisted, secret-independent response class.
5. Kill the active leader with `SIGKILL`. For three production election-timeout
   maxima, issue no authenticated health, ReadIndex or mutation traffic to the
   two surviving voters. Take one passive local `sys/leader` observation from
   each survivor, then enter the ordinary stable-leader gate with a bounded
   60-second window. Verify every acknowledged value, commit exactly once after
   failover, restart the old leader and require it to catch up. The quiet window
   is not a retry and does not treat elapsed time as evidence: the subsequent
   authority, readback and one-shot mutation checks remain mandatory.
6. Execute one authenticated `sys/step-down`, require another stable epoch and
   verify a fresh acknowledged value through every host. The bounded run must
   observe three leadership epochs and at least two distinct leaders.
7. Stop both peers. The single survivor must lose authority, return HTTP 503 for
   the one attempted write, and publish no data. Restart one peer, prove that the
   denied value remains absent, commit a fresh value, restart the final peer and
   require all hosts to converge.
8. Delete every synthetic application key, prove absence through every voter,
   and stop only the recorded fixture PIDs.

Read polling may repeat because it is observational. Mutating requests, including
CAS writes, snapshot trigger, step-down and cleanup deletes, are each issued once.
An unknown mutation outcome is not retried by this harness.

## First-start bootstrap convergence

Both profiles require exactly one Raft leader to be observable before any node
is unsealed. A pass must come from fresh remote roots and the first process
lifecycle; stopping and restarting a partially bootstrapped cluster is diagnostic
evidence, not a substitute for first-start qualification.

Every node durably binds a private marker inside its `raft_dir` to the cluster
identity and declared initial voter set. Markers remain pending while learners
are enrolled or catching up. Health polling may cause only the configured
bootstrap process, while current leader, to continue that immutable transition;
a follower can only observe and persist exact completion. No node exposes active
authority before its own marker is complete. Marker completion records history,
not a cached claim that current membership is ready: a restarted process may see
empty or local-only metrics while replaying its log and must stay alive but
fenced until committed, non-joint membership again contains at least three
enrolled voters. Later Autopilot removal or explicit membership administration
must therefore survive any node restart without restoring the original set.
Missing-marker legacy state is adopted only from local-only pending membership
or a stable enrolled set of at least three voters; joint, two-voter, uncommitted
or unenrolled state fails closed.

After the cluster elects its first leader, unseal may briefly race the initial
ReadIndex or role observation even though the immutable voter transition is
already converging. Service retries only the named pre-publication failures
`HA linearizable state is unavailable`, `HA control state is unavailable`, and
the two bounded HA-role observations. The retry is limited to twenty attempts
with a 50 ms pause. A node that becomes a follower stops anchoring and lets the
new leader own the transition. Durable publication failure, unknown outcome,
capacity failure and every unclassified error remain terminal and are never
turned into a blind retry. `ha_initial_anchor_tests.rs` checks recovery, role
transfer and immediate rejection of a terminal publication error; the private
multi-host profile remains the real first-start network proof.

## Four-host Autopilot cleanup

`ha_multihost_autopilot_live.py` has a separate fixed 55-check denominator and
requires four distinct hosts. It starts all four as pre-enrolled voters, commits
and reads a baseline through every host, then persists an Autopilot policy with
a three-voter minimum, a three-second stabilization window and a real 60-second
dead-server grace. A representative invocation is:

```bash
run_id=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
head=$(git rev-parse HEAD)
tree=$(git rev-parse 'HEAD^{tree}')
binary=/home/builder/heptabao-target/debug/heptabao-server
digest=$(sha256sum "$binary" | cut -d ' ' -f 1)

python3 qa/openbao-acceptance/ha_multihost_autopilot_live.py \
  --binary-source local:/home/controller/heptabao-target/debug/heptabao-server \
  --expected-binary-sha256 "$digest" \
  --source-commit "$head" --source-tree "$tree" \
  --node host-a,100.64.0.21,/home/operator/heptabao-auto-$run_id \
  --node host-b,100.64.0.22,/home/operator/heptabao-auto-$run_id \
  --node host-c,100.64.0.23,/home/operator/heptabao-auto-$run_id \
  --node host-d,100.64.0.24,/home/operator/heptabao-auto-$run_id \
  --api-port 46240 --raft-port 46241 \
  --work-root /home/controller/heptabao-auto-control-$run_id \
  --allow-private-tailnet
```

The profile stops a non-leader and derives health only from current-leader
ReadIndex and replication contact. It must first observe that voter as unhealthy
while still retained during grace. Only after the full persisted threshold may
membership contract from four voters to the configured safe minimum of three.
The survivors must continue committing and reading data.

Restarting the removed host is not readmission: it must not become active or
appear in committed membership from stale local state. The controller submits
one authenticated `join` using the current membership index. The host must enter
as a learner, catch up, remain non-voting through stabilization and only then
become a voter. The profile removes that rejoined node explicitly, proves another
removal below the three-voter minimum returns 409, kills the current leader,
checks policy persistence across failover/restart, verifies new writes through
all survivors, deletes every synthetic key and stops only recorded PIDs.

The runner does not shorten or mock the 60-second threshold, infer liveness from
SSH, retry a membership mutation, enroll a submitted address/certificate, or use
a force flag. Read polling is observational. A pass remains same-version private
lab evidence, not proof of WAN, storage, clock or long-horizon behavior.

## Process and artifact safety

Before `SIGKILL`, the stop path reads the recorded PID, resolves
`/proc/<pid>/exe`, requires the exact fixture executable, and checks that the
command line contains the exact generated server configuration. A mismatched PID
is refused rather than killed. Final cleanup follows the same boundary.

Remote fixture roots intentionally remain after a run. They contain private test
CA material, node keys, replication material, encrypted state and audit logs;
never upload them as CI artifacts. The controller writes a secret-safe
`summary.json`, but even that remains scoped local evidence until reviewed.
To remove a completed fixture, first verify that `process.pid` is absent and that
no process command line references the exact root. Then remove only the recorded
controller and three remote roots. Do not use a wildcard or a parent directory.

## What this profile does and does not establish

The three-host pass adds real separate-host evidence for mTLS peer identity,
standby forwarding, ReadIndex-backed readback, snapshot catch-up, leader process
death, old-leader recovery, explicit step-down, quorum-loss fencing and complete
rejoin. The four-host pass additionally covers current-leader health observation,
real grace-based dead-voter cleanup, the minimum-voter fence, non-automatic stale
host recovery and explicit learner readmission.

Neither profile exercises mixed-version rolling upgrade or mixed-version Autopilot, WAN
latency/loss, host power removal, disk-full or torn-write behavior, clock
rollback/jump, arbitrary membership discovery, long-horizon linearizability,
production certificates, or independent destructive qualification. Those remain
explicit blockers.
