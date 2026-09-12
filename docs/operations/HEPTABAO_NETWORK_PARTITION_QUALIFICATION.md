# Three-process encrypted-link network partition qualification

## Scope and entry point

`qa/openbao-acceptance/ha_network_partition.py` starts only its own three
`heptabao-server` processes under a newly created private work directory. Each
process has separate HTTP and Raft listeners, a distinct TLS certificate, local
durable files and one voter. The fixture inherits the cold synthetic seed,
cluster-identity, restart and quorum-loss checks in `ha_destructive.py`; it is
not an enrollment procedure for a production cluster.

The six directed loopback relays forward opaque encrypted TCP streams between
fixture-owned ports. They do not terminate TLS, disable certificate validation,
read credentials or record payloads. Peer certificate fingerprints and server
names remain unchanged when the transport address is replaced by a relay.
Every destination is a port allocated by this fixture and every connection is
to 127.0.0.1. There is no option to attach to an existing cluster or external host.

## Fault model and bounds

An edge represents one node's outbound connection path to a peer, not one-way
packet delivery inside an existing TCP connection. A bilateral isolation blocks
both connection directions involving the former leader. The asymmetric case
blocks that node's outbound connections while allowing inbound connections.
Full isolation blocks all six edges. Blocking closes established streams and
refuses new streams. Each state transition advances a generation so an old,
in-flight connect cannot be admitted after healing. Bytes are never retained
for replay when a link heals.

Each edge permits at most 32 active connection workers. A worker holds one
16 KiB relay chunk per direction, uses bounded socket operations, and drains no
unbounded queue. Excess connections are refused. Six acceptors and at most
192 workers are owned by the fixture; cleanup stops acceptors, closes channels
and joins workers within the stated deadline. An unexpected worker exception
or an unjoined worker makes the fixture fail. SIGTERM/SIGINT also fail the run
and enter cleanup rather than emitting a success receipt.

## Required observations

The same three process IDs must remain alive across each network partition and
its recovery. The remaining majority must elect a leader and accept one CAS=0
write to a new key. Its acknowledgement must contain integer version 1. Every
successful read of that acknowledged key must immediately return the exact
value and integer version 1. A successful stale response or 404 is a failure,
not a reason to retry until the value eventually becomes visible.

An isolated node must not claim active authority. HTTP 503 with `ha_active=false`
is unavailable; HTTP 429 with `ha_active=false` and `standby=true` is a standby
observation. A standby can retain a leader hint during a pre-vote partition,
so 429 is not proof of a reachable quorum. The fixture separately requires both
an existing-key read and a new write to return 503 while isolated. HTTP 200 from
an isolated node fails even if its body contradictorily says `ha_active=false`.
Safe status/active/standby observations are retained in the JSON report.

After healing, every node must serve the acknowledged majority value and show
that every refused write remains absent. Full isolation checks each node's
read and write refusal, then verifies all nine combinations of observing node
and refused source key after recovery. No mutating request is blindly retried;
a timeout, missing acknowledgement or incorrect version terminates the run.
Read-only 429/503 responses can be retried within a bounded readback deadline.

## Execution and receipts

Build the ordinary locked workspace binary. Supply its full SHA-256, not only
a branch name or a filename. The fixture checks that digest before and after
execution. The work directory must be a new absolute path; it contains synthetic
keys and service state and must never be committed or uploaded as an artifact.
Only the bounded JSON summary and sanitized command logs belong in evidence.

```sh
cargo +1.98.0 build --locked -p heptabao-server
binary="$PWD/target/debug/heptabao-server"
digest="$(sha256sum "$binary" | cut -d ' ' -f 1)"
timeout 360 python qa/openbao-acceptance/ha_network_partition.py \
  --binary "$binary" --expected-binary-sha256 "$digest" \
  --work-dir /absolute/new/private-network-fixture
```

The read-only `codex-openbao-replacement-ci.yml` runs this step on the exact head
and prospective merge after source identity, repository checks, Rust gates and
the existing process fixture. It is not marked `continue-on-error`. A skipped
step is not a passing network-partition observation. Each result belongs only
to its source commit/tree, executable digest and actual execution environment.
Commands in this guide do not assert that a particular candidate passed.

## Regression tests and remaining evidence

`qa/openbao-acceptance/tests/test_ha_network_partition.py` checks destination
ownership, opaque byte preservation, established-connection interruption,
generation changes, cleanup, fixed status interpretation, stale-success
rejection, bounded read-only retries and no uncertain-write replay. These tests
exercise the harness and are not substitutes for running the real processes.
The separate Rust bootstrap regression handles explicit `ForwardToLeader`
responses, including an empty leader hint; it does not authorize replay after a
membership timeout or weaken public write admission.

A scoped pass proves only the recorded process/network scenarios. It does not
prove multi-host WAN behavior, arbitrary concurrent-history linearizability,
forced snapshot installation, disk exhaustion, real power loss, rolling binary
version upgrades, membership changes, long-duration stability or independent
reproduction. Those requirements remain separate. The fixture always emits
`qualification=false`, `compatibility_claim=false`, `production_authority=false`
and `release_authority=false`; it cannot issue external acceptance.
