# heptabao-ha-service

Package: `heptabao-ha-service`

Source: `crates/heptabao-ha-service`

## Purpose and boundaries

Provides service-level leader routing, fail-closed quorum checks, authenticated peer framing, durable replay protection, snapshot integrity and membership-transition validation. It is not yet the concrete production `heptabao-server` Raft adapter or mTLS deployment.

## Public API and ownership

`HaService`, `ConsensusDriver`, `ForwardClient`, peer authentication/codec/state types, TCP bounded framing, snapshots and membership transitions form the API.

## State and data model

Client operations bind operation ID, kind and payload digest. Peer frames bind cluster, sender, receiver, term, sequence, kind, payload and HMAC. Peer sequence state is atomically persisted.

## Invariants and authorization

Linearizable work requires quorum. Followers forward to the current leader. Responses must match term and commit index. Peer frames require configured sender keys, receiver binding and monotonic durable sequence.

## Failure, retry and reconciliation

Operation ID reuse with different bytes is rejected. Persist failures are outcome-unknown. Replayed peer frames remain denied after restart.

## Concurrency model

Consensus ordering is delegated to one driver. A single-writer state lock serializes peer sequence updates; TCP calls have explicit deadlines.

## Security considerations

Keys and payloads are redacted from Debug. Frames are bounded and HMAC authenticated. Production mTLS and node certificate lifecycle remain mandatory external integration.

## Persistence and compatibility

Peer sequence state uses the versioned `HBPS1` HMAC format and atomic rename. It is not OpenBao storage-format compatibility.

## Observability

Typed errors distinguish quorum, leadership, stale response, replay, authentication, transport, capacity, snapshot, membership and durability failures.

## Operations

Operators configure stable node IDs, peer addresses, per-peer keys, timeouts, joint membership changes, snapshot transfer and audited stale-lock recovery.

## Tests and evidence

Tests cover leader execution, follower forwarding, deduplication, quorum loss, persistent replay, tampering, receiver binding, snapshots, joint quorum and TCP framing.

## Evolution and open boundaries

A concrete `heptabao-raft-runtime` adapter, TLS mutual identity, server listener integration, rolling upgrade, process kill/failover and destructive multi-node qualification remain required.
