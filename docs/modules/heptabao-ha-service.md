# heptabao-ha-service

Package: `heptabao-ha-service`

Source: `crates/heptabao-ha-service`

Engineering contract: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`

## Purpose and non-goals

Provides service-level leader routing, fail-closed quorum checks, authenticated peer framing, durable replay protection, snapshot integrity and membership-transition validation. Its concrete mTLS transport is consumed by `heptabao-server::ha::HaProcess`. The generic `HaService` facade and its consensus-driver contracts are not by themselves the full server composition or production deployment qualification.

## Public API and ownership

Current source binding: `docs/modules/CURRENT_SOURCE_BINDING.md` and
`planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json`. Any V1.4.7 generated
blocks below are historical lexical snapshots, not current API authority.

`HaService`, `ConsensusDriver`, `ForwardClient`, peer authentication/codec/state types, TCP bounded framing, snapshots and membership transitions form the API.

## State and data model

Client operations bind operation ID, kind and payload digest. Peer frames bind cluster, sender, receiver, term, sequence, kind, payload and HMAC. Peer sequence state is atomically persisted.

## Invariants and authorization

Linearizable work requires quorum. Followers forward to the current leader. Responses must match term and commit index. Peer frames require configured sender keys, receiver binding and monotonic durable sequence.

## Failure, retry and reconciliation

Operation ID reuse with different bytes is rejected. Persist failures are outcome-unknown. Replayed peer frames remain denied after restart.

## Concurrency and ordering

Consensus ordering is delegated to one driver. A single-writer state lock serializes peer sequence updates; TCP calls have explicit deadlines.

## Security and privacy

Keys and payloads are redacted from Debug. Frames are bounded and HMAC authenticated. Concrete rustls mTLS transport and pinned leaf identity checking exist. Production issuance, rotation, revocation and trust-root custody remain mandatory operational qualification.

## Persistence and compatibility

Peer sequence state uses the versioned `HBPS1` HMAC format and atomic rename. It is not OpenBao storage-format compatibility.

## Observability

Typed errors distinguish quorum, leadership, stale response, replay, authentication, transport, capacity, snapshot, membership and durability failures.

## Operations

Operators configure stable node IDs, peer addresses, per-peer keys, timeouts, joint membership changes, snapshot transfer and audited stale-lock recovery.

## Tests and executable evidence

Tests cover leader execution, follower forwarding, deduplication, quorum loss, persistent replay, tampering, receiver binding, snapshots, joint quorum and TCP framing.

## Evolution and open boundaries

The server now provides a concrete `heptabao-raft-runtime` adapter with one voter per process, mutually authenticated peer listener and forwarding path. Rolling-version upgrade, process kill/failover evidence and destructive multi-node qualification remain required on the unchanged candidate.
## V2.4 mutual TLS peer transport

`MutualTlsPeerTransport` uses rustls with a caller-supplied client configuration and validated `ServerName`; `serve_one_mtls_peer_frame` requires a caller-supplied server configuration whose client-certificate verifier has already authenticated the chain, then binds the single presented leaf certificate SHA-256 to an expected `NodeId`. Message-level HMAC and durable sequence fencing remain required in addition to TLS. Certificate issuance, revocation, rotation, trust-root custody and destructive multi-node qualification remain external operational gates.

The mutual-TLS client and accepted server sockets enable TCP_NODELAY while retaining
bounded framing, certificate identity checks and configured read/write timeouts.
The consuming server runs a fixed bounded peer worker pool rather than placing
all consensus and forwarded-client work behind one serial TLS receiver. These
changes do not supply membership policy, remote key custody or independent HA
qualification. The server guide defines its configured timing and admission bounds.
