# heptabao-ha-service

Package: `heptabao-ha-service`

Source: `crates/heptabao-ha-service`

Engineering contract: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`

## Purpose and non-goals

Provides service-level leader routing, fail-closed quorum checks, authenticated peer framing, durable replay protection, snapshot integrity and membership-transition validation. Its concrete mTLS transport is consumed by `heptabao-server::ha::HaProcess`. The generic `HaService` facade and its consensus-driver contracts are not by themselves the full server composition or production deployment qualification.

## Public API and ownership

`HaService::new(driver, forwarder, completed_limit)` owns its injected consensus and forwarding implementations plus a bounded completed-operation cache. `execute(&mut self, &ClientOperation)` serializes that generic facade: the operation binds a 16-byte ID, kind and owned bounded payload; reusing its ID with different bytes returns `OperationIdConflict`. A cached result is not an authorization decision and callers must authorize before this layer.

`PeerAuthenticator::new(cluster_id, keys)` owns configured 32-byte per-peer HMAC keys. `seal` binds sender, receiver, term, sequence, message kind and payload; `admit_peer_envelope` authenticates before advancing `PersistentPeerSequences`. The sequence owner opens one absolute durable root, persists incoming/outgoing progress and rejects replay across restarts. `ReplayDetected`/`PeerAuthenticationFailed` are denial; `OutcomeUnknown` requires authenticated reopen/readback; `QuorumUnavailable`, `NotLeader` and `StaleLeaderResponse` never become a successful stale read.

`MutualTlsPeerTransport::new(peers, client_config, timeout)` owns endpoint mappings, a shared rustls client configuration and a finite deadline. `exchange(peer, frame)` checks bounds and returns owned bytes. `serve_one_mtls_peer_frame` borrows the listener and pinned certificate map, takes a configured rustls server verifier and invokes one handler only for the authenticated `NodeId`. The caller must supply correct CA/client-auth policy before construction. `TcpPeerTransport` is a separate plain transport test adapter; the production-shaped server composition uses the mTLS path.

`SnapshotManifest::build`/`verify` bind chunk integrity and `MembershipTransition::joint_quorum` checks old/new voter majorities. They validate supplied facts rather than enrolling a peer or proving snapshot installation. The server consumes the concrete transport; its own `HaProcess` performs consensus routing instead of simply wrapping the generic `HaService` facade.

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

Current named source scenarios:

- `quorum_loss_and_operation_id_conflict_fail_closed` — `crates/heptabao-ha-service/src/lib.rs`.
- `authenticated_peer_replay_is_rejected_after_restart` — `crates/heptabao-ha-service/src/lib.rs`.
- `tls_endpoint_and_pinned_client_identity_are_strict` — `crates/heptabao-ha-service/src/lib.rs`.

Run `cargo +1.98.0 test --locked -p heptabao-ha-service --all-targets`. These are source anchors; a current test receipt is separate.

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
