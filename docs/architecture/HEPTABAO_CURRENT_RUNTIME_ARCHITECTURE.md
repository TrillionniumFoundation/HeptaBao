# Current runnable architecture and state ownership

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. This source-level map is for the current runnable candidate. [The complete 46-package map](../modules/CURRENT_RUNTIME_MAP.md) distinguishes the five runtime packages from the 41 separate contracts, prototypes and tools. See [current source binding](../modules/CURRENT_SOURCE_BINDING.md) for content digests and the historical snapshot boundary. No diagram confers qualification or compatibility authority.

## Actual workspace dependency graph

These are normal Cargo path dependencies, including the transitive directory guard. They are not a plan to rename the other packages into missing layers.

```mermaid
flowchart TD
    Server["heptabao-server"] --> Durable["heptabao-durable-service"]
    Server --> Transport["heptabao-ha-service"]
    Server --> Raft["heptabao-raft-runtime"]
    Durable --> Guard["heptabao-filesystem-guard"]
```

`ha-service` provides the concrete mutually authenticated peer transport and certificate binding consumed by the server. Its generic `HaService` facade is a separate model. `raft-runtime::ProcessRaftNode` provides one voter per process; `RaftRuntime` also retains a three-voter in-process test facade. Compiling those packages does not mean a single-node server automatically runs HA: operators must explicitly supply HA configuration and admit the cluster/key identity.

## Actual server modules and request ownership

```mermaid
flowchart TD
    Wire["http.rs: TLS, bounds, parsing"] --> Tx["service.rs: request transaction"]
    Tx --> Auth["private auth.rs: tokens and ACL"]
    Auth --> Login["federated_auth.rs: verifier helpers"]
    Tx --> Engines["engines.rs: mounts and dispatch"]
    Engines --> Backends["engines/kv.rs, transit.rs, totp.rs"]
    Tx --> Storage["durable-service: encrypted state"]
    Tx --> Audit["service audit: authenticated records"]
    Tx --> HA["ha.rs, ha_forward.rs, ha_state.rs"]
```

TLS parsing is followed by service admission. The service serializes mutable state, obtains and consumes a request-scoped private `Principal`, and rechecks authorization with the live `now`. Neither `AuthState` nor `Principal` is exported. Public Rust callers enter `Service::handle` or `handle_at`; only deterministic tests or a trusted embedding should supply the latter's clock. A normal request owns its JSON body; secret-bearing request/response data is cleared on the relevant drop paths with documented best-effort limits.

Audit is part of admission and response publication: a request record is persisted before dispatch, and a response record before releasing the result. Finite-use token consumption is itself persisted before dispatch. A later denied or failed operation can therefore have consumed the admitted use. A response/audit or transport failure is not evidence that the preceding state mutation did not commit. Parsing/rate-limit rejection records use the separate wire-rejection path; no claim is made that every failed TLS handshake can be audited as an application request.

## Current authoritative writers

| State | Actual owner and durable boundary | Route/verification entry |
|---|---|---|
| Tokens, password/role verifiers, ACL and auth mounts | private `auth.rs`, contained in Service state and encrypted by `durable-service` | `auth/*`, `sys/auth`, `sys/policies/acl/*`; `auth_tests.rs` |
| KV versions/metadata, Transit keys and TOTP state | `engines.rs` and `engines/*`, inside the same encrypted Service state | mount-relative engine routes and `sys/mounts`; `engine_tests.rs` |
| Init/seal/rekey state | `service.rs` seal metadata and optional client-secret initialization recovery object; `crypto.rs` Shamir/key wrapping; barrier activation authenticates durable state | `sys/init`, root `sys/init/ack`, `sys/unseal`, `sys/seal`, `sys/rekey/*`; `service_tests.rs` |
| Durable request ledger, journal and snapshot | `durable-service`; exclusive `filesystem-guard` owner | Service persistence, `sys/internal/recovery/*`, compaction/backup routes; durable-service tests |
| Audit sequence, HMAC chain and rotation checkpoint | service audit owner, private key and independently synchronized JSONL/manifest files | every admitted request and response; server audit tests |
| HA ordering, log/vote/membership and state-machine apply | `ha.rs` composes per-process `ProcessRaftNode`; peer transport binds certificates and messages | peer listener, forwarding and `sys/storage/raft/*`; HA and raft-runtime tests |

The standalone `token`, `policy`, `kv-engine`, `namespace`, `identity`, `lease`, `plugin-host`, `key-lifecycle`, `rollback-anchor` and `telemetry` packages are not these server owners. Their separately tested data models must not be substituted into a current storage, API or security claim. In particular the server does not yet integrate a general plugin backend, dynamic-secret lease subsystem, KMS auto-unseal provider or remote rollback anchor merely because corresponding crates exist.

## Historical and target diagrams

The V1 system-context/crate graph and authoritative ownership map retain proposed layers including package names that were never implemented under those names. The V2 mandatory/admitted/durable pipeline documents describe `RuntimeService`/`ServiceCore` compositions. They remain design and regression context; this document is the current executable assembly. Follow the operator runbook for current startup, audit capacity and backup behavior. Destructive HA, migration, upgrade, external provider and independent security/compatibility qualification remain separate evidence requirements.
