# HeptaBao Observability Catalog V1

Current runnable observations and separate telemetry model under `HEPTABAO-PLAN-2026-09-07-V2.1`. See [actual runtime owners](../architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md). No metric exporter, SLO or production qualification is implied by a workspace telemetry crate.

## Current server observations

| Surface | Actual output / meaning | Boundary |
|---|---|---|
| `GET /v1/sys/health` | initialized/sealed/standby, cluster identity, HA active/enabled and recovery-required fields; 200/429/501/503 status | Liveness alone is insufficient; active HA requires current authority and audit may withhold the response |
| `GET /v1/sys/seal-status` | Current initialized/sealed status, share threshold/progress and seal generation metadata | Never log actual submitted or returned shares |
| `GET /v1/sys/leader` | Current admitted leader/standby observation | Not an independent proof that a later read or mutation has quorum |
| Root compaction/backup responses | Generation, retained request count and journal byte counts or backup digest/format | On-demand administrative readback, not background metrics |
| Authenticated audit JSONL | Schema 2 event: sequence, previous MAC, time, kind, keyed path fingerprint and optional HTTP status; outer MAC | Mandatory admission/response record, independently synchronized and rotated |
| Process stderr | Listener-ready line and bounded startup/transport failure messages | Not a structured per-request telemetry stream or exporter |

Audit request/response kinds are `request`, `response`, `wire-rejection` and `wire-response`; initialization also records `initialization-response-prepared` before publishing the staged initial state. `path_digest` is retained as a field name but current requests use a keyed fingerprint over method, namespace, path and bearer; it is not plaintext or an unkeyed hash of the path. It does not include the body. A wire rejection uses a fresh attempt identity, rejection class and status because the request may not have passed parsing. No claim is made to audit every failed TLS handshake as an application request.

`audit_file` is the active segment. Configuration `audit.segment_bytes` (4096–33554432, default 33554432) and `audit.retained_segments` (1–64, default 8) bound automatic retention. The signed rotation manifest binds segment frontiers and an evicted-prefix anchor; it cannot reconstruct deleted events. Inspect files read-only and preserve the key/checkpoints. External archive delivery, alerting and retention policy are deployment responsibilities, detailed in the [operator runbook](HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md).

Do not log bearer tokens, passwords, secret IDs, JWTs, unseal shares, private keys, bodies or full secret paths. Operational diagnosis should use status classes, bounded sequence/generation numbers and protected readback. Monitor storage/inode headroom, restart failures, audit failures and unexpected 503/507 responses externally; no built-in Prometheus endpoint or automatically emitted catalog events are established by current source.

## Separate telemetry contract model

The following retained V1 event catalog is a **proposed model vocabulary**. These events are not emitted by `heptabao-server`, which does not depend on `heptabao-telemetry`.

| Model event | Proposed labels | Intended meaning |
|---|---|---|
| `request_completed` | `operation`, `outcome` | Request result |
| `namespace_created` | `outcome`, `generation_bucket` | Namespace transition |
| `mount_state_changed` | `backend`, `state` | Mount transition |
| `plugin_state_changed` | `kind`, `state` | Plugin lifecycle |
| `backup_state_changed` | `state`, `outcome` | Backup lifecycle |
| `operation_readback` | `operation`, `outcome` | Reconciliation result |

The standalone telemetry crate validates an allowlist of label **keys**. It does not enforce arbitrary label-value cardinality, implement an exporter, redact caller-selected values, or bound `MemoryTelemetry`'s event vector. Its caller must provide these controls before integration. See the module guide and named tests rather than interpreting this table as existing instrumentation.
