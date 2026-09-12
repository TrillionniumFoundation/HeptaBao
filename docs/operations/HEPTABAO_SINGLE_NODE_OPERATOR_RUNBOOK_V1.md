# HeptaBao Single-Node Operator Runbook V1

Current procedure for the runnable `heptabao-server` candidate under plan `HEPTABAO-PLAN-2026-09-07-V2.1`. The filename is retained for navigation; this procedure supersedes the earlier in-memory composition instructions. It is not production qualification. [Current architecture](../architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md) identifies actual owners; standalone contract crates do not add operating features to the executable.

```yaml
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Configuration and startup

Bind the exact binary/commit, Cargo.lock and configuration digest. Use a private Linux deployment directory, absolute data/audit/TLS paths and an owner-protected TLS private key outside `data_dir`. The service rejects unsafe paths and competing durable/audit writers. Never delete a lock or rename evidence to force startup.

Illustrative configuration with synthetic paths (supply real certificate files and an admitted listen address):

```json
{
  "listen": "127.0.0.1:8200",
  "data_dir": "/srv/heptabao/data",
  "audit_file": "/srv/heptabao/audit/audit.jsonl",
  "tls_cert_file": "/srv/heptabao/tls/server.pem",
  "tls_key_file": "/srv/heptabao/tls/server-key.pem",
  "max_connections": 16,
  "timeout_seconds": 15,
  "rate_limit_per_second": 200,
  "rate_limit_burst": 400,
  "rate_limit_entries": 4096,
  "audit": {"segment_bytes": 33554432, "retained_segments": 8}
}
```

Run `heptabao-server --config /absolute/server.json`. Optional connection limits are 1–128 and absolute socket deadlines 1–60 seconds. The per-IP token bucket bounds rate to 1–100,000/second, burst to 1–1,000,000 and tracked peers to 1–65,536. Defaults are shown above. Unknown configuration fields fail admission. Rate limiting is local to one process and does not establish distributed abuse resistance.

The listener can be ready while uninitialized or sealed. Startup does not implicitly unseal. Durable encrypted-state replay occurs when the barrier is activated on unseal; a listening socket alone does not prove successful state recovery. `GET /v1/sys/health` reports 501 when uninitialized, 503 when sealed/recovery-fenced or without required HA authority, 429 for an HA standby, and 200 for admitted active service. Audit failure can withhold the ordinary health result; consult local failure diagnostics as well.

## Initialization, unseal and rekey

1. Verify `GET /v1/sys/init` and `GET /v1/sys/seal-status` against the intended new data directory.
2. Initialize once with `POST /v1/sys/init`, an object containing `secret_shares` and `secret_threshold` (1–16 shares, threshold 1–shares). Store the returned bootstrap token and fresh shares through the deployment's custody procedure. Unsupported initialization fields fail before state creation.
3. Submit distinct returned shares through `POST /v1/sys/unseal` with the documented `key` value until the threshold is reached. A share authenticates seal generation, not arbitrary data-directory state. Read seal status after each step; never publish shares in logs or scripts.
4. Verify unsealed health and a synthetic application write/read before admitting clients. Configure policies, auth mounts and limited credentials through the [authentication guide](../auth/HEPTABAO_SINGLE_NODE_AUTH.md); retain bootstrap authority only under the operator's custody policy.

For a new initialization that must survive a lost response, first generate and privately retain 32 client-side CSPRNG bytes. Supply them as optional `recovery_nonce` in canonical padded standard base64 or 64 lowercase hex characters alongside `secret_shares`/`secret_threshold`. This HeptaBao extension returns `init_ack_required: true`. Repeating POST/PUT `sys/init` with the same recovery secret and identical effective share/threshold settings recovers the original shares and bootstrap token, including after process restart; it does not create a second cluster or new credentials. Defaults, when omitted, are 5 shares and threshold 3. Wrong or absent recovery credentials do not disclose the response. Ordinary initialization without this extension retains its original response-loss limitation.

The pending response is encrypted in owner-only `init-recovery.hbe` (at most 16 KiB), published with the staged seal metadata and encrypted state. Its wrapping key derives from the client secret and domain-separated seal binding, not the audit key. Preserve the client secret until the returned shares/token are safely held and verified; do not log it or place it in URL/query parameters. The server can reject an all-zero value but cannot prove client entropy quality.

After unsealing and verifying custody, an effective root token in the root namespace calls POST/PUT `/v1/sys/init/ack` with `{}` to remove and synchronize the encrypted pending response. Complete this acknowledgement before rekey or enabling HA; they are blocked while recovery remains pending. Acknowledgement returns 204 and ends replay of the initial sensitive response. An authorized repeat also synchronizes an already absent file, because absence after a failed directory sync is not enough evidence. A 503 directory-sync failure fences the live instance: preserve state and reopen before reconciling/retrying. Wrong recovery parameters return 400, failed authentication 403, no pending response 409, and unavailable files or an in-process/on-disk seal disagreement 503 (a changed binding encountered at restart fails authentication with 403); none permits automatic erasure/reinitialization. `GET sys/init` remains a nonsensitive status read. A legacy audit-key-protected `.init-escrow` artifact is not silently adopted; startup requires an explicit offline migration. Preserve all original state if recovery fails, rather than erasing initialized data.

`sys/rekey/init` and `sys/rekey/update` implement the bounded Shamir rekey/verification protocol described in the server guide and service tests. Rekey changes wrapping/share custody while preserving the barrier key; it is not KMS auto-unseal or a general data-key rewrap facility. Preserve pending verification state across response loss/restart and explicitly complete or cancel the ceremony. New shares must be verified before discarding the previous custody set.

## Limits, compaction and pressure

| Resource | Current enforced bound | Action |
|---|---|---|
| HTTP headers / normal body | 16 KiB / 256 KiB | Send one canonical JSON request per connection; chunked/pipelined requests are rejected |
| Snapshot request / response body | 32 MiB / 32 MiB | Snapshot-specific JSON/base64 transfer still has the smaller decoded limit below |
| Serialized Service state | 768 KiB | Remove obsolete data/credentials using authenticated APIs; compaction alone cannot shrink live secrets |
| Retained durable operation identities | 32,000 | Compact the journal when needed; compaction retains replay identities and does not reset this limit |
| Durable journal | 64 MiB | Root `POST /v1/sys/storage/raft/compact` with `{}`; inspect returned generation and before/after byte counts |
| Decoded backup transfer | 20 MiB | Export fails with 507 above the limit; keep size headroom before a restore drill |
| Active audit segment | 4 KiB–32 MiB, default 32 MiB | Automatic authenticated rotation occurs before the next record would exceed the configured segment |
| Retained sealed audit segments | 1–64, default 8, plus active segment | Archive sealed segments externally before retention removes older records |

Capacity or filesystem failure is not permission to continue unrecorded requests. New durable writes can fail before entry with 507; an unavailable audit path can block reads, health and denied attempts as well. A finite-use token may already have consumed its admitted use before a subsequent ACL or state-capacity rejection. Alert externally on byte/inode headroom and failed operations; there is no integrated metrics exporter or background retention daemon for general token/lease models.

## Authenticated audit rotation and retention

`audit_file` remains the active JSONL file with its existing HMAC key sidecar. Rotation adds `.rotation-lock`, a signed `.rotation.json` manifest, bounded sealed `.segment-<id>.jsonl` files and reserved staging material. Sequence numbers and HMAC chain continuity continue across segments. The manifest authenticates retained segment lengths/digests/frontiers and the base frontier of the evicted prefix. This authenticates the retained chain; it does **not** preserve all evicted event contents or provide a remote rollback anchor.

Rotation persists a complete archive, then pending manifest, then active-file truncation, then final manifest, synchronizing the relevant files/directories before deleting only authenticated obsolete segments. Reopen reconciles supported interrupted boundaries. Tampering, an unexplained archive/tail or lost required checkpoint fails closed; retain all files and diagnose rather than truncate the tail manually. Existing authenticated single-file audits can reopen without rewriting their old records; unkeyed legacy audit requires an explicit migration. Once rotation occurs, the active file resumes at a nonzero chain frontier: an older binary that does not understand the manifest cannot directly reopen it. Preserve the compatible binary version, original key and complete audit sidecar set for recovery. Copytruncate keeps the active inode stable, so a collector that only tails the active file must explicitly handle truncation; manifest-based sealed-segment collection is the reviewable archive boundary.

Under normal steady retention, sealed plus active data is at most approximately `(retained_segments + 1) * segment_bytes`; allow additional disk headroom for the in-progress archive copy, staging/checkpoints and old authenticated garbage during recovery. A lower configured segment size does not retroactively shrink an existing larger legacy segment. A deployment requiring complete history must consume only sealed segments listed in the signed manifest, verify their recorded digests, and copy them with their authenticated manifest/key context into independently protected storage before eviction. A segment filename alone does not prove completion because archive creation can still be in progress. The service does not implement remote archival or archive-delivery acknowledgement. With defaults, steady segment data is about 288 MiB; an in-progress full archive copy can temporarily raise this to about 320 MiB, plus bounded manifests/staging and retained recovery material. Restoring a consistent old copy of all local audit/key/checkpoint files still requires an external monotonic anchor to detect rollback.

## Backup and restore

`GET /v1/sys/storage/raft/snapshot` is root-authorized and returns JSON `data.snapshot` (base64), `sha256`, `generation`, `retained_requests` and `format: heptabao-encrypted-backup-v1`. Verify decoded bytes against `sha256` after transfer. This is a HeptaBao encrypted backup, not an OpenBao Raft snapshot; the route name does not imply byte-format compatibility. Keep matching seal/key custody and a separately preserved audit history. TLS and auth provider configuration also need their deployment backups.

Restore uses root `POST`/`PUT /v1/sys/storage/raft/snapshot` with exactly `{"snapshot":"<base64>"}` (illustrative payload). The service must be initialized and unsealed with compatible barrier custody; this endpoint replaces admitted local durable state rather than creating a fresh empty recovery-core target. Invalid encoding/authentication/shape fails, and an older generation is rejected. `snapshot-force` deliberately permits rollback only within the same local format after operator review. It does not create external rollback protection.

Direct local restore returns 409 while HA is enabled. Do not bypass this by editing a running cluster's files. The HA branch can trigger a Raft snapshot during export/compaction, but a trigger receipt does not prove remote snapshot installation. Validate restored generations, application secrets and replay behavior in an isolated drill before relying on a backup. Preserve originals and stop if the outcome is uncertain.

## Unknown outcomes and recovery

| Observation | Meaning | Operator action |
|---|---|---|
| Explicit pre-entry rejection | No new durable operation was admitted at that boundary | Correct the cause; account for any already committed token consumption |
| Successful committed response | State and required response audit completed | Do not repeat the mutation |
| Recovery reference / response lost after entry | A mutation may have committed | Stop blind retries; read back the resource and query the recovery reference |
| Recovery lookup `committed` | Durable replay found a committed generation | Return/read the committed result; do not issue another effect |
| Recovery lookup `aborted` | Durable recovery classified the admitted intent as uncommitted | Reconcile client state before deciding on a new request |
| Recovery lookup 404 | The reference is unknown | This is not proof of no effect; preserve evidence and investigate |

Root `GET /v1/sys/internal/recovery/<reference>` returns the bounded local reconciliation result. The generic `operator-api`/`operation-ledger` models do not add an arbitrary external-effect readback API to this server. A 503 or transport timeout by itself never proves an application mutation did not happen.

## HA and operating qualification

Optional `--ha-config /absolute/ha.json` enables one voter per process with pinned mTLS peers and the actual initialized application's cluster identity. See the server guide for required node/peer fields, 200 ms heartbeats, 1000–2000 ms elections and bounded forwarding workers. ReadIndex remains required; a local leader observation is insufficient. The synthetic destructive fixture uses cold-cloned development seed data and is not a production enrollment procedure.

Repository checks include `root_maintenance_routes_compact_snapshot_restore_and_reconcile`, `result_audit_failure_withholds_plaintext_and_preserves_consumed_token_after_reopen` and the `audit_rotation_*` interruption/tamper tests in the server package. Run `cargo +1.98.0 test --locked -p heptabao-server --all-targets`; the standalone smoke and HA fixtures exercise additional named scenarios. Independently witnessed restore, filesystem/power failure, HA faults, rolling upgrades, custody, archival retention and incident response remain qualification work.
