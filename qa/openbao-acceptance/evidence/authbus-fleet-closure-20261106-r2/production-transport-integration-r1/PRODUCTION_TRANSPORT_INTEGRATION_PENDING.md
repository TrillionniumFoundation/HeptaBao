# Production AuthBus transport: concrete integration pending

This is a source-bound integration plan, not an installed plugin or a runtime
qualification. OAuth provider maintenance remains separate and precedes traffic
cutover. Current provider dispatches, production credential CAS operations and
production gateway changes remain zero.

## Exact source boundary

The actual installed plugin source captured in the current Mac binding is
`index.js`, 54,455 bytes, SHA-256
`b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b`,
immutable blob `ae64a01b8e47d60421a73050cb0425552ed18d13`. Its original binding
job is `1a1b1bb80dc-fc05-7a81`. It constructs the legacy `BaoClient` in both the
health-observation callback and the regular cycle. `normalizedConfig` currently
omits `productionTransport`. The service stop callback clears a timer without
waiting for its existing operation tail or revoking the bearer.

The repository supplies the following distinct implementation under
`tools/authbus/production-transport/plugin/`:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| production-client.js | 3,434 | 0dc35bf575c1933272a4c3351bb07d37358748d7add968d1c577755477a97ea2 |
| strict-bao-client.js | 26,161 | 3c226b335257ff67c4f6e23091468d99cba97399eea40b396bb89a8e691e5294 |
| bounded-outbox.js | 18,043 | 77c86c49fca655d1c60112ce36ac9c3ef154f620b3e917f42ffa412307de9fa1 |
| private-outbox-store.js | 8,660 | e948edb2d461eedabd03e0acd83cc8b998553516e01ad41c16641360221c145d |

The repository README explicitly requires plugin integration. The successful
isolated SDK r4 strict-wire exercise did not install these files into the
production plugin and did not qualify a production transport lifecycle.

## Minimal installed-plugin delta

1. Import `ProductionTransportClient` from a fixed local, source-pinned plugin
   directory and retain validated `productionTransport` in `normalizedConfig`.
   Production mode must fail if this configuration is missing or invalid; no
   fallback to the legacy HTTP client is permitted for the enrolled deployment.
2. Replace both legacy construction sites with one shared
   `new ProductionTransportClient(config, ctx.stateDir)` accessor. Bind its
   lifetime to that exact service context/state root. Do not open independent
   transport stores from event and periodic paths.
3. During start, serialize `reconcile()` through the existing operation lock
   before starting a cycle. Refuse an unresolved operation using the original
   persisted identity. A startup failure must not manufacture a new epoch,
   operation UUID or state directory.
4. Recheck `stopped` after acquiring the operation lock in both the event path
   and cycle. Work already queued before stop must not create a new request
   after shutdown admission closes. Keep the original lock release in `finally`.
5. Stop first blocks new work and clears the timer, then awaits the complete
   existing operation tail and invokes the shared client's `close()` once.
   Propagate unknown revoke/transport/close outcomes; a cleared timer is not
   proof of termination. After an awaited startup cycle, check `stopped` before
   scheduling a timer, so a concurrent stop cannot be undone by start.
6. Qualify these lifecycle differences with the actual loaded plugin: startup
   reconciliation, queued-event stop, in-flight cycle stop, successful renew,
   known revoke, and unresolved operation retention. Preserve original
   dispatcher, socket, SQLite handle and process closure evidence. This work
   occurs at cutover, after the refreshed local-SDK fallback is established.

The existing transport uses a 30-second whole-operation deadline and the strict
client's 15-second request deadline. It renews an active renewable bearer near
expiry. A known expired active bearer may authenticate again; an unresolved
persisted intent cannot be cleared to obtain another bearer.

## Permanent server policy and enrollment inputs

All paths below are relative to the `openclaw-auth` KV-v2 mount. Host, agent and
profile identifiers and deployment digests are bound privately. The permanent
endpoint, CA, certificate pin, AppRole files and topology are provided by the
new deployment plan; retired QA endpoints are not promoted to production.

| Resource | Producer access and purpose |
| --- | --- |
| transport-v1/control | Read the exact version-1 enrollment document, private control digest and canonical owner |
| manifest and the selected canonical profile documents | Read the nonempty owner-bound canonical credential set |
| order-policy and scheduler-assignments | Read the actual plugin's ordering and scheduling inputs |
| transport-v1/HOST/outbox/slot-NNN | Read and CAS-update only pre-enrolled slots for this host |
| transport-v1/HOST/ack/slot-NNN | Read coordinator acknowledgments for this host |
| transport-v1/HOST/reports/AGENT_HASH | Read and CAS-update only this host's pre-enrolled agent reports |

The enrolled fixed-slot schema is `heptabao-authbus-fixed-slots-v1`; production
must be true, the private epoch is a UUID, slots are 1–32 and enrolled agents
are 1–128. Control admission also requires a positive bootstrap profile count,
retained slot versions of two, and a canonical manifest of 1–64 profiles whose
coordinator owner matches control. Producer policy does not grant coordinator
acknowledgment writes. The legacy `inbox/HOST/EVENT` path is not used by this
transport and must not be substituted for the actual slot/report policy.

AppRole login, token lookup/renew/revoke and strict TLS behavior remain the
transport's real API operations and need matching least-privilege server
capabilities. No credential or private enrollment value belongs in this plan.

## Two additional local state databases

The implementation's actual namespace is
`ctx.stateDir/authbus/production-transport/`. It creates exactly
`state.sqlite` and `operation.sqlite`, plus their observed SQLite sidecars.
These two databases are a finite addition justified by the new installed
implementation; they do not expand migration scope to arbitrary historical
directories.

`state.sqlite` uses WAL and FULL synchronous commits. It persists deployment
binding, bearer state and operation/outbox intent before dispatch. Its main-file
limit is 64 MiB and it permits at most 168 records. `operation.sqlite` uses
DELETE/FULL with a 64 KiB limit; its original immediate transaction is the
cross-process lock held across awaited network I/O. A process crash releases
this lock without reverting previously committed state intents. The configured
2 MiB WAL journal limit is a target, not a strict total-directory size bound.

The first pre-install rollback inventory may prove this exact directory and
both databases absent. Once the transport has dispatched any request, or has
an unknown outcome, the original private state, operation/outbox ledger,
epoch, request identity, response and reconciliation evidence must be retained.
The six original application databases may not be restored in a way that
erases this network history. Never remove the new state directory, change its
binding or epoch, or start with a new key to replay the operation.

Consistent backup uses SQLite backup or a completely quiescent directory with
all actual WAL/SHM/journal files; copying only the main SQLite file is invalid.
Rollback can return consumers to the source-bound local SDK configuration with
the refreshed credential generation, while retaining and reconciling transport
history. It cannot restore old rotated OAuth refresh tokens. Unknown provider
or source-CAS outcomes keep the original writer disabled until the original
attempt is reconciled; they do not authorize even a local-SDK restart.

## Execution order and remaining implementation

The maintenance parent first binds the actual gateway, exact wrapper/environment
and all observed consumers, then disables and retires writers once. It captures
a new source generation after retirement. Three selected-owner OAuth operations
each retain one durable intent and original complete response before one
full-owner-preserving SDK CAS. Duplicate refresh credentials are rejected before
dispatch, not automatically fanned out. Unknown effects never advance the next
ordinal. New capture and private original-ledger readback follow each known
commit.

After all three provider/CAS results are known COMMITTED, take the full-state
rollback baseline using those refreshed credentials. Prove the safe fallback's
actual selector, disabled AuthBus registration, cold SDK consumption and service
restart. Only then initialize the permanent enrolled transport, qualify its
real lifecycle, and perform per-client cutover and rollback. The existing
isolated inverse and synthetic launchd primitives remain limited evidence and
cannot replace these production observations.
