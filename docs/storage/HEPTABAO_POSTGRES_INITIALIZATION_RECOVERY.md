# PostgreSQL initialization crash recovery

The server prepares a recoverable local candidate before it writes PostgreSQL.
`Service::initialize_with_postgres_import`, `load_postgres_pending`, and
`finish_postgres_initialization` own this protocol. It is a scoped development
implementation, not full OpenBao compatibility or production qualification.

## Failure removed

The first server integration committed PostgreSQL artifacts before publishing
local seal metadata. An error or process crash could discard the generated
key material while leaving an occupied remote scope. Reinitializing with new
keys could not recover that scope. The current protocol preserves the same
candidate and generated identity across retries.

## Initialization and retry

1. PostgreSQL initialization requires a client-generated 32-byte
   `recovery_nonce`. The server accepts canonical lowercase hex or base64.
   The nonce is never persisted. This extra parameter is an explicit OpenBao
   API compatibility limitation until an equivalent compatible delivery path
   exists. The client must retain it until initialization is acknowledged.
2. Hold the descriptor-bound parent directory fence. Build the complete
   bootstrap state through FileBackend in a private random stage, together
   with seal metadata, the PostgreSQL profile, and the nonce-encrypted response
   containing the generated shares and root token. No remote write occurs yet.
3. Authenticate the intended final path, seal/profile, all three sealed
   artifacts and encrypted response with a separate nonce-keyed AEAD binding.
   Sync the files and directory, rename the stage to a deterministic sibling
   `.heptabao-pg-init-<digest>`, then sync its parent. The digest binds the
   final absolute path. After this rename, errors must retain the candidate.
4. Reopen that candidate under its FileBackend writer fence and authenticate
   the nonce binding. Require matching shares/threshold and the exact
   configured PostgreSQL profile. Resync the parent before remote import.
   Wrong nonce, configuration drift, relocated or altered artifacts fail
   before any remote effect. Pending initialization fences unseal and HA.
5. Acquire the PostgreSQL scope fence and call `initialize_or_match` with the
   complete sealed bundle. A genuinely empty scope is initialized in one
   transaction; an identical bundle succeeds without rewriting; any different
   bundle or orphan chunks are preserved and rejected. Unknown commit outcomes
   retain the local candidate. Retry uses a new connection and compares bytes
   under a fresh writer fence, never a poisoned session.
6. Prepare and publish a separate metadata-only final directory containing
   seal/profile and the nonce-encrypted response. Hold both the local and
   remote fences through publication and parent sync. The final directory
   contains no local snapshot, journal or ledger that could become a fallback.
7. Once final publication is durable, atomically rename pending state to a
   random retired sibling and sync the parent before recursive cleanup.
   Interrupted cleanup may leave sealed retired files, but cannot strand an
   incomplete active pending directory. Returning generated keys requires
   confirmed publication. A retry after final publication authenticates the
   final and pending identities before retiring any leftover candidate.

The authenticated `sys/init/ack` request removes the encrypted response after
the client has received its key material. Pending initialization must be
resolved first. A later PostgreSQL unseal always requires the matching trusted
process configuration; missing configuration cannot activate FileBackend.

## Backend reconciliation

`initialize_empty` rejects an existing manifest. In the same repeatable-read
transaction it also verifies that no chunks exist for the scope before
inserting the first manifest. Orphan chunks produce `Corrupt` and are
preserved. `initialize_or_match` accepts an existing byte-identical bundle;
a different bundle returns `RootNotEmpty`. Server recovery authenticates the
prepared bundle; the backend itself compares opaque sealed bytes.

## Verification and limits

Focused server tests cover pending creation, restart with the same nonce,
wrong nonce/parameters/target, modified and relocated artifacts, simulated
lost commit acknowledgement, conflicting remote state, audit/publication
failures, local/parent writer fences, final-plus-pending recovery, and
interrupted retired cleanup. These injected tests are distinct from real
process and database observations.

`postgres_durable_live.py` exercises a fresh PostgreSQL 17 instance, exact-bundle
retry through a new session, conflicting/orphan-state preservation, schema
validation, writer fencing and a real discarded COMMIT acknowledgement.
`postgres_service_live.py` exercises the HTTPS binary with database-unavailable
initialization, process restart, nonce recovery, KV persistence, second-writer
refusal and missing-config refusal. Its additional COMMIT-reply-loss scenario
compares the exact remote bundle after a service restart.

Receipts must state the source and binary actually exercised. None of these
profiles prove arbitrary machine power-loss, replicated PostgreSQL failover,
full OpenBao migration or independent production acceptance. Destroying both
local seal metadata and its backup is outside interrupted-initialization
recovery; PostgreSQL ciphertext alone cannot reconstruct the seal key.
