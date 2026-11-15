# heptabao-credential-broker

Status: `IMPLEMENTED_REVIEW_REQUIRED` / V3. This is a separately executed Unix
credential broker evaluated with synthetic credentials. It is outside the
`heptabao-server` runtime dependency closure and grants no production authority.
Shared rules are in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`;
the [module closure dossier](../module-closure/heptabao-credential-broker.md)
records the acceptance boundary.

## Purpose and non-goals

The library and CLI execute a narrowly authorized operation while keeping the
credential out of the task's result. The admitted adapters are numeric-loopback
HTTP and synthetic Ed25519 Git SSHSIG signing. Bootstrap requires
`synthetic_only: true`. General remote HTTP/HTTPS, DNS targets, SSH login, arbitrary
command execution and real-credential deployment are unsupported. This crate
does not implement a personal encrypted password vault or an OpenBao endpoint.

## Public API and ownership

`crates/heptabao-credential-broker/Cargo.toml` defines the library and executable;
`src/lib.rs` owns authorization, persistence, adapters and Unix socket framing,
while `src/main.rs` owns CLI parsing and exit status. The direct internal
dependency is `heptabao-filesystem-guard`.

The owner calls `initialize` with `Bootstrap`, then `issue` for one `Operation`
and `authorize_revocation` when needed. Tasks use `call` with a `Request`;
`Broker::open`, `Broker::handle` and `Broker::serve` enforce the policy and return
a `Receipt`. `Credential`, `SignedGrant`, `Grant` and `Revocation` are the public
data boundary. Grant issuance is an owner operation; the task-facing execute
path cannot select a new credential or expand an existing grant.

## State and data model

The private root contains `owner.key`, schema-1 `config.json`, schema-1
`state.json` and the broker socket. Configuration binds a random broker identity
to immutable credential policy. State retains the latest observed wall clock,
revoked grant IDs and operation receipts. `Operation` includes task/run IDs,
operation and credential IDs, target, method, path and canonical base64url body.
The request digest binds every field. Messages are bounded at 128 KiB, decoded
bodies at 32 KiB, state at 4 MiB and retained operations/revocations at 4096 each.

## Invariants and authorization

An HMAC-SHA256 grant binds broker identity, policy, task/run labels, operation ID,
the complete request digest and a lifetime of at most one hour. The broker checks
that binding, current policy, expiry and durable revocation before execute or
receipt lookup. Revocation has its own MAC domain. HTTP policy requires an exact
numeric loopback origin, method and ASCII path; redirects are never followed.
Git policy requires the exact `git:repository-id`, `SIGN`, `git` namespace and
payload. Task/run labels are assigned by the trusted owner; they are not
HeptaRuntime cryptographic task identity or proof of process isolation.

## Failure, retry and reconciliation

Before contacting an adapter, the broker durably records `outcome_unknown`.
After the bounded attempt it durably records a sanitized receipt before returning
it. A kill, timeout or missing acknowledgement therefore never authorizes an
automatic second dispatch. An exact repeated operation returns its retained
receipt; changed bytes under the same ID are rejected. An unknown result stays
unknown: external-effect reconciliation is not implemented by this candidate.
Storage failure fences the live broker; reopen and query under a still-valid
grant. A receipt with an observed HTTP status does not prove application success.

## Concurrency and ordering

`ExclusiveDirectory` allows one cooperating broker writer. The server handles
bounded local requests serially, and commits intent before adapter entry and the
result before reply. State capacity is an explicit refusal boundary, with no
receipt eviction that could re-enable an old operation. Persisted wall-clock
observations and the process monotonic clock reject detected regression; they
do not protect against rollback of the entire machine and its saved state.

## Security and privacy

The root is owner-private and credential/key files are private regular files;
descriptor-relative operations reject unsafe paths and competing writers.
The owner key and bootstrap credentials are local plaintext protected by the OS
account. A malicious process with the same UID can defeat that trust assumption;
this crate supplies no separate principal, hardware custody or signed runtime
attestation. Secret-bearing types redact debug output and clear owned buffers.
HTTP response headers, bodies and transport error strings are not returned.
Git results deliberately contain the public key and public signature.

## Persistence and compatibility

Configuration, state and grants use strict schema-1 structures; unrecognized
fields or schema values fail closed. Private temporary publication and directory
fsync establish the operation ledger boundary. The Unix protocol uses bounded
length-prefixed JSON. These formats belong to this candidate and have no declared
OpenBao compatibility or cross-version migration guarantee. Do not edit policy
files in place, roll the ledger back, or delete unknown-operation records to
force a replay.

## Observability

The CLI emits metadata, receipt classification and fixed error codes. `execute`
returns nonzero on denial, unknown outcome or an observed non-2xx HTTP status;
`status` can successfully return a found receipt whose outcome remains unknown
or failed. Callers must inspect the receipt fields. There is no metrics exporter
or centralized audit service in this crate, and logging request bodies, grants,
credential material or raw adapter responses is outside the supported contract.

## Operations

Build with `cargo +1.98.0 build --locked -p heptabao-credential-broker`. The CLI
provides `init`, `issue`, `serve`, `execute`, `status` and `revoke`; exact arguments
and private-file examples are in
`crates/heptabao-credential-broker/README.md`. Supply bootstrap secrets through
stdin and keep operation/grant files private outside the broker root.
`tools/heptabao_git_signer.py` is the separately reviewed Git adapter: it binds an
ordinary repository directory, Git directory identity, tree and payload before
using a preissued grant. Bare repositories, worktrees and an SSH-agent mode are
unsupported. A portable Git signature does not itself prevent cross-repository
copying of already signed content.

## Tests and executable evidence

Run `cargo +1.98.0 test --locked -p heptabao-credential-broker`. Integration tests
in `crates/heptabao-credential-broker/tests/process_e2e.rs` include
`real_process_api_echo_is_not_released_and_result_survives_restart`,
`wrong_target_body_task_signature_and_expired_grants_do_not_contact_target`,
`revocation_survives_process_restart`,
`killed_after_target_contact_remains_unknown_without_second_dispatch` and
`actual_git_commit_signing_and_verify_commit_bind_repository_and_payload`.
They exercise real local processes, denied contacts, restart and Git verification.
Current source presence is not a passing execution receipt. Retained evidence in
`qa/personal_credentials/evidence/20261106/manifest.json` keeps its original
commit/tree, binary, host and harness binding; a later candidate must obtain its
own applicable execution evidence.

## Evolution and open boundaries

Real runtime identity requires a trusted issuer and an isolated execution/peer
boundary that the task cannot impersonate. General outbound adapters need a
separate destination, TLS, response-release and side-effect recovery design.
Independent security review, upgrade/rollback qualification, long-running
operations and real-credential adoption remain open. Registering this module
does not qualify P0 server scope, P1 same-UID isolation or P5 production use.
