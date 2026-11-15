# HeptaRuntime task identity boundary review

Read-only review on 2026-11-06. No runtime, host policy, permissions, credentials,
services or production workloads were changed. This is a contract/source review,
not a deployed workload-identity qualification.

## Conclusion

The current broker's task/run values remain trusted-owner labels. The available
ordinary process API provides durable request and lifecycle correlation, but no
independently verifiable per-task grant or signature. Current same-UID isolation
therefore remains HOLD.

An existing isolated Linux jobctl implementation provides a possible OS trust
foundation. It is a different execution mode from all seven configured aliases
observed through the current connector. Merely importing the native runtime
library, copying a job ID, setting an environment variable, or forwarding tool
JSON does not establish the missing identity boundary.

## Current connector observations

`host_list` and the allowlisted `effective_config` projection reported the aliases
`ai395`, `desktop`, `mac`, `main`, `pocket4`, `rog` and `x230` with
`execution_mode=operator`. Each allows process execution, PTY, writes, job network
and detached fallback; the configured named-privileged-action count is zero.
The capability projection explicitly does not verify reachability, existing sudo
authority, particular argument authorization or a deployed binary identity.

`process_start` accepts host, executable, argv, cwd, caller-supplied environment,
stdin, a stable idempotency key and optional resource/time limits. It exposes no
per-task principal, dedicated workload UID, attestation audience, proof-of-
possession or signed-identity input/output contract.

The original start receipt of this review's earlier edge build contains a
runtime-generated job ID and a 64-character request digest. The ordinary status
of the completed P0 job `1a1af7e887f-fc05-6908` returns a job ID, launch nonce,
terminal-publication flags and exit status. Neither returned receipt contains a
signature, issuer key identifier, audience or independent verification evidence.
These values are useful reconciliation data; their presence is not a task
authentication credential.

Current `request_status`, `operation_status` and search tool descriptions
explicitly scope ownership to a verified private HTTP operator credential, whose
holders share that scope, or to a native stdio session. They explicitly do not
claim authenticated ChatGPT caller isolation. Process and PTY ownership retain
the trusted operator-account scope.

### Follow-up check of exposed tool contracts

A later read-only check of the exposed tool descriptions found
`execution_shadow_admit`. It validates and hashes a canonical execution intent,
but requires `final_use.state = not_granted` and explicitly does not start a
process, grant FinalUse or acknowledge an effect. Its caller-supplied
`principal`, `run_id` and `generation` fields are not an authenticated task
identity or a broker-verifiable attestation.

The rechecked `process_start` input still has no task-attestation, audience or
proof-of-possession field. `privileged_action` can restrict execution to an
administrator-configured symbolic action; that action boundary does not prove
the identity of a calling workload.

This follow-up did not invoke those tools or reread host configuration. The
actual operator-mode observations above remain the deployment evidence. The
isolated Linux source route below still lacks qualification of a corresponding
deployed binary, policy and broker-facing workload-identity verification path.

## Source reviewed and deployment boundary

The repository's default branch was observed at
`ba574f2a6a1b74e85191c58d7bec011720736bb9`; its older runtime source lacks several
current nonce/digest mechanisms. The relevant public native convergence branch
was separately pinned to:

```text
commit e1eb14ae8eff2fc2c3565a86a36b10dd44eac915
tree   3235972cb67030b2750f0d5558dd3e578cd93a41
branch work/native-runtime-convergence-20261030
```

That source commit was published 2026-11-03. No evidence obtained in this review
binds the currently installed connector binary to that commit. The source
findings below describe the pinned candidate and must not be relabeled as a
deployed exact-binary result.

## What the identity signals establish

| Signal | Established meaning in the reviewed contract | Insufficient for |
| --- | --- | --- |
| `job_id` | Controller-generated durable job reference, bound to a configured host and persisted request | Authenticating a calling workload or model task |
| `request_digest` | Full SHA-256 of typed process request fields, used for exact idempotency/reconciliation | A keyed signature, issuer assertion, or peer identity |
| `launch_nonce` | Target CSPRNG nonce correlated with original owner and terminal records | A secret bearer credential or a task attestation |
| `HEPTA_RUNTIME_JOB_ID` | Child environment field set by the supervisor after applying caller environment | A value other same-UID processes cannot imitate |
| PID/start identity | Original-process lifetime checks; pidfd is used where supported for some operations | Authorization from a PID supplied by a caller; isolation from the same OS account |
| User-systemd unit / `INVOCATION_ID` | Operator job lifecycle association | Isolation from a user who owns that user manager |
| Verified HTTP credential scope | Non-serialized middleware-injected owner scope after token verification | Distinguishing holders of the same token, ChatGPT users, conversations, or tasks |
| Operation AEAD/HMAC | Authenticated encryption and binding of retained SDK result bytes | A portable workload-identity certificate |

`src/mcp/runtime/jobs.rs` hashes the complete process payload with SHA-256,
including executable, args, host, cwd, env, stdin and limits. It generates the
remote launch nonce with `os.urandom(16)`, correlates supervisor UID/PID/start
identity and systemd invocation information, and checks terminal publication
witnesses. The reviewed jobs source has no task-signature or workload-attestation
verification path. Terminal witnesses are persistence/lifecycle evidence, not
cryptographic proof to an unrelated credential broker.

`caller_scope.rs` derives an opaque owner from an already verified HTTP token and
refuses requests lacking its trusted typed middleware extension. The owner is
not supplied by tool parameters or `_meta`. `operation_crypto.rs` derives
domain-separated result keys from that same verified credential (or ephemeral
stdio keys); its own contract says it does not authenticate credentials,
dispatch operations or grant replay permits. The cryptography does not create
per-task identity simply because the result object contains a task-like label.

## Existing isolated Linux foundation

The pinned source also has `src/bin/jobctl.rs`, a root-owned closed helper for
isolated Linux mode. It validates a root-owned policy and starts a system
systemd unit using a distinct DynamicUser. Its root-owned Record binds job ID,
full request digest, boot ID, random nonce, unit and invocation ID. The unit hides
runtime state and homes, protects control groups, removes capabilities and
applies configured resource/network restrictions.

This is a usable design foundation for separating workloads from broker keys.
It is not activated by the current operator aliases. The current exposed
ordinary API also lacks a broker-facing operation that proves a connected
socket peer belongs to one authorized root-owned job record. A root-owned
record is trustworthy only when a verifier actually reads it through a trusted
OS/channel boundary; a model-forwarded JSON copy does not preserve that trust.

The native facade documentation likewise states that its embedding host must
retain the original run, turn, generation, operation key and canonical payload
binding admitted by its existing owner. The embedding owner performs host,
executable and policy authorization before invoking the runtime. Model JSON
grants none of that authority. One process shares one runtime configuration and
state root; importing the library does not create per-cell isolation.

## Smallest useful next step and external dependencies

Without changing runtime deployment, the safe incremental improvement is an
audit association: the trusted embedding owner records the actual returned
`(host, job_id, request_digest)` alongside the broker operation and its existing
task/run labels. It must obtain those fields directly from its trusted native
call, not from agent-provided environment/JSON. This improves provenance while
retaining the explicit same-UID and workload-attestation HOLD.

To authorize an isolated workload rather than a trusted account, the missing
dependencies are:

1. A separately protected broker/issuer OS identity and key store, unreachable
   by the workload's filesystem, process inspection or mutation rights.
2. A reviewed and qualified deployment of the isolated Linux jobctl path, or
   another equivalent workload isolation boundary. No existing operator alias
   should silently change authority.
3. A broker-facing identity binding from the trusted owner: for example a local
   peer verified through kernel socket credentials plus a race-resistant
   PID/start/boot/system-unit/invocation mapping; or a short-lived issuer-signed
   capability with broker audience, canonical request digest, job nonce,
   generation, expiration and an isolated channel/proof-of-possession binding.
4. Explicit revocation, restart, unknown-result and unsupported-platform rules.

A signed bearer stored where an adversarial same-UID process can copy it does
not resolve the isolation problem. Cgroup names or environment variables supplied
by that process are also insufficient. The complete candidate needs negative
acceptance for another job, self-filled environment labels, PID/unit reuse,
wrong audience, expiration/revocation, restart, cancellation and replay. An
unsupported operator combination should be reported as unsupported, not counted
as a passed workload-identity case.

## Primary sources

- [Native library trust boundary](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/docs/NATIVE_LIBRARY_BOUNDARY.md)
- [Operator mode](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/docs/OPERATOR_MODE.md)
- [Runtime architecture and explicit attestation limits](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/docs/HEPTA_RUNTIME.md)
- [Durable jobs and request/launch bindings](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/src/mcp/runtime/jobs.rs)
- [Credential-authenticated metadata scope](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/src/mcp/runtime/caller_scope.rs)
- [Result encryption and HMAC boundary](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/src/mcp/runtime/operation_crypto.rs)
- [Root-owned isolated job helper](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/src/bin/jobctl.rs)
- [Credential-scope candidate limitations](https://github.com/TrillionniumFoundation/hepta-runtime/blob/e1eb14ae8eff2fc2c3565a86a36b10dd44eac915/docs/DC_FUNCTIONAL_V7_CREDENTIAL_SCOPE_CANDIDATE.md)
