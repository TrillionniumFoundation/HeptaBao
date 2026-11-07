# Synthetic credential operations and recovery

This procedure applies to the preview scopes in [STATUS.md](STATUS.md). It is
an implementation and evidence handoff, not authorization for production
credentials. Operator trust, unsupported targets and the runtime identity gap
are documented in the individual components.

## Prepare a bounded installation

1. Select the exact source revision, compiler, lockfile and platform combination.
   Build in a new private directory, record the full build command/environment
   and freeze copies of the resulting executables. A source checkout beside an
   existing executable is not proof that it produced that executable.
2. Create separate owner-private directories for vault, recovery documents,
   broker state, request files and ciphertext store. Use local filesystems with
   the required ownership, mode, locking and durability semantics. The Rust
   adapters refuse unsafe symlinks, hard links and public secret files.
3. Bootstrap only synthetic accounts. Supply secrets by bounded stdin from a
   trusted local caller or private file. Do not put them in model requests,
   argv, environment variables, repository content or logs.
4. For Chromium, install the exact extension ID and native manifest in a
   dedicated browser profile. Verify the native executable/configuration hashes.
   Confirm that the extension has only `activeTab`, `scripting` and
   `nativeMessaging`; unrelated profiles are outside this installation.
5. Run the scope's positive control, rejection, expiry, lock/revoke, independent
   restart and recovery cases. Retain original failures and count missing cases.

The physical Android qualification driver enters newly generated synthetic
passwords through the real password field. Its innermost `adb input text`
process temporarily has that synthetic value in argv. The driver retains the
value privately and excludes it from public receipts, but this test is not
evidence of an end-to-end argv-free secret path. It is not an installation or
input procedure for real credentials. The provider has no password-bearing
Intent, debug endpoint or QA-file input bypass.

The untrusted-agent boundary requires a different OS principal or equivalent
independently enforced protection. Current owner-level HeptaRuntime job labels
and environment variables do not provide it. A bearer grant cannot compensate
for an agent that can directly read the broker's owner key.

## Interpret a credential-use result

The broker durably records an operation before issuing its external effect.
`outcome_unknown` means the effect may have happened and no completed receipt
has been durably acknowledged. Do not issue the same effect under a fresh
operation ID to make an error disappear. Exact retries query/reconcile the
original operation without redispatch; external reconciliation remains an
owner task in the current preview.

`execute` returns nonzero for a denial, unknown outcome or non-2xx API response.
`status` can return zero while describing a failed or unknown operation because
the authorized status lookup succeeded. Inspect the receipt fields. A recorded
HTTP 2xx is evidence of the observed response status, not independent proof of
the target application's business operation.

Revoked or expired grants cannot execute or read old receipts. An independent
owner recovery/read path for such receipts is not implemented. Retain the
original private ledger and investigate under owner control; do not extend a
grant or discard ledger entries as an automatic recovery action.

## Recover a personal vault or a lost device

An encrypted `vault.hbv` backup and an independent unlocking secret are both
needed. Keep the recovery document out of the ciphertext synchronization store.
The password and recovery key are independent ways to unwrap the same data
key; an encrypted backup alone cannot restore access.

On a replacement device, create a new private vault root and supply `restore`
with the backup path plus either the password or recovery key over stdin. The
destination must not already contain a vault. Validate identity, revision,
item count and an explicit synthetic control before directing any client to it.
The original device and backup remain intact while this check runs.

If both unlocking secrets are lost, this implementation has no recovery path.
A password change preserves the recovery wrapper and does not revoke old
backup copies. Remote deletion of a lost device's already released plaintext,
hardware-bound keys and device revocation are unsupported.

For an interrupted mutation, reopen and inspect the current authenticated
revision before preparing another change. A publication error may have occurred
after the filesystem committed it. New mutations need the current revision;
never assume a nonzero exit means the previous write did not happen.

## Preserve offline conflicts

Treat the publication's `head_id`, operation ID and ciphertext digest as
separate values. The head identity advances even when identical ciphertext is
published again. Retain a local authenticated copy of the last accepted head;
the server cannot detect an attacker replaying an entire old server snapshot
without a trusted client frontier.

When a stale head is refused, retain both the local edit and the remote head.
Fetch and decrypt the competing version into a separate root, compare locally,
and explicitly choose or combine entries under owner control. Publish a new
operation against the observed current head only after that decision. The CLI
never silently drops a conflict or performs field-level automatic merging.

The physical two-device observation used an authenticated HeptaRuntime transport
and a store on the same trusted OS account as device A. Its temporary RSA
enrollment capsule was a synthetic test transport, not a production device
pairing protocol. Do not deploy the store as an unauthenticated network endpoint.

## Stage an upgrade and retain rollback evidence

1. Stop accepting new credential operations and lock clients. Reconcile or
   explicitly retain every unknown broker operation; inspect active owned
   processes through their original runtime handles.
2. Create encrypted backups and record source, artifact, format, vault revision
   and ciphertext digest. Record the extension/native manifest configuration.
   Keep recovery material separate from all public evidence.
3. Build the candidate in a new path. Restore a backup into a new private root
   and run the supported scope there before switching clients. Do not mutate
   the only working copy to test a migration.
4. Change a single configured client/provider only if its currently observed
   value matches the expected prior value. Retain the prior path/configuration
   and a private restoration record. Compare again before any rollback so an
   unrelated concurrent user change is preserved.
5. Before rolling back executable/configuration paths, clone the current state
   into a new private root and exercise the prior executable there. Verify
   reading and writing, authorization denials and revocation, and preservation
   of revisions, operation receipts and passkey counters wherever applicable.
   Being able to parse the current format is insufficient. Refuse rollback on
   any incompatible behavior and retain the newer state. Do not overwrite
   newer ciphertext with an older backup: that can discard valid writes.
   Restore old state into another root and explicitly reconcile it if needed.

The separately frozen format-1 broker pair completed 27/27 real upgrade and
rollback checks, including a SIGKILL after target contact, preservation of
unknown results and exact expiry/revocation/target denials. The
[original receipt](../../qa/personal_credentials/evidence/20261106/broker-upgrade-r1.public.json)
and [complete original packet](../../qa/personal_credentials/evidence/20261106/broker-upgrade-r1-remote-originals.tar.gz)
bind that result to the two tested executables and the trusted-owner loopback
scope. It does not qualify a client/provider switch or a different version pair.

The procedure above remains required for each proposed installation. Cross-version
format migration, signed release distribution and automated rollback are not yet
qualified. A format compatibility failure must stop the switch and retain both
candidates.

## Incident handling and support boundary

Lock clients, stop new issuance and revoke the affected grant when possible.
Record only bounded status codes, original job identities, hashes, versions and
timing in a public incident report. Preserve raw diagnostics privately; do not
paste request bodies, decrypted entries, native messages or UI input values.
Check the upstream application's own audit trail before repeating an uncertain
effect. Rotating an upstream secret is an owner decision because it can affect
other consumers.

Before expanding real adoption, the release needs an independent security
review, a deployed task-identity isolation boundary, supported-platform
compatibility receipts, upgrade/rollback evidence for the exact proposed
artifact pair and state format, sustained stability observations and named
operational ownership. Internal parallel
review and finite synthetic tests do not satisfy independent external review
or long-term operational evidence.

The recorded thirty-minute broker trial completed sixty planned cycles,
including duplicate-result retrieval, actual expiry/revocation refusals and
six graceful restarts followed by complete result recovery. Its
[original evidence](../../qa/personal_credentials/evidence/20261106/broker-stability-30m-public-evidence.tar.gz)
qualifies that frozen synthetic exercise only. It supplies no production
availability objective, workload capacity, arbitrary-version upgrade guarantee
or independent security approval. Continue to preserve unknown outcomes and
reconcile the target before considering any repeated effect.
