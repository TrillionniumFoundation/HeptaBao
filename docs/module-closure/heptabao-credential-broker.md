# heptabao-credential-broker module closure dossier

This record binds the module's design and acceptance scope to the exact Git
commit and `crates/heptabao-credential-broker/src` tree inspected by the closure
validator. It grants no compatibility, production, migration or release authority.

## Design and state ownership

The source owner is `crates/heptabao-credential-broker`. `src/lib.rs` implements
the owner-key/configuration boundary, HMAC grants, revocation, operation ledger,
numeric-loopback HTTP and Git SSHSIG adapters; `src/main.rs` implements the CLI.
Its only direct internal dependency is `heptabao-filesystem-guard`. The package
is outside the `heptabao-server` runtime closure. `Broker` owns one exclusive
writer, persisted receipts and clock observations; tasks supply an `Operation`
and owner-issued `SignedGrant` through the bounded Unix protocol.

## Module boundaries and trust assumptions

Bootstrap explicitly requires synthetic credentials. The owner account and its
private files are trusted: `owner.key` and credential configuration are not an
encrypted personal vault, and same-UID code is not isolated. Task/run labels
are owner assertions, not attested HeptaRuntime identities. HTTP is limited to
an exact numeric loopback target/method/path, and Git signs exact authorized
payloads in the `git` SSHSIG namespace. Server routes, remote TLS adapters,
SSH login and production credentials are outside this module's admitted scope.

## Failure semantics and ordering

Authorization and capacity checks precede durable `outcome_unknown` publication;
only then may an adapter be contacted. A bounded adapter result is sanitized
and durably recorded before reply. Same-ID exact retries return the retained
receipt, changed requests are refused, and an unknown effect is never
automatically redispatched. Storage uncertainty fences the process. Reopen
and query preserve uncertainty rather than manufacturing a successful outcome.
Revocation/expiry also gate receipt lookup; capacity does not evict old operations.

## Acceptance evidence

No in-crate test function was discovered under `src/`; executable integration
tests are in `crates/heptabao-credential-broker/tests/process_e2e.rs`. This is a
source-layout distinction, not an assertion that the package lacks tests.
`real_process_api_echo_is_not_released_and_result_survives_restart` tests actual
process execution and redacted receipt recovery;
`killed_after_target_contact_remains_unknown_without_second_dispatch` tests a
real process kill after external entry; the same file tests exact-target denials,
revocation, CLI exit status and actual Git commit/signature verification.

Required execution: `cargo +1.98.0 test --locked -p heptabao-credential-broker`.
Required documentation checks: `python scripts/validate_module_closure.py` and
`python scripts/validate_current_documentation_semantics.py`.
Retained public receipts are indexed by
`qa/personal_credentials/evidence/20261106/manifest.json`, with their own source,
binary and harness identity. They are not promoted to a different commit by
this dossier. Current candidate acceptance requires matching execution evidence.

## Known gaps and evolution

Same-UID isolation, trusted runtime task identity, general outbound credentials,
authoritative resolution of unknown external effects, upgrade/rollback safety,
independent security review and long-running production operation remain open.
The implementation state is `IMPLEMENTED_REVIEW_REQUIRED`. Read the matching
[module guide](../modules/heptabao-credential-broker.md) before changing grant
fields, storage ordering or adding an adapter.
