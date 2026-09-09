# HeptaBao V2.5 execution status

## Candidate

The authoritative implementation candidate is the current exact head of
`codex/openbao-replacement-v2.4-authoritative-closure-20260909`, proposed to
`main` by draft pull request #81. A mutable branch name, predecessor commit,
prospective merge commit or historical green workflow is not current-head
evidence.

## Repository-side closure added in V2.5

V2.5 adds a complete repository-side external-evidence admission boundary:

- closed evidence and trust-store schemas;
- an externally pinned trust-store SHA-256;
- strict verification-only Ed25519 with RFC 8032 regression vectors;
- enrolled actor, role, key-validity and revocation checks;
- source-author, issuer, signer and control-root separation;
- exact repository, commit, tree and profile binding;
- exact gate-specific case denominators;
- bounded duplicate-rejecting JSON input;
- descriptor-stable, non-symlink, streaming artifact size and SHA-256
  verification;
- hostile tests for self-signing, forged signatures, unknown/revoked/stale keys,
  payload mutation, incomplete or expanded case sets, path escape, symlinks,
  duplicate JSON members and artifact tampering;
- a single complete entrypoint that returns
  `ADMISSIBLE_EVIDENCE_NOT_AUTHORITY` and never changes an authority flag.

The corresponding machine register is
`planning/HEPTABAO_EXTERNAL_EVIDENCE_ADMISSION_REGISTER_V2_5.yaml`.

## Required current-head repository gates

Every source update invalidates predecessor evidence and requires fresh:

```text
python scripts/validate_repository_v2.py
python scripts/validate_compatibility_corpus.py
python -m unittest discover -s tests/repository -p 'test_*.py'
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --workspace --all-targets --locked
cargo +1.98.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.98.0 doc --workspace --no-deps --locked
cargo +1.98.0 build --locked -p heptabao-server
```

The exact PR head and the prospective merge with current `main` must both pass.
Pending, absent, stale, cancelled or failed checks do not close a blocker.

## Repository-controlled product workstreams

The following product workstreams remain open unless the current exact source,
module guides and tests jointly prove them complete:

1. networked production Raft and `heptabao-server` cluster composition,
   including authenticated peer lifecycle, forwarding, linearizable reads,
   snapshot transfer, membership change, quorum loss, rolling upgrade and
   disaster recovery;
2. complete external authentication, identity aliases/groups and MFA execution
   for the admitted OpenBao replacement profile;
3. interruption-safe full-format migration and rollback across mounts, policy,
   auth, identity, tokens, leases, Transit, audit and seal/KMS metadata;
4. complete independently observed OpenBao API, error, client and side-effect
   compatibility fixtures for the closed surface inventory.

A contract, denominator, in-memory test or repository-authored fixture alone is
not completion of these workstreams.

## Control and external gates

All of the following remain open until a current-head evidence package is
admitted by the complete V2.5 entrypoint and then accepted by the separately
controlled governance process:

- `HB-BLK-CTRL-001`: live `main` ruleset and protection enforcement;
- `HB-BLK-EXT-001`: independent program, product-security and
  storage/distributed review;
- `HB-BLK-EXT-002`: legal and license disposition;
- `HB-BLK-EXT-003`: incident-response and 24x7 operations readiness;
- `HB-BLK-EXT-004`: production signer and KMS/HSM custody;
- `HB-BLK-EXT-005`: independently controlled OpenBao Oracle evidence;
- `HB-BLK-EXT-006`: destructive multi-platform qualification;
- `HB-BLK-EXT-007`: independent reproduction.

Repository administrator access cannot manufacture an independent actor,
production custody, destructive campaign or operational history.

## Authority state

```text
qualification=false
compatibility_claim=false
migration_authority=false
release_authority=false
production_authority=false
authority_effect=NONE
```

These flags may not change as a consequence of repository-authored code, local
tests, an administrator bypass or validator success alone.
