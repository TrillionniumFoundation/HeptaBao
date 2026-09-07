## Exact source and package ownership

- Base ref / commit / tree:
- Head ref / commit / tree:
- Program Gate / Work Package IDs:
- Blocker IDs closed or advanced:
- Compatibility Profile impact:
- Durable domain / authoritative writer:
- Oracle baseline and fixture refs:

## Scope

- In scope:
- Explicit non-scope:
- Downstream consumers:
- Base-drift disposition:

## Security and correctness

- Threat-model delta:
- Security invariants affected:
- External effects and response-unknown policy:
- Audit / commit / effect happens-before:
- Persist / publish / acknowledge boundary:
- Secret-bearing types and redaction:
- `unsafe` introduced or changed: `NO` / registry reference

## Evidence

- [ ] Exact source, clean tree, toolchain, target and lock digest bound
- [ ] Requirement and invariant links added
- [ ] Positive tests
- [ ] Negative/adversarial tests
- [ ] Crash/fault/recovery tests where applicable
- [ ] Oracle differential or explicit deviation
- [ ] Dependency/SBOM/unsafe/native/build-script delta
- [ ] Migration/rollback/supersession note
- [ ] V1.2 semantic validator
- [ ] Rust fmt/test/clippy
- [ ] Failed and blocked executions retained
- [ ] Canonical resolved-state artifact emitted

Execution maturity before this PR:

Execution maturity after exact-head evidence:

Unexecuted / external evidence:

## Authority declaration

- [ ] This PR may integrate unqualified code but does not grant qualification, compatibility, dependency selection, production, migration, release or mixed-cluster authority.
- [ ] Qualification and compatibility objects have `authority_effect: NONE`.
- [ ] All operational authority flags remain false unless a separate verified, scoped, expiring and revocable grant is referenced.
- [ ] No real secret, root token, unseal share, private key or production snapshot is included.

Qualification receipt: `NONE` / reference
Compatibility claim: `NONE` / reference
Prototype selection receipt: `NONE` / reference
Authority grant: `NONE` / reference
Revocation: `NONE` / reference

## Review separation

Author identities:

Required accountable roles:

- [ ] Program
- [ ] Security
- [ ] Domain
- [ ] Compatibility / legal / crypto / distributed / storage / migration / release specialist when applicable

Conflicts of interest and delegation limits:

Known blockers or `EXTERNAL_ACTION_REQUIRED` items:
