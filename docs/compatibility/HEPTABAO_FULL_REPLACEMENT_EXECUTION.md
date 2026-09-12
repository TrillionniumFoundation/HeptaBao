# Full OpenBao replacement execution

This execution supplement belongs to `HEPTABAO-PLAN-2026-09-07-V2.1`, especially G3 and G4. It is not a competing master plan, a new current-source selector, or a completion receipt. The implementation tracker is issue #90; independent evidence remains a separate obligation, including the applicable lanes in #82.

## Target and scope

The owner requested full replacement on 2026-09-12. The comparison baseline is stable OpenBao 2.6.2. Do not silently mix a prerelease or change the denominator to fit implemented features. The starting inventory is `oracle/inventory/openbao-v2.6.2/surface-catalog.yaml`, bound by `qa/openbao-acceptance/complete_surface_corpus_v1.json`. Every inventory surface remains in scope, including external authentication and secret providers, client tools, storage, operations, migration and security. A missing provider must remain an open implementation/qualification item, not an omitted test.

Full replacement requires both behavior and operational interchangeability under an explicitly qualified profile. Similar endpoint names, the same ciphertext prefix, independently tested domain models and successful KV transfer do not establish this. HeptaBao must not delegate protected operations to an OpenBao process and call that an independent replacement.

## Ordered implementation tracks

1. Client execution: turn retry/CLI/agent/proxy contracts into usable bounded transports and executables, with verified TLS, explicit credentials, secret-safe diagnostics, cancellation and no automatic replay after an uncertain operation.
2. Core isolation: integrate identity, policy priority/constraints, token administration, cubbyhole/wrapping and general lease lifecycle into the actual Service transaction boundary.
3. Provider surface: complete authentication methods, KV/Transit formats, PKI/SSH/database/cloud and all other registered engines; connect real plugin and custody providers without weakening admission or audit.
4. Capacity and recovery: replace development-scale bottlenecks through measured storage and concurrency design; verify cross-host consensus, membership, snapshot installation, upgrades, power/disk/network failures and recovery objectives.
5. Cutover and interoperability: preserve or explicitly transform every relevant data format, rehearse writer fencing and rollback, and execute unchanged-candidate differential and application-level compatibility tests.

These tracks can be developed in parallel only with explicit ownership of shared files and state. The current runtime ownership map remains authoritative; independent crates cannot claim server integration merely because their names match a feature.

## Required evidence per increment

Each change must include implementation, current caller/route binding, module-specific technical and operational documentation, positive and hostile tests, and the current source inventory update when Rust or a module guide changes. Keep existing historical evidence unchanged. Record tests that were executed separately from tests merely added to source.

Required regression classes include malformed and oversized input, duplicate keys/headers, cross-namespace and cross-token access, stale/revoked authority, partial writes and response loss, crash/reopen, contention, deadline/capacity exhaustion and redaction. A request which may have reached the server must not be blindly replayed, including a nominally read-only request that can consume a finite-use token or dynamic credential.

Use the existing exact-head and prospective-main-merge workflows, formatting, strict lint, repository validation and Rust tests. No new materializer, workflow source mutation, reduced denominator, waived negative test, disabled certificate verification or invented external signature is part of this execution.

## Completion accounting

Maintain distinct facts for source existence, runtime integration, fixture coverage, actual execution, current CI and independent qualification. The number of crates and the fraction of documented modules are not product completion percentages. A local TLS fixture proves the tested transport boundary, not complete OpenBao compatibility. Independent tests must use a pinned official reference and the exact candidate, and record both protocol output and state side effects.

Implementation may proceed without production enrollment. Real secrets, infrastructure cutover, final license selection and release remain outside ordinary development. Until all applicable gates actually pass, retain `qualification=false`, `compatibility_claim=false`, `production_authority=false`, `migration_authority=false` and `release_authority=false`.
