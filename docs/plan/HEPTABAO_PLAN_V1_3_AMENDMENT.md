# HeptaBao Plan V1.3 Amendment

## Amendment scope

This amendment supersedes the V1.2.2 local-unified closure as the current repository-development input while preserving every V1.2 and V1.2.1 authority restriction.

## Decisions

1. Start the first bounded server vertical slice rather than expanding only governance and dependency probes.
2. Keep P0 loopback-only, in-memory and explicitly non-production.
3. Split protocol parsing and operation classification into a provider-neutral crate.
4. Treat Authbus as authentication input only; policy, token, lease and authorization state remain HeptaBao-owned.
5. Use Unix seconds for cross-process assertion validity and monotonic time only inside a process.
6. Disable automatic snapshots only in the in-memory replay probe whose purpose requires retained logs; preserve explicit snapshot tests elsewhere.
7. Discover a post-resume consensus leader rather than requiring leader identity stability.
8. Reconcile the reported local Oracle vectors without claiming repository transfer or qualification.
9. Add four repository-controlled blockers for the newly discovered H02/P0/Authbus gaps; retain all eight external blockers.
10. Keep CI read-only and exact-head bound.

## Explicit non-decisions

- no OpenRaft, runtime, TLS, crypto, storage or database candidate is selected;
- no Authbus signing format or trust root is selected for production;
- no P0 behavior is represented as OpenBao compatibility;
- no legal, security, reviewer, signer, Oracle or storage-lab evidence is fabricated;
- no authority grant is issued.
