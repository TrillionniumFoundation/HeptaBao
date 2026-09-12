# OpenBao Replacement Implementation Progress — 2026-09-12

Status: implementation in progress; **not a production-complete or compatibility-complete claim**.

## Verified baseline

Branch `codex/openbao-complete-replacement-20260912` established a clean implementation baseline at `2ade28ea8af7ffe5c4583238dffbe76efa3dc71d`. The repository's full qualification workflow passed both exact-head and prospective-`main` tracks, including repository-truth validation, compatibility-corpus validation, locked workspace tests, rustfmt, strict Clippy, docs, real TLS service exercise, real three-process HA, encrypted-link network-partition exercise, and source immutability.

## Identity implementation added after the baseline

The authoritative encrypted namespace state now owns durable Identity entity, entity-alias, internal/external group, nested-group cycle control, group-alias and lookup state. The OpenBao-facing semantics were subsequently aligned for entity/group lookup selectors, `custom_metadata`, alias cardinality per auth mount accessor, inherited/direct group reporting, and RFC3339 timestamps.

The H09-WP05 structural merge/dedupe/lineage tranche is implemented at `3f4bf6e94f133f97f84fa3b44e52e5fc3f78ba75`: `/identity/entity/merge` validates source/destination entities, moves aliases, requires explicit resolution of same-mount alias conflicts, rewrites group membership, records merged-entity lineage, and commits atomically from a candidate state. A targeted Rust 1.98 gate passed repository truth, the compatibility-corpus validator, `heptabao-server` tests, rustfmt and strict Clippy before that commit was pushed.

`force` is currently type-validated by the merge endpoint but does **not** constitute completed OpenBao MFA-secret merge semantics; Identity-scoped MFA secrets have not yet been integrated into the merge model. This remains an explicit gap rather than a compatibility claim.

## Remaining fail-closed scope

The broad Identity surface is not marked complete until its remaining OpenBao behavior is executable, including identity-to-auth policy projection, login alias/entity binding, MFA framework integration, OIDC provider/JWKS/rotation and HA invalidation evidence. The exact-denominator compatibility corpus remains authoritative; statuses must advance only when corresponding behavior and executable fixtures exist.

Repository-controlled OpenBao replacement work also remains outside Identity, including remaining dynamic-secret/lease behavior, CLI/Agent/Proxy behavior, migration/rotation paths, and the remaining Raft administrative/upgrade/snapshot/platform evidence required by the active development plan.

External legal review, independent security review, HSM-backed exercises, destructive platform validation and independent OpenBao-Oracle observation remain external completion gates. This branch must not self-attest those gates.