# heptabao-policy

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns deterministic path-capability policy evaluation. It does not authenticate callers, expand identities, store policies durably or implement deny overrides, templating or Sentinel-style evaluation.

## Public API and ownership

`PolicyStore` owns policy objects keyed by `Id`. `PolicyRule` owns a canonical path prefix and capability set. Callers supply the effective policy identifiers after identity and token expansion.

## State and data model

Policies are immutable after insertion in the current candidate. The store supports insert, get and remove. Rules match canonical paths only at exact or segment-prefix boundaries.

## Invariants and authorization

Authorization is default deny. Empty rules and empty capability sets are rejected. `Sudo` satisfies any capability only for a matching path prefix; a policy identifier that is absent from the store grants nothing.

## Failure, retry and reconciliation

Duplicate and missing-policy errors are deterministic before any external effect. Evaluation returns a boolean and has no ambiguous outcome or retry state.

## Concurrency and ordering

The package has no interior synchronization. A composition root serializes mutations to `PolicyStore` and may share immutable evaluation references concurrently.

## Security and privacy

Policy errors do not contain request paths or identities. The evaluator assumes inputs were canonicalized by `heptabao-domain` and never treats authentication as authorization.

## Persistence and compatibility

No persisted policy encoding is owned yet. A future encoding must version capabilities, preserve default deny and reject unknown mandatory capability values.

## Observability

The package emits no events directly. The service composition records allow/deny outcomes using bounded event names without embedding secret paths or token material.

## Operations

Policy changes are explicit store mutations. Production operation still requires durable storage, policy revision history and an audited administrative API.

## Tests and executable evidence

`cargo test -p heptabao-policy` proves default denial, capability separation, segment-bounded matching and duplicate rejection. Workspace Clippy runs with warnings denied.

## Evolution and open boundaries

Deny rules, parameter constraints, response wrapping, control groups and policy templates remain open. Adding them must preserve deterministic evaluation and explicit conflict precedence.
