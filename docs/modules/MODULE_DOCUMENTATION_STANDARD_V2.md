# HeptaBao Module Documentation Standard V2

Status: current normative standard for every Cargo workspace crate.

## Required narrative sections

Every module guide must retain implementation purpose, maturity, dependency direction, public API, state invariants, errors and retry semantics, data formats, security considerations, test strategy, extension rules, operational guidance, known gaps and traceability.

## Machine-bound facts

The following facts are generated from the exact candidate source and may not be maintained as unsupported prose:

1. Cargo manifest SHA-256;
2. all Rust source-file SHA-256 digests;
3. workspace-internal dependency declarations and dependency section;
4. public lexical declarations with source path, line, kind and declaration text;
5. discovered `#[test]` and runtime test functions;
6. exact mapping from Cargo package name to module guide.

The authoritative snapshot is `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`. Each module guide contains generated Public API and source-truth blocks. `python scripts/render_plan_v1_4_7.py --check` must fail whenever source, dependencies, tests or generated documentation drift.

## Scope boundary

The V2 parser is deliberately described as a bounded lexical Rust inventory. It does not perform Rust name resolution and cannot establish semantic API compatibility. Those limitations must remain explicit; success grants no qualification, compatibility, provider selection or authority.

## Change rule

A source change that affects any generated fact requires regeneration in the same pull request. Hand editing a generated block, deleting an API item from documentation, inventing a test, or retaining a stale dependency graph is a failing condition. Historical narrative remains evidence but may not override a newer generated source fact.

## Review rule

Critical modules require a reviewer to inspect both semantic narrative and generated source facts. Structural presence alone is insufficient. Approval must bind the exact pull-request head and prospective merge identity.
