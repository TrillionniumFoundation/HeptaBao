# HeptaBao module documentation standard V1

Every Cargo workspace member must have exactly one maintained developer guide under `docs/modules/<crate>.md`. The guide is an engineering contract, not marketing text. It must describe purpose/non-goals, maturity, authority boundary, writer ownership, dependency direction, public API, state invariants, error/retry/cancellation semantics, formats, security handling, tests, extension workflow, operations, known gaps and exact-source maintenance metadata.

A module is not documentation-complete merely because source, tests, a master plan or a version-change manifest exists. The validator treats missing sections, stale workspace coverage, duplicate entries, placeholder language, authority promotion and README state drift as failures.

Generated API indexes are review aids. Rustdoc remains required for public items, and future revisions should progressively enable `missing_docs` and doctests crate by crate.
