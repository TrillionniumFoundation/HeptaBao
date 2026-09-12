# HeptaBao Module Documentation Standard V3

V3 is the current standard for packages introduced or materially redesigned under Plan V2.0. Inherited V2 guides remain valid historical source-bound guides until the corresponding package changes.

Common engineering rules are normative in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md` and must not be duplicated in every module guide.

## Required module-specific sections

Every V3 guide contains exactly one section with each heading below:

1. `## Purpose and non-goals`
2. `## Public API and ownership`
3. `## State and data model`
4. `## Invariants and authorization`
5. `## Failure, retry and reconciliation`
6. `## Concurrency and ordering`
7. `## Security and privacy`
8. `## Persistence and compatibility`
9. `## Observability`
10. `## Operations`
11. `## Tests and executable evidence`
12. `## Evolution and open boundaries`

The content must be specific to the package. A heading followed only by a generic statement is not semantic completion.

## Evidence requirements

The guide identifies:

- the package manifest and source root;
- direct internal dependencies;
- the owner of each authoritative state object;
- public operations and their failure category;
- state transitions and invalid transitions;
- persisted/wire format versions, or an explicit statement that the package owns no persisted/wire format;
- metric/event names or an explicit statement that the package emits none;
- exact test commands and at least one named executable scenario;
- boundaries that remain external or unimplemented.

## Generated facts

Workspace membership, package identity, source roots, lockfile presence and discovered tests are machine checked by `scripts/validate_repository_v2.py`. Generated facts are evidence aids, not substitutes for design explanation. Frozen V1.4.7 tables must remain identified as historical and linked to `docs/modules/CURRENT_SOURCE_BINDING.md`; their bytes are not rewritten to represent new code.

`python scripts/validate_current_documentation_semantics.py` checks current API substance outside those tables, current named test anchors, the actual server runtime closure in `docs/modules/CURRENT_RUNTIME_MAP.md`, and marked critical declaration signatures. For an inherited V2 guide, a current semantic supplement may precede the preserved historical structure. A source-digest refresh cannot replace review of the parameters, failure semantics and integration boundary. These targeted checks are not an automatic proof of complete documentation.

## Examples

Executable examples live in Rust tests or `examples/` and are compiled by the current CI. Markdown snippets that are not compiled must be labeled illustrative.

## Closure rule

A guide is documentation-complete only when its source exists, its tests pass and the current capability matrix points to the guide. File presence alone is insufficient.
