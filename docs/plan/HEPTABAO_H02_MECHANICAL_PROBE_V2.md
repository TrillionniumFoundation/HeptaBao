# H02 mechanical probe current profile V2

Status: source-only implementation, pending exact-head hosted execution. Qualification is false; selection and authority effects are NONE. This lane makes no behavioral, independent-reproduction, general MSRV, safety, or production-readiness claim.

## Scope and reuse

This is an additive successor to `h02-probe-sbom-msrv.yml`, not an adapter-harness migration. It runs eight entries: Tokio minimal, rustls/ring, and rustls/aws-lc each on Rust 1.71.0 and 1.99.0; OpenRaft on 1.88.0 and 1.99.0. Historical profiles, compiler-sensitive V1 digests, artifacts, adapter contracts, native probes and authority gates remain unchanged. The V2 execution identity is distinct and its profile digests include the new compiler pair.

The runner loads reviewed byte-exact V1 normalization, manifest validation, metadata summaries and source scans. It also reuses reviewed byte-exact fault-lab V2 input isolation, strict JSON, hashing and low-level subprocess execution. It neither loads old evidence as new evidence nor mutates those helpers.

## Real graphs and execution

The rustls provider profiles and OpenRaft copy their committed lockfiles; Tokio has no committed lock and runs `cargo generate-lockfile` once per compiler. All subsequent metadata, all-target normal/build dependency tree, resolved package-feature projection, check and test commands use `--locked`. Actual initial and final lock hashes must match. Graph identity is per execution; the generated Tokio graph is not promised to be equal across runs or compilers. A resolution failure is retained as a failure, never hidden by relabelling another compiler's graph.

Materialization reads committed blobs, including the sibling public rustls fixture. Fresh external working directories and a config-free Cargo home prevent ignored repository files and inherited Cargo/Rust flags from entering the build. Only absolute PATH and RUSTUP_HOME are inherited. The runner captures actual `rustc --version --verbose` and `cargo --version`, every command and exit status, before/after config checks, source commit/tree/clean state, manifest/lock bytes, metadata and trees.

The metadata's selected candidate determines the exact isolated registry source/cache pair. Before native check/test, the crate checksum and archive VCS commit must match the profile, archive member bytes must match cached source bytes, and file sets must match except root Cargo-created `.cargo-ok` and `.cargo-checksum.json`. Symlinks and extra cached source/build files are rejected. The archive is retained for offline checksum/VCS/source-scan revalidation; cached source binding is rechecked after execution. Heuristic source scans remain unreviewed inventories.

## Evidence admission

Source validation and receipt recomputation are mandatory together with the JSON schema. The verifier takes independent expected source commit/tree, producer paths, run/attempt and runner identity. It reconstructs expected compiler/profile/commands/environment and recomputes artifacts, graph relationships and package evidence. The exact eight-entry directory set is required. Hosted validation uses the live PATH/RUSTUP_HOME; relocated offline verification requires independently supplied original runtime values with `--runtime-path` and `--runtime-rustup-home`. Recorded consistency alone does not attest runner binaries or image integrity.

Workflow admission is scoped pull requests plus manual execution, pinned existing actions, read-only contents, and no persisted checkout credentials. All entries run serially. Artifact upload occurs before the final mechanical-pass gate. Failed or missing toolchains, metadata, trees, archive binding, check/test or unknown outcomes cannot pass. All behavioral cases remain explicitly UNEXECUTED even when mechanical commands pass.

## Verification boundary

Python tests use synthetic metadata/compiler output for receipt logic and tiny real test archives for archive semantics; these are not native executions or candidate evidence. No local toolchain installation, package download or native build is required for source review. Completion still requires fresh hosted execution on the published exact commit/tree, independently bound eight-entry artifacts and terminal check results. This document does not claim a passing run of the proposed corrected source; the earlier failed run is recorded below.

## R2 graph and feature observation boundary

The root package's complete dependency declarations come from its committed Cargo.toml; the direct candidate's declarations come from its checksum-authenticated crate archive Cargo.toml. Required normal/build dependencies are cross-checked against typed metadata declarations and resolve edges, including alias, kind, target, source and exact pins. Every resolved edge must exist in its parent's actual lock dependency references; node.dependencies and node.deps must agree, and every node must be reachable from the root. Inactive optional lock packages need not resolve. This is not a second Cargo feature, target-cfg or general semver resolver, and transitive declarations are not independently archive-authenticated.

Both observations explicitly use all targets. The dependency tree uses depth-prefixed package rows; the separately named `package-features.stdout` artifact uses a flat resolved package-feature projection. Their package identities, normal/build edge union, source identities and resolved feature union are checked against metadata. The latter is not the V1 `-e features` causality tree and makes no feature-causality claim. This profile rejects new root dev dependencies rather than silently omitting them from normal/build observations. The existing V1 output and contracts remain unchanged.

All-target graph membership does not establish that every listed package was compiled on the Linux target. The actual scoped execution is cargo check/test on x86_64-unknown-linux-gnu. Clippy is not invoked and no Clippy qualification is claimed. Recorded consistency does not attest runner honesty, every transitive archive, or independent registry supply-chain integrity. Unsupported source/graph representations fail closed rather than being treated as arbitrary nonempty output.

Cargo 1.71 support for the chosen flags and package row grammar was checked against official pinned source:
- https://github.com/rust-lang/cargo/blob/rust-1.71.0/src/doc/man/cargo-tree.md
- https://github.com/rust-lang/cargo/blob/rust-1.71.0/src/cargo/ops/tree/mod.rs
- https://github.com/rust-lang/cargo/blob/rust-1.71.0/src/cargo/ops/tree/format/mod.rs
Current semantics: https://doc.rust-lang.org/cargo/commands/cargo-metadata.html and https://doc.rust-lang.org/cargo/commands/cargo-tree.html.

## First hosted run and proposed correction

Published source fe021e4995fda5c73ca11dcfbfea28409b015a23 ran as GitHub Actions run 37247651462. Its original eight receipts are preserved: both rustls/ring entries passed; both rustls/aws-lc entries completed check/test but were blocked by the view-comparison guard; Tokio and OpenRaft entries were blocked before check/test. These are historical results of that exact source contract, not passing receipts for this correction.

Tokio's pinned release manifest declares tracing-mock as `= 0.1.0-beta.1`; Cargo metadata represents the same requirement as `=0.1.0-beta.1`. The corrected comparison normalizes spaces/tabs after a comparator only. It does not alter operators or characters inside versions. The original failed capture did not retain Tokio's crate archive, so its exact archive manifest is unavailable; the regression records the actual native metadata and pinned upstream manifest separately, without substituting the latter for an authenticated archive.

The aws-lc metadata contains an optional ring branch reached through rustls-webpki's weak `ring?/alloc` reference; the actual Cargo tree does not activate that branch. The enabled normal/build projection retains mandatory and activated optional edges, then computes root reachability. Weak references alone never activate a dependency. Raw metadata is preserved alongside the checked projection. Reference: https://doc.rust-lang.org/cargo/reference/features.html#dependency-features . This remains a bounded consistency check, not an independent general Cargo resolver.

The OpenRaft failure was a real profile mismatch. The committed full probe includes openraft-memstore, whose OpenRaft dependency retains default features. The pinned upstream OpenRaft default feature activates tokio-rt and clap. The original minimal profile forbids clap and remains blocked for that graph. It is not weakened or relabelled.

The new explicit `HB-H02-PROBE-OPENRAFT-TOKIO-FULL-CURRENT-V1` contract is defined by `planning/HEPTABAO_H02_OPENRAFT_FULL_PROBE_PROFILE_V1.yaml`. It preserves the native source, memstore dependency and direct OpenRaft declaration. It requires exactly clap/default/serde/tokio-rt/type-alias, binds the recorded memstore-to-OpenRaft default-feature chain and candidate archive's default definition, and still forbids runtime-stats. Its distinct identity and digest include the exact feature set. No minimal-profile qualification or old result transfers to it.

Exact pinned upstream source trace at commit 2be3f99a23c0ec734aefc18d1c8e756b35567c35:
- `stores/memstore/Cargo.toml` blob 5ff8d3a6483b5df76582ef24289d853a7270108d declares OpenRaft with serde/type-alias and leaves defaults enabled.
- `openraft/Cargo.toml` blob c50ed79de92cd527d37aa20b607b64d6503f1837 defines default as tokio-rt/clap.
- The committed probe's direct OpenRaft declaration still disables defaults; feature unification through memstore is the additional source.

Future captures retain a checksum-verified crate archive before later VCS/source/manifest/profile admission, so a rejected contract keeps the actual bytes needed for diagnosis. Retention is not successful admission. Missing archives are labelled missing evidence, not checksum mismatch.

The checked-in regression fixture is a bounded gzip/base64 text encoding of original native metadata, both tree streams and original receipts, plus provenance-labelled manifest inputs. It preserves the original ZIP SHA-256 b9193de0c2529a18e550741341f53548951de3960ffb3aabeaf06ec0a275b8ec. Regression passes do not rewrite those receipts or constitute a new hosted run. Fresh exact-head execution remains required after independent source review.


The enabled-view guard also binds root and direct-candidate feature-definition maps to their actual manifests before any pruning. Normalization preserves explicit features and synthesizes Cargo's implicit optional-dependency feature only when no dep: reference suppresses it. This includes target-specific optional dependencies and dependency aliases. An edited metadata map cannot erase an authenticated candidate activation such as rustls logging→log→dep:log and then omit that branch from both trees. Transitive feature definitions retain the previously stated recorded-observation boundary.
