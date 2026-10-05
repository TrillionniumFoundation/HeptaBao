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

Python tests use synthetic metadata/compiler output for receipt logic and tiny real test archives for archive semantics; these are not native executions or candidate evidence. No local toolchain installation, package download or native build is required for source review. Completion still requires fresh hosted execution on the published exact commit/tree, independently bound eight-entry artifacts and terminal check results. This document does not record such a run.

## R2 graph and feature observation boundary

The root package's complete dependency declarations come from its committed Cargo.toml; the direct candidate's declarations come from its checksum-authenticated crate archive Cargo.toml. Required normal/build dependencies are cross-checked against typed metadata declarations and resolve edges, including alias, kind, target, source and exact pins. Every resolved edge must exist in its parent's actual lock dependency references; node.dependencies and node.deps must agree, and every node must be reachable from the root. Inactive optional lock packages need not resolve. This is not a second Cargo feature, target-cfg or general semver resolver, and transitive declarations are not independently archive-authenticated.

Both observations explicitly use all targets. The dependency tree uses depth-prefixed package rows; the separately named `package-features.stdout` artifact uses a flat resolved package-feature projection. Their package identities, normal/build edge union, source identities and resolved feature union are checked against metadata. The latter is not the V1 `-e features` causality tree and makes no feature-causality claim. This profile rejects new root dev dependencies rather than silently omitting them from normal/build observations. The existing V1 output and contracts remain unchanged.

All-target graph membership does not establish that every listed package was compiled on the Linux target. The actual scoped execution is cargo check/test on x86_64-unknown-linux-gnu. Clippy is not invoked and no Clippy qualification is claimed. Recorded consistency does not attest runner honesty, every transitive archive, or independent registry supply-chain integrity. Unsupported source/graph representations fail closed rather than being treated as arbitrary nonempty output.

Cargo 1.71 support for the chosen flags and package row grammar was checked against official pinned source:
- https://github.com/rust-lang/cargo/blob/rust-1.71.0/src/doc/man/cargo-tree.md
- https://github.com/rust-lang/cargo/blob/rust-1.71.0/src/cargo/ops/tree/mod.rs
- https://github.com/rust-lang/cargo/blob/rust-1.71.0/src/cargo/ops/tree/format/mod.rs
Current semantics: https://doc.rust-lang.org/cargo/commands/cargo-metadata.html and https://doc.rust-lang.org/cargo/commands/cargo-tree.html.
