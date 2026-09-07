# HeptaBao H02 Source-Integrity and Platform-Contract Execution Report

**Plan:** `HEPTABAO-PLAN-2026-08-28` revision `1.1`  
**Branch:** `codex/h02-source-integrity-evidence`  
**Status:** `IMPLEMENTED / NOT QUALIFIED / NO SELECTION / AUTHORITY NONE`

## Delivered

1. Corrected Tokio and rustls research captures to the canonical candidate IDs used by the H02 catalog.
2. Bound Tokio 1.53.1, rustls 0.23.43 and OpenRaft 0.10.0-alpha.33 to exact crates.io-index commit, path, blob and registry checksum.
3. Added a fail-closed source-integrity maturity policy separating Git identity, registry metadata, downloaded-byte evidence and independent review.
4. Added a manual, bounded GitHub Actions byte-rehash lane. It verifies downloaded `.crate` bytes against the registry checksum and the package VCS commit against the pinned release commit.
5. Added four deterministic execution profiles: runtime correctness, TLS security, Raft correctness and artifact provenance.
6. Added a pure-standard-library `heptabao-platform-contracts` crate. It defines provider-neutral runtime, TLS, artifact and Raft boundaries and contains no candidate dependency.
7. Added negative tests and validators that reject candidate promotion, qualification or authority from metadata-only evidence.

## Evidence maturity

```text
official Git metadata captures       3
crates.io registry checksums          3
downloaded .crate byte verifications 0
source archive observations           0
independent reproductions             0
execution profiles specified          4
execution profiles executed           0
prototype selections                  0
qualification receipts                0
```

The three registry checksums are public registry metadata, not proof that this branch downloaded and reproduced the package bytes. The workflow must execute on an attested runner, and a second environment must reproduce the evidence before critical selection.

## Security boundary

- GitHub-generated source archive digests are treated as observations, not publisher-signed canonical checksums.
- `.crate` bytes must match the exact crates.io-index checksum.
- `.cargo_vcs_info.json` must bind to the pinned release commit where present.
- Raw source archives and package bytes remain outside the implementation repository.
- Runtime, TLS and Raft candidate types cannot leak through the HeptaBao-owned contracts.
- `QUALIFIED`, compatibility, production, migration, release, crypto and Raft implementation authority all remain false.

## Next execution

1. Obtain a real Runner and run all Python/Rust gates.
2. Dispatch the byte-rehash matrix and preserve the generated runner evidence.
3. Reproduce the same evidence in an independent environment.
4. Generate SBOM and transitive, unsafe/native/build-script and advisory inventories.
5. Execute MSRV/Rust-1.98 and the four deterministic profiles.
6. Request independent platform/security/license and distributed-systems review.
7. Only then consider a bounded prototype selection receipt with `authority_effect=NONE`.
