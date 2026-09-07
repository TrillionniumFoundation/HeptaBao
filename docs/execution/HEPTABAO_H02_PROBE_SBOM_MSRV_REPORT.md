# HeptaBao H02 Candidate Probe, SBOM, Unsafe and MSRV Execution Report

**Plan:** `HEPTABAO-PLAN-2026-08-28` revision `1.1`  
**Branch:** `codex/h02-probes-sbom-msrv`  
**Stack base:** `codex/h02-source-integrity-evidence`  
**Status:** `IMPLEMENTED / UNEXECUTED REMOTE PROBES / NOT QUALIFIED / NO SELECTION / AUTHORITY NONE`

## Delivered

1. Added four exact, isolated candidate probe profiles: Tokio 1.53.1 minimal server runtime; rustls 0.23.43 with ring; rustls 0.23.43 with aws-lc-rs/post-quantum preference; OpenRaft 0.10.0-alpha.33 with Tokio runtime and Serde.
2. Every profile pins the exact version, feature set, target, probe toolchains, registry checksum and release commit.
3. Probe manifests opt out of the main workspace so evaluation dependencies cannot silently become HeptaBao runtime dependencies.
4. Added a machine-readable probe-evidence schema that distinguishes executed pass/fail, blocked, unexecuted and unknown results.
5. Added a deterministic collector that binds Cargo.lock, cargo metadata, normal/build dependency tree, feature tree, build/test logs and a heuristic source scan.
6. Added graph reduction for custom build scripts, Cargo `links` packages and native tooling such as `cc`, `bindgen`, `cmake`, `pkg-config`, `vcpkg`, `ring` and `aws-lc-sys`.
7. Added heuristic unsafe/FFI indicators while explicitly forbidding the counts from being treated as a security conclusion.
8. Added eight Python negative/semantic tests, including rejection of feature drift and false `EXECUTED_PASS` evidence with unknown steps.
9. Added a GitHub Actions matrix that can build the exact profiles on declared/baseline toolchains and emit sanitized, non-authoritative evidence even when a candidate build fails.

## Exact evaluation profiles

| Profile | Toolchains | Feature policy |
|---|---|---|
| Tokio minimal server | 1.71.0, 1.98.0 | no `full`, process, fs, io-uring or taskdump |
| rustls ring | 1.71.0, 1.98.0 | no aws-lc, FIPS or post-quantum feature |
| rustls aws-lc | 1.71.0, 1.98.0 | aws-lc/post-quantum comparison; no FIPS claim |
| OpenRaft Tokio | 1.85.0, 1.98.0 | no CLI/runtime-stats expansion; effective MSRV remains pending |

These are evaluation profiles, not dependency selections. The two rustls profiles deliberately keep the crypto-provider decision open.

## Evidence semantics

The probe collector can record `EXECUTED_PASS`, `EXECUTED_FAIL`, `BLOCKED`, `UNEXECUTED` and `UNKNOWN`. A cargo build failure is preserved as evidence rather than disappearing because a shell used `set -e`.

For a complete `EXECUTED_PASS`, the schema requires a clean source tree; all artifact digests; lock/metadata/build/test PASS; package checksum and VCS commit matches; failed=0; unknown=0. Even a complete local pass retains `qualification=false`, `selection_effect=NONE` and `authority_effect=NONE`.

## Current verified state

```text
probe profiles specified               4
probe profiles executed                0
lockfiles captured                     0
dependency graphs captured             0
source scans captured                  0
advisory scans captured                0
effective MSRV searches completed      0
independent reproductions              0
candidate selections                   0
qualification receipts                 0
```

The Python matrix/collector/schema tests were executed locally and passed. Rust and candidate builds were not executed in the local container because no Rust toolchain was present. This is local un-attested evidence, not H02 qualification.

## Next execution

1. Obtain a real Runner or attested self-hosted worker.
2. Run the eight profile/toolchain matrix entries and retain both pass and fail evidence.
3. Run the existing public package byte-rehash matrix.
4. Reproduce all critical package/graph evidence in an independent environment.
5. Review exact lock graphs for advisories, licensing, unsafe/FFI, build scripts and native tools.
6. Perform an effective-MSRV search and record lower/upper bounds for every profile.
7. Execute the still-unexecuted behavioral Runtime/TLS/Raft cases with replayable seeds.
8. Obtain independent reviews.
9. Only then consider a bounded prototype-selection receipt with `authority_effect=NONE`.
