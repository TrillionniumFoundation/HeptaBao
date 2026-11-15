# Dependency security audit and bounded upgrades

This audit starts from candidate `21f9c5fa032fbdba6b7d9289c94b890581fea2fa`. It records real advisory matches, applies compatible updates to the current workspace, and keeps historical qualification profiles distinguishable from current product dependencies. A passing compilation or functional suite alone does not establish that a dependency is free of known vulnerabilities.

## Method and denominator

The official [cargo-audit 0.23.0 release](https://github.com/rustsec/rustsec/releases/tag/cargo-audit/v0.23.0) was downloaded as the x86_64 Linux musl binary, without compiling a tool or product. Its archive SHA256 was verified against the GitHub release asset digest: `4f01c74ed84b2dffd0b1d37012a62cdf2a92c96e25bdf8eec7fcc0d4d3eb7811`.

The official [RustSec advisory database](https://github.com/RustSec/advisory-db/tree/4ef2df8e806a65e2f1ecc14f56f51249062b23d6) contained **1,509 advisories** at commit `4ef2df8e806a65e2f1ecc14f56f51249062b23d6`, dated 2026-11-13. No advisory ignore list, target-OS filter or target-architecture filter was used. The final current-workspace scan fetched both the database and crates.io index; it reported no yanked entries or index-read errors.

| Lockfile | All package entries | Registry entries | Initial vulnerability records | Other initial warnings |
| --- | ---: | ---: | ---: | --- |
| Root `Cargo.lock` | 443 | 387 | 9 | 3 unsound, 1 unmaintained |
| `probes/h02/openraft-tokio/Cargo.lock` | 123 | 121 | 0 | 1 unsound |
| `probes/h02/rustls-aws-lc/Cargo.lock` | 34 | 33 | 5 | 0 |
| `probes/h02/rustls-ring/Cargo.lock` | 27 | 26 | 5 | 0 |

These four lockfiles contain **410 distinct registry name/version pairs**. The OpenRaft probe also has the explicitly pinned Git dependency `validit` at `7016fa5e072a86092928144b3a3040381e6964e9`; a crates.io advisory scan does not independently audit that Git source. Local and vendored packages are not authenticated by a registry-version check.

The Python client declares no external runtime dependency. The QA requirements pin PyYAML 6.0.2, jsonschema 4.23.0 and, initially, cryptography 46.0.4. OSV's package/version API returned no records for the first two and **13 records representing seven distinct advisories** for cryptography. The Python build requirement `setuptools>=65` and transitive resolver selections are not a fully pinned Python lockfile.

Fourteen tracked JavaScript package manifests were inspected. None declares an installed `dependencies` or `devDependencies` set. Ten archived AuthBus plugin manifests declare the unpinned peer range `openclaw>=2026.7.1`; no npm/pnpm/yarn lockfile fixes the actual host version. These archived peer ranges cannot be given an exact-version npm security verdict from this repository alone.

Original scanner output, inventory, Python observations and the post-change scan are in [dependency-evidence](dependency-evidence/). `manifest.json` records their SHA256 values and the precise audited lockfile identity.

## Current workspace changes

Only the following six registry package versions change in the root Cargo lockfile. Current crate exact-version declarations are kept consistent; no Rust product source is rewritten.

| Dependency | Previous | Updated | Findings addressed |
| --- | --- | --- | --- |
| rustls | 0.23.44 | 0.23.46 | [2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285), [2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346), [2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347), [2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348), [2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349) |
| rustls-webpki | 0.103.15 | 0.103.16 | [2026-0382: distrusted intermediate keys](https://rustsec.org/advisories/RUSTSEC-2026-0382) |
| ctutils | 0.4.2 | 0.4.4 | [2026-0385: constant-time mask/comparison generation](https://rustsec.org/advisories/RUSTSEC-2026-0385) |
| anyhow | 1.0.100 | 1.0.103 | [2026-0190: mutable error downcast unsoundness](https://rustsec.org/advisories/RUSTSEC-2026-0190) |
| rustix | 1.1.4 | 1.1.6 | [2026-0486: zero-length xattr buffer initialization](https://rustsec.org/advisories/RUSTSEC-2026-0486) |
| tokio | 1.53.1 | 1.53.3 | [2026-0386: AsyncFd constructor I/O safety](https://rustsec.org/advisories/RUSTSEC-2026-0386) |

The rustls records are version matches with different runtime preconditions. Brotli decompression requires a nondefault feature that is absent from this workspace's lock graph; ECH rejection leakage requires enabled ECH and buffered pre-handshake application writes; session-debug leakage requires a custom session store logging those values. The source search did not find ECH configuration or such a custom session store. Current outbound HTTP and LDAP clients explicitly disable resumption, which limits the session-prediction downgrade issue on those paths. These observations do not justify leaving the affected TLS version in place, nor prove every possible consumer configuration harmless.

The webpki issue applies when configured trust anchors admit a path through the distrusted intermediates. The patch adds the upstream rejection; it does not replace the repository's configured trust policy.

## Python QA cryptography update

`requirements-plan.txt` now pins **cryptography 50.0.0**. This spans several release series because the newest matched advisory is not fixed on the 46.0.x line. The seven distinct upstream records are:

| Advisory | First fixed release | Area |
| --- | --- | --- |
| [GHSA-r6ph-v2qm-q3c2](https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2) | 46.0.5 | SECT subgroup validation |
| [GHSA-m959-cc7f-wv43](https://github.com/pyca/cryptography/security/advisories/GHSA-m959-cc7f-wv43) | 46.0.6 | DNS name constraints |
| [GHSA-p423-j2cm-9vmq](https://github.com/pyca/cryptography/security/advisories/GHSA-p423-j2cm-9vmq) | 46.0.7 | Noncontiguous buffer handling |
| [GHSA-537c-gmf6-5ccf](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf) | 48.0.1 | OpenSSL bundled in wheels |
| [GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww) | 49.0.0 | Certificate path-building amplification |
| [GHSA-m2h6-j472-rp4c](https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c) | 49.0.0 | Wildcard permitted-subtree constraints |
| [GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5) | 50.0.0 | PKCS#7 decryption error/timing oracle |

An isolated environment used the actual cryptography 50.0.0 wheel with OpenSSL 4.0.1 and the other unchanged top-level QA pins. The original acceptance suite ran **1,768 tests: 1,763 passed, three existing skips and two errors**. The two errors were the same independently diagnosed host restrictions: AF_UNIX socket creation and system ELF-loader UID admission. No new cryptography fixture error appeared. The test suite and admission assertions were not edited. The API compatibility observation is bounded to this suite; it is not a full live-provider or product qualification. OSV's followup query for cryptography 50.0.0 returned no records at the recorded observation time.

## Remaining findings and historical profiles

The current-workspace post-change scan still exits with failure for **two vulnerability records**, plus one maintenance warning. No suppression is introduced:

- [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071): `rsa` 0.9.10, fixed at 0.10.0, through `ssh-key` 0.6.7.
- [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387): `crypto-bigint` 0.5.5, fixed at 0.7.6, through elliptic-curve and p256/p384/p521 into `ssh-key` 0.6.7.
- [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134): `rustls-pemfile` 2.2.0 is unmaintained. This warning is not itself a reproduced parser vulnerability. Upstream recommends migration to `rustls-pki-types::pem::PemObject`.

The crates.io API reported 0.6.7 as the latest stable ssh-key release and 0.7.0-rc.12 as a prerelease. The stable release requires rsa 0.9 and p256/p384/p521 0.13; these constraints cannot select the patched major lines through a normal compatible lockfile update. A prerelease-wide cryptographic migration or a reviewed backport needs separate API and cryptographic verification.

The current broker admits only unencrypted Ed25519 Git signing keys and rejects other algorithms. The server's SSH CA uses its own `CaSigner` backed by OpenSSL for private RSA/ECDSA signing. These are concrete limitations on the obvious private-signing exposure; they do not remove the locked advisory records or establish a complete absence of secret-dependent work in parsing/import/verification and future callers. No timing exploit or key recovery was attempted or demonstrated in this audit.

The H02 probe manifests and lockfiles remain tied to their original dependency-profile IDs, artifact checksums, Git source commits and historical evidence. Updating only their dependency version would falsify that identity. Their original five rustls/webpki records per TLS probe and the Tokio warning in the OpenRaft probe remain explicitly recorded. They must not be represented as current patched product qualifications.

## Verification limits

`cargo metadata --locked --format-version 1 --no-deps` accepted the changed workspace and lock resolution. The dependency subtask did **not** compile the upgraded Rust product or execute its native tests; the integrating candidate requires fresh compilation, lint and runtime CI. The final workspace RustSec result remains nonzero for the two named records. Absence of additional database matches is not proof of complete supply-chain safety, and this work does not audit OS libraries, external provider binaries, unpinned host peers or every historical artifact's contents.
