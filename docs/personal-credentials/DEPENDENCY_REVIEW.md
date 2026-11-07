# Credential dependency review — 2026-11-06

## Result and required follow-up

At baseline `8cd4761`, this bounded **internal** review found two active RustSec
version matches in the broker's normal dependency closure: `rsa 0.9.10` and
`crypto-bigint 0.5.5`.
Both arrive through `ssh-key`'s broad `crypto` feature. The implemented signing
policy accepts only unencrypted Ed25519 keys. Remove the unused RSA and ECDSA
features, then verify the resulting dependency tree and the existing signing and
rejection behavior. The dependency reviewer made no changes; the subsequent
implementation and its separately bound evidence are recorded below.

This is dependency evidence for the synthetic candidate. It is not an
independent assessment, an exploitation demonstration, or production
qualification. The acceptance limits in [SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md)
remain in force.

## Subsequent bounded correction and verification

Local commit `c447536ae0343731d84c18291d2dcd712b3bea08`, tree
`50835fd4df6e7bdd2b551941a3fa012281c931c2`, changes only the broker's
`ssh-key` feature declaration to `std,ed25519` and adds two algorithm-policy
integration tests. The existing eleven process tests and `Cargo.lock` are
unchanged. This correction does not change the server's signing features.

Normal-edge resolution for the selected broker/vault/edge crates on Linux
x86-64 and macOS ARM64 now selects `ssh-key` features
`alloc,ed25519,rand_core,std`; neither `rsa` nor `crypto-bigint` appears in
these selected graphs. A separate root-side resolution reproduced the result
with 50 and 49 package/version pairs respectively. Resolving a target graph
does not mean that target's executable was run.

An isolated clean ai395 checkout built the three selected crates with Rust
1.98.0, passed formatting and Clippy, and froze the resulting executables.
The fixed broker executable SHA-256 is
`6fe0b6c78213e4bb1184ca4c4be7fc3e44dce4117f22097aab14efa567ac8a08`.
The original eleven real CLI/socket/API/Git/recovery tests and the two new
tests all passed: **13/13**. The new tests generate valid OpenSSH RSA and
ECDSA keys and confirm that both SDK and CLI initialization refuse them.
Both test executables explicitly used the fixed broker through
`HEPTABAO_BROKER_TEST_BINARY`. Their own digests, the fixed CLI digest and
the original build-path CLI digest match before and after execution.

The original runner stopped before any test when `cargo test --no-run` had
not produced the ordinary browser/sync CLI executables. Its failed receipt
is preserved. A recorded continuation built the ordinary CLI targets,
verified the existing broker/vault bytes were unchanged, then froze and ran
the tests. No build took place after the final tested artifacts were frozen.
The final original receipt is
[broker-ed25519-build-and-tests.public.json](../../qa/personal_credentials/evidence/20261106/broker-ed25519-build-and-tests.public.json),
SHA-256 `d29fff92ecbcdab6e52c905e6a4a96217d4c712f2c453dd5c63214e47c0e88bb`.
The prior failed receipt, source bundle, compiler-artifact record, actual
test output and selected graph outputs are retained alongside it.

Only the broker's thirteen functional tests ran against this new build.
The newly built vault/browser/sync executables receive build/Clippy evidence,
not the older P2/P3 functional results. The four original `a1b6ff4` retained
executables were verified unchanged and remain the artifacts used by their
original qualification profiles.

**Workspace boundary:** `heptabao-server` still declares `ssh-key` with
`std,crypto`. A wider workspace build can unify those features and reintroduce
the affected packages. The local full-workspace offline graph failed because
`axum 0.8.9` was not cached; the remote attempt separately failed on uncached
`xattr 1.6.1`. Both failed observations are preserved in their original logs.
Neither the selected-build correction nor the advisory review establishes a
clean full-workspace dependency graph or qualifies a server artifact.

## Scope and reproducible identities

- Reviewed source baseline: `8cd47619f4b928e493d49588e0d7931d6199a7f5`.
- `Cargo.lock` SHA-256:
  `ef3b19cf8b1b360f7888f11e3e5b1523e464762d6c24ce7e92b64d0d7d5c99a9`.
- Rust roots: `heptabao-credential-broker`, `heptabao-personal-vault`,
  `heptabao-personal-edge`, and `heptabao-filesystem-guard`, all `0.1.0`.
  The macOS closure also contains local `heptabao-darwin-vnode-events 0.1.0`.
- Resolved normal edges, including proc macros reached by those edges, for
  `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`. These contained
  81 and 80 distinct package/version pairs respectively. Their union contains
  **78 registry package/version pairs, 77 registry names, and five local crates**.
- Java scope: the pinned Bouncy Castle provider JAR and the copied AndroidX Slice
  adapter, its notice/license, the offline APK builder, and the Argon2 call site.
  No phone, credential store, private test artifact, or running service was accessed.

The read-only resolution command was run for each target, using the prepared
Cargo/Rustup environment and the existing lockfile:

```sh
cargo tree --locked --offline --target TARGET --edges normal \
  --prefix depth --format '{p} [{f}]' \
  -p heptabao-credential-broker -p heptabao-personal-vault \
  -p heptabao-personal-edge -p heptabao-filesystem-guard
```

An initial `--target all` request failed because `fiat-crypto 0.2.9` was not cached.
Nothing was downloaded or installed. The successful two-target results therefore
do not establish coverage of other targets or alternate Curve25519 backends.

### Direct registry dependencies and selected features

| Component | Exact direct versions / material feature choices |
| --- | --- |
| Credential broker | `base64 0.22.1`; `ring 0.17.14`; `rustix 1.1.4` with `fs,process`; `serde 1.0.229` with `derive`; `serde_json 1.0.151`; `ssh-key 0.6.7` with defaults disabled and `std,crypto`; `zeroize 1.8.1` |
| Personal vault | `argon2 0.5.3` with `zeroize` and default features; `base64 0.22.1`; `ring 0.17.14`; `serde 1.0.229` with `derive`; `serde_json 1.0.151`; `zeroize 1.8.1`; Unix `rustix 1.1.4` with `fs,process` |
| Personal edge | Same base64/ring/rustix/serde/serde_json/zeroize versions; local vault and filesystem guard |
| Filesystem guard | `libc 0.2.189`; Unix `rustix 1.1.4` with `fs`; macOS local vnode helper |

Manifest versions are pinned exactly. Transitive identities are locked with
registry checksums. The selected features were read from Cargo's resolved tree,
rather than inferred from the presence of a package elsewhere in the workspace lockfile.

## Advisory matching and actionable findings

The review retrieved the official RustSec repository at
[commit 26fd2d43f7280a1fb925a3743ec463017afe7119](https://github.com/RustSec/advisory-db/commit/26fd2d43f7280a1fb925a3743ec463017afe7119)
(commit time **2026-11-05T08:50:49Z**) on **2026-11-06**.
The immutable recursive tree
`6cec6aa884aba1df6d5c62888f21760f4bd1d1de` reported `truncated=false`.
All `crates/<selected-name>/*.md` entries were matched against the 77 observed
registry names. All **24 matching advisory blobs** were read by their immutable
blob SHA and their version ranges inspected.

| Finding | Exact dependency route | Upstream evidence and applicability |
| --- | --- | --- |
| **Active version match: RSA timing disclosure** | broker → `ssh-key 0.6.7` (`crypto,rsa`) → `rsa 0.9.10` | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), also CVE-2023-49092, has no patched version and expressly includes 0.9.10. The advisory describes possible private-key recovery when timing is observable. |
| **Active version match: integer arithmetic timing variability** | broker → `ssh-key 0.6.7` (`p256,p384,p521`) → `elliptic-curve 0.13.8` → `crypto-bigint 0.5.5` | [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html), dated 2026-10-23, lists fixes in `>=0.7.6`. Exploitability depends on the secret operation, compiler, CPU and observation channel. Advisory attribution: RustSec / RustCrypto, CC-BY-4.0; [upstream remediation](https://github.com/RustCrypto/crypto-bigint/pull/1365). |

The broker's `validate_credential` rejects encrypted and non-Ed25519 keys.
It runs during initialization and when `Owner::open` loads configuration;
the execution path signs an SSHSIG in namespace `git`. This reduces the apparent
reachability of the two findings in the supported signing workflow. It is not a
complete reachability proof: OpenSSH parsing occurs before the algorithm check,
and this review did not perform timing analysis or inspect every generated code path.

**Recommended correction:** retain `default-features = false` and replace
`features = ["std", "crypto"]` with `features = ["std", "ed25519"]` for
`ssh-key`. The cached 0.6.7 manifest confirms that `crypto` enables Ed25519,
P-256, P-384, P-521 and RSA; `ed25519` is independently selectable.
Confirm both affected packages leave the selected closure, including under the
actual workspace build configuration. Re-run the existing Ed25519 SSHSIG
verification and rejection checks. This recommendation was not applied or tested
by the dependency reviewer.

### Other matching advisories

The other 22 entries comprise 20 patched/unaffected version matches and two
withdrawn records. These are conclusions about the named advisories, not a claim
that the selected releases have no vulnerabilities.

| Selected package | Advisory IDs inspected | Disposition for the selected version |
| --- | --- | --- |
| `base64 0.22.1` | RUSTSEC-2017-0004 | Meets patched `>=0.5.2` |
| `blake2 0.10.6` | RUSTSEC-2019-0019 | Meets patched `>=0.8.1` |
| `curve25519-dalek 4.1.3` | [RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html) | Meets patched `>=4.1.3` |
| `ed25519-dalek 2.1.1` | [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html) | Meets patched `>=2` |
| `generic-array 0.14.7` | RUSTSEC-2020-0146 | Meets patched `>=0.13.3` |
| `rand 0.8.8` | RUSTSEC-2026-0097 | Meets patched `>=0.8.6,<0.9.0` |
| `rand_core 0.6.4` | RUSTSEC-2019-0035; RUSTSEC-2021-0023 | Meets patched ranges `>=0.4.2` and `>=0.6.2` |
| `ring 0.17.14` | [RUSTSEC-2025-0009](https://rustsec.org/advisories/RUSTSEC-2025-0009.html); RUSTSEC-2025-0010; RUSTSEC-2025-0007 | AES panic fixed in `>=0.17.12`; pre-0.17 maintenance notice excludes selected version; 0007 withdrawn |
| `sha2 0.10.9` | RUSTSEC-2021-0100 | Meets patched `>=0.9.8` |
| `smallvec 1.16.0` | RUSTSEC-2018-0003; 2018-0018; 2019-0009; 2019-0012; 2021-0003 | Meets each patched range; latest relevant 1.x boundary is `>=1.6.1` |
| `spin 0.9.9` | RUSTSEC-2019-0013; 2019-0031; 2023-0031 | Meets patched `>=0.5.2` and `>=0.9.8`; 2019-0031 withdrawn |
| `untrusted 0.9.0` | RUSTSEC-2018-0001 | Meets patched `>=0.6.2` |
| `zerocopy 0.8.62` | RUSTSEC-2023-0074 | Meets patched `>=0.7.31` |

For the remaining **62 registry names**, the pinned RustSec tree contained no
package advisory file. That observation has narrower meaning than a clean audit.
It does not cover unpublished issues, other databases, name aliases outside this
matching method, malicious package publication, or future advisories.

## Java dependency and copied-source binding

### Bouncy Castle

The [official download page](https://www.bouncycastle.org/download/bouncy-castle-java/)
lists `bcprov-jdk15to18 1.86`; the
[official 1.86 announcement](https://www.bouncycastle.org/resources/new-release-bouncy-castle-java-1-86/)
is dated 2026-09-15 and identifies multiple fixed security issues, including
CVE-2026-17508 concerning unbounded password-KDF costs. Both pages were consulted
on 2026-11-06. No claim of complete Java advisory coverage is made.

The reviewed builder, `qa/personal_credentials/passkey_build.py`, checks the JAR
against SHA-256
`fc50334d4d87b4272e72fa95ca748ead05bdef02ef760a5b13f64ffee317cd81`
before invoking it, and passes the whole provider JAR to D8. It preserves the
library's emitted license text in the provider APK assets. The notice records
[this Maven artifact](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15to18/1.86/bcprov-jdk15to18-1.86.jar).
The digest check was inspected in source; this reviewer did not independently
download/authenticate the JAR or inspect a resulting APK.

`Hbv.unlock` directly uses Bouncy Castle's Argon2 generator with fixed Argon2id
v1.3 settings: 65,536 KiB memory, three iterations, four lanes, and a 32-byte result.
The cost values are constants, rather than unchecked values passed through from
an imported envelope. Other crypto calls use Java/JCA. Bundling the full JAR
requires continued provider-level advisory review even though the intended
Bouncy Castle call surface is narrow.

### AndroidX adapter

`Entries.java` is a small copied/adapted Slice serializer, not a bundled AndroidX
runtime. Its source header and `NOTICE` identify AndroidX Credentials 1.6.0
`CreateEntry.kt`, `CredentialEntry.kt`, and `PublicKeyCredentialEntry.kt`,
AOSP attribution, and Apache-2.0. The recorded
[source JAR](https://dl.google.com/dl/android/maven2/androidx/credentials/credentials/1.6.0/credentials-1.6.0-sources.jar)
SHA-256 is
`8a7c14ff4fef351ea737072c74d8e837954bbb1082b55113ef44364d469ea1d7`.
The builder copies `NOTICE` and `LICENSE-APACHE-2.0.txt` to APK assets.

The [official Credentials release page](https://developer.android.com/jetpack/androidx/releases/credentials)
was consulted on 2026-11-06 and identifies stable 1.6.0. Release status does not
validate this copied serializer. The source JAR digest and adaptation diff were
not independently reproduced in this review; future upstream fixes do not
automatically update copied code. Device/OS Slice compatibility and callback
security remain separate evidence.

## License observations and evidence limits

Cached Cargo package manifests were inspected for all 78 registry
package/version pairs. Most declare MIT and/or Apache-2.0. Material additional
declarations include:

- `ring`: Apache-2.0 **AND** ISC; `untrusted`: ISC.
- `curve25519-dalek`, `ed25519-dalek`, `subtle`: BSD-3-Clause.
- `unicode-ident`: (MIT OR Apache-2.0) **AND** Unicode-3.0.
- `rustix` and `linux-raw-sys`: Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT.
- `zerocopy`: BSD-2-Clause OR Apache-2.0 OR MIT; `memchr`: Unlicense OR MIT.

These are manifest observations, not a completed redistribution/license audit.
Release packaging must preserve the applicable copyright and license material,
including third-party material within a dependency. Bouncy Castle's
[license page](https://www.bouncycastle.org/about/license/) was consulted on
2026-11-06; no source-to-binary license inventory was established.

This review does not establish build-dependency/toolchain safety, yanked-package
status, supply-chain provenance beyond the stated bindings, artifact
reproducibility, platform crypto-provider correctness, constant-time behavior,
or the security of the vault protocol and OS isolation. Build/dev dependencies
and the rest of the workspace were deliberately outside the normal-edge scope.
No full `cargo audit`/Java scanner run, fuzzing, independent pentest, or binary
inspection is claimed. Reassess after dependency/feature/target changes.

## Exact registry inventory

This is the union of the two successful normal-edge resolutions. Linux-only
entries are `curve25519-dalek-derive 0.1.1`, `linux-raw-sys 0.12.1`, and
`syn 2.0.119`; `errno 0.3.14` is macOS-only. Local crate identities are
listed in the scope above.

```text
argon2@0.5.3  base16ct@0.2.0  base64@0.22.1  base64ct@1.6.0
bitflags@2.13.2  blake2@0.10.6  block-buffer@0.10.4  cfg-if@1.0.4
cipher@0.4.4  const-oid@0.9.6  cpufeatures@0.2.17  crypto-bigint@0.5.5
crypto-common@0.1.7  curve25519-dalek@4.1.3  curve25519-dalek-derive@0.1.1  der@0.7.10
digest@0.10.7  ecdsa@0.16.9  ed25519@2.2.3  ed25519-dalek@2.1.1
elliptic-curve@0.13.8  errno@0.3.14  ff@0.13.1  generic-array@0.14.7
getrandom@0.2.17  group@0.13.0  hmac@0.12.1  inout@0.1.4
itoa@1.0.18  lazy_static@1.5.0  libc@0.2.189  libm@0.2.16
linux-raw-sys@0.12.1  memchr@2.8.3  num-bigint-dig@0.8.6  num-integer@0.1.47
num-iter@0.1.46  num-traits@0.2.19  p256@0.13.2  p384@0.13.1
p521@0.13.3  password-hash@0.5.0  pem-rfc7468@0.7.0  pkcs1@0.7.5
pkcs8@0.10.2  ppv-lite86@0.2.21  primeorder@0.13.6  proc-macro2@1.0.107
quote@1.0.47  rand@0.8.8  rand_chacha@0.3.1  rand_core@0.6.4
rfc6979@0.4.0  ring@0.17.14  rsa@0.9.10  rustix@1.1.4
sec1@0.7.3  serde@1.0.229  serde_core@1.0.229  serde_derive@1.0.229
serde_json@1.0.151  sha2@0.10.9  signature@2.2.0  smallvec@1.16.0
spin@0.9.9  spki@0.7.3  ssh-cipher@0.2.0  ssh-encoding@0.2.0
ssh-key@0.6.7  subtle@2.6.1  syn@2.0.119  syn@3.0.6
typenum@1.20.1  unicode-ident@1.0.24  untrusted@0.9.0  zerocopy@0.8.62
zeroize@1.8.1  zmij@1.0.23
```
