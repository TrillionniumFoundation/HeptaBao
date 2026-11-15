# HeptaBao repository audit and single-main reconciliation

Audit date: 2026-11-14, America/New_York. This work is authorized by the repository owner's request to audit the repository, merge its branches and retain one branch.

## Scope and acceptance

The repository operation has two distinct acceptance conditions: retain every initial branch tip and its immutable history in the final main ancestry, and reconcile the executable source deliberately. It does not turn an unqualified development repository into a supported production secrets service. Existing failed, unknown, missing and unexecuted results retain their original meaning.

The initial live Git inventory contains **600 branches, 552 distinct tip commits, 385 branches already contained by main and 215 not contained by main**. The latter reduce to **91 independent tips**. The fresh REST pull-request collection contains **52 open PRs, all Draft**. GitHub search was stale and omitted the newer PRs, so it was not used as the deletion denominator. Initial main is `7b4a59bdd72218c1e779eb32754a682cf465af7a`; it differs from `55f27e4258ea3f71ab7872cd7a44e8cbd4da1f18` only in the deliberately cleared README.

The original branch names and exact commits are in [branches-initial.json](branches-initial.json). The full per-tip review, including common bases, original trees, exclusive commits, per-file Git blob identities and explicit dispositions, is in [branch-reconciliation.json](branch-reconciliation.json). Initial PR metadata is in [pull-requests-initial.json](pull-requests-initial.json).

## Source reconciliation

The current source starts from PR #163 (`f0e4694e`) and combines the following reviewed work:

| Source | Integrated contribution |
| --- | --- |
| `b00819f1`, PR #162 | Streaming payload HMAC verification and memo validation; retained AuthBus and host qualification evidence |
| `0c83ba2f` and its six-commit chain | JWT policy schema 147, explicit/default policy provenance, local JWT batch admission, PKI lookup and orphan-versus-attached token lifecycle |
| `aaf65962`, PR #161 | Bounded credential broker, encrypted personal vault, personal edge, browser/Android adapters and audited consistency retry hints |
| `5327ffe7` | Verified startup rejection and cleanup regression intent, reconciled against the newer original-handle retirement contract |
| `bab45278` client slice | Complete managed Python secrets/template/cancellation integration and the bounded Agent renderer |

The resulting workspace has **53 modules**. The renderer is a library plus thin binary, retaining its original framing/renderer semantics while satisfying the current module-documentation contract.

Conflict resolution preserves the newest native snapshot publication proof and terminal-successor checks, original request deadlines, original Actor custody and no-automatic-replay behavior. It does not replace current Service files with older branch versions. The schema 147 reader/writer and restore downgrade checks are retained. The JWT tests retain the actual native Identity projection and KV graph, the independent issuer-mount control chain, batch issuance and post-commit audit/response vetoes.

Snapshot QA now uses one canonical, bounded gzip receipt, validates framing/CRC/trailing data and expanded size, and explicitly requests compaction before checking committed/purged frontiers. A successful backup download is not treated as proof of compaction, archive authenticity or restore qualification.

## Historical alternatives and evidence

All 91 tips receive a named disposition. Five complete current source/QA tips are integrated; the renderer/client slice is integrated separately; three tips have no net content change; two have byte-identical runtime or equivalent strict assertion evidence. The remaining 80 tips retain their complete original source and evidence through Git history without automatic activation.

This is a deliberate resolution of incompatible designs, **not a claim that all historical implementations are active or semantically equivalent**. The exact original sources remain recoverable using `git show <original-sha>:<path>` after branch names are removed.

Examples requiring explicit separation:

- `6fb6ac67` adds a separate dynamic-secret broker and `sys/dynamic-secrets/*` routes. These are not the current SDK/plugin lease owner and are not silently enabled.
- `ff53eee3` adds an independent RabbitMQ connection/role/lease owner. Current runtime assigns that backend to the Database owner; both cannot be activated by a textual union.
- `09408861` and `a5427185` include a persisted workflow journal/reconciliation model. Current workflows explicitly use the sequential local API profile; crash-resumable workflow support is not claimed.
- The older HBSC snapshot-clock/Denied403/immutable-clock proposals have a different authority protocol from the current native snapshot forwarding owner. Their incomplete or uncompiled status remains explicit.
- Barrier rotation preparation, eight-way preflush experiments, old store/journal designs and the remaining server/HA part of the Agent branch are preserved as historical proposals.
- Historical transport/materializer workflows are not reactivated. The validation branch with 44,095 exported paths remains accessible through history instead of duplicating historical execution trees into the current source tree.

No source history is discarded by branch deletion. Deletion is allowed only after fresh main ancestry verification for every recorded tip and a fresh exact-SHA comparison of the remote branch references. Any concurrently moved branch must be reconciled before deletion.

## Audit findings and corrections

### Installation and browser fixture custody

The Chromium installer accepted an executable or installation ancestry writable by a different UID. This was reproduced with actual filesystem permissions without executing an attacker program. The fix requires an owned executable with safe mode/link properties and protected directory ancestry; symlink and substitution cases fail closed. The corresponding Firefox ancestry boundary is checked as well. These guards do not make same-UID code untrusted; that remains outside the documented boundary.

The Firefox synthetic fixture originally passed Cargo's hard-linked top-level binary directly to an installer that correctly requires a single-link executable. The original fixture was reproduced at 0/13; a separately copied, private, hash-bound binary restored the original **13/13** scenarios with **43 owned children reaped**. Installer rejection of hard links remains intact. Chromium fixture staging likewise preserves the original build digests and separately verifies staged identity.

The credentials workflow now selects changes under both Android adapters and runs explicit installer/staging guards. Host-side Android controls and archived file integrity do not constitute phone qualification.

### CI fixture imports and process retirement

`test_x230_native_abi_capture.py` loaded its helper from the test directory instead of the acceptance root. The fix is tested from an unrelated working directory and against an adjacent shadow module; it fails closed if the intended helper is absent.

The HA rolling and historical snapshot fixtures sometimes waited for the intentionally rejected process, then tried to apply the live-node SIGKILL contract to that already-exited original. They now retire the exact waited process/log, preserve diagnostic and exit-code rejection, and keep live-node shutdown strict. Real-child tests cover zero exit, valid rejection, timeout and cleanup failure. Failed cleanup does not erase the original failure or unconfirmed handle.

### Current Kubernetes renewal versus historical behavior

The older `kubernetes_renewal_live.py` is explicitly a historical 2.6.2 fixture. It expects renewal after assertion expiry without provider revalidation. The current runtime instead retains original JWT custody and performs TokenReview again. Removing that validation to pass the historical fixture would restore unsafe lifecycle behavior.

OpenBao 2.7.1's [`pathLoginRenew`](https://github.com/openbao/openbao/blob/v2.7.1/internal/builtin/credential/kubernetes/path_login.go) calls `handleTokenWithLookup` before updating TTL; see [GHSA-gf3j-hm38-jhh5](https://github.com/openbao/openbao/security/advisories/GHSA-gf3j-hm38-jhh5).

The required current CI step now uses the existing real KIND/OpenBao 2.7.1 fixture with its **79 checks**, complete rejection routes, original TokenReview audit and cleanup requirements. Its candidate is bound to a successful normal build receipt, source commit/tree, binary digest and Rust ABI. The historical fixture and the original 17-versus-101 failed comparison remain unchanged and documented. The live cluster fixture tests RBAC revocation and ServiceAccount deletion/recreation; it does not itself wait for a TokenRequest JWT to expire. The service publication regression covers expired assertions across all three renewal APIs.

The ACL template 400-versus-403 difference was investigated using the actual pinned official 2.7.1 binary, rather than inferring behavior from one upstream source function. The unchanged historical scenario passed 99 pre-restart checks on that binary. Additional observations of `*`, `+` and `red*` confirmed normal service/batch GET and POST return 400, capabilities returns 403, and denied writes preserve state. The current wildcard renderer now matches that observed 400 response; ordinary permission denial, empty-metadata handling and capabilities keep their original contracts. Seven isolated tests of the actual renderer passed, and restoring only the old branch caused the new regression to fail. Complete Service cases compile but are not represented as executed by this isolated test. Exact binary/archive identities, actual observations and observer source are preserved in the [official oracle investigation](../2026-11-15-acl-template-oracle271/README.md).

### Dependency advisories and compatible corrections

The [dependency audit](DEPENDENCIES.md) examines all four Cargo locks, Python QA pins and JavaScript manifests against the recorded official databases. Six compatible Rust dependency updates address rustls, webpki, ctutils, anyhow, rustix and tokio findings. Python QA cryptography moves to 50.0.0 after an isolated 1,768-case acceptance run showed no new fixture errors beyond the same two host admission failures. Current exact crate declarations and the root lock remain consistent; historical probe identities are retained explicitly.

The current-workspace RustSec scan decreases from nine vulnerability records and four other warnings to **two vulnerability records and one maintenance warning**. It still exits nonzero. `rsa` 0.9.10 and `crypto-bigint` 0.5.5 remain behind the latest stable `ssh-key` dependency constraints; moving to the patched major lines requires a separately reviewed cryptographic API migration or backport. The standalone broker's actual dependency graph is Ed25519-only, and server private RSA/ECDSA signing uses OpenSSL, but these observations do not erase the workspace advisory matches. `rustls-pemfile` remains unmaintained. Historical probe and unpinned peer-package findings are also recorded rather than suppressed.

## Security review boundaries

The reviewed broker grants bind the serialized request, broker/config identity and task/run/operation identifiers. Unknown outcomes are journaled before dispatch and are not automatically replayed. Vault source review found bounded KDF parameters, separated AEAD domains, authenticated headers, private no-follow descriptor reads and writer/digest/revision checks. No additional reproducible bypass was found in this reviewed scope.

The current-tree secret-pattern scan examined 9,053 tracked paths at its recorded preparation point and found nine PEM-marker files. Each match was a format assertion or intentionally invalid synthetic PEM negative; no usable private-key literal was present in those nine findings. This is a bounded pattern scan, not an exhaustive history-wide secret-free proof.

The subsequent [Git history secret-pattern audit](SECRET_HISTORY.md) included the complete initial branch graph. Official Gitleaks reported 4,277 commits and about 900 MB of text/diff input, with 4,128 occurrences. All occurrences have explicit dispositions: hashes, request/record identifiers, source expressions, deliberately public synthetic fixtures, invalid test JWT/PEM or marker matches. The 14 JWT/private-key matches and 764 less-obvious generic matches received original-source review; no classification remains unresolved. The report retains the binary/archive and offline-verification limits and does not claim all repository bytes are secret-free.

Known limits remain: same-UID trust, caller labels without hardware/runtime attestation, no protection against complete vault snapshot rollback, and no hardware-isolated password/recovery or process-memory custody. Repository merge does not change these limits or `SECURITY.md`.

## Verification and retained failures

Validation results and original logs are recorded in [validation.json](validation.json). They must be read by source/command and result; targeted repair results do not retroactively pass earlier failed runs.

The preparation checks passed repository/module validation for 53 modules, 300 repository tests and 80 workflow-security tests. The complete acceptance suite initially ran 1,765 tests with three errors: one rolling cleanup API mismatch (subsequently fixed with targeted real-child tests), one denied AF_UNIX socket, and one local system-loader ownership admission refusal. The original client suite ran 224 tests with 218 passes, four existing skips and two AF_UNIX permission errors. These environment refusals were not converted to passes or removed from the suites.

The final acceptance rerun completed 1,766 tests: 1,761 passed, three existing skips and two environment admission errors remained (AF_UNIX creation and system-loader ownership). No assertion was relaxed to accommodate this host. The 17 installer guards, seven Firefox staging guards and four Chromium staging guards passed against the final browser changes.

The initial native build first lacked Clang builtin-header discovery; after configuring the actual available header path, the normal full-codegen attempt was terminated by SIGKILL. These attempts are retained as failed preparation, not full workspace test passes. Full `cargo check --locked --workspace --all-targets` and strict `cargo clippy --locked --workspace --all-targets --exclude qrcode -- -D warnings` then passed. Scoped broker/vault/edge/renderer executable tests completed 39 tests: 30 passed and nine broker process cases failed before Unix-listener startup. A separate minimal diagnostic confirms this host rejects AF_UNIX socket creation with EPERM while permitting socketpair and AF_INET; those nine cases remain failed, not passed. All vault, edge and renderer executable cases passed. Fresh GitHub Actions conclusions are recorded on the consolidation PR and are not inherited from preparation checks.

Earlier actual CI failures remain part of the record: [#163 run 42293086208](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42293086208), [#162 run 42338444046](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42338444046), and [#161 run 42320223033](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42320223033). CodeQL success is not a full native/compatibility qualification verdict. Physical HA, historical migration/restore, provider coverage and production cutover still require their original independent acceptance evidence.

The first published candidate `a0a699b76c9efa1c254990c5c95450b656a1efef` exactly matched the local final tree and retained all 600 initial branch tips, verified again using freshly fetched GitHub objects. Its [workflow trust checks](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/43668896167) passed for both head and prospective merge; its [personal credentials synthetic CI](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/43668883689) passed actual credential crates and native CLI cases. Its [full run](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/43668896303) correctly failed at two of 304 repository guards: the fixed 2.7.1 Kubernetes runner did not yet expose the explicit version argument required by the common oracle prerequisite guard. The repair adds a single permitted `--oracle-version 2.7.1` argument with the same fixed default and an explicit workflow argument. Real subprocess tests reject other versions before work-directory creation or external programs; the common oracle guard and all pinned artifacts remain unchanged. The repaired full repository suite passed 304/304 and the current/historical Kubernetes fixtures passed 35/35. This original failure is retained in the validation record. Later candidate conclusions are bound to their own head and merge identities on [PR #165](https://github.com/TrillionniumFoundation/HeptaBao/pull/165).

## Operational result

After combining the ACL correction and dependency updates, the complete all-target workspace compilation check, strict workspace Clippy, formatting, 304 repository tests, 80 workflow-security tests and 53-module closure passed again. Original logs are retained separately from earlier runs. The updated Python crypto environment and direct official-oracle observations have their own explicit scopes; neither is relabeled as full product execution.

Repository consolidation preserves a development main with its unresolved qualifications visible. The complete native workspace/runtime qualification is long-running (the earlier recorded run spent about 135 minutes in its Rust stage alone and about 322 minutes overall). Its pending, cancelled, failed or successful conclusion must be taken from the exact candidate's live run on PR #165. A pending or superseded run is not a pass, and this audit introduces no suppression, altered denominator or branch-protection bypass to obtain a green verdict.

The final publication and cleanup receipt records the resulting main SHA, final branch count and exact remote reread. Branch consolidation does not grant production, release, migration, credential rotation or service cutover authority, and this task changes none of those live services.
