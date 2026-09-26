# Section-six integrated runtime and remote validation

Subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`; not a replacement master plan,
compatibility admission, release or production rollout.

## Exact implementation inputs

This candidate starts from remote PR96 `1425b9e20fdbba0c78c75a67849feef418adbf1c`
(tree `13b30c5c0bbbd92f76b70181f981e3f2887eb6b5`) and integrates the previously
local online-auth candidate `bf83a7130de266e220ba7cc107f39bbadcdc7b9a`
(tree `986cf8d7522ee3189e095628bd67156e555a8f8b`). The latter includes the
`95206fd79adedd879530c6f4295a97cbb6510060` capacity/error-ordering/preflight work.
The merge is semantic, not an overwrite of one source tree with the other.

The record-store delivery `d4797a1bbfba1676fa643dfe3567035ff2460d7af` was not in
the available source bundles or remote product refs at integration. Its delivery
report is not source. This candidate neither contains nor discards that separate
implementation and must not claim redb storage, record-store HA, a larger state
budget or its prior tests. A future integration must reconcile its format with
this candidate's application schema 5; the same schema numeral is not proof of
compatible serialized state.

## One durable maintenance policy, both compatible metadata routes

`DurableService::put_with_maintenance` is retained for PR96 callers and delegates
to `put_with_compaction`. Both use the same exact-request policy: only a definite
pre-entry journal-capacity refusal permits one authenticated checkpoint and one
retry. Identity conflicts, uncertain publication, full permanent replay ledgers,
I/O failures and recovery fences do not authorize repetition or garbage collection.
All inherited negative tests remain. The Service mirrors the durable recovery
fence even if checkpoint publication failed without a new operation intent.

Both `GET /v1/sys/internal/storage/capacity` (PR96 shape) and
`GET /v1/sys/internal/capacity` (expanded shape) remain root-token/root-namespace
only, audited and non-reserving. Neither is an OpenBao compatibility claim.
Legacy and expanded route tests both execute. The original PR96 capacity fixture
is retained byte-for-byte as `capacity_legacy_live.py`, with its original
private-output negative tests and a separate required real-service CI invocation. Capacity rejection after committed
Raft or provider effects retains reconcile-only semantics and cannot be confused
with a safe before-entry retry.

## Actual Kubernetes gate

`qa/openbao-acceptance/kubernetes_cluster_live.py` creates a fresh randomly named
single-node KIND cluster only with explicit `--allow-disposable-cluster` permission.
KIND v0.31.0 Linux amd64 is pinned by SHA-256
`eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa`.
Linux arm64 uses its separate official executable digest
`8e1014e87c34901cc422a1445866835d1e666f2a61301c27e722bdeab5a1f7e4`.
The runner selects the native architecture and verifies its executable before
contacting Docker; unsupported architectures do not fall back to emulation.
The node image is `kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f`.
These fixed upstream inputs come from the official KIND release metadata:
https://github.com/kubernetes-sigs/kind/releases/tag/v0.31.0 . They are a synthetic
acceptance baseline, not a recommendation to deploy that version or a promise of
support for all current Kubernetes distributions.

The fixture uses the actual API server, etcd-backed objects, RBAC role/binding,
ServiceAccount TokenRequest and TokenReview endpoints. The reviewer receives only
`create` permission on `authentication.k8s.io/tokenreviews`, not cluster-admin.
The fixture's administrator certificate is used only to provision its own cluster.
HeptaBao's authentication mount receives the reviewer bearer and API-configured
CA/host. The separate Kubernetes secrets engine retains its startup endpoint
enrollment. Neither receives the cluster administrator key.

Required observations include actual audience and namespace rejection, a modified
signature, encrypted Service restart, deletion/recreation of a same-named account
with a different UID, denial of the old JWT, separate local identity for the new
UID, revoked/restored reviewer RBAC, and auth-unmount local-token revocation.
Read-only TokenReview/SubjectAccessReview observations wait for control-plane
cache convergence before one tested login; uncertain logins are never retried.
Issued HeptaBao service tokens use native local renewal against their current
role. The fixture renews an existing token while reviewer RBAC is revoked,
without another TokenReview. Later ServiceAccount deletion does not continuously
revoke issued local tokens. The separately issued Kubernetes secret tokens keep
their bounded, nonrenewable lease behavior.

Ambient KUBECONFIG, external/exec credentials, TLS bypass, remote Docker hosts and
nondefault Docker contexts are rejected or removed. The only admitted API origin
is the loopback endpoint in the single newly generated embedded-certificate config.
The report directory is admitted before creating any cluster; all certificate,
JWT, kubeconfig and database state stays in a new 0700 root and is removed. Cleanup
is attempted after every failure. The report contains fixed case names and public
source/binary/version identifiers, not runtime secrets. Missing KIND, Docker,
image admission or actual API prerequisites is blocked (exit 77 where applicable),
never a simulated pass. Containers are not separate physical hosts, and a passing
fixture is not browser UI, distribution, physical-fault or independent security
qualification.

Run in a disposable Linux amd64 or arm64 Docker environment:

```text
python qa/openbao-acceptance/kubernetes_cluster_live.py --binary /absolute/heptabao-server --kind /absolute/pinned-kind --output /absolute/new-0700-dir/kubernetes.json --allow-disposable-cluster
```

The [recorded ARM64 run](../../qa/openbao-acceptance/evidence/actual-kubernetes-bede079.json)
passed 47 checks against production source `a14a7fd` with clean harness
`bede079`. It exercised actual Kubernetes v1.35.0 API/etcd/RBAC on a new local
KIND node, then removed the node. Completion requires named security and
lifecycle observations, not a fixed numeric check count. This receipt qualifies
that selected binary and single-host scenario only.

Upstream protocol references:
https://kubernetes.io/docs/reference/access-authn-authz/authentication/ and
https://kubernetes.io/docs/reference/access-authn-authz/rbac/ .

## Exact Python prerequisites and current-head evidence

`scripts/verify_python_environment.py` compares every direct exact requirement in
`requirements-plan.txt` with the installed distribution version. Missing packages,
newer-but-different versions, duplicate names, empty requirements and loose ranges
do not satisfy this gate. It does not claim a transitive dependency lock. CI runs
this read-only check immediately after dependency installation on both the exact
head and real prospective-main tree. Earlier local executions using different
PyYAML/jsonschema versions are not upgraded into exact-pin evidence.

The original workspace, strict lint, rustdoc, TLS, HA, encrypted-link partition,
private clients, real PostgreSQL, fixed official-binary corpus, KV migration,
Transit re-encryption and five-process Raft gates remain required. The new native
OIDC and Kubernetes protocol/HA fixtures remain separate from actual-cluster
execution. A failed, absent, timed-out or stale-head run remains failed or blocked.
Current CI logs/receipts bind each execution, not this document or prior PR prose.

## Remaining implementation and authority boundaries

Record-store convergence and HA; replay retirement and large streaming states;
remaining authentication/MFA, generic providers, plugins/KMS/HSM and full clients/UI;
all-asset migration, write freeze and atomic single-writer cutover; mixed-version
and multi-host/disk/power qualification remain open. Hepta's real Rust consumer and
separate signer require their own exact-source execution before its pin advances.
No pin, deployed service, secrets, branch protection or main merge is modified here.
Independent review/custody/operations evidence cannot be self-issued by this work.
The original 60-surface/55-case corpus is unchanged. Both development maps remain
subordinate projections, not compatibility receipts; available profile changes
must never promote their original fixed-corpus status.
