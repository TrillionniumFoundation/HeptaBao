# Genuine Kubernetes renewal qualification for OpenBao 2.7.1

`qa/openbao-acceptance/kubernetes_renewal_271_cluster_live.py` is the current
renewal gate. It compares a source-bound native HeptaBao binary with the pinned
official OpenBao 2.7.1 archive member against one newly created KIND cluster.
The existing 2.6.2 synthetic renewal fixture remains historical evidence.

OpenBao's [2.7.1 renewal implementation](https://github.com/openbao/openbao/blob/v2.7.1/internal/builtin/credential/kubernetes/path_login.go)
revalidates the stored JWT with `handleTokenWithLookup` before extending a lease.
This is the fix for
[GHSA-gf3j-hm38-jhh5](https://github.com/openbao/openbao/security/advisories/GHSA-gf3j-hm38-jhh5).
Removing TokenReview to match 2.6.2 would restore the vulnerable lifecycle.

## Required CI binding

Both exact-head and prospective-merge lanes run this profile as a required
step after the pinned KIND and official 2.7.1 prerequisites. The normal locked
server build writes its native-build receipt only after its actual command
returns successfully and the commit, tree and clean source still match the
initial binding. The fixture checks that receipt and its hash against the
same source and executable. Missing Docker, failed downloads, missing receipts,
a timeout, a failed check or cleanup failure blocks the full verdict. The
600-second CI process envelope does not alter the fixture's request deadlines,
79-check denominator, single-attempt mutations or ownership checks.

The historical 2.6.2 script and its expected statuses remain unchanged. In
[run 42320223033](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42320223033),
the current candidate reached 17 observations and denied renewal after the
fixture expired its assertion and disabled its provider; the old reference
completed 101 observations with provider-free renewal. That failed comparison
is preserved. Wiring this separate current gate does not relabel that result
or establish a new live pass.

The existing live denominator covers reviewer RBAC denial and deleted/recreated
ServiceAccounts; it does not wait for a real TokenRequest JWT to expire.
Service publication regressions separately inject expired/revoked-assertion and
unavailable-provider outcomes on every token renewal route and require no
auth/wrapping authority and byte-identical auth state. Those are unit evidence,
not a claim of live expiry coverage.

The test uses a loopback-only API server, etcd, real TokenRequest JWTs and real
Kubernetes RBAC. It creates its own `hb-accept-<random>` cluster and two namespaces
inside that new cluster. It rejects ambient kubeconfig and remote Docker inputs.
It does not use an existing cluster or mutate production namespaces.

| Input | Required identity |
| --- | --- |
| KIND | 0.31.0, Linux AMD64; SHA-256 `eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa` |
| Node | `kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f` |
| Reference | Official 2.7.1 binary and archive pins checked by `official_openbao_launcher.py` |
| Candidate | Explicit source commit, tree, unchanged tracked source and binary SHA-256 before and after; hash-bound `heptabao.native-build.v1` receipt |
| API audit | Metadata-only TokenReview records bound to the actual reviewer UID; unique audit IDs, exact resource/path/stage/verb and expected HTTP status |

The fixed denominator is 79: 29 named checks for each implementation and 21
common checks. An incomplete denominator, failed case, source change, credential
in the report, missing final audit artifact, or failed lifecycle cleanup keeps
the result failed. Build-receipt admission is part of `candidate_source_freeze`
and does not add a case or change the denominator.

The native build receipt must record the exact source commit, tree and candidate
binary SHA-256, integer `build_exit_code: 0`, `source_freeze_verified: true` and a
nonempty bounded native ABI. The receipt file's expected SHA-256 is mandatory.
Matching independent source and binary pins cannot replace a build receipt.

The four renewal routes are self, administrator, accessor and a token with a
loopback CIDR bound. Self, administrator and CIDR renewal must return the same
renewable token. Accessor renewal must return the issued accessor and withhold
the bearer token. Each route must cause one successful real TokenReview. The
first positive renewal for each
issued token must extend its exact expiry; subsequent calls do not depend on
second-level timestamp changes. The following scenarios are separate:

1. Revoke the reviewer's TokenReview RBAC while the worker JWT remains valid.
   Every route must deny renewal, return no auth/wrapping authority and leave
   its exact `expire_time` unchanged. The API audit must show one rejected
   TokenReview with HTTP 403 for each renewal.
2. Restart each service with the same encrypted store while reviewer RBAC
   remains revoked. Repeat all four routes with the same denial requirements.
3. Explicitly restore reviewer RBAC. A new renewal must succeed with a fresh
   real TokenReview.
4. Delete the worker ServiceAccount and observe that the real API rejects its
   old JWT. Repeat all four denied renewals. These TokenReviews reach the API
   successfully (HTTP 201), which rejects the old ServiceAccount identity.
5. Recreate the same ServiceAccount name with a different UID. A new JWT can
   log in, while the old JWT stays rejected. Auth unmount revokes issued tokens.

Only the generated node is stopped or removed. Cleanup verifies its full
container ID, cluster label, name, pinned image and private audit-policy mount.
It removes that ID without force only after observing the same instance has
stopped with PID zero, verifies its anonymous volumes are absent and verifies
no container with this owned cluster label remains. Stop errors and observed
state transitions stay in `cluster/owned-cleanup.json`. There is no Docker
daemon restart, wildcard process signal or shared network/volume cleanup.

Set `HB_ORACLE_BINARY` and `HB_ORACLE_ARCHIVE` to the official pinned inputs;
`HB_ORACLE_WORK_ROOT` can point at the private evidence parent. Supply:

```sh
python3 qa/openbao-acceptance/kubernetes_renewal_271_cluster_live.py \
  --binary /absolute/frozen/heptabao-server \
  --expected-binary-sha256 <sha256> \
  --candidate-source-root /absolute/frozen/source \
  --source-commit <commit> --source-tree <tree> \
  --native-build-receipt /absolute/frozen/native-build.json \
  --expected-native-build-receipt-sha256 <receipt-sha256> \
  --kind /absolute/pinned/kind \
  --work-root /absolute/owner-controlled/new-evidence-root \
  --allow-disposable-cluster
```

The private evidence includes `summary.json`, immutable numbered phase files,
actual TokenReview metadata and cleanup observations. Preserve failed runs;
supplementary cleanup evidence does not rewrite their original result. A pass
qualifies this renewal/revocation surface for the exact candidate recorded. It
does not grant production authority or prove full OpenBao replacement.

The nonsecret actual reviewer ServiceAccount UID is stored in the report. Each
login or renewal must add exactly one previously unseen audit ID with that UID
and reviewer username, `ResponseComplete` stage, `create` verb, the exact v1
TokenReview resource and request URI, and the scenario's expected API status.
Each operation records its audit ID and user agent for inspection. User agents
are descriptive metadata and never authorize an event. The final metadata file
must retain every audit ID already admitted; capture or write failure makes
lifecycle cleanup and the overall result fail.

Earlier R1–R6 receipts retain their original results and runner identity. In
particular, an earlier R6 pass with independent source/binary pins proves only
its recorded renewal/revocation surface. It does not satisfy this runner's new
native-build receipt requirement. Unit tests use synthetic receipt/event data
to verify rejection rules and never count as a live provider qualification.
