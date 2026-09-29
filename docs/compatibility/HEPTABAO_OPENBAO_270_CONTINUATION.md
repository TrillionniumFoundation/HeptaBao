# OpenBao 2.7.0 continuation and admission boundary

## Target, not a completion claim

The replacement target for this continuation is **OpenBao 2.7.0**, released on
2026-09-23. The existing historical 2.6.2 oracle remains independently selectable.
No historical receipt is relabeled as 2.7.0. A passing bounded profile is not
whole-surface admission, all-asset migration, independent security qualification,
or permission to replace a production cluster.

Official release: <https://github.com/openbao/openbao/releases/tag/v2.7.0>.

## Exact artifact custody

The newly admitted executable platform is Linux amd64 only. Its official release
source revision is `ca305a02daa68b203325daa1b25c18d7a252d4b3`.

| Object | SHA-256 |
| --- | --- |
| Official `checksums.txt` release asset | `654f25b6e105d42c38881d511b28d51a57d0eff1925aff368d7d286ab9a5d501` |
| `openbao_2.7.0_linux_amd64.tar.gz` | `c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667` |
| Unique regular `bao` member and executed binary | `9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e` |

The launcher requires BOTH the exact archive and the exact executable. It hashes
the executable inside the archive separately. Missing, duplicate, linked or
nonmatching members are rejected; live health must report the selected version.
Restart reuses the same selected version and cluster identity, without init.
An unverified architecture is refused before reading caller files or starting a
process. The historical 2.6.2 arm64 pin is not a 2.7.0 arm64 qualification.

The continuation obtained the large archive through a public transport mirror
only after independent retrieval of the official checksum asset; its exact bytes
were verified before extraction or execution. That transport is not a second
Oracle authority. The committed CI acquisition command below downloads from the
official release endpoint with HTTPS-only redirects and bounded reads.

```sh
python scripts/prepare_openbao_oracle.py --version 2.7.0 --output "$PRIVATE_ORACLE"
export HB_ORACLE_BINARY="$PRIVATE_ORACLE/bao"
export HB_ORACLE_ARCHIVE="$PRIVATE_ORACLE/oracle-official.tar.gz"
python qa/openbao-acceptance/policy_templates_live.py \
  --oracle-version 2.7.0 --binary "$CANDIDATE" --output "$PRIVATE_REPORTS/templates.json"
```

Output directories must be new or caller-owned as required by each command, and
report parents must have mode 0700. No live deployment endpoint or credential is
accepted by these bounded comparison runners.

## Storage and version-specific behavior

OpenBao 2.7 removes `file` as a server storage backend. The new non-HA reference
fixture therefore uses durable `pebbledb`, preserving its non-HA topology rather
than silently substituting a Raft cluster. Explicit Raft reference fixtures remain
explicit. This is reference-fixture configuration, not a claim that HeptaBao reads
an OpenBao PebbleDB database or an OpenBao Raft snapshot.

Reference: <https://openbao.org/docs/configuration/storage/pebbledb/>.

A present forbidden wildcard in an Identity ACL substitution must fail the entire
ACL evaluation, including a templated deny beneath a broad literal grant. The
pinned 2.7.0 reference reports HTTP 400 when the affected token attempts a request;
root inspection of that target through `sys/capabilities` instead reports HTTP 403
and discloses no partial capabilities. An ordinary policy denial remains HTTP 403.
The historical 2.6.2 profile has its separate 403 malformed-request contract. A 400/403 union is not used to manufacture differential agreement.

The candidate returns a fixed redacted error, does not echo Identity metadata,
and retains negative read/write, unchanged-state, capability-inspection, restart
and root-repair checks. Missing Identity values remain distinct from forbidden
present substitutions. Existing namespace and token boundaries are unchanged.

## Integrated 2.7.0 continuation behavior

Wrapping credentials now admit exactly `update` on `sys/wrapping/unwrap` and
`auth/token/revoke-self`. Execution and capability inspection share the same
path predicate. POST/PUT self-discard removes the wrapper without exposing its
captured response or affecting a peer wrapper. The original negative authority,
expiry, namespace, replay and durable restart checks remain applicable.
`wrapping_revoke_self_live.py` runs independently against both native services.

`auth/token/revoke-orphan` uses the existing service transaction to remove the
selected stored service-token parent and detach only its direct stored children.
Grandchild edges, policies, issuance metadata, token lifetimes and unrelated
credentials remain unchanged. Sudo admission precedes target resolution; missing
targets and batch tokens remain rejected. `token_revoke_orphan_live.py` requires
83 distinct observations per side, including native process restart and later
ordinary subtree revocation. It is not full Token API qualification.

The HA `/sys/leader` response explicitly includes boolean `is_self`, including
`false` for a standby, matching the 2.7.0 contract. Non-HA responses remain exactly
`{"ha_enabled":false}`. The endpoint stays a passive local observation: it does
not consume a bearer use, manufacture read authority, or replace ReadIndex.
`sys_leader_live.py` selects only the verified 2.7.0 executable and archive,
checks reference health version, uses PebbleDB for the non-HA reference and Raft
for the HA reference, then separately exercises candidate HA lifecycle behavior.
The upstream fields `active_time` and `leader_cluster_address` remain explicitly
unsupported, rather than fabricated from an unrelated local clock or peer socket.

The repeated physical-host replay failure is now covered by a paced real-Raft
regression in `process/replication_tests.rs`. Accumulated multi-entry replay uses
a 128 KiB serialization target while preserving the 768 KiB hard wire limit and
all existing proposal admission. A legal larger entry is sent intact as a
singleton. Only a subsequent entry is deferred; none is dropped, split, admitted
out of order or acknowledged without durable replication. The upstream RPC
budget is unchanged. A small-batch target does not guarantee progress for every
large singleton, slow disk, congested link or WAN deployment.

`ha_multihost_live.py` now anchors a committed index and requires the recovering
node's own passive applied frontier to reach it before declaring catch-up. A
forwarded secret read is no longer sufficient evidence of local recovery. The
loaded profile retains all 54 baseline checks plus its 11 load checks; neither
readiness delays nor retrying business mutations may substitute for those checks.
Earlier failed campaigns and matched-but-invalid report traces remain evidence,
not successes that can be inherited by a new source revision.

## Mandatory CI lane

The immutable head/merge workflow independently acquires 2.7.0 and runs these
19 selected profiles with `--oracle-version 2.7.0`: core isolation, Identity,
response wrapping, wrapping-token self-discard, token orphan revocation, Transit
ML-DSA, consistency-header middleware and actual candidate Raft prerequisites, the product
Python Client and Unix-socket Proxy consistency chain, capabilities, PKI, PKI
extension configuration, SSH OTP, file audit management,
namespaces, ACL parameters, ACL templates, wrapping TTL bounds, KV metadata CAS
and KV enumeration. A separate required step runs the fixed-version
`sys_leader_live.py` lifecycle with the same verified 2.7.0 oracle. Each comparison needs two nonempty complete
passing traces; matching failed prefixes and process success without matching
cases do not qualify. Any failed profile makes the step fail.

The ACL template comparison is moved from the historical lane into this required
2.7.0 lane because its malformed-input contract changed. Other historical profiles
remain separate. The workflow does not waive failed gates or use continue-on-error.
Reports include exact candidate commit/tree, worktree cleanliness, binary/archive
hashes, runner/launcher hashes, target version and actual reference storage backend.

## Consistency middleware and transport continuation

`http_consistency.rs` validates `X-Vault-Index` and ordered `X-Vault-Inconsistent`
values before logical, leader or snapshot dispatch. Indices decode from the
2.7 JSON/base64 envelope; foreign clusters are ignored, duplicate indices and
unsupported policy combinations fail with 400. Unsupported authentication
headers and ambiguous token/framing duplicates remain rejected.

On a standby, the native `heptabao-raft-v1:<u64>` prerequisite must be no greater
than both committed and locally applied indices. `fail` returns 429 with
`Retry-After: 1`; `await-state` waits without holding either the application or
HA mutex; explicit forwarding uses the existing authenticated execution path.
All paths retain the original request deadline and response reserve. A watermark
never authenticates a caller, materializes application state, grants ReadIndex
permission, or authorizes retry of an uncertain business effect.

The listener accepts `consistency_max_index_wait` as a bounded nonnegative
string duration: decimal fractions, consecutive components and the ns/us/µs/μs/
ms/s/m/h units are supported, along with a leading plus and bare zero. Examples
include `25.5ms`, `1s250ms` and `0.5m`. Fraction conversion follows Go's bounded
significant-digit and IEEE-754 nanosecond conversion, including boundary rounding;
whole components and the final budget use checked integer nanoseconds. The limit
is rechecked after conversion. Negative, malformed, over-128-byte and over-60-second values
fail before listener startup. The existing 25 ms minimum and 60 s maximum are
unchanged. Numeric JSON values, nonzero unitless strings and arbitrary HCL are
still outside this native JSON profile. `consistency_fallback_behavior` remains
`fail` or `forward-active-node`; `consistency_missing_header_forward` is unchanged.
The parser adds no retry, changes no Raft deadline, and cannot extend a caller's
original transport deadline or response reserve.

Successful active responses may carry an index only after current-owner linear
observation; failure to obtain this optional metadata cannot convert an already
committed operation into a failed mutation. The header contains only server-
encoded cluster/index metadata. HA `HBFQ4` explicitly negotiates the `HBFS2`
response sidecar; directions, cluster identity and index types remain validated
inside the existing mTLS transport. HBFQ1–3 requests keep their original HBFS1
response shape. The explicit legacy-v1 rolling mode still omits metadata rather
than inventing an index. No blind fallback/replay is added for unknown versions.

`consistency_headers_live.py` requires 52 independent middleware observations
for each of native HeptaBao, official 2.7 PebbleDB and official 2.7 Raft, plus a
separate candidate three-process lifecycle. That lifecycle checks forwarded write
indices, future-index rejection, bounded waiting, authorization and finite-use
preservation, wrapping, restart with a local applied frontier, handoff and quorum
loss. It is not an independent OpenBao multi-node or physical-host qualification.
Native binary snapshots retain their existing transport contract; general mixed-
version client/Agent/Proxy behavior and all backend index formats remain broader
than these checks. Tests must actually execute on the reported immutable source;
the existence of this profile is not a passing receipt.

The PostgreSQL migration profiles now derive the expected current schema from
`git show <exact-build-commit>:crates/heptabao-server/src/service.rs`, never from
the candidate's observed capacity reply. They still require unchanged legacy
read state/frontier, a real mutation promoting the schema, old-reader refusal,
unchanged application artifacts after refusal, and successful current-reader
reopen. Their legacy schema-55/schema-56 commit/tree pins are unchanged.

## Product Python Client and Proxy consistency evidence

`client_consistency_live.py` now executes 35 checks each against native HeptaBao,
official 2.7 PebbleDB and official 2.7 Raft; the unchanged 28-case candidate Raft
lifecycle enters through the product HTTPS Client. A further 14 checks launch the
normal Unix-socket Proxy process with an admitted synthetic sink and a three-node
candidate. Ordered headers, response indices and Retry-After survive actual TLS
and proxy hops; future-index writes have independent unchanged-version readback,
and explicit forwarding commits once. This fixture does not execute an Agent
login/renewal loop and does not establish physical-host or full CLI compatibility.

The SDK retains optional response metadata without turning an acknowledged
mutation into a retry. No cross-request index cache or new bearer authority is
introduced. See `clients/python/README.md` for caller responsibilities when a
response index is absent or invalid. All local refusals are recorded separately
from HTTP observations, and each required trace has an explicit fixed denominator.

The full-workspace run at `5e816021` exposed a test-start race: the selected
follower's committed frontier changed from 4 to 5 while processing pending initial
membership. `Cluster::new` had awaited only the leader. The consistency regression
now waits for that exact initial leader commit to be both committed and applied
on its actual standby before starting the measured request. A deterministic
precondition test rejects incomplete, missing, ahead and wrong-leader observations.
The middleware's original wait/transport limits and both exact unchanged-frontier
assertions remain; application digest, durable generation and audit sequence are
also required to remain unchanged. No production consensus code or timeout is
changed by this fixture correction. The earlier failed run remains evidence.

## Explicit remaining blockers

A full replacement claim is still prohibited until the complete inventory and
2.7.0 delta are independently exercised. In particular:

- External keys, the ML-DSA/PQC surfaces and control-group approvals still require
  their own implementation and exact 2.7.0 reference evidence. The consistency
  middleware now has a real implementation and a required native comparison;
  its bounded profile does not establish general client or storage compatibility.
- General upstream plugin compatibility, complete provider and directory-service
  semantics, namespace key custody/delegation, and full PKI/SSH/JWT/OIDC behavior
  remain broader than the selected passing profiles.
- Complete CLI/Agent/Proxy/UI/platform behavior and authenticated all-asset OpenBao
  migration, cutover, and reverse-delta recovery are separate admission gates.
  HeptaBao-to-HeptaBao rolling tests are not an OpenBao migration result.
- Loaded physical-host HA, disk-full/torn-write and real power-loss testing, WAN
  and long-horizon linearizability, and independent security qualification cannot
  be substituted with loopback three-process scenarios.

Keep raw failures alongside successful reruns. Bind each result to the source and
binary actually executed; a later documentation-only commit is not a new runtime
qualification. Publish only safe reports, never service state, keys, root tokens,
unseal material, credential-bearing logs, or private fixture contents.

## Transit ML-DSA implementation scope

The existing Transit owner now implements generated `mldsa-44`, `mldsa-65` and
`mldsa-87` seeds, raw Base64 public-key descriptors, randomized pure signatures,
verification, rotation, retained-version policy and explicit signing-seed export.
The public-key export does not make the seed exportable. Private export and all
cryptographic requests still enter the existing ACL/audit/namespace transaction.
`transit_mldsa_live.py` independently exercises fresh native services and restart
against the checksum-pinned official 2.7.0 executable. Only an actually completed
report at its recorded source counts; adding the runner is not a passing receipt.

The dependency is exact-pinned RustCrypto `ml-dsa` 0.1.1, with `zeroize`, `alloc`
and `rand_core`, plus the already pinned system entropy dependency. Its upstream
documentation explicitly states that the implementation has not been independently
audited: <https://docs.rs/ml-dsa/0.1.1/ml_dsa/>. This is not independent security
admission. No OpenBao implementation source was translated for this addition.

Key import, certificate chains, PKI ML-DSA, PQC TLS, external-mu/context/hash
options and full field/error parity remain unqualified. Nonempty derivation
contexts, prehash/signature options and unsupported fields are explicitly refused;
they are not silently mapped onto pure signing. See the schema-62 format contract
for old-reader refusal, retained key material and mutation-only promotion.

## Local qualification port selection

The three-node fixture selects its six API/Raft ports as one bounded batch, with
all selection sockets simultaneously bound until the batch is complete. A port
freed by an earlier node can no longer be selected again for a later node in the
same fixture. The duplicate-port check remains. All handles close on success or
partial allocation failure, and malformed counts are rejected before allocation.
This is not a cross-process port lease: an actual later bind/start failure still
fails the campaign. It does not replay initialization or application mutations,
change any HTTP/HA deadline, or admit a failed earlier campaign as passing.
