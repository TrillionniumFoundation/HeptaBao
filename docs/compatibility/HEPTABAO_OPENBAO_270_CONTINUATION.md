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

## Mandatory CI lane

The immutable head/merge workflow independently acquires 2.7.0 and runs these
14 selected profiles with `--oracle-version 2.7.0`: core isolation, Identity,
response wrapping, capabilities, PKI, PKI extension configuration, SSH OTP, file
audit management, namespaces, ACL parameters, ACL templates, wrapping TTL bounds,
KV metadata CAS and KV enumeration. Each comparison needs two nonempty complete
passing traces; matching failed prefixes and process success without matching
cases do not qualify. Any failed profile makes the step fail.

The ACL template comparison is moved from the historical lane into this required
2.7.0 lane because its malformed-input contract changed. Other historical profiles
remain separate. The workflow does not waive failed gates or use continue-on-error.
Reports include exact candidate commit/tree, worktree cleanliness, binary/archive
hashes, runner/launcher hashes, target version and actual reference storage backend.

## Explicit remaining blockers

A full replacement claim is still prohibited until the complete inventory and
2.7.0 delta are independently exercised. In particular:

- Wrapping tokens' new `auth/token/revoke-self` authority is not implemented by
  this continuation. A separate known-red regression preserves the failure;
  ordinary wrapping and wrapping-TTL profile success does not close it.
- External keys, the ML-DSA/PQC surfaces, control-group approvals, and the new
  X-Vault consistency-header behavior require their own implementation and exact
  2.7.0 reference evidence. This continuation does not admit them by inference.
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
