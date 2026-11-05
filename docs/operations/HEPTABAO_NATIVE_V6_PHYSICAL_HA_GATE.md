# Native V6 physical HA gate

`qa/openbao-acceptance/native_v6_ha_multihost_live.py` is a separately named
physical-host profile for Mac, ROG and Pocket4. It starts three new synthetic
fixture roots with the explicit `--experimental-native-v6-ha` server flag.
It has **89 required checks**. It does not change or borrow the separate
mixed-native loopback baseline's 62-check denominator.

Adding this profile is not evidence that its physical run passed. A pass needs
the final, secret-safe `summary.json` from one actual execution, exactly 89
distinct successful cases, the same source and native artifact bindings, and
successful cleanup of all owned server processes and SSH children. A failed,
interrupted or still-running job remains unqualified.

## Inputs and isolation

The command accepts the existing multihost arguments, including these bindings:

| Argument | Required meaning |
| --- | --- |
| `--source-commit`, `--source-tree` | The exact frozen source SHA-1 identifiers. |
| `--binary-source`, `--expected-binary-sha256` | Canonical source and digest for the default native artifact. |
| `--node-binary` | Optional per-node native artifact override, bound to the same source commit and tree. |
| `--native-build-receipt` | Exactly one hash-bound build receipt per voter, including successful build, verified source freeze and native target ABI. |
| `--node` | Exactly three distinct SSH aliases, private addresses and **new** owner-controlled absolute roots. |
| `--work-root` | A new absolute directory under an existing canonical owner-controlled parent. |
| `--allow-private-tailnet` or `--allow-private-lan` | Exactly one admitted private address scope. |

The optional API, Raft and three mesh port bases must describe disjoint
unprivileged ports. There is no request-budget override. Use the same already
verified host and artifact arguments as the baseline, with **fresh** work and
node root paths. `--help` lists the complete syntax without contacting a host.

The original complete loopback SSH mesh carries actual end-to-end pinned mTLS
between the three physical voters. SSH and SCP require existing host-key
verification and noninteractive authentication. This profile does not qualify
direct LAN partition behavior. The certificates and replication key are new,
synthetic, private fixture material.

Each new node root gets an owner marker bound to the run identifier, device,
inode and absolute path. Startup and termination preserve the existing Linux
PID/start-ticks/pidfd checks or Darwin exact BSD `ps` identity checks. The Darwin
PID observation remains explicitly non-atomic. The process adapter admits only
the standalone seed or the exact native-HA argv in that same new root. It does
not stop an existing ordinary HA service or accept a foreign numeric PID.

## Actual runtime sequence

The profile creates a small V5 seed through real HTTPS initialization, unseal,
KV2 mount setup and two versioned writes. It stops that seed, checks its cold
archive for unsafe entries, and clones its private data to the other two new
roots. The three HA processes then elect a leader while sealed, unseal, and
activate V6 through the actual root-authorized HTTP route.

Two no-op requests exercise unchanged KV2 configuration and deletion of absent
metadata. They must return 204 while both the actual local durable generation
and actual Raft committed index remain unchanged. These observations do not
invent a public V6 root-hash API or relax the root-CAS intent's unequal-root
requirement.

Seventeen consecutive CAS writes add exact 2 MiB values to one retained KV2
history, producing 34 MiB of large payloads at versions 3 through 19. Every
write is submitted once, followed by SHA-256 readback. The profile checks the
actual native capacity route and all retained versions. It then soft-deletes
the small V5 version 1 and destroys the small V5 version 2. Their 404 responses
must contain null secret data and the correct version/deletion metadata; all
17 large native versions stay readable.

Large requests go directly to an observed elected leader. The existing 1 MiB
forwarding frame is retained. A separate small, authenticated KV write and
reads through standbys exercise real forwarding and ReadIndex admission.

The lifecycle then performs an actual identity-checked leader SIGKILL,
reelection, complete retained-history readback, a new acknowledged write, and
old-leader cold rejoin with observed local Raft frontier catch-up. With two
voters stopped, the remaining node must lose authority, reject one write with
503 and no secret payload, and reject a protected read. After quorum returns,
the denied key must be absent on every node. An all-voter stop/reopen preserves
the actual committed frontier and data, followed by another new write.

Each HTTP operation remains within **15 seconds**. The runtime's independent
fresh ReadIndex/closure admission remains capped at **8 seconds** inside the
original request. Read-only election/frontier observation windows allow the
cluster to settle between requests; they do not retry a mutation, unseal,
publication or unknown write outcome.

## Missing-ciphertext leader recovery

After ordinary cold unseal has verified each node's current native store, all
three processes stop. The profile quarantines every regular ciphertext leaf
matching `v6-[0-9a-f]{64}.blob` from two voters' owned
`raft/native-v6-ciphertext` directories. It retains all manifests, directory
identities, locks, Raft data and local barrier data.

Quarantine reserves each destination with a no-replace hard link. The complete
destination set, private inventory and parent directory are fsynced before
source names are removed; both affected directories are then fsynced. Each
leaf is checked with no-follow file access, identity, owner/mode, size and full
SHA-256. An interruption can leave duplicate private links but cannot turn an
unverified destination into authority to remove source bytes. An incomplete
quarantine remains a failed fixture, not an automatic retry.

Only the two missing-ciphertext voters start first. They elect a sealed leader,
so the selected leader necessarily lacks its native ciphertext. The complete
third voter starts sealed as a recovery source. Immediately before unsealing
the selected missing leader, its store must still contain zero ciphertext
leaves. Cold unseal and all retained-history reads must then succeed within
their original budgets, with `sys/leader.is_self` confirming that the reader
is the actual current leader.

The resulting physical files must include at least 34 MiB of rebuilt
ciphertext, with every rebuilt leaf's name, length and SHA-256 matching the
original private quarantine inventory. Only the currently required closure
must return: old unreachable ciphertext can remain quarantined. HTTP success
alone is insufficient, because the test also requires actual native-store
leaf reconstruction.

## Evidence and remaining gates

The runner keeps fsynced phase receipts and a final private `summary.json`.
Public console output contains only a fixed result classification and check
count. Secrets, response payloads, unseal material and private keys are not
included in that receipt. The new node roots retain their private process,
audit and configuration evidence for later explicit inspection.

Successful cleanup removes the synthetic application metadata and confirms
its absence, stops only owned server identities, and closes the controller's
own SSH children. It preserves the new fixture directories and quarantines as
reviewable evidence. It does not delete any old production asset.

The companion local tests exercise actual temporary files and owned native
child processes. They check refusal of a substituted PID, live unrecorded
processes, wrong owner markers, symlink leaves and corrupt rebuilt bytes. They
also check that process-cleanup failure still terminates an owned SSH child.
These local tests do not count toward the physical 89-check result.

Native HA snapshot export/restore remains a separate gate. This profile never
calls the baseline backup endpoint or labels its unexecuted snapshot checks
as passed. Physical power loss, disk-full recovery, long-horizon linearizability,
production traffic switching and old-production cleanup also remain outside
this synthetic profile. If a controller connection disappears while a job's
state is unknown, inspect that original job and its owned evidence; do not
repeat the physical mutation sequence as a substitute for reconciliation.
