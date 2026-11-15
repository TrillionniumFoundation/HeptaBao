# Direct LAN98: exact inputs, original deadlines, and evidence scope

This change prepares the existing 98-check Mac/ROG/Pocket4 fixture for newly
built binaries. It repairs four cases in which a read started before an outer
deadline could supply successful evidence after that deadline. It also binds
the actually imported `fixture_mounts.py` in the driver's source inventory and
adds a read-only projector from a completed physical host-run summary to the
existing native-build receipt format. No product code, required check name,
denominator, declared deadline, mutation retry policy, TLS setting, or
production service is changed.

The product cohort for this preparation is commit
`0f1c996136aae94e99c2b709a5797ffea479f6cd`, tree
`8befd5cedfb7ccafee5f707e5985d49eeb78fb60`. The product's full manifest contains
2,882 files. Actual new binary and completed host-run digests must be supplied
from their primary host receipts; the template intentionally leaves them null.
This document and the local checks are not a new physical LAN98 result.

## Source and binary identities are separate

The original driver's `--source-commit` and `--source-tree` arguments bind the
**tested product binary cohort**. Each of the three native-build receipts must
match those two identifiers, its actual binary SHA-256, build exit code 0,
verified source freeze, and the actual target host's native ABI. The Mac and
Linux binary bytes are naturally different, but their source cohort must be
identical. One actual Linux artifact and its receipt may be explicitly bound
to both Linux voters; each voter still gets its own receipt binding, remote
binary digest check, and actual hostname/OS/architecture check.

The **executing QA driver** can be a later commit containing only this
deadline/evidence change. Keep its actual Git commit/tree and exact eight
source blob/SHA-256 values in the outer launch receipt. Do not relabel a 0f1c
binary as having been built from that later QA commit. The driver's own
`runner_sha256`/`helper_sha256` records and final unchanged-source check bind
the executing bytes independently. The eight imported/directly executed files
are:

- `qa/openbao-acceptance/native_v6_ha_direct_lan_live.py`
- `qa/openbao-acceptance/native_v6_ha_multihost_live.py`
- `qa/openbao-acceptance/ha_multihost_live.py`
- `qa/openbao-acceptance/ha_three_host_loopback_live.py`
- `qa/openbao-acceptance/native_fixture_recovery.py`
- `qa/openbao-acceptance/fixture_mounts.py`
- `tools/physical_ha_loopback_mesh.py`
- `tools/physical_ha_peer_preflight.py`

Keep the checkout layout intact: the loopback helper imports its pure plan
helper through `../../tools`, even though the direct-LAN profile creates no
SSH tunnel. This QA profile needs standard-library Python with its declared
syntax support, OpenSSL, and the existing SSH/SCP host aliases. It does not
borrow the migration controller's Python-specific source identity mechanism.

## Project actual physical55 build evidence

`native_build_receipt_from_host_run.py` reads the **completed** primary
host-run summary, its exact manifest, the retained successful build/compiler/
binary-format command logs, and the actual owned binary. It verifies file
identity while reading, all supplied SHA pins, the exact native build command,
the compiler's host triple, native binary format, and both complete source
checks recorded by the pinned host runner. The output's source-freeze basis is
that primary host-run verification, not a new source walk by the projector.

Run the projector on each artifact's owning host after `runner_completed` is
true. Supply actual absolute owned paths and exact digests:

```sh
"$LAN_PYTHON" "$LAN_DRIVER/qa/openbao-acceptance/native_build_receipt_from_host_run.py" \
  --summary "$LAN_ACTUAL_HOST_SUMMARY" \
  --summary-sha256 "$LAN_ACTUAL_HOST_SUMMARY_SHA256" \
  --manifest "$LAN_ACTUAL_PRODUCT_MANIFEST" \
  --source-commit 0f1c996136aae94e99c2b709a5797ffea479f6cd \
  --source-tree 8befd5cedfb7ccafee5f707e5985d49eeb78fb60 \
  --runner-sha256 38024bcb83884da1b8b1b8aa4865c9c545fd0bb30f4d235c7a34e0d5d07815bc \
  --output "$LAN_NEW_NATIVE_BUILD_RECEIPT"
```

The output path must be new, inside a canonical owner-controlled directory.
It is created with `O_EXCL|O_NOFOLLOW`, mode 0600, and file/directory fsync;
an existing receipt is never overwritten. Inputs reject symlinks, multiple
hard links, unexpected ownership, writable group/other bits, oversized data,
and changes during the read. The projector neither compiles nor executes a
binary, and performs no network operation.

A successful build from a host run with a failed scoped test can be projected
as successful **build evidence**. Its original `failed_or_blocked` scoped test
status is retained in provenance. This does not make the failed test pass and
does not assert that LAN98, migration, credential cutover, or cleanup passed.
The format matches the unchanged `validate_build_receipt` admission routine.

## Exact launch input

Fill `LAN98_LAUNCH_INPUT_20261019.template.json` from current observed inputs.
The historical addresses below are only the actual old 03 mapping; obtain a
fresh local address/host observation before placing them into `current_lan_ipv4`.

| Voter | SSH alias | Historical LAN IP | TLS DNS name | New root admission |
| --- | --- | --- | --- | --- |
| 1 / Mac | `macbook-pro` | `192.168.0.7` | `node-1.heptabao.synthetic` | `/Volumes/T5/…` |
| 2 / ROG | `rog` | `192.168.0.10` | `node-2.heptabao.synthetic` | `/home/qian-qi/…` |
| 3 / Pocket4 | `pocket4` | `192.168.0.9` | `node-3.heptabao.synthetic` | `/home/alex/…` |

All roots, plus the coordinator work root, must be new under an existing
canonical owner-controlled parent. The controller refuses occupied API/Raft
endpoints and does not gain authority over an existing listener. Source
artifacts use `source-alias:/absolute/path`; `local:/home/qian-qi/…` is the
coordinator's native Linux artifact source. The historical X230 binary from a
different source cohort cannot satisfy the 0f1c bindings.

After filling and independently pinning those inputs, this is the exact CLI
shape on the main coordinator. Every variable below is an actual input, not
an invitation to use a sample hash or existing fixture root:

```sh
"$LAN_PYTHON" "$LAN_DRIVER/qa/openbao-acceptance/native_v6_ha_direct_lan_live.py" \
  --binary-source "$LAN_LINUX_BINARY_SOURCE" \
  --expected-binary-sha256 "$LAN_LINUX_BINARY_SHA256" \
  --node-binary "macbook-pro,$LAN_MAC_BINARY_SOURCE,$LAN_MAC_BINARY_SHA256,$LAN_PRODUCT_COMMIT,$LAN_PRODUCT_TREE" \
  --node-binary "rog,$LAN_LINUX_BINARY_SOURCE,$LAN_LINUX_BINARY_SHA256,$LAN_PRODUCT_COMMIT,$LAN_PRODUCT_TREE" \
  --node-binary "pocket4,$LAN_LINUX_BINARY_SOURCE,$LAN_LINUX_BINARY_SHA256,$LAN_PRODUCT_COMMIT,$LAN_PRODUCT_TREE" \
  --native-build-receipt "macbook-pro,$LAN_MAC_RECEIPT_SOURCE,$LAN_MAC_RECEIPT_SHA256" \
  --native-build-receipt "rog,$LAN_LINUX_RECEIPT_SOURCE,$LAN_LINUX_RECEIPT_SHA256" \
  --native-build-receipt "pocket4,$LAN_LINUX_RECEIPT_SOURCE,$LAN_LINUX_RECEIPT_SHA256" \
  --source-commit "$LAN_PRODUCT_COMMIT" --source-tree "$LAN_PRODUCT_TREE" \
  --node "macbook-pro,$LAN_MAC_IP,$LAN_MAC_NEW_ROOT" \
  --node "rog,$LAN_ROG_IP,$LAN_ROG_NEW_ROOT" \
  --node "pocket4,$LAN_POCKET4_IP,$LAN_POCKET4_NEW_ROOT" \
  --api-port 46230 --raft-port 46231 \
  --work-root "$LAN_NEW_COORDINATOR_ROOT" --allow-private-lan
```

The node order fixes IDs 1/2/3. The direct profile rejects tailnet mode and
non-RFC1918 addresses. Its inherited unused mesh port arguments must still be
distinct; the defaults 55200/55300/55400 are valid and create no tunnel child.
Use the exact process identity returned by the outer owned launcher to poll
the run. A lost launcher response is not permission to submit it again.

## TLS observations and direct application traffic

The controller creates a new private CA and three leaves with serverAuth and
clientAuth, each leaf's synthetic DNS name and its actual IP SAN. Direct
server/HA listen and peer addresses stay on the declared LAN IPs. SSH only
installs owned files and controls exact owned processes; no forwarding,
routing, firewall, or existing service configuration is changed.

Six independent real peer TLS probes originate on the three actual voters.
They use the local leaf/key, trusted CA, TLS 1.2 or later, the destination's
synthetic DNS SNI, `heptabao-raft/1` ALPN, and the exact destination leaf hash.
They prove those six pinned handshakes, not election or application authority.
Three additional API handshakes use synthetic DNS SNI and pin each API leaf.

Ordinary business HTTP uses the existing `base.api` urllib path:
`https://<actual-ip>:46230/v1/…`, a trusted CA and the **IP SAN**, disabled
proxies, no redirects, and bounded JSON responses. It does not inject the
synthetic DNS SNI or pin a leaf on every business request. Thus the independent
DNS-SNI handshake probe and ordinary IP-URL HTTP are different observations.
The first fresh-node listener check must receive a complete health response
through that actual urllib path on the new binary; an older DNS-SNI probe
cannot substitute for it. No TLS/SNI workaround is included in this change.

## Fixed fault profile and unchanged budgets

The native parent has 89 required checks. The direct profile replaces the
single loopback-mesh check with its endpoint check, six peer checks and three
API leaf checks, for exactly **98**. The exact name set still equals the old
03 required denominator; no failed stage has been removed.

| Phase | Required evidence | Original bounds / behavior |
| --- | --- | --- |
| Fresh V5 seed | New private roots, source/native ABI receipts, one initialization, explicit KV2 mount, two retained versions, cold archive | 45s listener; one mutation attempt; 128MiB/16,384-entry cold seed bound |
| HA bootstrap and activation | Original keys, real sealed election, all voters unsealed, one V6 activation, V5 history preserved, no-op generation/frontier unchanged | 60s stable election, 2.2s stability; 15s HTTP; independent 8s native admission |
| Native history | 17 single CAS writes of 2MiB each, versions 3–19 retained exactly, total 34MiB, v1 soft-deleted and v2 destroyed, small standby write/read | Each large read goes directly to the elected leader; no forwarding-frame enlargement |
| Leader loss | Identity-checked SIGKILL, different elected leader, exact retained history and new write, old voter cold restart and local applied-frontier catch-up | Fixed 6s election quiet period; 60s leader/catch-up; no write replay |
| Quorum loss | Stop two exact owned voters, last voter loses authority, one denied write and read, denied key absent after recovery | Original 35s authority-loss deadline; one 3s health request at a time; 15s application request |
| All-voter restart | Stop all, persistently restart 2/3/1, sealed election, original-key unseal, each local frontier caught up, exact history and new write | Original 45s listeners, 60s elections/frontiers, 15s requests |
| Missing ciphertext | Stop all; quarantine two voters' owned immutable leaves; elect an empty sealed leader; rejoin intact source; fetch exact 34MiB closure on original-key unseal; compare rebuilt leaves | Owned root/device/inode checks; preserved manifests/Raft/barrier; original 15s request / 8s admission |
| Finish | Synthetic metadata removed once, absent on all nodes, helpers and all binaries unchanged, secret-safe report, all exact owned processes stopped | Cleanup required even on failure; exactly 98 passing checks required for direct qualification |

Additional unchanged bounds are 1.5s listener HTTP calls, 2s leader-health
calls, 8s base leader calls, 2s sealed-health calls, 1,500ms peer timeout,
8,000ms forwarding timeout, 32 HA inflight, 15s SSH per direct preflight host,
2s per TLS probe operation, and a 5s owned process-stop observation. File
copy/install/archive helpers retain their separate existing timeouts.

The repair only rejects successful observations at or after the original
outer deadline. It does not reset or extend that deadline. The synchronous
HTTP helper's socket timeout is not a separately cancellable wall-clock
worker; a late operation may still take time to return, but cannot now supply
passing evidence for these outer gates. `wait_local_frontier` already had its
own remaining-budget and terminal checks and is unchanged.

## Mutation custody, unknowns, and cleanup

The private recovery ledger binds the new run and actual node/binary cohort.
Initialization is submitted once and its actual keys/token are retained only
in the new owner-only recovery file. Before later mutations the ledger
rechecks that credential file's original identity/digest and fsyncs an intent
containing method, route, body digest, and CAS metadata. It saves the outcome
after the single request. A transport error or an intent without an outcome
remains unknown. HTTP acknowledgement is not promoted into an inferred
storage commit, and neither an unknown mutation nor a lost startup response
is automatically repeated.

Cleanup inspects only the new fixture marker, root identity, exact binary/
argv, and owned process identity. Linux uses start ticks, a pidfd and an
identity recheck; Darwin retains its explicitly limited non-atomic BSD process
identity check. It never uses a broad process-name kill. If startup succeeded
without a usable identity receipt, an unowned-looking process is a cleanup
failure requiring read-only reconciliation, not permission for a broad kill
or a second launch. Failure on one node does not prevent attempts to clean up
the other owned nodes.

The missing-ciphertext injection is limited to stopped synthetic fixture
roots. It creates no-replace hard links into an owner-only quarantine,
records and fsyncs the complete inventory and directories, then unlinks the
original leaf names after identity rechecks. The bytes remain available for
forensics. It does not delete old OpenBao assets, backups, or any other
client's directories. Public receipts contain hashes, bounded state and
identities; actual tokens, unseal keys, private keys and payload bytes stay
inside their owned fixture roots.

## Retained prior evidence and local validation

Old 03's actual summary SHA-256 is
`9dcc095d0824464d32cb34f39e5a53fb26f3c5501729c3752952a81e4fba9a7f`.
It recorded 15 of the fixed 98 checks before `node_1_listener_timeout`: 18
connection refusals and 27 TLS handshake timeouts over 45.009208 seconds.
It had no initialization, business mutation, migration, or HA qualification;
its owned node-1 process was stopped. Its source cohort and binary hashes
are old and cannot be used as this run's candidate.

A separate older complete-HTTP diagnostic demonstrated health 501 using
synthetic DNS SNI from Mac and main to Mac. It used the older binary and is
neither a result for the new binary nor a result for ordinary IP-URL urllib.

The projector's five local synthetic-metadata tests passed, including changed
artifact/log rejection, bool/nonzero build exits, incomplete/mismatched
source records, duplicate commands, wrong ABI, symlinks and existing-output
refusal. They are not an actual compiler run.

The final deadline regression run passed all five test methods in about
three seconds. The original source failed the four affected methods (six
assertion failures because boundary and late native traces are separate
subcases); timely listener success passed. Listener and leader tests use
actual loopback TLS/IP-SAN verification, complete HTTP responses, and the
real urllib helper. The leader's individual health/leader requests stay
inside their 2/8 second limits while their enclosing deadline expires.
The fixed 60s sealed and 35s quorum tests explicitly use scripted monotonic
traces plus bounded delayed read callbacks; they are not 60/35 second live HA
experiments. The first sandboxed attempt could not create local sockets;
the successful execution used approved access only to a private 127.0.0.1
responder. Earlier r1 logs, including the replaced quorum-stub diagnostic,
remain retained next to the final r2 receipt.

Evidence lives in `evidence/resumed-20261019/lan98-preflight-r1/`. The local
source-inventory receipt preserves every one of the 98 required names and
the exact base/current driver digests. No new physical Mac/ROG/Pocket4 LAN98,
large forwarding, native HA snapshot/restore, real power loss, disk-full,
long-horizon linearizability, production cutover, or old-asset cleanup is
claimed by this preparation.
