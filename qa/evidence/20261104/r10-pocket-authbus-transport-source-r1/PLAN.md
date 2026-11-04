# Pocket R10 public-artifact relay — source review plan

## Scope and present status

This is a new source-only relay candidate for canonical R10 commit
49503322c7f446e5eb41e7744f1fdbd7f1192ecc, tree
1d4211f91e1b34a2ed087a3bbef2e2884bac88e9. Both normal 44-test gates and
the common desktop artifact intake have already completed and were independently
accepted by root. This packet does not claim Pocket transfer or consumer runtime.

The relay copies exactly three public build files from the already accepted
desktop intake to a fresh Pocket artifact directory. It does not call a provider,
read an authentication store, initialize HeptaBao, start a server or consumer,
change a production connection key, release a hold, or alter older generations.

## Exact source and destination

Source directory:
 /home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-shared-artifacts-r1/incoming

Destination:
 /home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1/shared-first-cycle-r10-artifacts-r1

| Source basename | Destination basename | Bytes | SHA256 | Source / destination mode |
| --- | --- | ---: | --- | --- |
| heptabao-server | heptabao-server | 109091112 | 67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113 | 0500 / 0500 |
| native-build.public.json | native-build.public.json | 801 | 0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77 | 0400 / 0600 |
| normal-release-result.public.json | normal-build.result.public.json | 3227 | 75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee | 0400 / 0600 |

The normal result changes basename only. Its full original bytes are preserved.
All source versions are fixed from the actual intake file_info originals, and
the actual 14209-byte intake result is bound by SHA256
f8fd7d32498cb8d291407f5cc352f79584c57e55d48f028f26048097bb0bd7bf.
The receiver uses O_EXCL, verifies whole content and readback, and never overwrites
an existing destination. A failed partial fresh root remains evidence.

Desktop controller:
 /home/qian-qi/heptabao-ha-closure-20261103-r1/pocket-r10-artifact-relay-control-r1/pocket_r10_artifact_relay_r1.py

Desktop output:
 /home/qian-qi/heptabao-ha-closure-20261103-r1/pocket-r10-artifact-relay-r1

## Verified route and trust boundary

Read-only route job 1a1a8313db3-fc05-2df6 completed with authoritative exit 0,
complete and durable output. It ran ssh -G only, with no remote SSH connection.
Its child was reaped and its process group observed empty. Raw stdout is retained
with SHA256 a2fca034263c1dc97e516e078572eff78e0af2f60bea22ce1948d3a1232a4fb2.

The actual alias is pocket4-ts; its effective host is 192.168.0.9, port 22,
user alex, HostKeyAlias hepta-node-pocket4. BatchMode, strict host key checking,
UpdateHostKeys=no, ConnectTimeout=8 and ConnectionAttempts=1 retain the original
reviewed relay prefix. The route has an existing ProxyCommand, recorded by
SHA256 d13580ec3a9719e7b54969df0524f254e1d8040db86b0914b4085d6803847d85;
the candidate does not assert that no proxy exists.

The relay binds and rechecks the exact main SSH config and transport known_hosts
bytes and identity before and after. The effective-config receipt is explicitly
a prior observation, not a claim that the runtime relay repeats ssh -G.
Private identity-file contents are never read or copied.

Desktop and Pocket machine-id digests are fixed to the original accepted machines.
The previous R8 relay and actual receiver/authority receipts are retained as
reference evidence, not as a new R10 transfer result.

## Minimal changes and original budgets

The 35 recorded source replacements reverse byte-for-byte to the complete
16935-byte R8 relay, SHA256
a3dfbde3750b2651d1e687d28c9c19fdebcb37b7d113e25708b62fa8b7b5dbfd.
Changes bind fresh roots, R10 source/artifact identities, the actual shared-intake
schema and receipt, source versus destination modes, exact source versions, and
the route/trust observations. Seven complete lifecycle/file helper functions are
unchanged. The embedded receiver is also supplied as its exact extracted source
for independent review.

The old per-Git-command 15 seconds, SSH transfer 180 seconds, receiver alarm
180 seconds, and SSH cleanup total 10 seconds are unchanged. The receiver's
original alarm ends before final receipt publication; this packet does not
describe it as a newly proved end-to-end publication deadline. A proposed NEW
remote supervisor limit of 360 seconds covers this source-bound run. It is not
represented as an old outer value or a relaxation of the inner budgets.

No automatic business retry is allowed. Once SSH starts, an absent, partial or
invalid receiver response is unknown. Completion requires a validated complete
receiver response, authoritative parent exit 0 and durable output, source/trust
fences, direct child reaping and empty owned process group. A returned JSON object
alone is insufficient. The parent never signals a group after reaping its direct
child; it only observes possible remaining members.

## Sequence and authority

1. Root and the independent reviewer read this candidate and its actual route
   originals. No 109 MB transfer is authorized by publication of this packet.
2. After source approval, a fixed create-only atomic carrier stages the exact
   relay source and, if used, its extracted receiver for syntax-only compilation.
   It must hash and read back every file before executing any relay.
3. Root assigns a desktop/Pocket I/O window. Run one fixed key:
   heptabao-r10-pocket-artifact-relay-495033-20261104-r1
   with /usr/bin/python3 -I -S -B, the fixed controller path and
   --expected-controller-sha256 651df23534c8410f1a34691968a1d1a1c76c4931675622aef41aae34ff02f96f.
4. Preserve actual ACK, authoritative status, stdout/stderr, desktop intent/result,
   Pocket receiver intent/result, and three independent Pocket file_info originals.
   Reconcile an unknown ACK with the same key; never start a second business run.
5. Only after root accepts the actual transfer may the separately approved
   Pocket R10 prepare/preflight chain bind these artifacts. Consumer live and
   all production migration steps remain distinct decisions.

The approved Pocket QA inert source stage can proceed separately. Its 10 source
files and qa-pins do not execute the consumer. Any future Pocket result remains
Pocket-specific and cannot establish Mac, ROG or X230 client and backup migration.
