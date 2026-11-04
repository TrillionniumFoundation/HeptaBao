# Phase B R3: concrete local stage, separate from prepare/runtime

This is new staging source for the already reviewed R3 controller. It does not
change that controller, either exact reference, binding code, acceptance cases,
or CLI/HTTP/action deadlines. No target module is imported or executed.

## Preconditions outside this stage

Root must first accept the actual full canonical desktop source stage at
/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-validation-source-r1
(commit 49503322c7f446e5eb41e7744f1fdbd7f1192ecc,
tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9) and the actual single shared
artifact transfer. These are separate owners' receipts, currently still pending.
Source file checks here do not substitute for full Git tree/fsck qualification.

The shared incoming source is fixed:
 /home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-shared-artifacts-r1/incoming
It must have UID1000/mode0500. Its three files are fixed:
- heptabao-server: 109091112 B, SHA67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113, mode0500.
- native-build.public.json: 801 B, SHA0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77, mode0400.
- normal-release-result.public.json: 3227 B, SHA75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee, mode0400.

These are expected pins from whole verified actual R10 release receipts. They
are not a statement that the destination has already been created or verified.
The shared transport receipt is planned at the sibling control/result.public.json.
No second ROG-to-desktop binary transfer is proposed.

## Exact scope

The sole new target is
 /home/qian-qi/heptabao-ha-closure-20261103-r1/official271-native-cli-phaseb-r3-control-r1
with qa/ and artifacts/ subdirectories. Both this target and future live root
must be absent. mkdir and every target file create are exclusive; existing
assets are never overwritten, unlinked, chmodded or restarted.

The 257060 B stdin source carrier is frozen by whole SHA and eight per-file pins:
the unchanged five runtime QA sources, exact actual original44 combined JSON,
exact six-group JSON, and a partially resolved binding template. The template
remains ready=false in its original carrier. Artifact/source records come from
the published exact Git blobs, not a reconstructed or retyped report.

The helper copies the three incoming files using stable source FDs, exact source
owner/modes/length/SHA, and same-FD target complete hash/name/custody readback.
Target server mode0500 and receipts0600 match the reviewed Binding contract.
The shared source and raw receipt bytes remain unchanged.

The only additional existing reads are:
- /etc/machine-id, with the actual earlier desktop SHA d90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3;
- exactly four archive/audit product files and the R10 test witness, each pinned;
- the known official2.7.1 binary at official271-standby-oracle-control-r1/artifacts/bao;
- actual /usr/bin/python3 resolved executable, /usr/bin/git, /usr/bin/openssl;
- four exact retained public results for Phase A, earlier strict wire and the two formal HA lanes.

No home traversal, credential input, environment dump, source repository write,
Git process, network request, product/CLI start, provider operation or backup
payload read is performed. Actual utility and official file metadata plus old
fences are captured with complete stable-FD hashing and final metadata fences.
The helper never executes any of those binaries.

## Binding and termination

Only observed complete file identities fill the remaining UID/mode/length fields.
The new binding can then set ready_for_readonly_prepare=true; this means its input
fields have been materialized, not that prepare or a product test has run.
The stage reports source_full_git_verification_performed_by_stage=false.

The helper uses one separate 300 s local staging envelope. Proposed invocation:
actual desktop /usr/bin/python3 -I -S -B -c [exact staged helper source]
 --external-controller-sha256 [exact source SHA]
with the exact frozen source carrier stdin and a 330 s outer job cap.
Root reviews the source and actual prerequisites before authorizing that call.

The output file stage.result.public.json records fsynced new files before final
FD closure and explicitly says fd_close_pending=true. Complete runtime stdout
and authoritative terminal exit are required to establish all_stage_fds_closed
and stage success; no file-only success is sufficient. The terminal stdout adds
elapsed_after_closure_ms and within_stage_deadline after all FD closes. A late
close fails the stage, and the exit decision checks the same 300 s deadline again
after stdout flush. Source and target copy FDs are both closed even if the first
close raises; a failed stage cannot assert all_stage_fds_closed. Any exception keeps the
new partial directory and reports failure without retry or deletion.

After one successful stage, root reviews the complete binding, stage output and
canonical/transport receipts. The already frozen R3 controller performs its
separate read-only prepare only after that review; its actual full source,
receipt and utility checks remain unchanged. Live B01-B05 requires another exact
prepare-result admission and its own separately authorized fixture window after
the strict wire owner is terminal and cleaned.
