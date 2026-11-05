# Bounded stored-request locator — R2 source packet

Status: source and selected offline components only. Neither proposed host request has been submitted. This packet does not authorize replay of either original business request.

## Purpose and separate physical scopes

The desktop scope searches the already named desktop worker job directory for the original X230 fence request. The ROG scope searches the ROG worker job directory for the original ROG source request. They are separate `host` values and separate observations, even though both positive ACKs independently name `/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs`. A worker path name containing “mac” is not evidence of a Mac host.

| Scope | Physical host | Known positive job | Target full request digest |
| --- | --- | --- | --- |
| desktop-fence | desktop | 1a1aaa6db3e-fc05-45a6 | 2cd54d3522e4fccfef1e26edd4e86f7908e08e9183e1bb2bfdd8caad83ee4bf5 |
| rog-source | rog | 1a1aad691c1-fc05-47e5 | bae96736cb7abc92a03e93f7e55f5c108a152dcf5f5aeb237643b935218df42b |

Both original requests, both positive requests and ACKs, and both previously published digest proofs are included as exact public raw reference files. The runtime reference is an exact public source blob, **not** an attestation that either deployed worker runs that source.

The source first opens the fixed ancestor chain, then independently validates its host-specific known anchor before scanning any candidate names. A target match requires the full digest, matching string fingerprint, exact job ID/directory/unit, all seven typed execution fields, and the original full args-array hash. The report never emits argv or other jobs’ contents. Stored `stdin.bin` is never opened. The historical complete stdin participates in the reproduced original digest, but this observer cannot re-hash its stored body.

## Concrete bounds

The inherited source soft deadline is one 15-second monotonic interval. Each proposed supervisor cap is explicitly **NEW 45 seconds**, not a recovered old outer cap. No deadline is reset for names, candidates, closure, or output.

- At most 16,384 directory names and 1,048,576 observed name bytes.
- At most 128 canonical candidate job IDs in the fixed time window.
- The original 262,144-byte per-request budget now reserves one byte for the EOF probe, so an admitted file size must be strictly less than that value.
- The original 8,388,608-byte aggregate budget is checked before opening a request body using remaining capacity for declared bytes plus one EOF probe. Every byte returned by read, including an unexpected tail byte, is counted before refusal.
- At most eight matching target records; JSON remains bounded to 65,536 nodes and depth 64.
- A new 65,536-byte public-output cap can only refuse; it does not increase input or time budgets.

Both scopes retain the original lower floor 1793864424254. For ROG this is intentionally earlier than its own positive anchor; it is a finite wider search window, not a host-equivalence claim. One wall-clock ceiling is sampled before I/O. Directory membership is not atomic or claimed stable. A single over-limit name can be received before its size is measured and refused; no success or further request read follows that refusal.

## R2 changes from exact R1

The complete 15-hunk review diff reconstructs the whole 24,872-byte candidate from the exact 18,882-byte base. Both CONFIGS texts, the nine inherited cap lines, and twelve selected unchanged definition bodies match exactly; see `proofs/static-invariance.public.json`.

1. Signals record cancellation while an owning region is protected. The main resource lifetime is protected before signal handlers are installed and remains protected through its one final cleanup attempt. Explicit `remaining()` checkpoints still stop work on pending cancellation and the original deadline. This prevents a second signal from escaping the entry to final cleanup.
2. Each returned file descriptor is registered inside a protected interval. A registration exception remains explicitly unknown; it is never counted as closed.
3. FD closure has persistent ordinal/role/attempt/result rows. The FD is removed from the retry set before its single close attempt. A failed close contaminates overall closure, even when all other descriptors are closed.
4. Scandir construction and the iterator's single explicit close attempt have their own ledger. An uncertain iterator close is not retried. This is an explicit Python iterator-object close ledger, not a claim that the underlying C directory descriptor receives exactly one close syscall; Python may auto-close it at exhaustion.
5. Request admission uses remaining aggregate capacity before body access. Returned blocks and the tail probe are charged before shape/refusal checks. File-close failure cannot skip the containing job-directory close.
6. Candidate names are deduplicated, bounded before append, and restricted by the one fixed floor/ceiling interval. Only target-matching job IDs and public hashes are exported.
7. Success additionally requires every registered resource closed, no registration uncertainty, no pending cancellation, and both the post-closure and post-flush checks of the original clock.

Synchronous OS operations are not hard-preemptible by this soft clock. Late return cannot succeed; the external 45-second supervisor remains a separate termination boundary. Failure cleanup may consume time while refusing success. No retry, larger cap, fallback path, child process, network operation, host signal send, or file write was added.

## Exact proposed requests

The two files under `requests/` contain complete SOURCE-only `process_start` arguments. They use the existing public `/usr/bin/python3`, `-I -S -B -c`, the exact candidate bytes, fixed scope, exact self SHA, fixed cwd, and separate new locator idempotency keys. They have empty/omitted stdin and timeout 45.

- desktop: `heptabao-bounded-job-locator-desktop-e1148f85-20261105-r2`
- rog: `heptabao-bounded-job-locator-rog-e1148f85-20261105-r2`

No carrier or on-host source publication is required. These are read-only source proposals, not submitted intents. Root must explicitly admit an exact request before host execution. A lost start ACK permits reconciliation of that same locator job/key, never replay under a new key.

## What a result can and cannot establish

A complete `bounded_read_completed` report is accepted only together with authoritative exit zero and full durable original stdout; the post-flush deadline can make an otherwise candidate-success report exit nonzero. Matches prove only stored request bindings at the observations made. They do not prove launch, execution, terminal success, complete inventory, absence, deployed runtime source identity, or permission to replay an original effect.

Partial matches from a later failed scan remain observations, not a success gate. Missing/unreadable/mutated files, refusal, cancellation, late publication, incomplete output, and unknown closure must be retained accurately. No-match never converts either original UNKNOWN to “not submitted.”

## Selected offline checks and retained failure

The current selected-AST component run has actual local executor exit zero and 25/25 checks. It imports no complete candidate module and performs no target host operation, real candidate FD, real directory scan, child, network, or real signal. Fake OS descriptors and clocks exercise actual selected Reader/Signals/main methods. `sys.settrace` triggers only synthetic boundaries.

Coverage includes the original unregistered-open cancellation negative case; protected registration and close; once-only failed closure; remaining-budget admission; counted EOF-tail rejection; cancellation after returned data; iterator failure/registration; duplicate/time-window names; nonmatching-argv redaction; and cleanup/cancellation/post-flush success gates.

The first local component attempt is retained with its actual exit 1 and exact source/input/command. It reached an assertion in the fake main fixture; source-level diagnosis found that the AST fixture had omitted the derived JOBS_PATH constant. That fixture was corrected. Separately, the main resource-lifetime signal guard was tightened, and the new cleanup-entry signal case was added. The successful run and its complete command/input are recorded independently. The original 30 R1 pure checks were not rerun and are not presented as R2 FD or host qualification.

## Provenance and publication

All packet files are public source, public requests/ACKs, or public local component evidence. Original unsafe-width ACK integers are preserved in raw text and are not reserialized as originals. Full 64-hex digests, not parsed legacy 64-bit fingerprints, bind identity. The complete reference source identifies RequestBinding serialization order and remote stdin removal; see the exact reference and binding proof.

This is an unreferenced Git tree only: no commit, ref, pull-request publication, host job, production access, service operation, or original-business replay.
