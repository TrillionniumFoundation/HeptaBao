# R1190 — live committed-cursor double observation (precommit QA)

Scope: isolated source candidate, no production V6 signed root, storage
writer, migration, HA promotion or OpenClaw/AuthBus configuration change.

## First failure

The original R1180 authenticated_preflight took the actual publication
fence as a borrowed *snapshot*. Its AEAD traversal could inspect a valid
candidate while the authenticated committed generation advanced elsewhere.
An A-to-B-to-A transaction can restore the same encrypted header, so a
digest comparison alone cannot detect the stale observation.

An intentionally one-read live-cursor adapter failed a real Rust red test:
encrypted_native_live_cursor_second_read_detects_aba_after_aead.
The failure proves the second observation is required.

## Correction

NativePublicationFence::authenticated_preflight_against_live_cursor now
requires a trusted callback that reads the independently authenticated
durable/HA publication cursor. It obtains a first live snapshot, verifies
the exact source, original namespace custody and every candidate AEAD page
under the unchanged original request deadline, then obtains a second live
snapshot. The complete generation-and-header identity must still match.
Namespace owner and original deadline are rechecked after the second read.

The stable case returns only the proposed next-generation fence and never
installs it. A changed generation with identical header (ABA) and an owner
revoked during the second observation are rejected. Both refused and
successful preflights leave the old encrypted pin unchanged.

## Crucial gap to production

**The two observations are not atomic**. A concurrent publish after the
second read remains possible. Only the Service owner may recheck authority,
quorum, replay epoch, generation and original deadline *inside* the
durable transaction that atomically makes encrypted objects and the signed
root visible. Post-Raft ambiguous writes must fence and reconcile, not
retry. This QA adapter is not a production publication permit, and its
closure must not be supplied by untrusted client data.

There is still no V5-to-V6 atomic migration or production KV2 V6 writer,
nor completion of four OpenClaw production credential rotation, restart
and rollback, or full OpenBao 2.7.1 compatibility. All old provider
services and production user credentials remain untouched.

## Evidence

ROG isolated branch qa/r1190-live-committed-cursor.
Source base: e83e4d2a1d23097bff160cae9482f5911a09f6a3.
Logs under /home/qian-qi/heptabao-271-r104/r1190-live-cursor-evidence/.
No completion claim is made without each natural exit and test denominator.
