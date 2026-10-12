# R795 — HA completed-index preflight diagnostic (isolated)

R785 used real X230, Pocket4 and ROG nodes with synthetic state. The
original leader was SIGKILLed after initial snapshot catch-up. Only 29
of 69 required checks completed; no stable surviving leader was admitted.
Pocket4 entered recovery_required=true and sealed after an index-related
503 response. The other surviving node remained standby.

## Interpret conservative error flags accurately

HaRecoveryIndexAdmissionFailure::from(Response) assigns
index_write_attempted=true to ambiguous errors even when a failure occurs
BEFORE entering the index admission function. The flag protects against
unsafe replay but is not evidence that seal.json was actually written.
No inner heptabao-ha-index stage marker appeared in the R785 node2 log.

## New static, secret-free phase markers

The completed-index reconciliation path records a static failure stage:
pre_index_deadline, pre_index_verify_completed_owner,
pre_index_verify_durable_fence, pre_index_state_present,
index_admission_entered, post_index_verify_completed_owner or
post_index_verify_durable_fence. It also records whether the index
admission function was entered separately from the conservative
write-possible flag. No passwords, tokens, secrets, full identities,
paths, credential materials or user data are emitted by this marker.

The existing error, guard, seal and permanent fail-closed recovery
semantics remain unchanged. A successful targeted source test alone
does not grant HA or production release.

## Required hard gates and rollback

Pin the exact source and binary, execute actually matched Rust tests,
then rerun the real three-host fault scenario using new private fixture
roots and dedicated ports. Require a real SIGKILL, new stable quorum
leader, ReadIndex, authenticated read/write, rejoin, and cleanup.
Never bypass recovery_required or retry a previously accepted mutation.

Original R785 evidence is kept under the qian-qi private qualification
directory and R796 independent forensics receipt. The diagnostic-only
worktree can be retired without modifying existing OpenBao, OpenClaw
or any production custody path. Full OpenBao 2.7.1 replacement HOLD.
