# NEW R10 snapshot relay — implementation prerequisites R3

This addendum narrows the proposed API design in tree f4109bab0f558c67b7212f9df1621a5900b087d5 (API_ADDENDUM_R2.md, SHA f115b15ee8d1b8edd748e7584eb351b97ff680c8e77f3e531948128d45caa9e8). It is a new source-only design identity. No implementation, runtime test, production change or qualification is claimed. R2 remains unchanged.

## OPEN 1: the real native writer for negative custody

R2's proposal to reuse the existing DurableService conditional journal is not yet connected to a proved, callable writer/admission path for the active normal native-v6 record-root and HA profile. The existing retirement journal is evidence of a mechanism and bounded lifecycle, not permission to call that specialized API for snapshot traffic. Neither a flat State write nor a generic batch that bypasses native record ownership is acceptable.

Before implementation can be accepted, identify exact callable functions and affine input types for both leader and origin negative-custody writes. Demonstrate that they use the active native owner, authenticated separate records, real HA admission, original request deadline and conditional generation checks. Show the committed, rejected and unknown outcomes from that actual path. This proof must include reopen and historical restore preservation; a synthetic KV or flat in-memory test cannot close it. The private PreparedNativeRestoreAttempt still belongs to the same live HaProcess after real admission, and serialized IDs cannot construct it.

Status: OPEN. No available-source trace in R2 proves that simply adding a DurableService resource supplies this path.

## OPEN 2: origin journal publication versus the retained transfer source

R2 proposes leader negative custody before Ready, then origin negative custody before Proceed. If either publication changes the shared native HA root or generation, it may invalidate the already admitted SnapshotTransferPlan.base/source. This cannot be repaired by assigning the new generation to old fields or calling the admission function again: either would lose the source proof or risk another token use debit.

A concrete implementation must prove one of these two mechanisms from actual storage and owner APIs:

1. The negative record has genuinely separate physical and authenticated persistence whose write does not change the selected service root/generation; its ordering, crash recovery and relation to the restore owner must still be proved.
2. A real typed allowed-source transition captures the exact committed bookkeeping publication while retaining the original Auth/Actor, source custody and deadline. It must verify the original and next roots, distinguish that one permitted publication from every unrelated update, and transfer ownership without repeating application admission or debit.

Neither mechanism is selected or proved by this document. Even an actual recapture of a later head is insufficient if it silently accepts an unrelated concurrent state change. The ordinary local restore path must keep its existing operation-allocation behavior. Failure after Ready or Proceed remains unknown and does not permit a new deadline, nonce, upload, Begin or root-CAS replay.

Status: OPEN. The source/generation handoff described in R2 is a requirement, not an existing implementation capability.

## Consequences for the next implementation step

Keep default standby streaming relay disabled until both prerequisites are closed by exact source and meaningful native-owner tests. Existing Raft pending/restore lineage remains the only truth about historical restore effects. Any new custody record can identify and reconcile negative delivery obligations; it cannot reconstruct an attempt capability or authorize replay. Do not call the retirement API, introduce a second restore engine, or treat a static manifest or design review as a durable recovery test.

The Phase B live-r1 failure is separate evidence: the first leader save was unknown and produced no archive. This addendum does not diagnose that failure, claim its repair, or authorize a retry.
