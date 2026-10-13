# R1180 — Native V6 precommit identity + ciphertext, QA only

This change belongs to an **isolated** Stage C candidate. A validated
candidate does not become application state, a durable signed V6 root, or an
admitted OpenClaw/AuthBus provider. No production service uses this guard yet.

## Precommit identity and ABA

A content-addressed encrypted header is not a sufficient CAS source. In the
sequence A→B→A the old and current encrypted roots can be identical. The
NativePublicationFence therefore carries a **nonzero, monotonically advanced
committed generation** in addition to the encrypted header. The generation
must come from the independently authenticated durable/HA publication cursor;
clients cannot manufacture it. Zero, wrapped, skipped, or stale generations
fail closed. An unchanged KV2 mutation does not authorize a new generation.

## Candidate ciphertext integrity

An identity/generation match alone still does not prove that every non-root
object in the detached candidate is present or unmodified. The R1180
`authenticated_preflight` additionally reopens the candidate with its actual
namespace key, exact mount/incarnation, cluster and replay epoch, checks every
AEAD ciphertext, authenticates its graph and requires full object consumption.
The original request deadline and owner callback must survive that work.

This is a **precommit observation**, NOT a durable compare-and-write. The
future Service writer must recheck the current committed generation, original
namespace custody, quorum, epoch, and writer deadline inside the same atomic
publish of all V6 ciphertext objects and signed root. A post-Raft ambiguous
local failure MUST enter recovery fencing, not retry the mutation blindly.

## Deterministic negative controls

- A→B→A returns the same object header but the stale generation is rejected.
- Zero or u64 overflow generations, missing/noop-inconsistent candidates,
  scope or domain mismatch and owner revocation are rejected.
- A missing non-root object or one AEAD bit flip is caught by authenticated
  reopen even though bare root/epoch preflight can match.
- Both valid and rejected candidates leave the old committed pin unchanged.

## Release boundary

No V6 durable Service writer, V5→V6 atomic migration, HA-replay-fenced
publication, live four-client credential rotation, rollback, or full OpenBao
2.7.1 replacement has been qualified by these checks. Old OpenBao and
production OpenClaw configurations must remain unchanged.
