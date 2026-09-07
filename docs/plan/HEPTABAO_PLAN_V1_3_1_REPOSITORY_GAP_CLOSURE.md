# HeptaBao Plan V1.3.1 — Repository Gap Closure

**Plan ID:** `HEPTABAO-PLAN-2026-08-28`  
**Revision:** `1.3.1`  
**Status:** `NORMATIVE_REPOSITORY_GAP_CLOSURE_INPUT`  
**Authority effect:** `NONE`

## 1. Purpose

V1.3.1 converts the materialized V1.3 source into one ordinary reviewable integration branch and closes the repository-controlled defects found by the V1.3 audit. It does not alter any legal, independent-review, signing, incident-operation, restricted-Oracle, power-cut-laboratory, compatibility, qualification or authority boundary.

The canonical implementation lane for this closure is `codex/plan-v1.3-gap-closure-v2`. The source was anchored from materialized commit `b694d24a16ee9714fb888e72aca86f16effd1761` and is reviewed through PR #45. Compressed source transport and CI-authored source publication are not normal delivery mechanisms.

## 2. Repository-controlled closure scope

The patch must provide all of the following on one exact remote commit and tree:

1. a total request-read deadline that cannot be extended by byte trickling;
2. a hard concurrent-connection bound with fail-closed saturation behavior;
3. a request-attempt identity allocated before parsing so malformed, Host-invalid and socket-failed requests can be audited;
4. stable transport rejection detail codes;
5. an optional bounded single-use `X-HeptaBao-Request-Id` development contract, separated from the future HA Authbus replay authority;
6. HTTP 204 wire responses with zero body bytes and `Content-Length: 0`;
7. durable-store writes that never recreate an opened storage root after deletion or replacement;
8. legacy adoption that rejects unresolved authoritative-data temporary artifacts;
9. one read-only exact-head workflow covering every workspace crate, plans, tests and H02 probes, with fail-closed discovery of both `.yml` and `.yaml` workflow files, strict duplicate-key rejection, glob-aware active-branch admission checks, mandatory canonical workflow presence, read-only permissions and non-persisted checkout credentials;
10. machine-checked current status, transport test vectors, Authbus request-ID lifecycle and audit-outcome documentation, including every dynamically loaded validator dependency in the active manifest;
11. every transport rejection response must configure a bounded write deadline before any response bytes are written, including accept-loop capacity rejection;
12. every response must share one absolute response-write deadline; partial write progress and the final flush consume the same deadline rather than restarting a per-call timeout;
13. per-connection worker creation must use a fallible API; allocation failure releases the admission count, records `connection-worker-spawn-failed`, closes the connection and cannot panic the listener process;
14. `deadline <= received_at` must be classified as `InvalidDeadline`, before clock-expiry evaluation, with an exact negative regression test;
15. operation-specific body validation must reject ignored or non-exact bodies before authentication, request acceptance and dispatch, using the stable `operation-body-forbidden` detail code;
16. parsed headers, parsed request bodies, P0 response bodies, socket ingress buffers and rendered response wire buffers must not expose secret values through derived `Debug` or implicit `Clone`; owned byte buffers are overwritten on all controlled drop/return paths;
17. the owned canonical target and in-memory KV path must use redacted diagnostic views and controlled overwrite on drop; Authbus canonical-target verification must not allocate a duplicate target string;
18. P0 single-field JSON rejects raw unescaped quotes, Authbus request-binding/identity `Debug` is redacted, and the canonical request digest preimage and unsigned signature payload are overwritten immediately after their providers return, including provider failure.
19. repository identity is bound to stable GitHub repository ID `1349115072` and current full name `TrillionniumFoundation/HeptaBao`, while source ratification is bound separately to designated accountable account `ProfHepta` (`102159240`); an organization transfer cannot silently redefine the ratifier or make historical repository names valid for current execution.

These are process-level best-effort controls. They do not claim compiler-proof zeroization, allocator page scrubbing, swap exclusion, core-dump prevention, locked memory or independent side-channel qualification.

## 3. Exact execution gates

### Gate A — plan and policy

- all inherited V1.1–V1.3 validators pass;
- `scripts/validate_plan_v1_3_1.py` passes;
- all Python regression suites pass;
- active workflows remain read-only and checkout credentials are not persisted;
- missing canonical workflows, duplicate trigger keys, `.yaml` side lanes, branch-glob side lanes and unmanifested validator dependencies fail closed;
- no repository-controlled state is promoted from source presence alone.

### Gate B — root Rust

On Rust `1.98.0` and the committed root lock:

```text
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

### Gate C — P0 transport and secret surface

The exact binary and root unit suites must demonstrate:

- loopback-only startup;
- normal health/init/unseal/KV behavior;
- init accepts exactly `{}` and ignored bodies fail closed before dispatch;
- no body on HTTP 204;
- duplicate Host and Host/listener mismatch rejection with audit evidence;
- duplicate client request-ID rejection;
- a partial request cannot remain connected past the total read deadline;
- no response can remain in partial-write or flush progress past one absolute response-write deadline;
- audit artifacts are non-empty and contain the expected stable detail codes;
- saturation and all other transport error responses use the same bounded absolute write path;
- the listener has no infallible per-connection thread creation path and a worker-allocation failure cannot leak capacity or panic the process;
- deadline equal to or before receipt is rejected as an invalid envelope rather than an ordinary timeout;
- request target, header values, body bytes, response bodies, Authbus subject and binding bytes are absent from safe `Debug` output;
- canonical target, KV path, request, response, wire, digest-preimage and signature-payload owned buffers execute their explicit overwrite paths;
- Authbus canonical-target comparison does not construct a second target string;
- raw unescaped quotes are rejected by the bounded P0 JSON subset.

### Gate D — H02 exact-head

The same exact source must compile and lint the OpenRaft graph on Rust `1.88.0` and `1.98.0`, then execute all 24 in-memory, hostile, blocker and durable entries. Any failed, blocked, unknown, malformed, missing, duplicate, unexpected or unexecuted entry fails the aggregate.

### Gate E — independent closure

Critical repository blockers require current review receipts from distinct accountable reviewers. Repository automation cannot issue those receipts for itself.

## 4. External boundary

The following remain real external actions and cannot be closed by source changes:

- `HB-BLK-CTRL-001`: enforced canonical-branch ruleset;
- `HB-BLK-EXT-001`: independent accountable reviewer identities;
- `HB-BLK-EXT-002`: signed legal, license, clean-room, trademark, patent and export disposition;
- `HB-BLK-EXT-003`: private disclosure, 24x7 incident ownership and drills;
- `HB-BLK-EXT-004`: isolated signing, transparency and emergency revocation;
- `HB-BLK-EXT-005`: restricted Oracle capture and signed transfer;
- `HB-BLK-EXT-006`: independently operated filesystem/power-cut laboratory evidence;
- `HB-BLK-EXT-007`: independently operated reproduction.

Every external blocker remains `EXTERNAL_ACTION_REQUIRED` until its declared completion object verifies. Missing evidence is not interpreted as success.

## 5. Promotion rules

```text
SOURCE_PRESENT
→ COMPILES
→ EXECUTED_PASS
→ INDEPENDENTLY_REVIEWED
→ QUALIFIED
→ COMPATIBILITY_CLAIM
→ SCOPED_AUTHORITY_GRANT
```

No transition is implicit. V1.3.1 fixes `qualification=false`, `compatibility_claim=false`, `selected_candidates=[]`, `selection_effect=NONE` and `authority_effect=NONE`.

## 6. Stop conditions

The repository-controlled patch is technically complete only when Gates A–D pass on one exact head. It is review-complete only when Gate E receipts exist. Program-wide gap closure additionally requires all eight external/control completion objects. Until then the truthful state remains technical remediation in review with external action required.

## 7. Current pointers, ratification and workflow arbitration

The V1.3.1 manifest explicitly overrides the `current_plan` and
`current_state_input` pointers inherited from the V1.2 manifest.  Its
`current_plan` is this V1.3.1 closure document, `current_state` is the
V1.3.1 gap-closure status object, and `current_state_input` is the final
closure input.  The V1.2 manifest and its status objects remain indexed as
historical evidence; they are not deleted or silently rewritten.

Static status and manifest objects never carry a moving commit, tree or runner
claim.  Repository identity and ratifier policy are nevertheless explicit and
non-moving: the current execution repository is `TrillionniumFoundation/HeptaBao`
with stable GitHub repository ID `1349115072`, while the designated source
ratifier is account `ProfHepta` with account ID `102159240`.  The repository
owner organization may differ from that ratifier after transfer; neither role
is inferred from the other.  Historical name `ProfHepta/HeptaBao` remains audit
lineage only and is rejected by current execution receipts.  Ratification
authenticity is resolved only from the exact head Git object: the subject is exactly
`chore(provenance): owner-ratify V1.3.1 canonical source tree`, both author and
committer identities are non-automation identities, the commit has one parent,
and its tree equals the parent's tree.  This source check is provenance
binding, not a signature, independent review or qualification receipt.

Gate A resolves the active state-input and normative-manifest paths explicitly
and records their hashes alongside the exact source binding.  Historical V1.2
defaults are retained for audit compatibility, but cannot silently become the
active V1.3.1 resolution input.

The consolidated workflow is the sole canonical technical evidence lane for
this revision.  It covers two pull-request source lanes (`head` and the
distinct synthetic `merge`) and all four technical gate groups (plan and
Python, root Rust 1.98, classified P0, and the 24-entry H02 matrix).  Legacy
workflows may still run for historical or diagnostic purposes, but their
results are non-authoritative and cannot satisfy this lane's closure
arbitration.  Duplicate or stale evidence is arbitrated fail-closed: a newer
head cancels an older run while retaining its history, ancestor-only artifacts
are rejected, duplicate matrix entry IDs fail the aggregate, and a technical
result is usable only when both source lanes complete. The two heavy lanes
remain separate jobs but are admitted with `strategy.max-parallel: 1`. A
superseded workflow skips its aggregate when `cancelled()`: using `always()`
at job scope can start checkout work even after cancellation and retain the old
workflow-level concurrency group, leaving the replacement run pending. The
corrected group uses the `v2` epoch so an already queued predecessor cannot
block the repaired lane. Each lane's technical receipt additionally binds the
digest and fields of the GitHub REST identity
record used for owner-ratification checks and records a locally recomputed
arbitration key (PR/dispatch, head SHA and source lane) plus the required lane
set.  These fields support deterministic head/merge aggregation without
trusting a run-listing API.  These rules select evidence; they do not grant
authority.

### Post-run lane arbitration

The canonical workflow runs `scripts/arbitrate_v1_3_1_lanes_v1.py` after the
matrix jobs with `!cancelled()`: ordinary success, failure or skipped-needs
outcomes are still aggregated, while an explicitly cancelled superseded run
does not enqueue a new aggregate job. Its strict aggregate schema requires exactly the
`head` and synthetic `merge` receipts for a pull request, the same immutable
head SHA/base/event-merge binding, a distinct merge source commit, and
digest-bound PASS technical receipts.  Current run/attempt IDs, numeric job
and runner identities, duplicate keys/digests and superseded artifacts are
checked fail-closed.  Missing or malformed artifacts produce a schema-valid
`FAIL` aggregate and a non-zero job; they are never treated as success.  The
aggregate retains `qualification=false`, `compatibility_claim=false` and
`authority_effect=NONE`.

The active normative manifest is independently validated against
`schemas/heptabao_normative_document_manifest_v1_3_1.schema.json`.  Inherited
legacy workflows are explicitly indexed as `HISTORICAL` with
`authority_effect: NONE`; they remain audit lineage, not active evidence.
