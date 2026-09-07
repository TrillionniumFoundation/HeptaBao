# HeptaBao V1.3.1 Final Repository-Closure Protocol

## Scope

This protocol closes the remaining repository-controlled evidence gaps on PR #45 without converting technical evidence into qualification, compatibility, candidate selection or operational authority.

## Canonical source identity

No static document is permitted to claim a moving pull-request head. Every execution resolves and records repository, stable repository ID, exact commit, exact tree, event head, event base and GitHub's synthetic merge commit directly from the event, Git and the GitHub API. The source-head lane and merge-candidate lane must execute different commits on a pull-request event.

The current execution repository is `TrillionniumFoundation/HeptaBao` with stable GitHub repository ID `1349115072` and repository-owner login `TrillionniumFoundation`. Historical full name `ProfHepta/HeptaBao` is retained only as audit lineage. The designated source ratifier is separately bound to GitHub account `ProfHepta` with account ID `102159240`; a repository transfer does not transfer or redefine that accountable identity. The repository owner and ratifier are intentionally permitted to differ, and both are verified independently.

The canonical source head must end in an ordinary designated-ratifier commit. The ratification commit must be authored and committed by the designated ratifier outside the `github-actions[bot]` identity, carry the exact subject `chore(provenance): owner-ratify V1.3.1 canonical source tree`, have one parent and preserve its parent's exact Git tree. This republishes the complete reviewed tree through a human-controlled source event while retaining bot-authored ancestors as provenance rather than hiding them.

The machine-readable final input records this as
`ratification_authenticity`. Verification must inspect both the Git author
and committer identities, bind their GitHub login and numeric account ID to the
designated ratifier, and reject automation fragments such as `github-actions`
or `[bot]`; no static document may predeclare the moving commit or tree. A passing provenance check still is not a cryptographic
signature, an independent review or a qualification/authority decision.

For machine checks, the required phrases are: **both the Git author and committer identities** are inspected; this is **not a cryptographic signature**. The wording is intentionally explicit so a stale or abbreviated workflow cannot silently weaken the provenance rule.

The V1.3.1 manifest also overrides inherited historical `current_plan` and
`current_state_input` pointers without deleting the V1.2 lineage. The active
status object and final closure input point back to that manifest and to one
another explicitly, so a consumer cannot choose a stale status file by
accident.

The exact-head resolver is invoked with the active V1.3.1 state-input and
manifest paths. It validates their cross-pointers, hashes the selected
document set and records both input paths and digests in the derived output;
the legacy V1.2 resolver defaults remain available only for historical checks.
Inherited legacy workflow definitions are indexed explicitly as
`kind: HISTORICAL` with `authority_effect: NONE`; they remain audit lineage
only and cannot satisfy the active V1.3.1 evidence lane.

## P0 evidence classes

The 14 P0 entries are not one homogeneous runtime matrix:

- 11 entries are `RUNTIME_SOCKET_OBSERVED` and must be induced through the loopback socket and bound audit evidence;
- two entries are `EXACT_HEAD_COMPILED_SOURCE_BOUND`: the one-absolute-write-deadline implementation and fallible worker-spawn/capacity-release implementation are compiled, unit-regressed and source-bound, but the socket harness does not claim that it deterministically induced those internal failure paths;
- one entry is `BEST_EFFORT_CONTROLLED_DROP_SOURCE_BOUND`: controlled Drop/redaction semantics are compiled and tested, but allocator, compiler, swap and post-drop memory inspection are explicitly outside the evidence.

The classified result must report 11 executed passes, two exact-head compiled source-bound passes and one best-effort source-bound pass. It is forbidden to report 14 runtime transport passes.

The canonical P0 command remains `scripts/p0_transport_exact_v1.py`. When that
entrypoint delegates implementation to another repository file, every byte of
the delegated implementation is itself an explicitly indexed `NORMATIVE`
manifest member and required-manifest path. The current delegated core is
`scripts/p0_transport_exact_core_v1.py`; the terminal-reset regression is
`tests/plan/test_p0_transport_reset_tolerance.py`. Removing either path from
the exact-source manifest, replacing the wrapper import, or bypassing the
strict response parser fails the plan suite. A terminal TCP reset is treated as
end-of-stream only after response bytes have arrived; the resulting head and
body still have to satisfy the original strict parser and exact
`Content-Length`. A reset before any response bytes, a partial response, or a
non-reset socket error remains fail-closed.

## Durable legacy-adoption equivalence

The H02 durable lab must preserve and compare the authoritative legacy log bytes and exercise the adopted store through the OpenRaft storage traits. Evidence must compare:

- log state;
- persisted vote;
- committed log identifier;
- all retained log entries;
- retained membership entries;
- the same values after `open_existing` reopens the newly adopted store.

The state-machine adoption proof separately compares client state, last-applied log, stored membership and the reopened state. Creating an initialization marker alone is not a no-data-loss proof.

## Exact head and synthetic merge

On a pull request, one matrix job checks out the exact head and one checks out `github.sha`, verifies that it is distinct from the head, has exactly two parents and that those parents are the event base and event head. Each lane independently executes:

1. every plan validator and Python regression suite;
2. Rust 1.98 root workspace format, tests and strict Clippy;
3. classified P0 socket/audit evidence;
4. Rust 1.88 and 1.98 OpenRaft tests and strict Clippy;
5. the complete 24-entry H02 application matrix;
6. a machine-readable technical receipt bound to the source and runner.

Missing, skipped, blocked, unknown, malformed or ancestor-only evidence fails the lane.

### Workflow coverage and duplicate arbitration

The consolidated workflow is the sole canonical technical evidence lane for
this revision and must execute both `head` and distinct synthetic `merge`
source kinds across all plan/Python, root-Rust, classified-P0 and H02-24-entry
gates. Other legacy workflows may still be triggered for historical or
diagnostic evidence; they are non-authoritative and cannot satisfy this
closure's lane arbitration. Concurrency is scoped to a pull request and its
head SHA (with `source_kind` retained as the lane key): a newer head cancels an
older run but does not erase its recorded history. The heavy source matrix uses
`strategy.max-parallel: 1`; this bounds hosted-runner admission without
collapsing the distinct head and merge jobs or allowing either receipt to stand
in for the other. A cancelled predecessor must skip its post-run aggregate via
`if: ${{ !cancelled() }}`. Failure or skipped technical lanes still reach the
aggregate, but workflow-level cancellation cannot enqueue fresh checkout work
and keep the predecessor concurrency group alive. The workflow-level group is
versioned (`v2`) so already wedged predecessor runs cannot block the corrected
policy. The latest exact-head run is selected only if both lanes complete;
ancestor-only artifacts are rejected.
Within a matrix summary, missing, unexpected or duplicate entry IDs are
aggregate failures, never a reason to discard a conflicting result.

The H02 summary is only complete when its dependency binding is byte-bound:
the validator re-reads the canonical `Cargo.toml` and committed `Cargo.lock`
and compares both SHA-256 values. It also requires the evidence root supplied
to `--h02-evidence-dir`; for every one of the 24 entries it rejects missing or
symlinked stdout, stderr or exit sidecars, path traversal and duplicate aliases,
then recomputes all three digests. The exit sidecar bytes must match the
recorded exit code exactly. A summary that merely contains digest strings, or
that is uploaded without the 72 sidecars, cannot satisfy a completion receipt.

The receipt validator itself is source-bound. The post-run aggregate
materializes the validator, H02 runner and their schemas from each lane's
immutable commit before revalidating that lane; a synthetic-merge-only helper
cannot reinterpret an exact-head receipt. Provider job snapshots must carry
an aware ISO-8601 timestamp, preserve the raw API bytes and report a complete
single-page `total_count`; a truncated or naive timestamp response fails
closed. The final job snapshot must remain completed/successful, retain the
same runner labels and preserve the receipt step prefix.

Each lane also emits a technical completion receipt. The receipt includes a
digest of the GitHub REST identity record used for owner-ratification checks;
the validator compares that digest and every identity field to the uploaded
record, so an unbound or partially uploaded identity file cannot qualify as
source evidence. It also records the locally recomputed arbitration key,
immutable head SHA, source lane and required lane set, allowing head/merge
receipts to be grouped without trusting a GitHub run-listing API. The receipt
remains non-authoritative and does not replace an independent review.

After the matrix jobs, a post-run lane-arbitration job downloads only the
current workflow run's receipt artifacts and invokes
`scripts/arbitrate_v1_3_1_lanes_v1.py`. On a pull request the aggregate must
contain exactly one `head` receipt and one distinct `merge` receipt. Both must
bind the same immutable PR head SHA and base/event merge values; the head
receipt supplies the immutable head tree, while the merge receipt must bind
GitHub's exact synthetic merge commit. Duplicate lane/key/digest/runner
identities, stale or superseded run IDs, missing companions, ancestor-only
commits, and any non-PASS technical receipt fail closed. The job emits a
schema-valid `FAIL` object (with an explicit `failure_class`) when evidence is
missing and exits non-zero; `UNEXECUTED`, `BLOCKED`, `UNKNOWN`,
`TECHNICAL_FAIL`, `DUPLICATE`, `SUPERSEDED` and `SOURCE_MISMATCH` are all hard
failures. A missing artifact can never be interpreted as a pass. This
aggregate only arbitrates technical evidence and keeps all qualification,
compatibility, selection and authority fields false or `NONE`.

## External boundary

Branch/rules enforcement, independent reviewer identity, legal disposition, incident operation, isolated signing and revocation, restricted Oracle transfer, independent power-cut/filesystem testing and independently operated reproduction remain external action packages. Repository automation cannot manufacture those facts. Technical receipts therefore retain all qualification, compatibility, selection, production, migration and release authority fields as false or `NONE`.
