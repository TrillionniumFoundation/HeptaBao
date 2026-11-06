# One existing public launchd label: one removal, exact rereads

Status: **SOURCE ONLY; no Native GO, no slot initialization, no execution.**

The baseline is the exact R3 read-only libproc diagnostic. Its original full packet is `eb98487932a9b9aecc6780b81ec015be55cd8d3b`; root independently qualified its returned observation chain in `56129f46fd94d072e301c4e558481efd817aed55`. That result records the label as not running, with runs 1, no PID and last exit 1. The public ready/terminal and current typed ESRCH observations are exact prior observations. They do not establish the earlier managed process's historical closure.

## Narrow change

The candidate adds an explicit `OneLabelCleanup` subclass and one finite sequence. It reads the same fixed public inputs, checks the same parsed target/path/program/9 arguments, binds the current ready/terminal/marker full9 to the actual R3 report, and requires the original child and controller deadlines to have elapsed. A pre-effect numeric ready-PID observation and the full public path fences must pass before one fixed `launchctl bootout gui/501/org.heptabao.qa.home-t5-context-20261106-r1`.

The potentially state-changing operation is marked attempted before dispatch. Bootout can request termination through launchd; this is explicitly disclosed. There is no numeric PID/group signal, managed wait/reap, bootstrap, retry, fallback target or finally bootout. The two post-effect print calls use the unchanged exact missing-service predicate; the unchanged second numeric lookup and final public fences are between/after these observations.

Success means the current ordered label-removal observation is complete and this controller's application FDs/direct helpers are closed before the deadline. It never changes `originalR4ManagedScopeStillUnknown=true`, `historicalReadonlyR2Helper87650ClosureStillUnknown=true`, `registrationClosureClaimed=false`, or the earlier failed records. An attempted effect without the complete new confirmation chain leaves current registration outcome unknown. No target absence is inferred from ESRCH alone.

The source does not claim that sequential print/file checks acquire an atomic service identity lock. It does not claim historical descendant closure.

## Preserved limits

- Original 45-second controller, 35-second helper admission and 60-second outer deadline.
- Original four direct-command cap: preflight print, one bootout, two missing-service prints. Each call remains at most 10 seconds, clipped to the original admission end, with 65,536 returned bytes and the original total command-byte cap.
- Unchanged two native lookup windows, each at most 4 seconds, maximum six explicit numeric calls. Existing internal helper/reader calls are not renamed as those six.
- Unchanged 64 FD-attempt/row cap, 4,096 metadata calls, 256 reads and 262,144 application read bytes; zero application writes.
- Unchanged public output cap 65,536 bytes; future original process reads at most 16,384 bytes, immutable payload pages at most 8,192.
- No T5 access, private capsule, credentials, SDK, product/consumer launch or provider/model changes.

## Mechanical scope and evidence

There are **7 strict source hunks** and **2 strict journal hunks**. Source hunks cover the truthful cleanup description, ten fixed additional error literals, exact observed constants, the subclass/fence helper, main sequence and final result predicates. The full original FixedIO, ProcessReader, ReadOnlyControl/libproc methods, print/missing predicate, validators, embedded helpers and old budgets are unchanged. Journal changes are only the fresh slot, exact request pin and source-derived observation-key prefix.

`verify-source.js` was evaluated as pure V8 only. **61 source/binding checks passed.** It never evaluates Python, starts a process, calls the Native runtime or gives product qualification. The first checker used JSON insertion order for the terminal error mapping and failed; its source/error remain under `history.*`. Only that checker comparison was corrected to semantic sorted mapping equality. The candidate was not changed by that correction.

Two unsubmitted drafting corrections are recorded: marker full9 uses the exact tuple result type of the unchanged marker reader; the inherited no-mutation docstring was corrected. Neither draft was executed. Reverse diffs retain their exact source bytes without copying another large carrier.

## Reproducible pure interface

Read the flat packet files into a map of exact UTF-8 strings. Load the two pure helper files (`pure-helpers.original.js` and `unified-diff.original.js`) and `make-verifier-inputs.js`. Construct `H={pin:gitBlobMeta,apply:strictApplySource}`, then `cleanupInputsFromFiles(files,H)`; pass that value and H to `verifyCleanupSource`. The input builder was compared field-for-field with the actual already-evaluated input and matched. This packaging check did not rerun the candidate or the old resource components.

The complete source/request/journal pins are in `CONTRACT.public.json` and the manifest. A separate exact root GO is still required before initializing the fresh journal slot or invoking the state-changing request. Root will independently bind the current typed `stdin` digest/fingerprint; no obsolete `stdin_text` binding is used.

After actual scoped cleanup has been reviewed, the active task is the existing complete AuthBus trustworthy-source/AppRole/TLS/KV/Policy/renew/revoke flow, with its original budgets and full selected-instance assertions. This package does not authorize that later run.
