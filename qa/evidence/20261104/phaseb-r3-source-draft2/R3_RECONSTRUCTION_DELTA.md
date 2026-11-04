# R3 reconstruction delta and reference call boundary

The R2 main/binding/evidence bytes are unavailable. Accordingly this file is a
contract-level reconstruction note, not a claimed unified diff against R2.
The accompanying NEW_FILES.patch is a literal /dev/null-to-R3 source patch.

## Exact reference reuse

Native reference 68149 B/a0bac997 is byte-identical to the recovered original.
R3 subclasses its Fixture:

* unchanged invoked source: __init__, cold_clone, ready, stable_leader, roles,
  and the strict HTTP request/child parser path;
* setup keeps the original function code, defaults, closure and every other
  global. Its only changed function-global binding is stop_owned, in a scoped
  globals copy. The exact owned seed is routed to the original native stop
  function through the shared explicit-stop ledger; the module is untouched;
* bounded wrapper: request clamps each exchange to the current action and
  tracks missing/uncertain mutation boundaries;
* replaced owner-specific methods: check, openssl, spawn, start_owned_child and
  finish; these bind new input identity and original reviewed CLI child custody;
* never invoked: old main admission, stage_artifacts, verify_artifacts,
  source_and_fences, old observe negative matrix, old finish report.

Official CLI reference 46586 B/18318841 is byte-identical to the published
original. R3 inherits start_child, await_owned_cmdline, record_child_provenance,
run_private and interrupted, and calls exact stop_owned/stop_provisional.
R3 bypasses its constructor and never calls setup, synthetic_archive, Peer,
case, finish, prepare or main.

The stop ledger covers explicit seed/cold normal stops and final cleanup:
exact Popen/capture custody and an attempt placeholder precede the original
TERM 5 s / KILL 5 s dispatch; repeated collection retains that result without
reallocating the normal stop budget. It does not change the exact references'
separate deadline emergency SIGKILL + wait 5 s. The original emergency stage
may still be followed by one original final 5+5 s cleanup allocation. Both
stages remain bounded, and timeout remains unknown with no business replay.

The reference globals ROOT and Python __file__ serve only the new owned process
working directory and the exact standalone strict HTTP child. R8 source/artifact
globals cannot authorize the R3 runtime. The R3 Binding validates R10 directly.

## New modules

phaseb_binding_r3.py defines canonical R10, actual normal artifact and 44-test
receipt admission, file/physical host/source/old-evidence fences, five source
member hashes, and the immutable original deadline values.

phaseb_evidence_r3.py implements native canonical archive inspection, nested
schema 2 audit/append-prefix observation and captured literal/encoding scans.
It explicitly leaves seal/MAC authentication and client framing unproven.

phaseb_controller_r3.py implements B01-B05, synthetic normal seed, three actual
normal native processes, two distinct CAS3 mutations, exact all-node API data
readback, two permitted known-terminal cold regressions, no-replay unknown
barriers, generated config/credential fences and independent owned cleanup.

A fake native archive or stubbed peer is never used as a product positive.
The two supplied synthetic component files exercise observer rejection and
actual new controller branch logic with fake dependencies; neither executes
reference helpers, a product process, an actual stop signal or an archive upload.
They and the pure-memory stdin wrapper are explicitly unexecuted in this draft.

## Draft 1 to draft 2 source changes

The precise accompanying diff is against the recoverable NEW R3 first draft,
not against lost R2. It preserves every original business request and deadline.
It adds an explicit pending boundary across restore API/JSON/report validation,
marks malformed replies after dispatched mutations unknown, and shares the
normal cleanup allocation across seed/cold explicit stops and final collection.
The seed hook changes only that scoped stop symbol, retaining exact references.
The evidence component file gains a memory-callable run function; the new
controller component file and stdin wrapper provide a separate offline gate.

## Publication / execution boundary

Only unreferenced draft Git objects are created. No ref or production file is
changed. The binding template's ready_for_readonly_prepare=false and null
artifact/host fields are deliberate; the template is not executable admission.
Full source review and actual Python parsing/components are still required,
then concrete physical artifact/source binding and one fresh read-only prepare.
A live run requires a separately reviewed exact prepare result SHA.
