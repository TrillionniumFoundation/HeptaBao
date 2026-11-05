# QA builder R2: direct-child custody for short commands

## Status and retained failure

This is a new SOURCE candidate. It does not claim a successful ROG custody component, Rust build, six H2 receiver components, TLS request, or product qualification.

The unique R1 job `1a1aa9fa851-fc05-4547` is retained in full failure tree `fa98f537f52e0eb75c8d26a53084a79a87564878`. Its second read-only Git command entered the unchanged CLI reference's empty-cmdline visibility observation and failed `owned_child_identity_changed_while_cmdline_pending`. The original result remains `command_outcome_unknown=true`. Both recorded Popen children were subsequently reaped with return code 0 and empty remaining groups. The later tree stdout matches the expected tree, but neither that stdout nor wait0 completes the missing original guard. R1 dispatched no Cargo, component, product, or HTTP request.

## Change boundary

The candidate adds one builder-local `qa_command_owner_class` and changes the main function's owner factory, wait call, and result schema. Nineteen other original top-level definitions are byte-identical. The two constants for the owned control/project roots change to fresh `-r2` paths; the file basename deliberately remains `build_native_h2_client_r1.py` inside the new control directory so the existing fixed-path guard and carrier remain exact. Neither old directory is reopened for a command or modified.

The canonical df026 commit/tree, normal60 qualification, tool pins, target five-field identity, target path, source guard commands, mode/owner rules, six QA test names, Cargo flags and offline lock-subset checks are unchanged. The six retained inputs (Rust client, Rust components, manifest, canonical lock, owner reference and CLI reference) are byte-identical. The new build binding only replaces the two root values and the six input paths under the new control root. The original CLI reference and PhaseB owner source are not edited.

The actual importer and normal stager provide the narrow precedent: a Popen returned directly from a controlled argv is registered immediately, waited, and checked for terminal status and an empty group. They do not require a fast command to remain alive for a separate proc argv observation. R2 adds an unreaped-child proof and terminal cross-check to that builder-only contract.

## Ownership and terminal proof

1. Only the builder's four fixed executable paths are admitted: pinned Git, rustc, cargo, and its retained QA test executable. The argv is copied to an immutable tuple. A shell, preexec function, executable override, or inherited extra file descriptor is not accepted through the allowed options.
2. The actual Popen is appended provisionally before any post-spawn observation. The inherited signal deferral covers creation and immediate registration. An exception after return retains the child for the original cleanup collection.
3. Before any poll or reap, two bounded reads of that child's proc stat must agree on pid, parent, process group, and start ticks. The parent must be this builder and the group must equal the direct child's pid.
4. Between those reads, `waitid(P_PID, pid, WEXITED | WNOHANG | WNOWAIT)` must succeed. `ECHILD` is a refusal. A returned terminal event must identify the same uid/pid and an actual exited/killed/dumped status. A running child may return no terminal event; that is custody evidence only, never command completion.
5. Normal waiting remains under the existing absolute command deadline. It observes the same unreaped child with WNOWAIT, at an increasing delay capped at 50 ms, and never launches a second command. Before reaping, an actual terminal event and the same start identity are mandatory. The subsequent Popen.wait must return exactly the code represented by that event.
6. Only the existing command-level exit0, original deadline, stream custody, empty-group and subsequent source/artifact checks permit success. Nonzero exits remain nonzero. A missing event, changed identity, conflicting status, cancellation, read/close error, or deadline failure stops later work.
7. The original owner `stop_once`, cleanup ledger and TERM5/KILL5 behavior are reused verbatim. Normal observation never grants another stop budget. A previously reaped process group is not signalled by this change.

This proves the controlled invocation and lifetime of the builder's child. It does not claim an independent live proc executable/argv observation; each new provenance row explicitly records `live_proc_argv_observed=false`. No code reads or accepts an empty cmdline. Successful Popen construction and the documented POSIX child/exec protocol are part of the proof, together with the already-pinned tool bytes and before/after checks. The public CPython v3.12.3 source references document that API contract; they do not assert that the pinned ROG Python was built from that exact tag.

## Checks already performed

The complete builder and publisher are parsed/compiled as code without executing their modules. Removing the new helper and reversing the five main/root/schema substitutions reconstructs all 35,155 original builder bytes. The in-memory component runner uses the actual selected helper methods and actual retained stop_once ledger, with injected OS/Popen implementations. Eighteen cases pass, including already-terminal, running-to-terminal, nonzero/signal status, no terminal event, ECHILD, parent/start identity mismatch, terminal and wait disagreement, deadline, SIGCHLD disposition, deferred signal, and descriptor failures. The close-failure case intentionally retains a false FD-closure result. No real child, network, product, or target main ran in these memory components.

These checks do not establish real Linux syscall behavior or ROG qualification.

## Proposed actual component gate

`requests/owned-components.proposed.exact.json` contains a complete reviewable request, not authorization. It selects only named definitions from the three pinned source strings on stdin. It does not execute any target main or module top-level product/fixture action. It first and finally verifies the same Python and Git whole-file pins.

Three explicit, public, repository-free commands share one 15-second absolute observation deadline: ordinary Git version; the same command with its first stat observation deliberately delayed until its already-registered child is terminal but unreaped; and an invalid fixed Git option whose nonzero terminal code must be retained. The delay subclass calls the actual new methods and never replaces or creates an additional child. Anonymous memfd output is bounded, hashed and closed; there are no on-disk outputs, Cargo invocations, source-repository operations, credentials, provider or network calls. All children use the original stop-once ledger. The new outer supervisor proposal is 45 seconds, covering the shared 15-second component action and original 5+5 cleanup. It does not change any builder cap.

Only an accepted actual component receipt can qualify this new custody path on ROG.

## Proposed publication and build

The inert request creates the fresh R2 control directory and publishes the same eight named files, with only the new builder/binding content changing. Five original publisher function definitions remain byte-identical. Its original 60-second outer bound and create-only checks remain.

The build request remains inner600/outer660. Git/tool15, lock20, build180, component-build180, list15, six-components30 and cleanup5+5 are all unchanged. The existing target is never created or repaired by this builder; current identity is rechecked. Source and artifact whole-file checks remain in their original places.

The component, inert, and build requests each have a new fixed R2 key. None has been submitted. Root review and separate actual gates are required; the old failure is never replayed or rewritten.
