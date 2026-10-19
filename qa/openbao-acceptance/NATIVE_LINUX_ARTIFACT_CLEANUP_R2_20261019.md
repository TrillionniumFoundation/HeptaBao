# Transferred Linux artifact runner: owned group cleanup R2

This is a narrow follow-up to the frozen R1 artifact runner, whose SHA256 is `d4206c72bded887e807563b85de45568a60b319f035097291d622160d91c3620`. It changes no product source, compiler settings, capsule identity, source binding, selected test name, denominator, or product-facing fixture request.

## Concrete gap and evidence boundary

R1 returned immediately from `stop_owned` when `Popen.poll()` had already observed/reaped a completed leader. That proves the leader exited; it does not prove that a descendant in the same process group stopped. A libtest that exited while leaving a child could therefore produce a successful leader receipt while retaining a live owned descendant. No such residual child has been observed in the actual X230 0f1c run. The real 53/55 result is retained, and this cleanup gap is not offered as the cause of its two snapshot-related failures.

The local R2 test now executes the actual `execute_command` wrapper with a real synthetic leader. That leader creates a child in its own group, waits until the child has installed SIGTERM-ignore, and exits 0. R2 observes and retains that exit using Linux `waitid(WNOWAIT)`, sends TERM and then KILL only to its original owned group, observes no live group members, and finally reaps the original leader. The receipt preserves the leader's actual exit 0 and separately records the descendant cleanup. This is a local process-custody proof, not a HeptaBao or X230 acceptance result.

## Ownership and original limits

Immediately after each new-session `Popen`, the runner records the actual Linux PID, parent PID, process-group ID, session ID, user ID and `/proc` start ticks. A live or exited-but-unreaped leader reserves the PID/session identity through cleanup. No `poll`, `communicate` or early `wait` occurs in the owned command or server paths. An already reaped leader or a changed identity refuses numeric group signalling.

`waitid` observes completion without reaping and uses the original absolute command deadline. The unchanged 1800-second command ceiling remains in force; the final elapsed-time guard still rejects late success. Cleanup retains the original TERM5/KILL5 ceiling. Kernel identity observation has bounded access to the same-group members and emits no command lines or environment. The receipt records the original group, live members before signals and before leader reap, signal names, leader exit and reaping, and the separate `owned_live_group_empty` predicate. Failure to establish group cleanup stops the executor after preserving its command record.

The actual server probe uses the same reserved-leader cleanup. `owned_process_stopped` now requires both leader reaping and absence of observed live owned group members. Its native executable, TLS helper, health request, 45-second readiness window, 15-second HTTP limit and uninitialized/no-credential behavior are unchanged.

## Scope and validation

An AST comparison against the exact frozen R1 source confirms that the only changed existing functions are `stop_owned`, `execute_command` and `probe_actual_server`. Six small kernel-identity/wait helpers are added. All other existing function ASTs and every top-level statement are unchanged. In particular, the exact 17-group/55-case profile check, source/capsule/ELF identities, original test-result parser and production-authority restrictions remain unchanged.

The four real local process cases and all six unchanged artifact-custody regressions passed, 10/10. The new cases cover a TERM-resistant descendant after a successful leader exit, original wait-deadline expiry while custody remains held, refusal after reap, and refusal for changed start ticks. The original six cases retain compile-artifact identity, source/list/log binding, streamed byte-copy constraints, exact selector names, partial result counts and actual local ELF-loader metadata checks.

The new checks are in `tests/test_native_linux_artifact_cleanup.py`; the unchanged existing checks remain in `tests/test_native_linux_artifact_run.py`. The raw local output and exact source hashes are in the companion `evidence/native-linux-artifact-cleanup-r2-local-20261019` log/JSON. The local tests use a consistent PID/procfs view. The previously observed tool sandbox's PID namespace mismatch is not bypassed or treated as a product failure.

No Runtime, SSH, live credential, Cargo, HeptaBao server, LAN fault or X230 re-execution was performed for this delta. Existing actual-run receipts and frozen R1 remain untouched. Applying R2 to a future candidate's diagnostic artifact lane does not change the original producer or executor attribution.
