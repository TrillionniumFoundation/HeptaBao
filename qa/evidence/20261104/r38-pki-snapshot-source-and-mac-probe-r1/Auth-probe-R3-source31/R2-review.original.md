# FD registration correction R2 — SOURCE ONLY

## Blocker and correction

B independently found a real R1 failure branch: after `os.open` returned, construction of the row or `rows.append` could fail. The returned FD would then be absent from `rows`, so the old `all(row.closed for row in rows)` predicate could misleadingly be true. The child could report a known failed observation with unproved descriptor closure. SOURCE38 and its 73 source-literal checks remain unchanged historical objects; those checks were not runtime qualification.

R2 adds a pre-syscall attempt ledger in the existing signal critical section. It records an attempt and a pending outcome before `os.open`. Only an `OSError` from the syscall expression itself is counted as a known no-return error. The row-construction/append/registered-counter/pending-decrement sequence is in a separate protected try block. A failure after return leaves pending and/or registrationUnknown. It does not guess a descriptor, blind-close, retry registration, reset the ledger, or declare the attempt complete.

The final `allClosed` now requires all of these conditions:

- attempts = knownNoReturnErrors + registered;
- registered = the number of rows actually present;
- pending = 0 and registrationUnknown = false;
- every registered row was closed by the unchanged once-close method and no close error remains.

If a row was appended before a later registration error, normal final cleanup may close that registered row once, but this does not erase the unresolved registration history. The same conservative predicate governs both controller and child. The parent also validates the exact five-field child open ledger before accepting a child terminal observation. A failed child gate keeps observationComplete false and therefore keeps the bootstrapped attempt's outcomeUnknown true.

## Minimal changes

The common I/O source changes only `__init__`, `open_fd` and `public`: three strict hunks. The controller core changes only `validate_child_io`: two strict hunks. The child's full `child_main` function is byte-identical. All bootstrap, ready/admission, actual birth, inactive observation, PID reuse, bootout, deadline and main-finally functions remain byte-identical. The four embedded original modules, original strict78 parser and T5 anchor remain byte-identical.

The final controller and child are reconstructed mechanically from R1 by those known code blocks, the two new closed source error-code literals, and the derived embedded child bytes/SHA. The exact request changes only stdin and its previously unsubmitted identity key. The journal changes only slot/request pin/observer prefix, with two strict hunks; its functions are unchanged. Neither R1 nor R2 journal slot is initialized.

All original budgets and ownership rules remain. The existing maximum 64 is now applied to open attempts as well as registered rows; it is not increased. No host, SDK, credentials, old label, capsule, source file or service has been accessed or changed by this correction.

## Verification actually done

The targeted pure V8 verifier performed 58 delta/hash/strict-reconstruction, unchanged-block and accounting-boundary checks. It did not rerun R1's 73 checks or B's 120, compile/execute Python, inject an actual Python exception, open any FD, or call Runtime. The included eight arithmetic boundary states demonstrate why the unresolved-return cases cannot satisfy the new closure predicate; they are explicitly not a fault-injection/runtime test.

The R1 local compile-only tool failure is still preserved in SOURCE38. No new local compiler attempt or compile qualification is claimed.

## Exact candidate

- Controller: b50c5755c364ffdafed997e5f4f4362292d14b21, 168003 B, SHA256 7b73f40e9cd440189b69a0c42eec2e382382387305bf284989c152404f130b6a.
- Managed probe: 27f07eda5bdec7d5581ee524d4fc157dad1e1cd7, 36312 B, SHA256 a5140fef8f152900d39c939ac56226476a7bb3eb9008e29671f8668dfabb3d84.
- Request: a25adf6d1696f82da384f43296e364cb2b94406c, 170119 B, SHA256 2161a89e20c3bccca6a97c76a3b31b84e174a9ff1734c819f971034ec1ac93f2.
- Key: heptabao-mac-owned-home-t5-probe-7b73f40e-20261106-r2.
- Journal: 4efef900d6de8829f62194614bb12927169e9ad0; new slot owner_launchd_home_t5_probe_gitfirst_r2.

This is a new source revision awaiting the narrow independent B/root review. It is not a host execution GO and does not change any historical UNKNOWN.
