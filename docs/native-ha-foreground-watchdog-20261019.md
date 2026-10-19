# Direct LAN98 foreground owner — 2026-10-19

## Status and evidence boundary

This is a QA-only launcher change for the actual Darwin/native node in the existing direct LAN profile. No Rust product source, TLS material, endpoint, network permission, runtime data or application request changed. All 98 checks and the original HTTP 15 s, native ReadIndex 8 s, listener 45 s, election 60 s and quorum-loss 35 s budgets remain mandatory. The process start bound remains 60 s; an explicitly requested stop and its successful cleanup remain within the original 5 s. The historical 36/98 result remains failed and unchanged.

The new helper has passed seven real local owned-child checks using Linux and an explicitly attested system Python. They create only synthetic Python fixture executables and no network sockets, SSH connections, Bao process or credentials. This is not a Darwin watchdog run or a LAN qualification. The first local run's interpreter refusal, the two intervening successful candidate receipts, and the final successful receipt are retained separately with their actual source hashes.

## Actual observation motivating the change

The old launcher starts the native process with `start_new_session=True`, waits 0.4 s, writes its PID/start identity and exits. Its remote SSH/Python parent chain ends immediately. The separately executed TCP diagnostic kept an SSH/Python owner alive. With the same original Mac binary and original path, its 126 observations reached TLS frame write, with no tcp_connect HostUnreachable event. Owned dummy endpoints closed these connections, yielding 89 UnexpectedEof and 37 ConnectionReset events. Each Linux listener saw 63 other Mac-IP accepts and one independently matched Python source port; the Python controls each connected once. All diagnostic groups were cleaned. The summary explicitly does not attribute each accept to the native PID and does not identify TCC or an original network-policy cause. It does not count as HA.

The new change isolates the launcher lifetime in the real acceptance profile. The native argv, inherited environment, inherited cwd, stdout/stderr log and new-session flag match the old native launcher. Only Darwin/native startup and stop use the foreground owner. Mac V5 seeding and every Linux process action still call the original implementation.

## Integration and custody

`NativeRun` gains one overridable `owned_process_action` method. Its start, stop and final cleanup each call that method. Every other original method is AST-identical, including all application stages and timing logic. `DirectLanRun` selects the single actual Darwin host after the existing host/ABI checks; it installs one hash-bound helper into that already owned fixture and binds the explicitly supplied interpreter path and SHA. It adds no tunnel, listener, route, firewall rule, signature or production-service operation.

Each native incarnation gets a new 128-bit launch nonce under the original run/root marker. The root device/inode, exact binary SHA, helper SHA and product commit/tree are checked before the native Popen. A launch intent, active marker and consumed nonce directory prevent another Popen after an uncertain result. Restart occurs only when the original acceptance flow explicitly starts a new incarnation after verified stop. No watchdog restart loop exists.

The local owned SSH client stays foreground with stdin attached. A small public heartbeat proves its continued parent lifetime. An explicit kill request carries only the launch nonce. Loss of stdin, an expired parent heartbeat, a protocol error or unexpected native exit triggers owned cleanup and fails the run; none grants a replacement start. The direct caller checks that its foreground session remains live before new application requests. Already existing HTTP mutation and UNKNOWN/no-retry logic is unchanged.

## Darwin exit identity and signals

The actual Mac microprobe established that WNOWAIT can observe the same exit twice while Popen.returncode remains None. BSD ps still reports the original PID, PPID, PGID and lstart for that zombie, but getpgid/getsid fail with ESRCH. Darwin also reports waitid.si_uid=0 for an actual uid501 child. The helper therefore never derives ownership from si_uid and never interprets ESRCH as an empty process group.

At live capture, it verifies the actual session leader and group. A first fast exit or transition during capture is accepted only through the same ps identity and repeated WNOWAIT observation. Exit events bind the exact PID, SIGCHLD, terminal CLD code and status; ps separately binds UID, PPID, PGID and start identity. No poll, wait or communicate reaps the child before group cleanup. While its PID is still reserved by the original Popen, the helper projects actual live members of that group, sends the original SIGKILL fault to the verified group, observes it empty, and only then reaps the leader. Leader-reaped and live-group-empty are separate claims. The implementation claims no cleanup of arbitrary external groups or unrelated processes.

The seven local cases cover explicit SIGKILL and one consumed launch, parent EOF, normal native exit without restart, a real zombie with a live same-PGID survivor, changed-owner refusal before any signal, delayed observation against an unchanged absolute stop deadline, and the real supervisor/pipe lifecycle through a local transport substitution. The zombie case prohibits either live-only API during zombie capture/cleanup. Actual SSH and Darwin runtime behavior still require execution by the root operator.

## Terminal evidence and deadlines

A file cannot certify the duration of its own unfinished fsync. The remote `foreground-watchdog/<launch>/terminal.json` is therefore explicitly cleanup-only: its `ok` is false and deadline qualification is null even when the live stop succeeds. It permits independent identity/group reconciliation but cannot turn a timeout or unknown outcome into a passed fault. After that fsync, the owner checks the original deadline and emits its live terminal response. The controller independently checks receipt, thread closure, local owned SSH group closure and final artifact work against its original absolute 5 s. Its retained raw wire and preliminary complete file are also explicitly unqualified for the controller deadline. Only the final live return object, after the last clock check, supplies the qualified observation to the main LAN report. A failure-only local SSH cleanup has its own bounded rescue but never changes the failed result or resets the original stop clock.

Public receipts contain process identities, source/ABI hashes, source locations, counts and phase results. They contain no configuration payload, environment values, TLS key, root token or unseal key. Original private process logs and recovery records remain in their owned fixture roots.

## Exact invocation inputs

Keep all existing LAN98 source, binary, producer receipt, node, port and fresh-root arguments. Add these two arguments:

```text
--darwin-watchdog-python /opt/homebrew/opt/python@3.14/bin/python3.14
--darwin-watchdog-python-sha256 cbf84109626aa1013bbe408fbb9590bd0f1c1548f038b2221c6b8b87de26ca43
```

The observed interpreter is 3.14.3, 52,448 bytes, realpath `/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14`. This attests the interpreter binary, not every standard-library dependency. The input template leaves all fresh product commit/tree, produced binary receipts and fixture roots null until actual same-source Mac/Linux artifacts are selected. QA source hashes are recorded separately from that product cohort; the old TCP binary is not a substitute for those fresh artifacts.

The template enumerates the nine runtime QA files and their exact hashes, including the new owner helper. The private fixture gains `native_ha_foreground_watchdog.py`, the active launch marker, per-launch intent/identity/ready/terminal records and the ordinary PID/log files. The local controller gains a per-launch private directory with SSH identity, public wire observations and cleanup evidence. Every file belongs to the new fixture or controller root.

## Source bindings

The structural receipt records both existing changed files' exact base/candidate SHA, every unchanged original method, the fixed denominator and budgets, all 98 case names, and the actual receipt hashes. The required base hashes are `b9253d5fcfcd7bf527c3efa9f4c9de116e3d81e75a676596d8cf112e0e31a4fc` for native multihost and `8c6861238b372d43db2ebc26bead1f4d8f23aa57c903e4bd0924dcf09b8cfb90` for direct LAN. The reviewed shared `ha_multihost_live.py` remains `e0c26f9858713303f3f57fab08057f535c893090b21c8eb6648711a164803e6b`, preserving the earlier terminal 45/60 s checks.
