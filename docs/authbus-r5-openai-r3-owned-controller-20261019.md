# OpenAI R3: single-submission main controller

This adds the outer Python controller for the already frozen OpenAI R3 SDK fixture. It does not change that fixture, its 15 source files, 16-member archive, either shared SDK adapter, or the native/cold four-case controller. Actual OpenAI SDK execution remains pending until a main-host receipt is collected.

## Run and reconcile

Transfer the frozen source archive and this single Python file into new files directly under `/home/qian-qi/heptabao-next-gates-20261017`. The controller has no non-stdlib Python dependency. Do not import or execute the local regression test on main as part of the SDK run.

```sh
python3 -B /home/qian-qi/heptabao-next-gates-20261017/authbus-openai-r3-once-20261019.py --packet /home/qian-qi/heptabao-next-gates-20261017/authbus-openai-r3-20261019.tar.gz --run-root /home/qian-qi/heptabao-next-gates-20261017/authbus-r5-openai-r3-actual-20261019-01
```

The run root must not exist. Its exclusive creation is the one-run claim; a repeated command refuses without adopting or modifying an existing run. `controller.json` is atomically replaced with a flushed, directory-fsynced journal after each stage. The submission count is saved before the one `Popen` call. Its original child PID and session identity are recorded before waiting. There is no retry, PID search by process name, service operation, network command, production write or credential input.

For an unknown tool result, read the existing run's `controller.json`. Reconcile its controller PID, child PID, original session identity, boot ID and terminal receipt. Do not resubmit the same run or choose a fresh run to bypass an unresolved original process. The original Node output stays in `node.stdout.log` and `node.stderr.log`; its original public receipt stays in `fixture/public-receipt.json`, including on failure. The parent should save the original bytes and hashes before interpreting them.

## Exact input custody

The controller pins the original R3 archive at 66,245 bytes and SHA-256 `29ff0adcfffe64632d683482c34a10696329796b7a56f3d656502b546c881fb7`. It verifies exactly 16 unique, bounded, ordinary archive members, their canonical names and mode 0644, the exact manifest bytes, all 15 source SHA-256/Git blob identities, and the complete closed source tree. It uses exclusive file creation rather than archive extraction into existing directories. New source directories are created explicitly with mode 0700.

The manifest is pinned at SHA-256 `e47f38e9b04d68d9570b1432c71f3fb42764d79309c80f4de5eb4bfc84cc0d5b`. Its embedded SDK input object is bound to standalone SDK-manifest SHA-256 `b4aad3e15807db250900505d3cf5ab0e1d319d762c08cdb5a839edf214fb3a65`. Before launching Node and after its cleanup, the controller verifies the exact 35 SDK JavaScript inputs, OpenAI activation metadata, package.json and openclaw.mjs: 38 files. Files are regular, no-follow, bounded and stable across the checked read. The installed SDK is not modified or copied.

The Node executable is also pinned to the actual successful native R1 input: `/usr/bin/node`, 124,827,920 bytes, SHA-256 `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`. It is streamed for hashing rather than read into a large Python buffer. The actual public receipt must report Node `v22.23.3` and SDK `2026.7.1-2`.

The child receives only explicit PATH, locale, timezone and a new private temporary directory. No API credentials, existing OpenClaw state variables, NODE_OPTIONS or proxy environment is inherited. `HOME` remains absent so Node resolves the actual account home and the frozen runner's private-home read guard continues to cover that real location. The frozen runner supplies its own absolute state/config/OAuth paths and its verified package-bin discovery context.

## Original deadline and original processes

The one original 180-second monotonic budget starts before input checking and source staging. All preflight reads, staging, the SDK execution, successful cleanup and final source/SDK verification count against it. The Node invocation has exactly the two frozen runner flags: `--openclaw-root` and `--work-dir`. It does not receive a reset deadline, new lease or retry parameter. The original SDK/coordinator deadlines remain unchanged.

The process method follows the existing native artifact controller's `waitid(..., WNOWAIT)` approach. The original `Popen` leader is held unreaped, reserving its PID/PGID/SID while descendants are inspected. Normal completion, timeout and interruption all clean that same session before waiting the original leader exactly once. SIGTERM and, if needed, SIGKILL address the still-owned original process group. A descendant that changes PGID but remains in the owned session is bound with a kernel pidfd and rechecked before signaling. Reparenting after leader exit is accepted as an expected PPID change; PID, start time, UID, SID and PGID remain bound.

Cleanup retains the existing five-second TERM and five-second KILL limits. Necessary cleanup after an expired business deadline may finish later, but the original run stays failed. It cannot obtain a success from a new cleanup deadline. Metadata or signaling failure is retained explicitly; a last-resort wait of the original leader never becomes a clean-session proof. Signal handlers record interruption and let the registered original handle reach cleanup instead of abandoning the child during its creation window.

This controller handles the verified fixture's child-session descendants. The frozen Node source forbids subprocess creation after its one synchronous owned OpenSSL certificate generation. It does not claim to contain an arbitrary malicious process that escapes all session ancestry or to survive an uncatchable SIGKILL of the controller itself; any missing terminal receipt stays unknown and requires original-process reconciliation.

## Success qualification and local results

The outer controller requires the original child receipt to contain all 32 scenarios in the frozen order, all individual assertions passed, the original PID/parent PID and runtime versions, 15 source pins and 35 SDK overlay pins, the unchanged real activation metadata, and successful fixture process-context restoration. Native HeptaBao, cold SDK, external provider and production flags must remain false. All forbidden network/process/write/home-read counters must be zero.

The exact five real Undici rows must have provider, CONNECT and verified TLS request counts of 1/0/1/1/0, zero mapped fetch calls, one guarded runtime entry per actual request, UNKNOWN observed before each request, and total accepted CONNECT count three with zero proxy denials or upstream failures. Source and SDK pins must still match after all originals are cleaned.

Eight local custody regression tests passed using synthetic Python children and the exact frozen archive. They cover archive/hash closure, unexpected source files, symlink/empty-input refusal, all SDK input classes plus metadata tampering, the original handle's single wait, an already-exited leader with a live descendant, and timeout cleanup of an owned descendant that starts another PGID and ignores TERM. The last case verifies pidfd KILL while preserving the expired original deadline. No installed SDK, real host, provider or credential was used.

The first local run's failure log is preserved. It found an intermediate-directory mode assumption that was fixed by explicit creation, and the sandbox's `/proc` PPID/SID view did not match the actual session syscalls. Identity assertions were retained; the same local synthetic tests were then run through an automatically approved executor escalation with real kernel metadata. The successful run took 5.63 seconds. Its process tests adopt and reap their own orphan fixtures using a test-process-only subreaper, preventing leftover test zombies.
