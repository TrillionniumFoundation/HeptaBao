# heptabao-linux-parent-death module closure dossier

## Design and state ownership

This local crate registers one fixed Linux parent-death SIGKILL callback on an
owned command. It retains only the captured numeric parent identity. The server's
persistent Wrapper ownership thread remains responsible for the owned Child,
pidfd and actual terminal wait; this crate never reports reaping.

## Module boundaries and trust assumptions

The safe API takes a Command and accepts no caller PID, signal or closure. One
audited unsafe call registers its closed pre-exec hook. Only rustix syscalls and
allocation-free OS errno construction run in the forked child. Existing crates
keep `forbid(unsafe_code)`. Linux binds this signal to the spawning thread, so
the runtime invokes it from the persistent owner rather than a request thread.

## Failure semantics and ordering

The child first installs SIGKILL and then checks that getppid still names the
captured parent. A parent that died before installation causes spawn failure;
death after installation causes kernel termination. The provider exec image is
the existing sealed mode-0500 memfd and changes no credentials. Normal runtime
revocation still uses its exact pidfd and owned Child wait. A killed server cannot
report TerminalReaped: an external collector may observe kernel terminal state
and, when it owns the adopted child, its own wait result.

## Acceptance evidence

**Named executable anchor:** `spawning_thread_exit_kills_and_reaps_actual_child` in `crates/heptabao-linux-parent-death/src/lib.rs`.

`spawning_thread_exit_kills_and_reaps_actual_child` executes a real child, then lets
its spawning thread exit while the parent process remains alive. The owned wait
must observe kernel SIGKILL without an administrative signal to satisfy the test.
Genuine provider executable coverage is supplied
by `crates/heptabao-server/examples/wrapper_lifecycle_consumer.rs` and the external
owned-process consumer: real provider AutoMTLS admission, a joined request caller
followed by genuine Encrypt/Decrypt, controlled retirement with TerminalReaped,
and actual server SIGKILL/normal exit followed by held-pidfd kernel observation.
Source and binaries must be bound to the exact committed head; a registered
signal or successful signal request alone is not accepted as termination.

## Known gaps and evolution

The binding covers the immediate trusted provider, not escaped descendants or a
provider that clears its own signal. Unsupported prctl rejects spawn. No general
purpose process callback or arbitrary process signalling API is exported.
