# heptabao-linux-parent-death

The fixed `bind_owner_death(&mut Command)` Linux hook registers SIGKILL before
exec and rejects an already changed parent. It accepts no PID, signal or callback.
The Wrapper runtime invokes it from the persistent child ownership thread, which
retains its owned Child and pidfd until an actual terminal wait. Request admission
threads can exit while that ownership thread and provider remain live.

`spawning_thread_exit_kills_and_reaps_actual_child` runs an actual child executable,
lets its spawning ownership thread exit while the parent process remains alive,
and requires an owned wait with kernel SIGKILL. The genuine Wrapper lifecycle consumer separately checks
server SIGKILL/SIGTERM, live encryption after the caller thread exits, and normal
provider retirement with the runtime's actual terminal wait.

The sole unsafe boundary registers a closed `pre_exec` callback. After fork the
callback uses only rustix prctl/getppid syscalls and raw OS errno conversion; it
does not allocate, lock, access environment, log, format, or call caller code.
Every existing workspace crate retains its prohibition on unsafe code.

Only the immediate provider is bound. This does not contain provider descendants
or force an arbitrary provider to retain a signal it deliberately clears. The
admitted Wrapper image is a sealed mode-0500 memfd without a set-ID/capability
transition. Existing exact image identity, AutoMTLS and lifecycle fences remain
the provider admission authority.

See the [module closure dossier](../module-closure/heptabao-linux-parent-death.md)
and the [Linux kernel userspace contract](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
