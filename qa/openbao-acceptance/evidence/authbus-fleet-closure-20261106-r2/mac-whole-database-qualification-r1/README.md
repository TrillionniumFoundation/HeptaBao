# Mac whole SQLite qualification r1 — failed before restore

The unique original job `1a1b30415f3-fc05-8076` exited 1. Its 3,328-byte stdout is complete and durable, with zero stderr. The original sandbox Python child exited 1, was reaped exactly once, had no live group members, and its streams closed. Parent descriptors and the worker's twelve SQLite handles, twelve store descriptors and six input descriptors closed. Overall process-custody success is false because the workload failed; the explicit resource-closure observations remain valid.

The worker created six new synthetic databases using the installed OpenClaw agent and shared-state schemas. It then encountered `AttributeError` on its first namespace check. No backup or restore stage passed; `restoreStarted` is false and the restore-operation count is zero. No production database, configuration, gateway, provider or SDK was accessed.

The separate read-only capability job `1a1b306b4da-fc05-8079` exited 0 with complete 472-byte stdout and zero stderr. It verified the original Python runtime, observed that `os.listxattr` and `os.getxattr` are absent, and found the `flistxattr` libc symbol. It did not call the symbol, create a SQLite connection, start a child or change any production state.

The original r1 launcher, result and fixture remain unchanged. The successor r2 uses a new root and key and a source-reviewed held-descriptor Darwin query; r2 is not a retry or reclassification of r1.

The retained local Linux test is distinct evidence: the complete six-database exercise passed there under its explicit `unix` VFS. That result is not a Mac qualification. Both revisions retain a 64 MiB per-database fixture bound and do not qualify real production sizes, consumer quiescence, provider rotation or gateway restart.
