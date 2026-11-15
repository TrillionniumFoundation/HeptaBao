# Mac whole SQLite qualification r2 — 13 stages passed

Unique original job `1a1b30f982e-fc05-808d` succeeded with exit 0. Its complete, durable stdout is 6,999 bytes, stderr is empty, and the original parent elapsed time is 0.2028289157897234 seconds. The original worker stdout was independently read from the new private fixture and matched its complete 3,290-byte receipt and SHA-256.

The one original sandbox Python child exited 0, was reaped once, had no live group members and closed its streams. The original custody receipt passed. All 60 SQLite connections, 549 store file descriptors, six worker input descriptors and 47 parent file descriptors closed once. All 258 Darwin descriptor-based xattr observations proved no attributes and closed their original descriptors.

## What the actual exercise did

The fixture used the installed OpenClaw schemas for five agent databases and one shared-state database. It added synthetic non-auth table, index, trigger and view data, opened six old read transactions, and committed synthetic fresh credential values after those transactions began. Each whole backup came from a new independent read transaction, so the latest WAL contents and all three fresh synthetic credentials were captured while the old keepers continued to see the old state.

All thirteen recorded stages passed. Six complete baseline snapshots and six complete candidate snapshots were created. Before restoration, all original readers and writers were closed. The fixture retained eighteen original base/WAL/SHM files, completed forty-eight exclusive namespace actions, restored all six complete baseline databases, and reopened six new writers. Full schema, data pages, non-auth data and trigger effects matched; the fresh credential values were not rewound to their pre-provider synthetic state.

Source-to-backup page-image comparison excludes only the explicitly documented SQLite header bookkeeping fields and separately requires the backup schema cookie and the complete SQLite schema to match the reviewed contract. Archive-to-restored-file comparison is exact. No restored header or schema was rewritten to force the comparison to pass.

## Source and execution limits

The final launcher is 101,655 bytes with SHA-256 `8674a4cc5435400c40326905ff6b6150c25ae02246aa39cd84200e7480d99b29`. Its three embedded modules match their staged source bytes; all three internal imports resolve to the r2 modules. The parent re-read the installed schema sources and original custody/runtime sources before and after execution.

The Darwin-only fix uses one fixed `flistxattr(fd, NULL, 0, 0)` call per admitted held descriptor, with declared `ssize_t`/argument types, explicit errno, and full file identity plus flags before and after. Zero result with zero errno is required. Any attribute, unsupported operation, permission error, identity drift or missing symbol is refused. The Linux branch is unchanged. Eight local negative/closure tests were recorded before the actual run.

The original 45-second parent, 30-second worker and 70-second supervisor budgets remain unchanged. The finite fixture limit is 64 MiB per database. This is an actual Mac synthetic qualification of whole-database backup/restoration and closure. It does not qualify the current production database sizes, running consumers, SDK import, gateway restart, real provider rotation or production rollback. Production source reads, writes, provider calls and service actions are all zero. The failed r1 result remains failed and is retained separately.
