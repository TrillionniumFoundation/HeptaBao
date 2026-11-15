# Separate Mac largest-database capacity campaign

This prepared campaign is distinct from the completed small streaming
qualification, job `1a1b347c2f5-fc05-81b8`. It reuses the exact 42,128-byte core
whose SHA256 is `6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a`.
The preparation manifest records the frozen launcher and all six embedded
source pins. No production database or credential is an input.

The synthetic primary must contain at least 2,469,126,144 logical SQLite bytes,
the largest database observed in the successful current Mac inventory. Its
upper fixture bound is that size plus 32 MiB. It stores 2,355 deterministic,
non-zero, 1 MiB payloads, then performs the complete six-database lifecycle.
Both independent backup outputs, retained candidate archives, cold restore,
all schema objects and non-auth data are verified. After restore, every one of
the 2,355 payload rows is read and compared with its original synthetic bytes.
The campaign has 17 cases, including the three capacity-specific assertions.

The actual final source page count is measured after the synthetic fresh-token
writes, before the baseline captures. The core still requires each complete
source namespace generation to remain exact. No timestamp, inode, WAL or SHM
identity comparison is weakened for this fixture.

## Finite independent budgets

The new campaign has a 600-second parent, a 540-second original worker and a
630-second supervisor. Before large allocation, a single original pinned
`vm_stat` command has a 3-second budget and must complete with full custody.
At least 1 GiB of currently free pages must be observed. Total RAM or inactive
pages are not counted as guaranteed available memory.

Fresh `statvfs` measurements of the new owned HOME fixture must show at least
26,463,895,552 available bytes: eight times the maximum primary fixture size
plus 6 GiB. These are discrete observations, not reservations. The production
whole-six-database disk budget remains unqualified: it must be calculated from
the fresh sum of all six real databases and their actual WAL, retained
candidate, staging and backup peaks. This fixture does not reproduce the full
current six-database size distribution.

SQLite's allocator heap limit remains 256 MiB; file buffers remain 1 MiB and
backup steps 128 pages. The 512 MiB process RSS threshold is a measured peak
acceptance check after execution, not an OS-enforced process memory ceiling.
All created files and any failed partial outputs remain under one new private
synthetic root. No original failed operation is replayed or relabeled.

## Local preparation evidence

The first Linux-only 8 MiB scaled exercise failed closed at
`snapshot_generation_after_begin`. All original SQL handles and file
descriptors closed, and restore had not started. Its original receipt is
retained; the precise changed field was not captured during that first run.

A single subsequent local diagnostic added namespace field observations to a
new synthetic fixture while leaving the core source and every comparison
unchanged. It completed all 17 cases. That later result does not explain the
first failure and does not turn it into a pass. Both use a documented local
8 MiB variant, so neither proves Mac behavior or actual 2.47 GB capacity.

The actual Mac campaign is authorized only after the original physical HA
campaign's full process and stream closure. Once dispatched, a failure or
unknown result must be reconciled under its original job identity; a new
key must not repeat an uncertain restore.
