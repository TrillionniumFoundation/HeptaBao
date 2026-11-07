# Mac streaming whole-database qualification, small fixture

The original Mac job `1a1b347c2f5-fc05-81b8` completed with authoritative
`succeeded`, exit 0, complete durable output, no timeout and no automatic retry.
Its exact 15,326-byte stdout is retained with the original launch, terminal and
bounded read response. A separate native-file read recovered the original
11,566-byte worker stdout and matched its hash to the parent receipt.

The immutable operation key was
`heptabao-mac-whole-sqlite-streaming-small-qualification-20261106-r1`.
All created state is under the new private synthetic root
`/Users/qianqi/heptabao-authbus-whole-database-streaming-small-20261106-r1`.
This run read no production database, credential row or provider endpoint and
performed no production service action.

## Actual scope

The unchanged installed public agent and registry schema definitions seeded
six synthetic databases. Fourteen lifecycle cases passed: fresh independent
whole backups including WAL, preserved non-auth extension data and schema,
three synthetic post-provider values, retained candidate snapshots, all six
closed-file restores, all 18 old base/WAL/SHM files retained, and cold reopened
writers with working triggers. This is a database-library qualification. It
does not establish a real provider epoch, complete production consumer
quiescence, production gateway restart or production rollback.

The core used SQLite Online Backup API twice from the same fresh BEGIN read
transaction, compared the two complete disk outputs with only the three
documented bookkeeping header ranges normalized, then streamed whole-file
copy/hash/restore with a 1 MiB buffer. The copying authority is SQLite's backup
API. No independent direct-source-page oracle is claimed, and there were no
`serialize` or `deserialize` calls.

Five additional mechanism cases passed on Mac SQLite 3.53.4: the same read
transaction retained its snapshot across an actual external synthetic commit;
the two closed outputs agreed; another fresh reader saw the new commit;
the first actual BUSY callback refused without retry; and output corruption
outside the three header ranges was rejected. The mechanism receipt therefore
contains one intentionally incomplete backup and one intentionally incomplete
comparison. Those are expected negative outcomes, with all original handles
closed, not a blanket claim that every negative operation completed.

## Resource closure and capacity limits

The lifecycle recorded 24 backups, 32 backup progress steps, 48 once-only
restore namespace actions, 72 SQLite handles and 639 file descriptors, all
closed once. The mechanism cases closed 7 SQLite handles and 13 descriptors;
the worker closed 6 explicit inputs and the parent closed 47 descriptors.
The original child completed one wait, had no live group members, no custody
gaps and closed streams. The 294 actual Darwin held-FD xattr checks all found
no attributes and completed without error.

The worker's observed peak RSS was 37,961,728 bytes. The 512 MiB RSS threshold
is an after-the-fact acceptance check, not an operating-system-enforced
process limit. SQLite's separate process heap limit was 256 MiB. The original
45-second parent, 30-second worker and 70-second supervisor budgets were used.

The core's 4 GiB maximum per database is a code bound. This small fixture did
not prove restoration of the current 2,469,126,144-byte primary database or of
the full current six-database production sum. A separate new capacity campaign
must establish that evidence; production disk admission must additionally
include all six actual files and retained WAL, candidate, staging and backup
peaks.

## Earlier local preparation

The archive retains Linux-only local boundary, mechanism and lifecycle
receipts, including the earlier pre-freeze local lifecycle result. Their
platform and source versions remain distinct from this actual Mac run.
No failed or preparatory result has been relabeled as Mac qualification.

Public evidence contains code pins and synthetic values only. No live
configuration hash, credential byte, credential-derived identifier or digest
is included.
