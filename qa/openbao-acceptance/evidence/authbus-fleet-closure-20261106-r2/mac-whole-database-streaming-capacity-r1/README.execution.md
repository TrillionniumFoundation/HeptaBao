# Actual Mac largest-database capacity result

The one original job `1a1b35e1142-fc05-8275` completed with authoritative
`succeeded`, exit 0, complete durable stdout, zero stderr, no timeout and no
automatic retry. Its immutable operation key is
`heptabao-mac-whole-sqlite-streaming-capacity-qualification-20261106-r1`.
The full 17,589-byte parent stdout, both lossless read pages, the original
terminal and launch response are retained. An independent native-file read of
the original 10,545-byte worker stdout matched the parent-recorded hash.

The new synthetic primary was **2,472,751,104 bytes**, 603,699 pages of 4,096
bytes. This exceeds the current observed largest production database of
2,469,126,144 bytes. All **17 cases passed**, including full six-database
baseline and candidate backups, retained old namespace files, cold restore,
restored schema and non-auth data, and fresh new writer behavior. Every one
of the 2,355 deterministic 1 MiB payload rows was read after restore and
compared byte for byte with its original synthetic input.

The core was byte-identical to the completed small Mac campaign:
`6a6a6630204687c56e12bc0e616e062b4e574c0665bb177d938409e739b30f4a`.
The actual launch source was 168,014 bytes with SHA256
`8cdf5777c921fbe927131304e658d25dd9ddfefcdffa17775f70ae4d982089ce`.
The 600-second parent, 540-second worker and 630-second supervisor limits were
not increased. Parent elapsed time was 30.014270457904786 seconds; worker time
was 29.856526374816895 seconds.

## Resource evidence

The actual run recorded 24 original backup calls and 18,896 bounded backup
steps, 48 once-only restore namespace actions, 72 SQLite handles and 639 file
descriptors. All original operations completed and all these handles closed
once, with every explicit cursor closed. The worker's six explicit input
descriptors and parent's 83 descriptors also closed. The original worker had
one original wait, no live group members before reap, no custody gaps and
closed streams. Its separate original memory-observation command and retained
custody helpers also completed and closed, with zero unknown outcomes.

Observed Darwin peak RSS was **73,596,928 bytes**. This is a post-run measured
peak acceptance result, not an OS process memory limit. SQLite's allocator
heap limit was 256 MiB; streaming buffers were at most 1 MiB. There were no
database serialize/deserialize calls. Fresh admission observed 1,312,473,088
currently free memory bytes and 251,746,947,072 available HOME filesystem
bytes; neither was treated as a reservation.

Two independent SQLite Online Backup API outputs from each fresh BEGIN
snapshot were compared across every page. SQLite is the source-copying
authority; this evidence does not claim an independent direct-source-page
oracle. The exact three permitted bookkeeping header normalization ranges
remained unchanged. Source generations retained every full9 comparison.

## Remaining production boundary

This proves the largest-current-single-database capacity within a complete
six-database synthetic lifecycle. It does not reproduce the entire current
six-database size distribution and does not admit the production disk budget.
Production backup must use the fresh sum of all six databases plus actual
WAL, retained candidate, staging and backup peaks.

Production consumer quiescence, a real committed provider epoch, production
gateway restart, complete configuration/cache/environment/plist rollback and
cutover remain separate requirements. This campaign read no production
database or credential, contacted no provider and performed no production
service action. The earlier failed Linux scaled run remains failed, and its
later successful diagnostic is not an explanation or replacement of it.
