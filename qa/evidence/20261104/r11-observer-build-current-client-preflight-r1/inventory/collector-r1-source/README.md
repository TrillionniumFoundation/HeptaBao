# Finite current client and backup-registration collector R1

Status: **source candidate only**. This packet has not been parsed by a host Python interpreter, executed on a host, or admitted for a production transition. It does not load an SDK, open SQLite, call a provider or the former J3160 endpoint, change services or containers, read an encrypted archive or recovery key, or create a host output file. A later invocation must bind these exact source and manifest bytes and receive its own runtime authorization.

The collector is a bounded observation of the selected current paths and registrations. A complete observation is useful input to the next per-host consumer and recovery plan; it is not a cutover, whole-host absence, current SDK, backup restoration, or service-manager qualification.

## Fixed source inputs

- Controller: `finite_client_inventory_r1.py`, 44922 bytes, SHA256 `4b7dfc869bca690e942e0f201e6e050a9a1f4ee31827b7bb3202ec66bd2f4282`.
- Stdin manifest: `finite_client_inventory_manifest_r1.public.json`, 85939 bytes, SHA256 `b52cec525ecf14161a0f6a396545d25e0532dfe5284dd07bf63b670fe570862f`.
- The controller rejects any other manifest hash before interpreting its paths or commands.
- The finite registration source is `f458db4ebda522c3054c48eca917b8d7aaafcef33c13892a846c53441b49aa64`; the four-host matrix is `aa23dcf2c01b9ea0372a67942510b6e9d8b49a1d3e823b2e62344748fdb92cf0`. Their exact public originals were independently recovered and reviewed.
- Nine public backup receipts are one historical capture/transport/restore chain, packet tree `4b7685d5c87a01646fddaab6fd330606ba7b4a4c`. The capture is dated November 2, 2026; transport and restoration ran November 3. Its historical `main` home is Linux `/home/qian-qi`, UID 1000. It does not establish current Mac identity or the current backup contents of another host.

## Denominator and one shared host budget

| Host | Fixed entries | Predeclared passes | Fixed queries | Maximum observations in one pass | Total predeclared metadata observations |
| --- | ---: | ---: | ---: | ---: | ---: |
| Mac | 38 | 15 | 7 | 31 | 357 |
| ROG | 46 | 17 | 4 | 31 | 434 |
| X230 | 18 | 5 | 6 | 32 | 112 |

An entry is a named leaf, not an allowance to discover a directory. Every explicit metadata operation in this controller is charged to a fixed pass. Each ancestor contributes lstat-before, fstat-open, and lstat-after; a read leaf contributes lstat-before, fstat-open, fstat-after-read, and lstat-after; a metadata-only leaf contributes two lstat observations. Main DB, WAL and SHM are three separate leaves. Deep DB families are in separate passes. Missing or refused paths still remain in the denominator. Runtime recomputes the exact parent sets and counts and rejects duplicate, omitted or over-budget entries.

The 32-observation counter describes the controller's explicit lstat/fstat calls. It is not a claim about the kernel's internal lookup operations, Python imports, or the filesystem operations performed inside the fixed standard query utilities. Those child commands instead have fixed argv, bounded output, and their own deadlines within the same host envelope.

All passes, queries, manifest input, file reads, and final process observation share one original **45-second** monotonic deadline and one **8 MiB** bytes-read ceiling. A document or query stdout+stderr pair is at most 2 MiB. Public output is at most **64 KiB**. Each selected query has at most 10 seconds and the final owned-process table query at most 5 seconds, both shortened by the original host deadline. There is no reset between passes or queries. The proposed remote outer cap is explicitly **NEW 60 seconds**, not a claimed recovery of a historical wrapper value.

The ordinary one-attempt cleanup allowance is TERM plus wait 5 seconds, then KILL plus wait 5 seconds only while the direct child remains unreaped. Cleanup may finish after the 45-second observation deadline to establish a safe terminal state, but cannot produce success after that deadline. The outer cap does not grant more observation time.

## Exact read and public-projection boundaries

Known native auth/config and three AuthBus connection files are bounded **hash-only** reads. Their values are never parsed into the public output. Six caches are also hash-only. Config, plist, unit, selected environment file and cron projections reveal only the specific fields required to determine current routing and registered dependencies. Full raw config, credential values, environment assignments, arbitrary commands, script bodies, stdout/stderr and Docker environment are not published.

A public path must be a simple absolute literal with no whitespace, shell metacharacters, substitution or traversal components. A rejected value is represented by its digest and an unresolved marker. Inline command text is never executed and nonliteral paths are not followed. Endpoint projection omits userinfo, path, query and fragment, retaining scheme/host/port and a digest of the original string. No network request is made.

Each filesystem traversal uses held directory descriptors, O_DIRECTORY/O_NOFOLLOW and the fixed relative component names. Parent name identity is checked before opening and again at the end of its pass. Read files must be regular, single-link, reviewed-owner and not group/other writable. Reads use one O_NOFOLLOW/O_NONBLOCK descriptor, initial size bound, exact size, digest, final descriptor identity and final name identity. All owned descriptors have a single close attempt; an ambiguous close error is reported and prevents success.

DBs and their sidecars are metadata-only: no SQLite connection, copying or sidecar creation is attempted. Backup roots and the already recovered X230 public receipt locations are also metadata-only in this collector. It does not enumerate their contents or infer an active backup producer from a name.

The fixed queries are:
- Mac: five exact gui/501 launchd labels, diskutil for the already known T5 UUID, and the current owner's crontab.
- ROG: three exact user systemd services and the current owner's crontab.
- X230: one exact system service, three exact prior transient user services, one exact Docker ID and the current owner's crontab.

These are standard installed query tools with no shell, environment-derived executable, or execution of a file discovered in the inventory. Utility binary provenance is not represented as product qualification. Query projections never include process argv/environment or Docker Config.Env/command/health-log fields. The final ps query asks only PID, PPID, PGID and state; the full table stays private in memory and only owned groups are emitted. A Docker record with no mounts or ports never authorizes deletion or declares the node dispensable.

## Absence, drift and partial outcomes

Only a leaf's own two matching ENOENT observations under a verified held parent become `absent`. An absent, inaccessible, changed or symlink ancestor leaves descendants `blocked_by_ancestor`; the collector does not infer their absence. It reports incomplete observation rather than silently resolving a symlink or treating a refused read as a missing file.

In particular, the fixed Mac spelling `/etc/crontab` may encounter a system alias. The implementation does not assume its destination or follow it. If this occurs, the result records the unresolved branch. A separately observed exact active reference may justify one exact subsequent read; this does not create a generic manual-discovery or backup gate.

All entries and queries remain represented in success or failure. File drift, prior-hash mismatch, malformed projection, budget exhaustion, signal, incomplete child cleanup, or a missing final parent fence prevents `completed_finite_observation_only`. Some requested registrations may legitimately have disappeared since the historical matrix; that is a current observation, not permission to revive or remove them.

No cross-file atomic snapshot or unchanged-atime claim is made. Raw bytes are not retained for hash-only reads. Metadata compares omit atime because a read may update it. Before/after equality is bounded to the exact intervals and paths observed.

If the full projected report exceeds 64 KiB, the process emits a small **incomplete** report with the candidate report's size/hash and fixed denominator, never a truncated report described as complete. Success additionally requires authoritative exit zero after stdout publication and the original 45-second deadline. A receipt/status string alone is insufficient.

## Owned child and cancellation behavior

Popen and FD registration defer Python signal delivery only across the creation-to-ledger interval. Cancellation then prevents all new observations. Each child is a new process group, every cleanup attempt is recorded once, and already-reaped groups are never signalled. After the selected queries, a single bounded ps snapshot verifies every owned group is empty. The ps process's own row is excluded only after its actual reap; any other member still fails cleanup.

The collector makes no business request and performs no automatic retry. A lost remote ACK must be reconciled through the original exact idempotency key and durable status rather than launching another observation under a new identity.

## Pocket reuse and remaining work

The manifest includes Pocket explicitly even though this controller has only Mac, ROG and X230 execution choices. It preserves the accepted current prepare (51 pins), preflight (18 records), and actual R10 live fixture (66 outer records; four phases 128/128/95/95 records). Those phase labels are not unique-case counts: the corresponding unique-label counts are 112/112/77/77. The original checks and evidence are unchanged.

Reusable Pocket observations cover the exact current config/flags, both agents' local/effective/raw store state and local5 default, six caches, independent native4 auth/config, the installed registry row and stable main-file copy, plus the exact unchanged held units/drop-ins/markers and their inactive states. This fixture performed real isolated credential generation reads/writes, a new-process cold start, and strict local/effective/raw/cache CAS inverses.

It did not establish original production CA/AppRole custody, the entire actual service command/drop-in relation, all current backup/timer/crontab registrations, a real manager restart or hold release, or independent current encrypted backup coverage for local5/native4. The manifest lists only those remaining current scopes and their actual historical references. There is no fictional ninth backup gate, all-account/provider gate, or claim that Pocket's result covers another host.

## Next review and execution conditions

1. Independently read this controller and manifest, then parse/compile the exact Python source in an inert-only job. A finite pure-component check should cover redaction, parent/count admission, shared-deadline refusal and cleanup accounting before reading private current files.
2. Root assigns a host and a single fixed invocation. Source and manifest are passed byte-exact; no controller writes are necessary for the `-c` form. One host runs at a time unless separately coordinated.
3. Capture complete raw authority and stdout; verify all counts, raw bytes/SHA, incomplete markers and owned cleanup before using observations.
4. Expand only an exact active command/configuration/restore reference found in accepted output. No recursive discovery, speculative manual path, provider call, legacy J3160 probe, SQLite open or production transition is part of this packet.
5. Use the accepted Mac output to finish an isolated T5 credential/cold/restart/inverse plan. Any production gateway stop/restart or hold release remains a separately reviewed concrete action.

No actual collector result is included in this packet. Historical evidence and source-level arithmetic are explicitly separate from runtime evidence.
