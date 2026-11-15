# Current Mac source inventory R3 — actual bounded read-only success

Original job `1a1b3333a55-fc05-8103` completed with exit 0. Its complete, durable stdout is 22,682 bytes, SHA-256 `348ef71e4a87f202f7cf1db7160282bc438f32f77715eb99a5459fe740946e37`; stderr is empty. The parent elapsed time was 0.3344665 seconds within the original 45-second shared budget and 70-second supervisor budget.

The exact six database namespaces and the corresponding private observations passed all original file-generation checks before and after closure. Seven guard close calls returned once; all seven SQLite connections, 99 explicit cursors and nine additional held/output descriptors closed. The single inventory child exited zero, was reaped once and had no live group members or custody gaps. The original memory command and both gateway print commands completed and closed. All parent and six observer descriptors closed, with zero unknown command outcomes.

| Slot | Kind | Logical database bytes | WAL bytes | SHM bytes | Reader PRAGMA journal_mode |
|---|---|---:|---:|---:|---|
| 1 | Agent, configured primary slot | 2,469,126,144 | absent | absent | delete |
| 2 | Agent | 157,589,504 | 0 | 32,768 | delete |
| 3 | Agent | 209,686,528 | 0 | 32,768 | delete |
| 4 | Agent | 223,727,616 | 0 | 32,768 | delete |
| 5 | Agent | 15,298,560 | 0 | 32,768 | delete |
| 6 | Shared state | 202,899,456 | 5,969,912 | 32,768 | wal |

`journalMode` records the PRAGMA value on each admitted reader connection. The first five use the existing held-file immutable route; these values are not observations of a later writable connection or an independent file-header check. No journal mode was changed. No credential rows were read, and credential ownership was not revalidated by this inventory.

The finite inventory found five configured agents, five plugin-discovered database paths and five registry mappings, with no additional paths among those sources. Both source-proven dotenv inputs were absent. This does not prove coverage of every active consumer, SDK-resolved custom directory, independently running Codex process or its cache.

The same original parent observed the registered gateway twice with identical complete process birth identity, exact loaded arguments, plist bytes, configuration bytes and full file identities. PID 18437 remained the original UID 501 process, KeepAlive was configured, and its observed descendant set was empty. The private current restore-input packet is durable. This is a discrete observation; it does not prove JavaScript memory flags, continuous quiescence or completed production rollback. Preparation of fallback review artifacts was refused with `fallback_nonlogin_finite_shell_switches`; that refusal is retained.

The actual `vm_stat` observation reported 6,796,361,728 currently free bytes. Inactive memory and total 32 GiB physical memory were not treated as guaranteed available capacity. This observation is not a reservation. The existing 64 MiB-per-database synthetic whole-state qualification does not cover the 2.47 GB primary database. A capacity-bounded backup/restore implementation and actual consumer retirement remain separate gates.

The R3 change addresses the observed guard-interface mismatch. It closes every guard before projecting resources, continues after an individual close/public failure, never retries an uncertain caller close, and obtains four counts only from the exact original list-of-dictionary vectors. Missing fields and unknown types fail closed. Nine local targeted regressions passed before the single Mac execution; those local cases are not extra Mac business cases.

Production writes, provider calls, service mutations, gateway RPC calls and cutover all remain zero. R1 and R2 retain their original failed results. No private configuration, credential, database content, identifiers, content digests or restore packets are included in the public archive.
