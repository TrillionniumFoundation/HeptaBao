# HeptaBao continuation checkpoint — 2026-10-19

## Current decision

Full replacement of OpenBao 2.7.1 remains **unproven**. The runtime connection has recovered and execution has resumed on the actual Mac external disk. Production traffic has not been switched and old OpenBao services, binaries, data and backups have not been removed.

This checkpoint supersedes the disconnected-host status in the earlier revision of this file. The old Mac R2 launch was reconciled against the filesystem and process inventory: its source/output directories were absent and no corresponding build was running. The new runs below have distinct owned directories and receipts.

## Actual Mac native KV2 import result

Source commit `f43a015b69e3b9cc1fad88ea4e4efdda7250417c`, tree `367adee67df1f4fda8875012e5b50564aab4d213`, was materialized under:

`/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018/source-f43`

All **2,790** source blobs, executable modes, path closure and the recursive Git tree were verified before and after execution. The host was macOS 26.6.2 arm64, using Rust 1.98.0 and the existing offline cache. Test compilation succeeded in **345.214 seconds**. Exact discovery selected **8** native graph-import tests; execution produced **7 passed / 1 failed**.

All five Service cases passed: legacy/native history comparison and cold CAS; unauthorized, malformed and replay rejection; actual durable locator append/fsync followed by a lost acknowledgement and cold recovery; root-commit lost acknowledgement followed by cold selection of the complete new root; and snapshot restore followed by cold recovery with exact history.

The failing codec case selected an arbitrary object of kind `Block`. That kind also stores metadata values, which the live view can already cache. It therefore did not reliably remove a payload object. The revised case records the exact payload references read by actual version 4 and version 5 point reads, removes each reference, and requires both cached/cold transition validation and the real point read to reject it. Missing metadata-root cold open is checked separately. The revised case retains the original name and the group count of 8; **its execution is still pending at this checkpoint**.

The server binary also built successfully in **183.662 seconds**, with 71,133,472 bytes and SHA256 `6c056d15e54b9790de4d6c0c329dd12a85a34165c88248f464b508869a3cebaf`. The overall run remains failed because one required test failed.

Evidence: [complete failed test log](../qa/openbao-acceptance/evidence/resumed-20261019/mac-native-kv2-import-f43-failed.log), [final owned-run summary](../qa/openbao-acceptance/evidence/resumed-20261019/mac-native-kv2-import-f43-summary.json).

## Historical recovery CI remains a real gate

The newer [5ea CI run 39146883387](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/39146883387) is distinct from the earlier 46cf run.

| Actual host | Historical cases | Snapshot cases |
| --- | --- | --- |
| macOS job 117732420727 | 3 / 6 passed | 7 / 7 passed |
| Linux job 117732420481 | 1 / 6 passed | 7 / 7 passed |

Both host builds compiled; the remaining failures concern activation-source identity in a fixture that creates a token before activation, a forbidden historical admission path, cold unseal, and cold follower forwarding. These are under separate source-level investigation. A fixture correction must capture the actual V5 source at activation and retain strict subsequent comparisons. Product errors must be fixed without changing request budgets or retrying uncertain mutations. The newer f43 run exercises the additional eight native import cases as well.

## Actual LAN TLS and complete HTTP response

A separate owned diagnostic used the previously built **71063e** binary with SHA256 `1546755960a23eb5e27cf5be474e63d63466a79ecb1f69e425cad95f78c9dcb4`, whose Mac firewall entry already existed.

The main host reached `192.168.0.7:46230` with TLS 1.3 in 0.023 seconds; the Mac reached its own LAN address with TLS 1.2 in 0.031 seconds. Both verified the CA, server name and exact certificate leaf, then read the complete HTTP 501 response, all 329 body bytes, and `initialized: false`. No credential or initialization request was sent. The owned server was terminated and reaped, and no firewall setting changed.

This resolves the earlier diagnostic's premature client close after reading only `HTTP/1.1 `. The old receipt proves only its TLS handshake; it is retained as historical evidence. The complete response diagnostic is **not** a three-voter failover test or evidence for the newer binary.

Evidence: [complete LAN HTTP receipt](../qa/openbao-acceptance/evidence/resumed-20261019/mac-lan-complete-http-root-r2.json), [bounded probe](../qa/openbao-acceptance/tls_complete_http_probe.py), [owned live diagnostic](../qa/openbao-acceptance/mac_lan_complete_http_live_20261019.py).

## AuthBus actual SDK storage result

The actual installed OpenClaw SDK **2026.7.1-2**, running Node **22.23.3**, passed **21 / 21** isolated SQLite owner checks with synthetic OAuth values. This includes locked commit and readback, stale digest rejection, cross-provider rejection, unrelated profile/selection preservation, an actual SQLite transaction abort, and successful subsequent recovery.

The initial run exposed a real SDK return-contract mismatch: a no-op transaction can return a store object and a failed transaction can return null. The adapter now requires that its own locked updater applied and that the returned store contains the exact new credential digest, followed by an independent readback. It does not accept object truthiness as successful mutation. The first failed receipt remains in the repository.

Evidence: [21-check receipt](../qa/openbao-acceptance/authbus/refresh-r5-sdk-actual-passed-20261019.json), [actual command receipt](../qa/openbao-acceptance/authbus/refresh-r5-sdk-actual-passed-20261019-command.json), [SDK decision history](authbus-refresh-r5-sdk-20261018.md).

This run did not exercise the actual shared OAuth refresh caller, a real provider refresh, or the native R5 HeptaBao backend. Those gates remain open. It did not use J3160 or mutate production credentials.

## Required next closures

| Gate | Required remaining evidence |
| --- | --- |
| KV2 | Dedicated bounded native large-import profile; actual OpenBao 2.7.1 source export; complete 34 MiB history import, cold restart, snapshot restore, hostile-input and unknown-ack recovery |
| HA | Same-source Mac/ROG/Pocket4 leader kill, reelection, ReadIndex, quorum loss, persisted restart and exact history; required X230 checks |
| AuthBus | Actual shared SDK refresh boundary and final provider dispatch fence; native TLS/AppRole/KV/Policy/renew/revoke; trusted credential custody without J3160 |
| Per-host cutover | Real credential read/write, restart and rollback for every host before its client traffic switches |
| Cleanup | Inventory every client and backup migration, then remove old services, binaries and regenerable intermediate assets |

The prior physical 98-case run stopped during listener readiness; it did not kill a leader. Neither the 34 MiB archive fixture nor the native import Service cases prove a complete 34 MiB OpenBao migration. Original failed evidence, Raft roots and recovery custody remain preserved. Pocket4 heptatrader has not been modified.
