# Finite current Mac consumer inode observation

This evidence covers one bounded set of nine actually observed processes and 45 known database, sidecar, cache and legacy-file metadata targets. It reads no database content, credential, Keychain, other-process argument or environment. No observed consumer receives a signal. The original helper's own cleanup is separately recorded.

## Original attempts

| Attempt | Original runtime job | Result |
| --- | --- | --- |
| r1 | `1a1b376e3e0-fc05-8304` | Known failed, 3,517-byte complete stdout. This Mac's pinned lsof rejected the unsupported `-D` option. Nine full process identities were admitted. The lsof child exited 1, its streams/group were closed, and all 51 explicit descriptors closed once. |
| r2 | `1a1b37b35bf-fc05-8321` | Known failed, 3,446-byte complete stdout. Removing only `-Di` let original lsof exit 0 with 6,702 bytes and no stderr. The parser refused the actual blank access marker. Original child and all 51 descriptors closed; the after-fence was not reached. |
| r3 | `1a1b3804d06-fc05-8343` | Succeeded 0, 10,299-byte complete stdout, no stderr, 0.063 seconds. The fresh lsof output covered nine processes and 253 file records; all nine full birth/executable identities and all 45 known metadata/absence bindings remained unchanged. All 56 explicit descriptors and the one original helper closed; unknown count was zero. |

Both failed attempts remain failed. The parser-only correction accepts the observed single space as `unspecified`, never as read/write authority. Six local framing/privacy tests pass. The complete r2 original output was parsed offline as nine processes and 252 file records, including 115 unspecified access markers; that offline result does not add the missing after-fence or reclassify r2 as successful. No device-cache-ignore behavior is claimed on this Mac build.

## Actual r3 association

All seven exact device/inode matches belong to gateway PID 18437 and the registered state database: base target 20, WAL target 21 and SHM target 22. One SHM mapping is reported as `txt` with unspecified access; the other six matched descriptors have observed `r` or `u` access. None of the other eight selected processes matched the five auth databases, known caches or legacy paths in this discrete snapshot.

The four registered relay processes (964, 983, 987 and 989) have PPID 1. The standalone Node/Codex relation 89324 → 89325 was actually observed. The two ChatGPT-bundled Codex processes have parent/process group 66293. They are not gateway descendants, but this fact alone does not prove separate credential provenance.

This is a discrete finite observation, not a complete kernel consumer census or proof about cached credentials. No matching open file does not prove no credential use. `consumerQuiescenceQualified`, `completeActiveConsumerClosure` and `kernelWideVisibilityClaimed` remain false. Independent Codex selector/provenance classification and the registered relays' explicit retirement remain separate gates.

## Scope and preservation

The original native process inventory selected this finite set; unrelated process names are not published. Every attempt uses one pinned lsof helper with a 10-second cap within its original 45-second parent and 70-second supervisor. Metadata targets are fixed: 24 database/sidecar names, six AuthBus caches and 15 registered-agent legacy names. Sources, original runtime envelopes and exact stdout bytes are retained. The 500-byte r1 stderr and source/process private bindings stay on the Mac under their original private attempt roots; only bounded safe error projections are published.
