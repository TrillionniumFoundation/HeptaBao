# Mac main3 API r3: preserved preflight failure

The r3 attempt prepared canonical 4bde9's normal Mac server and passed **108/108 QA guards**, then stopped at the unchanged full-nine-field source-generation gate. **No server launch, credential API request, provider call, or production cutover occurred.** This directory preserves the failed attempt and its two subsequent read-only diagnostics; it does not convert r3 into a successful API qualification.

## Exact outcomes

| Operation | Runtime job | Authoritative outcome | Complete stdout / stderr |
| --- | --- | --- | --- |
| Create-only source, private QA roots and normal binary copy | `1a1b1eb0570-fc05-7b80` | succeeded, exit 0 | 8,652 / 0 bytes |
| 108 guards and actual fresh-capsule preflight | `1a1b1f0702c-fc05-7b97` | failed, exit 1 | 18,256 / 14,374 bytes |
| Source namespace field differences | `1a1b1f1fcec-fc05-7ba3` | succeeded, exit 0 | 5,237 / 0 bytes |
| Registry ctime interval projection, two observations | `1a1b1f3d1a6-fc05-7bb3` | succeeded, exit 0 | 2,082 / 0 bytes |

All four outcomes were read from their original runtime jobs. Outputs are complete and durable, with no automatic retry or timeout. The preflight's three owned read-only helper processes were reaped, their groups empty, all returned source and volume descriptors closed, and both new GUI labels absent. No cleanup signal or bootstrap was needed.

## Source and generation binding

The prepared product remains commit `4bde9aee03fcd27c59e13607e529b1cee594b249`, normal binary SHA256 `5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c`. The configuration selects `native_v6_file`; the planned activation route is `sys/storage/native-v6/activate`. No fixture option is enabled.

The fresh source capsule producer was job `1a1b1e80c81-fc05-7b6c`, succeeded 0. Its public receipt binds a fresh actual SDK read of five auth scopes and three main-owner credentials, with fifteen consumer references. All three provider access tokens remain expired; provider availability is unqualified. Capsule bytes, profile identifiers, credential values or digests, private configuration/generation values, private qualification bindings and TLS private keys are excluded from this archive.

Twenty complete files were independently read back from the Mac, including all fifteen source files, the HOME wrapper, preparer, public plan, normal server configuration and public TLS certificate. The corresponding read-back RPCs and original source text are retained. The qualification-bound private capsule identity remains in the failed r3 private directory. It is not overwritten.

## What the failure establishes

All 108 QA tests passed with zero skips. The actual preflight then rejected `current_source_full_generation_exact`. This count is a QA guard denominator; it is neither the product's 107-test suite nor an AuthBus API business-case count.

The independent namespace diagnostic found all five auth database generations and explicit sidecar absences unchanged. Only the registry database, WAL and SHM `ctime_ns` fields differed. The other eight identity fields matched. This metadata observation does not establish a credential-content change.

The independent timing projection placed each current registry ctime after the namespace diagnostic job's submission, therefore well after the capsule producer had terminated. Two observations separated by two seconds found the full identities unchanged during that interval. These observations exclude the producer's earlier close as the cause of the **latest** observed metadata update, but do not identify the writer or establish continuous exclusion.

## Continuation boundary

The r3 execution loader is retained as `execution-loader-never-invoked.py` for review and was never invoked. A later attempt may place a fresh, source-bound capture child and the full-nine-field admission in the same original 600-second parent budget; capture remains bounded to 45 seconds and the two service phases retain 120 seconds each. Such a later attempt must retain r2/r3 failures and use new create-only roots, authority bindings and stable keys. No reduced generation comparison or replay of r3 is authorized by this evidence.

Layer B actual-plugin/SDK store transfer, production-client restart and rollback, provider refresh and production cutover remain separate gates.
