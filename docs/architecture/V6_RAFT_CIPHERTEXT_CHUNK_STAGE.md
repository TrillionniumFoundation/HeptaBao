# Experimental native V6 ciphertext chunk staging over Raft

**Status: isolated first-stage implementation, not V6 HA.** No production service starts native V6 with `--ha-config` as a result of this change. Do not remove V6's single-node ownership checks or retire OpenBao 2.7.1.

## Exact implementation

The `heptabao-raft-runtime` crate gains the default-OFF feature `experimental-v6-raft-objects`. When explicitly compiled with the feature, `RecordObjectKind::NativeV6CiphertextChunk` can be staged using the existing `RecordCommand::Stage` application-object protocol. This is a **replicated, journaled opaque byte blob**, not a trusted native V6 root.

A chunk must contain 25 to 262,144 bytes, no children, zero logical record count and metadata byte counts matching its exact sealed bytes. The immutable object ID is SHA-256 of the fixed domain tag `heptabao.raft.native-v6.ciphertext-chunk.v1\0`, an eight-byte big-endian ciphertext length and the ciphertext bytes. Changing bytes, IDs, counts, children or length fails validation. Untrusted ingress cannot claim authenticated V6 barrier custody merely by setting this kind.

Legacy `PublishedRecordRoot` explicitly disallows this kind as a direct root reference. No new root publication command, application read routing, quorum acknowledgment or ciphertext decryption authority was introduced. In default builds the new enum variant and constructor do not exist.

## Real tests on the exact experimental candidate

Feature-on runtime tests verify the actual durable Raft Stage journal, staged bytes after restart, follower snapshot installation and cold reopen, and **absence of any committed root**. Negative tests reject changed ciphertext under a fixed ID, changed length, illegal children, under/over-sized chunks and attempted V5 root publication. Feature-off runtime tests verify that the existing V5 path continues to work.

## Unresolved design and release blockers

1. The current Raft JSON application-object store has a 47 MiB snapshot accounting bound. A 139 MiB V6 migration archive cannot simply be placed in one Raft JSON snapshot; a bounded independently durable replicated ciphertext object store or equivalent chunk lifecycle is still needed.
2. A staged hash proves exact bytes only. It does **not** prove barrier/actor/ACL authority, cluster epoch, native graph closure, AEAD validity, quorum-wide ciphertext durability or committed publication.
3. A future *single* authenticated V6 root command must bind cluster ID, epoch, original operation ID, prior root, monotonic generation, complete object dependency closure and committed Raft index. It must fail closed on stale roots and leader loss.
4. Service must not return success until majority Raft commit **and** the required exact local V6 root publication are verified. Unknown response outcomes remain reconcilable and must never be blindly replayed.
5. No production rollout before real Mac ARM64, X230 Linux and main Linux same-source Raft V6 fault tests, repeated 66-version migration, AuthBus and OpenBao 2.7.1 differential tests.

This scope is intentionally narrower than Draft PR #116. It is the first *executable* object-staging step, **not** a substitute for PR #116's end-to-end commit authority.
