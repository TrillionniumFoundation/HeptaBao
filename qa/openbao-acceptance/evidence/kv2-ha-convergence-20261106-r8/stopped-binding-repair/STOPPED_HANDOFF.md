# Stopped candidate handoff: initial Python role repaired

The first manager/init attempt remains failed and uninitialized. The new candidate was then retired with three distinct, original native jobs: before query `1a1b28d5d67-fc05-7e99` returned 0, exact-label bootout `1a1b28ed7a1-fc05-7e9f` returned 0, and after query `1a1b28fb493-fc05-7ea2` returned 113 with the exact quoted-label absence message. Each had its own 15-second cap.45seconds is their sum, not a shared outer wall-clock deadline. The original unexecuted plan that misstated this was preserved and superseded before dispatch.

Repair job `1a1b295b02c-fc05-7ec7` actually completed with exit 0, complete/durable native terminal, full 3473-byte final stdout and 3300-byte public receipt. It made one fresh read-only exact-label query, received 113, and changed only `initial launch binding.files.python` from the controller's qualified venv copy to the separately verified real base Python used by the unchanged plist. The base executable is 34640 bytes with public SHA256 `cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13`.

The actual publication preserved the original initial archive and an exact copy of the former current binding, wrote a durable private intent, then performed one atomic replacement and full readback. Root independently re-read the current binding, archive, retained old current and private closure using original native sizes/hash/version/permission metadata. The exact object difference is solely `files.python`. State is still `initial_empty`; `seal_file` is null. All 51 original FDs closed. The one short query child was waited once with no live group members or gaps. No server was started, no initialization/HTTP request was made, no key/root/share/nonce content was read, and no old service or asset was removed.

## Remaining boundary

The kernel's actual `SystemPolicyRemovableVolumes` denial for launchd/xpcproxy accessing the T5 log path remains unresolved. Nothing in this repair grants or bypasses that macOS permission. The candidate remains stopped. The original data directory was still empty and all five nonce/root/share leaves were absent before and after repair. No KV2 mount, preactivation seed, business import, HA, AuthBus or traffic switch has been qualified.

After lawful macOS authorization, continuation needs a new bounded existing-candidate admission and a new operation key. The original create-only manager/init controller and its old key must not be replayed: the plist, guard and initial binding already exist. The future step must consume this stopped/repaired generation, reobserve actual manager/domain/TLS ownership, and issue initialization at most once after confirming the untouched initial state.

## Evidence handling

Private dispatches, native request fingerprints, complete GUI stdout with inherited environment, and binding/private-closure content hashes stay private. Published source is the reviewed template with its two fixed private/public data assignments masked; its hash is not presented as the full mixed executed-stdin hash. Safe launch records are explicit field projections of retained original native acknowledgments. Original terminal text and public stdout/stderr are preserved byte for byte. The failed manager and both read-only attempts remain separate immutable packages.
