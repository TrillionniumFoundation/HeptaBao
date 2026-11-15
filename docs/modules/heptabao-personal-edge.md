# heptabao-personal-edge

Status: `IMPLEMENTED_REVIEW_REQUIRED` / V3. This package contains separately
executed Chromium native messaging and opaque ciphertext sync candidates. It is
outside the `heptabao-server` dependency closure. Shared rules are in
`docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`; see its
[module closure dossier](../module-closure/heptabao-personal-edge.md).

## Purpose and non-goals

The browser adapter releases one selected login only after local unlock and
exact origin checks. The sync store retains whole encrypted snapshots with
explicit compare-and-swap conflicts. These are distinct local entry points;
the crate is neither a network sync daemon nor a remote-device authorization
service. It supplies no Android Autofill provider, Passkey provider, sharing
protocol, automatic field merge or general browser compatibility claim.

## Public API and ownership

`crates/heptabao-personal-edge/Cargo.toml` declares the library and
`heptabao-browser` / `heptabao-sync` executables. Its direct internal dependencies
are `heptabao-personal-vault` and `heptabao-filesystem-guard`. The library exposes
`validate_origin` and `authorize_fill`; the latter requires exact stored/actual
origin equality, top-frame use and an unlocked session. `sync::CiphertextStore`
owns the exclusive directory fence, publication state and retained ciphertext
inventory. Its `open`, `head`, `receipt`, `fetch` and `publish` methods expose
`sync::Receipt` and `SyncError`. The Chromium worker, popup and page validation
live separately in `clients/chromium/`; the embedding browser establishes page
identity rather than trusting a string supplied by page content.

## State and data model

The native host holds a `VaultSession` only while unlocked. Its default absolute
lifetime is 60 seconds, configurable within 1–300 seconds; an independent idle
check runs at 100 ms intervals. A fill response carries at most two seconds of
remaining authorization. The worker tracks connection/lock epochs and clears
held credential fields when cancellation or expiry is observed.

The sync schema-1 `state.json` binds one vault ID to a current receipt and an
immutable operation-to-receipt map. Each receipt contains a generation, head ID,
ciphertext SHA-256, operation ID and request digest. Files contain only opaque
encrypted snapshots. Bounds are 4 MiB per snapshot, 64 MiB total retained blobs
including orphans, 4096 publications/objects and 2 MiB state/pending buffers.

## Invariants and authorization

Supported origins are canonical ASCII HTTPS origins with a dotted DNS hostname
and an optional nondefault port. IP literals, ambiguous spelling and suffix
matching are refused. The extension accepts only its own popup connection,
binds a unique browser-supplied POPUP context/document, and rechecks that same
binding after awaits. When the parent Chrome window reports unfocused while its
popup owns focus, a nonce-bound 500 ms challenge must confirm the expected window
and visible, focused popup. The final renderer independently checks top frame,
actual origin, document focus, form safety and the monotonic deadline before
assignment. Locked, navigated, hidden, cross-origin or ambiguous forms fail closed.

Sync `publish` requires the exact prior receipt's head ID, not merely a matching
ciphertext digest. A new generation and request identity prevent the A→B→A case
from making a stale expected head valid. A transport adapter remains responsible
for authenticating users and authorizing their vault; knowledge of a vault ID is
not remote authorization.

## Failure, retry and reconciliation

Browser lock, close and expiry invalidate pending authorization. A request already
dispatched into Chrome cannot be recalled; lock acknowledgement waits for that
actual outcome rather than claiming the queued effect was cancelled. Native
output is nonblocking with a 30 ms frame deadline; a blocked output pipe exits
the host and drops the session instead of retaining keys indefinitely.

An exact sync retry returns its original receipt. A reused operation ID with
different bytes or expected head is refused. Publication writes the blob before
atomic state publication and fsync. An uncertain storage outcome fences the live
store; reopen validates receipts, referenced blobs and their durability before
serving them. Orphan recovery accepts only matching bytes supplied by the caller.
Conflicts and capacity never silently discard another device's version.

## Concurrency and ordering

The sync directory lock permits one cooperating writer. Browser asynchronous
steps recheck popup identity, epoch and lease after awaits; lock acknowledgements
cannot overtake a dispatched fill. The worker conservatively starts the fill
budget before the native call, and passes a final deadline into the renderer.
These checks limit authorization lifetime; they cannot retract plaintext already
assigned to a page or defeat arbitrary suspension of the entire OS process.

## Security and privacy

The extension uses `activeTab`, `scripting` and `nativeMessaging`, without broad
host permissions, a persistent content script or remote script injection. The
local OS owner, extension installation and browser are trusted. A successful fill
necessarily releases the chosen username/password to the authorized page; page
scripts can read those fields. No automatic form submission is performed.
Application buffers are cleared where owned, but managed JavaScript strings and
already delivered IPC payloads have no complete-memory-erasure guarantee.
The sync store needs no master password, recovery key or data-encryption key;
clients must authenticate downloaded ciphertext before using its contents.

## Persistence and compatibility

Sync state is strict schema-1 JSON plus content-addressed ciphertext files. Every
referenced blob is checked on reopen, and orphans count against capacity. Historical
committed snapshots remain fetchable; no pruning, compaction or automatic merge
is implemented. Replay of an entire older server state requires a client-retained
trusted frontier to detect; CAS alone does not solve that rollback boundary.
The native messaging protocol and Chromium extension form one candidate bundle.
Compatibility with a different browser, extension version or platform requires
separate evidence rather than borrowing a prior bundle's result.

## Observability

Native replies contain bounded status and requested metadata; a fill reply is
secret-bearing IPC and must not be logged. Sync receipts expose public ciphertext
digests, generations and operation IDs. Fixed errors distinguish conflict,
operation conflict, capacity, corrupt state and unavailable storage. There is no
remote telemetry exporter. Test reports retain public build/harness identity and
case outcomes while keeping native frames, passwords and private state out of
published evidence.

## Operations

Build with `cargo +1.98.0 build --locked -p heptabao-personal-edge`. The
create-only `tools/install_personal_browser.py` writes the selected local native
host installation; follow `crates/heptabao-personal-edge/README.md` for the exact
manifest and extension flow. Keep native vault roots and sync roots private and
separate. Provide authenticated transport outside the sync CLI, retain encrypted
backups and preserve conflict versions. Capacity exhaustion requires an explicit
future retention/migration decision; removing ledger entries to free space is
not a supported recovery procedure.

## Tests and executable evidence

Run `cargo +1.98.0 test --locked -p heptabao-personal-edge` for the current Rust
test `exact_https_origin_only` in `src/lib.rs`. Broader executable profiles are
`qa/personal_credentials/personal_edge_live.py` for actual native pipes and sync
processes, `native_backpressure.py` for blocked pipes, `browser_worker_test.mjs`
for worker scheduling with mocked Chrome APIs, `browser_live.py` for a real
browser and `two_device_sync.py` for separately identified devices. A mock pass
is not a real browser pass, and two local directories are not two physical devices.
Retained receipts in `qa/personal_credentials/evidence/20261106/manifest.json`
apply only to their recorded source, binaries, browser, harness and environment.

## Evolution and open boundaries

Every additional browser/platform, remote transport, shared vault and device
revocation feature needs its own identity, cancellation and recovery design.
Current synthetic evidence does not qualify real websites, arbitrary form
structures, Android, Passkeys, independent security review or P5 production use.
Keep unsupported combinations explicit, and update the module guide and separate
integration receipts whenever the native host and extension boundary changes.
