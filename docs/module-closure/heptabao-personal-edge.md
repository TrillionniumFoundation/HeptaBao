# heptabao-personal-edge module closure dossier

This record describes the exact-head browser/native and ciphertext-store source
boundary. The closure validator binds `crates/heptabao-personal-edge/src` through
Git; this dossier grants no compatibility, production or release authority.

## Design and state ownership

The package depends directly on `heptabao-personal-vault` and
`heptabao-filesystem-guard`, and is outside the server runtime closure.
`heptabao-browser` owns a bounded-lifetime local vault session;
`sync::CiphertextStore` owns an exclusive opaque-blob root, schema-1 state and
immutable publication receipts exposed through `heptabao-sync`. The extension
code in `clients/chromium/` is a separate part of the browser integration bundle.

## Module boundaries and trust assumptions

Browser fill relies on an installed trusted extension, a browser-supplied popup
binding, active top-page identity, explicit local unlock and exact HTTPS origin.
Native messages and any intentionally filled page fields carry plaintext and
must not be logged. The OS owner remains trusted. Sync holds encrypted snapshots
only, but a surrounding transport must authenticate and authorize devices.
Neither a vault ID nor a ciphertext digest supplies that authorization. The crate
does not implement an Android or Passkey provider, a network sync server or sharing.

## Failure semantics and ordering

Epoch, focus and monotonic lease checks reject pending fills after lock, close,
navigation or expiry. Already dispatched Chrome work cannot be recalled; lock
acknowledgement waits for its observed outcome. Nonblocking native output exits
on a bounded write deadline so a blocked pipe cannot retain an unlocked session.
Sync compares the exact generation/request-bound head ID, rejects stale-head
updates without overwriting committed versions, and rejects altered retries.
Clients retain their rejected local branch for an explicit conflict decision.
Blob publication precedes durable state/receipt
publication. Uncertainty fences the live store; reopening validates and fsyncs
all referenced state before receipts are returned. Orphans count against capacity,
and retained versions are not silently discarded.

## Acceptance evidence

**Named executable anchor:** `exact_https_origin_only` in `crates/heptabao-personal-edge/src/lib.rs`.

Required Rust execution: `cargo +1.98.0 test --locked -p heptabao-personal-edge`.
`qa/personal_credentials/personal_edge_live.py` covers actual native/sync
processes, and `native_backpressure.py` covers real blocked pipes.
`browser_worker_test.mjs` uses mocked browser APIs and proves only scheduling
behavior of the worker under those mocks. `browser_live.py` is the separate real
browser profile; `two_device_sync.py` requires separately identified devices.
The public evidence manifest in `qa/personal_credentials/evidence/20261106/`
retains each execution's source, binary, harness and environment. An earlier
receipt is not evidence for newly changed native or extension code.

Run `python scripts/validate_module_closure.py` and
`python scripts/validate_current_documentation_semantics.py` for documentation
binding. Passing documentation guards is not a browser or platform acceptance run.

## Known gaps and evolution

The implementation remains `IMPLEMENTED_REVIEW_REQUIRED`. Remote transport
authorization, trusted rollback frontiers, storage retention/compaction,
additional browser/platform support, sharing and device revocation are separate
work. Page-visible plaintext and already dispatched browser effects cannot be
erased retrospectively. Independent security and production qualification remain
open; see the [module guide](../modules/heptabao-personal-edge.md).
