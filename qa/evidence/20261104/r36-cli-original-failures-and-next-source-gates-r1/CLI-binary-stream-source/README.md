# Snapshot binary body contract: first concrete Rust slice

This patch adds a feature-gated compilation unit to heptabao-ha-service and ten selected Rust tests. It is SOURCE only: it has not been formatted, compiled or executed. Its exact base is the unchanged HA-service lib.rs in 4e808. No dependency or Cargo.lock changes are proposed.

The one lib.rs hunk adds the private module and public data-only reexports under native-v6-peer-ingress. All other lib.rs bytes remain identical. The full patch also contains the two complete new files.

## Implemented code

- One fixed 8-byte profile, DATA records with exact sequence and length, and a terminal frame count/length/SHA256.
- A maximum 65,536-byte DATA buffer and the unchanged 2,488,803,400-byte largest native-HA archive ceiling. The server must pass its smaller feature-specific archive bound.
- No empty DATA frames, no DATA after a short final chunk, no count overflow, no out-of-order sequence, no extra trailing stream bytes.
- A VerifiedSnapshotBody is minted only after exact END fields and an underlying successful EOF. Exact payload length alone, a valid archive prefix, raw transport failure or empty application read cannot mint it.
- Every read/write/flush attempt, including Interrupted retry, checks the same original Instant before and after. Actual blocking I/O must remain wrapped in the existing deadline-bound authenticated transport.
- A sticky decoder error prevents resumption into a successful result.
- A consumer that stops before all archive bytes cannot finish; a one-byte terminal check rejects remaining body rather than silently draining it.
- The encoder performs at most one rejecting EOF-byte observation at the exact source cap and never emits that byte. It does not reconnect, repeat source bytes, or close a transport.

EncodedSnapshotBody and VerifiedSnapshotBody are distinct, non-cloneable data-only bindings. Neither grants peer authentication, Actor admission, storage mutation, publication, retry or HTTP delivery authority. No peer stream is registered by this slice.

## Integration requirements that remain mandatory

The reader must sit on the authenticated cluster TLS stream, whose Read differentiates close-notify from unexpected TCP EOF. The actual transport must end its write side after END. This slice alone deliberately cannot prove that an arbitrary Read implementation is TLS.

The leader must admit the original native request once before upload, retain the original pending plan, obtain the verified body before finish_external_request, and convert failed body termination into an error before any restore publication. The existing native import cannot be treated as complete merely because it parsed a valid archive prefix.

For downloads, keep the private SnapshotFile and bind the exact binary descriptor to the dedicated source-completion receipt. For historical restore, retain the existing original_auth/original_identity/activation and actual new epoch terminal gates. The original ordinary JSON receipt cannot be attached to this byte witness. The remaining authenticated stream and Service/completion integration is being implemented separately; this slice is not a product repair qualification.

## Proposed selected tests

The ten test functions are exact source in native_snapshot_body_tests.rs. They exercise a body larger than the old ordinary 1 MiB frame, empty-body END, exact payload with missing END, corrupted digest, trailing bytes, declared oversize before payload, invalid short/nonfinal sequence, partial archive consumption, TLS unexpected-EOF after a valid END, expired deadlines before I/O, and the exact-cap rejecting EOF probe. One function covers two closely related terminal corruptions.

These tests have not run. The synthetic EOF adapter checks error propagation only; it is not an actual TLS handshake or close-notify test. Actual pinned mTLS/once Actor/native restore/owner/cancellation tests and fresh official CLI B04/B05 remain required after integration.

## Preserved evidence and scope

The original CLI exit1, B04 invalid archive and B05 false success/known400/unchanged state remain in 871aa23bfee256e91247fbb7e6d42c4cb82d181d. No original Runtime request or business operation has been repeated. This packet carries no Runtime request and changes no repository ref. Architecture and full source anchors are in bcde44a90cb096361dd9f4edb61e5d9228893a68.
