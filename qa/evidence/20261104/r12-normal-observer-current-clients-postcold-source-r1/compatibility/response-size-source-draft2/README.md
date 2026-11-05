# Response size: private local-redirect indirection (draft 2)

Base: exact PR head 6d3040a2dbd06661a67f5c62df259ff446eb8515, tree 2ec2be733f5499cb632e529159a296f3c6f62cd1. This unreferenced source proposal leaves the independent 3cb diagnostic branch, its actual normal build, all host sources and all refs untouched. Draft 1 remains unchanged.

## Production change

The sole production edit is the reviewed private representation change in service_response_headers.rs: Option<LocalRedirect> becomes Option<Box<LocalRedirect>>. Construction boxes the same value; validation uses as_deref to borrow the same LocalRedirect. take_local_redirect first takes the optional box, then moves out its payload and returns the original by-value Option<LocalRedirect>. Its signature and one-time ownership remain unchanged. Empty/default headers do not allocate the box.

Response's original fields, status/body, body-erasing Drop, already boxed UnwrappedJson, and consistency ResponseIndex are unchanged. Existing copy_for_forward still deep-clones the same payload; the new Box does not share authority. Header wiping, request/deadline/profile/origin checks, quota and ordinary header filtering, serialization refusal of local redirects, and bounded deserialization remain exact original code. This changes private Rust in-memory layout, not HTTP/HA wire encoding. It does not claim a stable C ABI or keep the old private object size.

## Two layout regressions

The first test, unchanged from draft 1, asserts size_of::<crate::service::Response>() < 128. Draft 2 adds only one test to the existing ha_index_phase_tests module in service_recovery_keys.rs, asserting size_of::<HaRecoveryIndexAdmissionFailure>() < 128. That module already imports super::* and can inspect the private type. Removing the new five-line test yields the entire original recovery source byte for byte; none of its production behavior changes.

The exact three derived Clippy diagnostics are the same HaRecoveryIndexAdmissionFailure type at service_recovery_keys.rs:227 and the closures at :455-491 and :621-639. One layout assertion covers this single type at all three result sites. No size is reported as measured yet.

## Existing CI and planned verification

The two captured lanes both used exactly:

    cargo +1.98.0 clippy --locked --workspace --all-targets --exclude qrcode -- -D warnings

The captured step listed CARGO_BUILD_JOBS=1 and EXPECTED_SOURCE/PR_HEAD/PR_BASE. It did not list RUSTFLAGS; this packet does not infer that inherited RUSTFLAGS was empty or absent. Existing command excerpts, full log blob identities and the two lane identities are recorded in existing-ci-command.public.json.

Both old lanes had 69 successful workspace test summaries and then failed only result_large_err: 1,616 Response diagnostics and three HaRecoveryIndexAdmissionFailure diagnostics. Those failures remain the actual results for the old source. This proposal does not add allow attributes, modify thresholds, select a smaller workspace, change features, change CI, or suppress either layout assertion.

Root will review the two full sources and four-hunk diff, choose a fresh candidate source identity, then trigger the existing CI gates on that candidate. The existing workspace tests will execute both layout regressions, and original strict Clippy must pass with its original arguments. Relevant existing redirect/header/quota/consistency/unwrap tests keep their original assertions. No Cargo, rustfmt, product process, branch/ref write or test was executed to prepare this packet.

## Source checks already performed

Whole-byte before/after identities were calculated. The three-hunk header diff and one-hunk recovery diff strictly reconstruct their complete candidates. The header production substitutions and added test reverse exactly to the original header file; the recovery test reverses exactly to the original recovery file. The header candidate is byte-identical to draft 1. The peer's draft-1 source review remains attached with its original limited scope; it is not relabeled as measured layout or compiler qualification.

The candidate is not yet compiled, measured, Clippy-clean, behaviorally qualified or production-ready.
