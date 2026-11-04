# Minimal Clippy source repair for the next combined candidate

This is a source proposal, with exact read-only provenance and no compile, test,
Clippy, runtime, production or GitHub qualification claim.

The failed CI is run `41837754898`, head job `126600985114`, exact head
`f9139c3b37b6373df3e4b4c61ebdd4f847afac4d`. Its complete Rust workspace test
step succeeded; the strict Clippy step failed on the three diagnostics retained
in `clippy-errors.original.txt`. Later workflow gates were skipped. The existing
command remains `cargo +1.98.0 clippy --locked --workspace --all-targets --exclude qrcode -- -D warnings`.

## Four changed files, three diagnostics

`engine_native_kv2_lossless_export.rs` and
`service_snapshot_lossless_export.rs` remove only the redundant deadline callback
argument from the parallel engine export method. A full tracked-Rust search of
the actual clean R8 tree found exactly one definition and one callsite, recorded
in `physical-r8-callsite.public.json` and the independently read successful job
status. The only caller passes `&|| deadline.check().map_err(|_| RecordError::Invalid)`.
The callee now creates that same lazy closure from the same passed original
deadline. It does not create a new deadline, call the closure at construction,
or move any actual check invocation. The early and final `check()` calls are
unchanged; the same closure is passed by reference to the unchanged lower-level
parallel writer. The separately admitted `source.before_delivery()` callback,
its argument position, the original owner/session checks, and the stop flag's
error-path `Ordering::Release` store are unchanged. No worker implementation,
concurrency limit, deadline duration or request budget changes.

`ha_forward.rs` combines the StaticKv1Lease pattern check and its existing
short-circuit validation in a let chain. Validation still runs only for that
variant; a present raw wrapped reply still short-circuits projection validation.
The same rejection string and the same return remain. This does not modify the
SSH full-reply profile, its carrier, nonce, mount validation or capacity limits.

`service_native_auth.rs` combines the existing non-GET condition and the sudo
authorization error match in a let chain. GET still does not perform this extra
sudo check. Every other admitted method checks the same original actor,
namespace, path and request time and returns the same error status/message.
The preceding capability authorization and following owner capture stay in
place. No ACL or error-precedence condition was removed.

## Exact base separation

`original/` and `candidate/` bind the exact four f913 source blobs; their patch is
`clippy-source-fix-f913.review.diff`.

`original-r8/` and `candidate-r8/` bind the R8 physical source
`384c957612186d64c5a530044af0ae62c568cc3d`, tree
`d5a0f91a4d47f7c8d5f34170ea167d10dc036e04`; their patch is
`clippy-source-fix-over-r8.review.diff`. The two export files are byte-identical
between f913 and R8, verified by exact Git blobs and physical source hashes.
The full `ha_forward.rs` and `service_native_auth.rs` files differ because R8
includes reviewed SSH changes. Only one exact matching local snippet is changed
in each R8 file. Do not overwrite these R8 files with the full f913 afterfiles.

All four physical before-file hashes and Git blobs match the proposal's pins;
the source is clean and identical before/after the read-only whole-tree query.
No production source, frozen R8 source, Cargo target or reference was written.

## Integration and verification boundary

Apply the four R8 afterfiles or the exact R8 patch only after checking their
before pins, then combine with the separately reviewed R9 HTTP and Mac fixture
changes in a fresh source tree. Keep the CI/docs/script-only changes in the
reviewed PR baseline as instructed by the root integrator. The resulting normal
build, targeted runtime gates and unchanged strict Clippy command still need
actual execution; the original R8 and CI failures remain independent records.

The existing parallel export actor/deadline tests, the original full34 migration
and recovery checks, and the existing HA/static-KV1/ACL coverage remain applicable.
No mirror-of-implementation unit test was added for these three local refactors.
