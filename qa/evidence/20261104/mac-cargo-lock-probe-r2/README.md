# Mac Cargo release-lock evidence

The actual pinned Cargo 1.98.0 binary waited for an exclusive `flock` held through an `O_RDONLY|O_NOFOLLOW` descriptor on this fixture's `target/release/.cargo-lock`. After unlocking, the same child produced a fresh non-test release artifact. Its process group was empty after reaping. The complete operation used 0.318526 seconds of the original 30-second budget.

Durable job: `1a1a7848b96-fc05-2ba5` (exit 0). Result SHA-256: `d9be1b814a0f7834f22eef219c765a3dae8ede2b6be60ca02f1b88600cc69403`. The first wrapper attempt, `1a1a77f3353-fc05-2b9a`, failed before directory creation because it incorrectly required UID 501 on the root-owned APFS mount. Both attempts and the narrow wrapper correction are retained.

This verifies the release build-directory locking primitive for this actual toolchain. It does not reserve the whole Cargo home or host, does not test a product build profile, and does not qualify HeptaBao HA, storage, or replacement. No product source cache, production service, or client was changed.

`root_review.js` exports the independent pure review function and its checksum helper. Supply a map of repository-relative evidence paths to exact UTF-8 contents as the first argument and `sha256String` as the second. The recorded review was executed in code mode after the local execution environment became unavailable. All original SDK receipts are included.
