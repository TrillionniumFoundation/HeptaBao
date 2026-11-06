# Offline checks and preserved limitations

The final `verify_source.py` run returned exit 0 and produced
`VERIFY.result.public.json`: 799 source-only checks, 641 unchanged existing
function definitions. The script uses a small lexical masker and balanced
delimiters. It is not a Rust parser, compiler, formatter or product test.
The ten Rust regressions are source only and have not run.

The final command was `python3 ha_native_jwt_source_r1/verify_source.py` from
the shared scratch workspace. The session 12095 completion was observed as
exit 0. Its final native wrapper was not separately saved as an exact SDK
file; `EXECUTION.public.json` records that observation and must not be called
an original SDK transcript.

Preserved checker history:

- The first lexical implementation was excessively slow because it sliced
  the remaining source per character. It is retained as
  `verify_source.attempt1.py`. Its old local session 73135 did not provide a
  terminal SDK within the recorded observation; a later signal attempt found
  no such OS process. This is not a Runtime/product operation or a successful
  cancellation claim. It cannot authorize product work.
- The next local check failed on a checker-only assumption that
  `LoginIdentity` lived in `auth.rs`; its exact module is `auth_identity.rs`.
  `VERIFY.attempt2.failure.public.json` retains that failure.
- A later checker selected the wrong plan function spelling. The actual
  existing method is `prepare_native_live_root_checked`.
  `VERIFY.attempt3.failure.public.json` retains that failure.
- The final checker fixes those selectors and the local masking performance;
  it does not change any of the nine frozen Rust candidates.

Passing byte checks did not expose the two later functional blockers in
`CROSS-REVIEW.md`. R1 remains a recorded intermediate proposal, not a product
PASS. The successor must preserve these originals and record its own delta.
