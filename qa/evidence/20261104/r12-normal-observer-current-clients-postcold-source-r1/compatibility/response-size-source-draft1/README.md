# Response size: private local-redirect indirection (draft 1)

Base is exact PR head 6d3040a2dbd06661a67f5c62df259ff446eb8515, tree 2ec2be733f5499cb632e529159a296f3c6f62cd1. This is an unreferenced source-only candidate. It does not change the running 3cb build, any host source, CI configuration, lint allowance, threshold, branch or PR.

## Cause and minimal change

Response itself keeps its original five fields and Drop body. UnwrappedJson already owns a boxed private state (auth_wrapping.rs 65-85); ResponseIndex is a String wrapper (http_consistency.rs 92-105). The large inline member is ResponseHeaders' optional LocalRedirect, whose origin/profile/deadline payload was carried even by ordinary error Responses.

Only service_response_headers.rs changes. Its private Option<LocalRedirect> becomes Option<Box<LocalRedirect>>. The local constructor boxes the same value. Validation obtains the same &LocalRedirect with as_deref. take_local_redirect consumes the optional box once and returns the original by-value LocalRedirect, preserving its signature. Empty/default headers do not allocate this box.

## Preserved behavior and ownership

- No changes to Response fields, constructors, status/body, UnwrappedJson, ResponseIndex, request deadlines, redirect profile/origin validation or return types.
- No new clone/Copy/serde/public constructor. Existing copy_for_forward uses the same deep Clone semantics for the same LocalRedirect payload; Option<Box<T>>::clone does not share ownership.
- Header serialization still refuses a local redirect and cannot downgrade it into an ordinary Location; SDK/HA deserialization still cannot construct local routing authority.
- Header name/value wiping Drop remains exact original code. Taking the box moves its original payload; dropping an untaken box runs that payload's normal destruction. Response's body erasure remains unchanged.
- All ordinary header filtering, quota merge, transport-owned restrictions and output bytes remain unchanged. This deliberately changes private Rust in-memory layout; no C representation or stable external binary layout is asserted. HTTP/HA wire encoding is unchanged.

## Validation plan

Source checks in this packet: exact before blob, whole-file strict apply of the three-hunk diff, and exact inverse of the four production substitutions plus removal of the new regression test. No Rust executable was run.

The added test asserts size_of::<crate::service::Response>() < 128, to catch regression of the central type under the actual build configuration. Current estimates are Response about 104 bytes and the old 224-byte response-containing errors about 120; these are estimates, not measured facts. The three derived large-error diagnostics still need their exact type/site mapping from the already captured CI log.

After root review and an available authorized host window: actual pinned rustfmt; actual layout test and the three derived type layout checks where applicable; original no-forward/redirect/header/quota/consistency/unwrap custody tests; strict Clippy with unchanged workspace/all-targets/feature flags and -D warnings. The ongoing 3cb Cargo target is exclusively owned and is not used for any such command now. Root chooses the later source commit and dispatch.

The captured CI failures and old source remain evidence. This candidate cannot be described as compiled, Clippy-clean, behaviorally qualified or production-ready before the corresponding actual results.
