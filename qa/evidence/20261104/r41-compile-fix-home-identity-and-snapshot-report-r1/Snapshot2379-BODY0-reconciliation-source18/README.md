# Exact BODY0 admission-reconciliation proposal

This packet contains SOURCE only. It has not initialized a live slot, admitted a read, polled Runtime, or changed the prior paused context.

The original BODY0 admission returned a complete MCP timeout SDK and no operation ID. Public source review c08c41228c8a88dc1d660ee44e928aa3a1b97484 establishes a private Existing branch but no callable lookup-only interface. The proposed request is exactly the original 432-byte request, including its original idempotency key, public path, version, offset 0 and limit 65,536. It is explicitly a conditional admission, which may return an existing binding or establish a new one. It is not represented as retrieval of the missing old ACK.

## State and execution boundaries

The new slot is snapshot_2379_formatter_body0_admission_reconcile_r1. The original slot remains snapshot_2379_rog_formatter_gitfirst_r1. The new initializer validates a separately whole-read root GO, the pinned UNKNOWN state, and the live old context's unchanged paused/pending/error/request boundary. Every subsequent state access rechecks the same old projection. There is no store to the original slot, no resetting of its pending/called markers, and no new interpretation of the old -32603 SDK.

The candidate has only three Native call sites: exact operation_start, returned-ID operation_status, and returned-ID operation_result. It removes business START, metadata observation, generic formatter authorization and BODY1 dispatch paths from its base. Loading this file has no action. The supplied GO-shaped JSON intentionally has authorization=NOT_AUTHORIZED_SOURCE_TEMPLATE and is rejected by initialization.

Future authorized sequence:
1. Whole-read the new exact root GO and this source. Initialize the separate slot once, with the original pinned UNKNOWN text.
2. Prepare the original request unchanged using a fresh journal call key such as snapshot2379-format-body0-reconcile-admit-r1. External request/intent/armed records must complete before a model/tool-call boundary.
3. Invoke that prepared Native statement once. Preserve its complete SDK in store, then external Git whole storage, before reading isError or native fields.
4. Accept reused=true or reused=false only as the current receipt says. Both retain originalAttemptOutcome=UNKNOWN. Admission alone never proves completion or bytes.
5. Prepare and invoke only status for the actually returned ID. Require completed/stored_observed/inactive before deriving pages. A failed, unknown or inconsistent state stops this proposal.
6. Page the original immutable payload from offset 0 with limit 16,384, no gap/repeat and at most 1 MiB retained bytes. Every page follows the same external-arm and SDK-before-parse sequence.
7. Whole-store the complete payload before interpreting its original native result. Require exact report path/version/118,925 total size, the original range extent 0→65,536 with eof=false, 65,536 decoded bytes, and actual chunk SHA256. Whole-store its native text and closure record. The result is one range, not a complete report.
8. Stop and report the new receipt, original payload, range and closure. BODY1 remains unsubmitted and requires separate parent disposition.

The exposed operation contract promises no redispatch for identical-key retries; the inspected source is not an attestation of the deployed revision. This proposal makes the possible New admission explicit and does not read private credentials or state to decide the branch. A new admission receipt with reused=false must not be used to say that the old client call was never received.

## Minimal source changes

The base is 12488e539c55f7be153e20857e162b3f80d49caf (31928 bytes). The candidate is 2708256540fc7476705c9bbb95f9f8b9e0637e49 (23211 bytes; SHA256 dde3323415dd2490da5825bf5d9685edaaf0ee6acd7b243a512e369bd2fce5af). Twelve explicit replacements form nine strict unified hunks. The five unchanged helper definitions are gfNeed, gfMetaEquals, gfSave, gfIntegerText and gfReconcileSameGitArchiveReadOnly. The existing original-SDK-before-parse archival order and outer caught-error preservation remain.

The new initialization/validation code narrows the allowed calls and retains both reused outcomes. The range closer only accepts the first 65,536 bytes, marks completeFileBody=false, and publishes a distinct closure while preserving the original UNKNOWN. Source metadata and the report SHA are reference pins from the already qualified file_info; a prefix alone never authenticates the full report SHA.

## Verification and historical error

48 pure V8 byte/source checks passed. The strict forward/reverse patches and all ordered replacements reconstruct the full candidate/base. A JavaScript function wrapper was syntax-compiled but not invoked; no candidate function, fake OS, Runtime call, Rust compiler or test was executed. Current old state was only inspected for consistency with the pinned UNKNOWN record.

An initial local source-construction command failed because a string replacement used incorrect indentation. It did not produce a candidate or invoke Native. That local error is preserved. The corrected construction used the actual source indentation and passed the full strict-diff checks. The original BODY0 error and all old qualification packets remain unchanged.
