# Mac SQLite prerequisite: second source generation

This packet is source-only. It is not a second execution, a production read, or a
qualification. The prior exact R1 failure is preserved in tree
0afe32c5bf0f96be1089cf5b976f529e80327ab5: five cases passed, the sixth failed with
absence_not_reopened_as_present, and the seventh was not executed. All owned
resources closed and the authoritative job exited 1.

## Exact correction

The sixth case first held the main inode and optional sidecars through the
actual database() method, then appended one byte to that exact held inode.
Calling auth_rows() again re-entered database(), where the intentional
absence_not_reopened_as_present guard ran before immutable_query() reached its
metadata verification. The new case retains the original main object and calls
the actual immutable_query() directly. Its query lambda must never run. The
assertion is unchanged: exact current_input_fd_name_or_metadata_changed and zero
opened connections. No alternative refusal is accepted.

The capture library remains exact 23,578 bytes / 606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693.
No hold, verify, immutable URI, authorizer, cancellation, row bound, or deadline
implementation changed. All seven case names and predicates remain. The 45-second
shared deadline, three-second query cap, clipped diskutil 30 seconds, and original
retained-child cleanup remain. The two actual selected definitions were exercised
with fake dependencies locally: the old entry produces the original refusal;
the new entry produces the existing drift refusal before any connection/query.
That is an entrypoint component, not a SQLite or Mac result.

## New paths and preserved sources

The new controller is qa/mac_capture_sqlite_synthetic_r2.py. Its fixed owned case
root is capture-sqlite-synthetic-r1/reviewed-attempt-r2 under the already-owned
candidate root. This new child is within the library's existing fixed synthetic
prefix, so production/library scope is not broadened. None of the six old case
directories is used as a new input or output. New directory creation is exclusive;
an existing path refuses the run. The old R1 controller stays present.

The append-only inert carrier reads and verifies all six payloads and compiles
them without running either component entrypoint. It loads the same three
import-safe custody libraries from verified public bytes, holds the exact T5
anchors, and runs the same owned volume query. It verifies the five original
files against their full nine-field identities from the actual successful inert
receipt, both before and after publishing only the new R2 source. It also creates
a new inert-synthetic-r2-candidate.public.json. It does not recreate ROOT/qa,
overwrite an old file, run SQLite, read current credentials, or start a service.
Published readback uses a fresh held read descriptor, not the write descriptor.
Its stdin remains below the unchanged 131,072-byte cap.

## Dispatch and terminal rules

inert-start.public.json and synthetic-start.public.json are separate proposed
exact requests with separate stable keys. Each has outer 60 seconds and shared
inner 45 seconds. No request from this packet has been submitted. Root currently
holds all new Mac work for the HA window.

The inert must first have actual authoritative exit 0, complete durable original
stdout/SDK, exact new-file readback, all five preserved identities, final T5
anchors, and all descriptors/owned commands closed. Synthetic execution requires
a separate root GO. A lost acknowledgement is reconciled by the same key/job,
never replayed under a new key.

A full synthetic proof requires actual seven-case success, authoritative exit 0,
the original raw stdout and source/runtime identities, closure and the original
deadline. This failed R1 proof remains inadmissible. Neither a successful
synthetic nor a successful inert authorizes current credential capture, service
management or a production migration. Runtime proof covers the actual Python and
_sqlite3 files/versions, not every dynamically loaded dependency.

## Local source checks

The whole new controller and carrier parsed and compiled in the restored local
Python environment without executing either module. Six controller hunks and
seven carrier hunks strictly reconstruct their full candidates. Eight original
top-level helper functions in each file are byte-identical. The two entrypoint
components use only selected actual function definitions and fake dependencies;
they open no database, file, socket or child process. The earlier unavailable
environment observation is not reclassified as a source failure or runtime pass.
