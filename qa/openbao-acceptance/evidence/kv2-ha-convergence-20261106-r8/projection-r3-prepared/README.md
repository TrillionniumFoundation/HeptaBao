# Allrows projection r3: strict POSIX file URI preparation

This is the frozen proposed r3 input, with local guard results and independent source review. It records no actual r3 stage or projection execution. The actual r1 and r2 failed generations remain preserved. Formal KV2, HA, AuthBus, traffic cutover and cleanup remain unqualified.

## Why this change exists

The actual r2 projection failed after its first two of eight obligations, before any SQLite connection. A separate fixed Mac code-only job reproduced the unchanged audit rejecting the first lazy import of urllib.request from Python 3.14.3 Path.as_uri. It read only two public code files and used a synthetic path. This follows the earlier independently observed __future__ lazy import; r2 already preloads that module before the audit. Neither diagnostic relaxes the audit or replaces a real successful projection.

## Exact change

Only INPUT, OUT and DEST change to fresh r3 names. In cold_database, a guard requires POSIX, a Path instance and exactly the single-slash absolute anchor. The URI encodes os.fsencode(path) through the already imported urllib.parse.quote_from_bytes with slash safe, prefixed with file:// and the unchanged mode=ro&immutable=1 query. Every subsequent statement, every other function and class, the audit implementation, ownership/once-close logic, source provenance and 52/60-second budget remain unchanged.

The focused fresh-process guard compares eight synthetic cases, including Unicode, spaces, percent, question mark, fragment characters and an undecodable filesystem byte, with the exact pure pathname2url function from official CPython v3.14.3. It also rejects a relative path, a double-slash authority-like root and a Windows path. No real SQLite connection occurs in this guard; urllib.request stays uncached. The previous ten meaningful guards and this one new guard all passed locally, eleven total, with original logs retained. This is controller validation, not actual Mac projection qualification.

## Fixed inputs and execution boundary

The five public inputs and one private fixed-input file are identified in input-stage/STAGE_INPUTS_MANIFEST.public.json. The private file remains byte-for-byte the same as r1 and r2; all six prior r2 inputs were compared with the root agent's actual native file_info originals before preparation. Only the public controller bytes change. The stage template changes only its fresh OUT constant.

The full private stage request embeds those six fixed inputs; the full private projection request binds the exact controller and unchanged private input. Their bodies and private fingerprints are excluded here. RUNTIME_REQUEST.public.json is an explicitly redacted, non-executable description. Stage and projection each retain their original 52-second work gate, 60-second Runtime limit, native nice 5 and separate fixed r3 idempotency key. Existing r1/r2 inputs, outputs, private failures and projection directories are not overwritten.

Actual admission still requires the root agent's review, fresh create-only stage, independent native verification of all six files and a single authoritative projection terminal with complete durable stdout, all eight checks and full resource closeout. A private allrows projection alone grants no long-lived service, production storage, HA, AuthBus or traffic qualification.
