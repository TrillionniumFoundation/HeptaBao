# KV v2 version-array wire compatibility with OpenBao 2.7.0

The pinned official `bao kv delete -versions=6` command sends a PUT request with
a string element in `versions`. HeptaBao previously required unsigned JSON
integers and returned HTTP 400. The Python client emitted integers, so its
successful checks did not expose this incompatibility.

The shared delete, undelete and destroy parser now resolves the complete array
before changing any version. It accepts the signed integer wire values observed
through the public 2.7.0 API, including strings, booleans and null. Nonpositive
values select no stored version. Empty arrays, invalid elements, fractional
numbers and values outside the signed 64-bit range return HTTP 400 without
partially changing the selected versions.

String parsing follows the measured public behavior: decimal, a leading-zero
octal representation, hexadecimal/binary/octal prefixes, optional signs and
valid underscore separators. It does not trim whitespace. The safe observation
`"010"` deleted version 8 while version 10 remained readable; `"1_0"` deleted
version 10 while version 8 remained readable. No upstream implementation source
was read. The public [KV v2 API](https://openbao.org/api-docs/secret/kv/kv-v2/)
is the protocol entry point; the additional wire coercions were established
with the pinned executable, rather than inferred from the documentation.

## Evidence and remaining qualification

The original full CLI run used client commit
`288eba8e1174dad90f2f6dc74111503c8f759f41` and independently bound server commit
`be83853127cf742f44405d0631181a605ed48b35` (binary SHA-256
`c3ea56dd5f9c94b7c9b6f1747c41918f380a3a2d054f6e0b3566264da385ec66`).
The Python interface completed 68 checks, while the official CLI stopped at its
47th check, `v2_delete_exit`. Report SHA-256:
`c0da7524c52c90099f5094b008f472d5e06b35f8f904d9a0575917323f52625d`.
That failed run is retained as a failure.

The final private typed-version observation contained 91 rows: a real official
CLI request and 45 public API inputs against each server. Report SHA-256:
`50a35640ee1755b5c9976eb44c643d337113142610fefc3037676d46f7c3613c`.
The probe source was captured and unchanged before/after (SHA-256
`46ba17a95dba0dab8998f4306c6b6e83878c98dc6365b24e4a4460cfc9fcd16c`).
Reports retain only operation/type/status/effect predicates, not requested CLI
stdout, response values, value digests or credentials. Fresh native/oracle
processes and the TLS relay stopped; independent process scans were empty.
HTTP and command budgets remained 2 seconds and 10 seconds.

Seven Mac regression tests cover string-array lifecycle and reopening, typed
inputs, nonpositive no-ops, full-array rejection before mutation, mixed arrays,
idempotence, missing entries and the octal/decimal version-selection distinction.
All seven passed. Server all-targets Clippy with `-D warnings`, formatting and
diff checks also passed, using Rust 1.98.0 and locked offline dependencies.

A new integrated runtime binary still needs the complete 272-check CLI run.
The original failing run, the older oracle-only CLI run and these narrow tests
do not establish that complete runtime result or whole OpenBao replacement.
