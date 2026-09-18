# Deployment-owned file audit API and explicit HeptaBao extension

The mandatory local authenticated file device is installed at process startup.
Every admitted request and response still uses the same audit writer, HMAC chain,
rotation checkpoint and descriptor ownership. Runtime API calls cannot replace
its destination or disable it. Both interfaces below require an authenticated
root principal in the root namespace; an invalid bearer or non-root caller is
not allowed to inspect or modify the binding.

## Standard OpenBao 2.6.2 declarative-device profile

`GET /v1/sys/audit` lists the process-owned `file/` device. As observed against a
checksum-pinned real OpenBao 2.6.2 process with a declaratively configured file
device, `GET /v1/sys/audit/file` returns 405; duplicate `POST`/`PUT` enable and
`DELETE` return 400. The complete configured device remains unchanged after
these refusals. This is not dynamic API enrollment or arbitrary device parity.

The previous candidate-only fixture incorrectly treated per-device GET and
idempotent enable as upstream behavior. It failed when actually executed against
the official binary. The corrected comparison starts the official source with a
fixed synthetic private file device; it does not enable deprecated API enrollment,
accept a union of statuses, or classify two matching failures as positive coverage.
The current `duplicate_enable_rejected` case replaces the incorrectly named
`enable_idempotent` case. Historical source-bound receipts are not relabelled.
The original 60-surface denominator and all independent-admission flags remain
unchanged. `deployment_owned_file_v2` explicitly identifies the new profile.

## HeptaBao-only binding inspection

`GET /v1/sys/internal/audit/file` returns the fixed path, revision and rotation
bounds. `PUT`/`POST` at that internal path retains the earlier idempotent
`type=file` binding check, including exact file path, retention and revision CAS.
It cannot install a new destination. `DELETE` is rejected. Applications using the
old nonstandard per-device detail/CAS API must select this explicit extension;
standard OpenBao callers must use the listing API instead.

The rotation checkpoint persists `segment_bytes` and `retained_segments`.
Reopening with a different policy fails closed; valid legacy checkpoints are
promoted on the next durable rotation. No audit-state schema change is required.

## Verification and scope

`qa/openbao-acceptance/audit_file_live.py` executes real listing, exact standard
refusals and unchanged-device readback against both processes. The Rust
`sys_audit_exposes_and_binds_mandatory_file_device` regression separately checks
the internal extension, invalid-token rejection and standard-route isolation.
This is a bounded API comparison, not independent whole-device or production
qualification. The separate HTTP, TCP socket and Unix syslog implementation
profiles neither disappear nor become covered by this file-device comparison.
