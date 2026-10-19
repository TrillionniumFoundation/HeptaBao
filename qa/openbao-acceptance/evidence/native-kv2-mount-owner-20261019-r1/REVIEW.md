# Root native KV2 mount owner candidate

## Concrete missing behavior

An active native V6 Service currently rejects `sys/mounts/<path>` management with 501 before the existing mount handler runs. Creating the KV2 mount before activation is possible, but an operator cannot create another KV2 mount, inspect its individual descriptor/tune view, change its supported metadata, or retire and recreate it through the same active storage implementation. This patch addresses that concrete route and owner gap. It does not rename the fixture startup switch, change the normal default storage profile, change a migration CLI, or claim that the remaining OpenBao feature set is admitted.

Base source: commit `b24c6de7831a7389e39ac069277a9e85e858ef98`, tree `3356f0a94616e9e1804f497239f33546e16db577`. This candidate is independent of the frozen HTTP signed-zero R2. It has not been formatted, compiled, or executed on a host.

## Scope and authorization

The selector requires an actual active native root and root namespace. The new dispatcher explicitly rejects HA and admits only creation of a KV2 backend or management of an actual paged native KV2 mount. Other backends, conversion to KV1, other namespaces, remount, rekey and the existing unsupported routes retain their restrictions. The established mount handler still owns body schema, overlap checks, supported tune values, optional `cas_revision`, revision increments and path-incarnation tombstones.

The actual request Actor, its original RequestClock/deadline, parameter ACL, operation ACL and sudo for writes are checked before target existence/type inspection. Public mount reads require read permission. The same original Actor and body are checked again before publication and at terminal delivery; a successful empty mount mutation does not inherit the Auth revocation route's intentional 204 self-revocation exception. Native credential/Auth routes keep that existing exception and their original behavior.

## Independent change constraint

`NativeKv2MountOwner` binds the original engine metadata, selected canonical mount path and intended operation. It permits only the real dispatcher result for that path:

- Creation requires an absent path, pristine new KV2, revision 1, and the existing retained incarnation floor.
- Tune retains the same paged backend and incarnation, and accepts the ordinary unchanged revision or one exact increment.
- Deletion removes that mount and advances its tombstone exactly once. Deleting an already absent path cannot increment it again.
- A read or failed domain request cannot change the registry metadata.

The opaque engine metadata digest excludes paged payload owners only because the second typed-root check independently binds every KV2 graph. The planned root may add exactly one pristine zero-payload paged graph on create, remove only the selected path's graph on delete, or leave all graphs exact on tune/read. KV1, unrelated mounts, namespaces, database, Raft, Auth, replay epoch and all other owner/reader-floor fields are unchanged by the mount plan. Supported writer-schema advancement remains subject to the existing root and State validation.

The two original Auth constraints are retained: `EngineState::native_auth_identity_only_change` and `auth_only_root_change` are byte-identical. They are selected for the original Auth route. A mount request uses its different typed owner; the Auth identity guard is not weakened to authorize mount changes.

Publication reuses the actual native conditional root append, original source proof and durable ownership checks. Its request label is `native6-kv2-mount-...`; no retry is introduced for a failed or uncertain publication. The request's existing native delivery capsule retains the independent mount constraint through the mandatory audit. Terminal Auth clock observation can advance the Auth owner under the established terminal writer/current-Auth validation, while the installed mount metadata, graphs, other owners, epoch and reader floors stay bound to the selected mount publication. A seal/unseal ownership change still vetoes success.

The metadata digest streams into SHA-256 under the original deadline and existing application-owner bound. No secret data or credentials are written to diagnostics. No global JSON number, response size, archive profile or storage capacity constant is changed.

## Three new real Service regressions, still unexecuted

These are a separate three-case group. The original 55 Rust cases and 31 full34 driver checks are unchanged.

1. Create a mount after actual activation; require existing payload graphs to remain unchanged; write two versions containing a wide integer and long decimal with real CAS; soft-delete the first version; tune metadata without changing payload graphs; cold reopen; export a native snapshot, write a later version, restore the actual archive and cold reopen again. API values use the existing OpenBao binary64 projection, while the authenticated storage witness requires the independent exact payload hash/length for both retained versions. Then delete/recreate, require the next incarnation, and prove that old data stays absent after another cold reopen.
2. Use an actual issued policy token without sudo. Both unsupported-type creation and existing-mount mutations must fail before the target can create resources. Keep ordinary reads authorized. Reject stale mount CAS, an unknown field, non-KV2 creation and downgrade; require registry incarnation/revision and payload graphs to remain unchanged.
3. Begin from actual empty initialization, unseal and activation with no KV2 graph. Create the first KV2 mount. A one-shot cfg(test) observer runs only after the real request and response audit records, confirms the actual committed graph, and calls the real `sys/seal` route. The original request must return 503 and release no success data. A new cold Service must recover the single committed mount at incarnation/revision 1 and perform actual credential-shaped KV read/write without replaying create.

Each request retains a fixed 15-second scope. Tests use the actual Service/FileBackend, original encrypted paged payload reader, original snapshot transfer and normal audits. The observer supplies no fake Principal, clock, archive result, response or audit success, is consumed before the nested real seal request and exists only under cfg(test). No OS server process is spawned by these tests.

## Required actual validation and limits

Run the exact new group with the existing native feature profile, source manifest and target lock, `--test-threads=1`, and the original 1800-second command budget. Discovery must report exactly the three names in `source-and-test-review.json`. A native-service-only compile remains relevant because the new owner is gated by `fixture-native-v6-service` and must not require the HA feature.

This workspace performed only local source review, immutable base checks and patch construction. There is no Rustfmt, Cargo, Service or HTTPS success claim for this candidate. The actual 55/55 and full34 31/31 results from the parent R5 source do not qualify these new changes. HA mount management, default startup/profile promotion, broader namespace/engine functionality and per-host production cutover remain separate work.
