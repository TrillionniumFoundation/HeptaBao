# Allrows projection r3: actual completion and independent verification

The single actual projection job 1a1b2b773d7-fc05-7f73 completed with exit 0, complete durable output, confirmed terminal publication and no timeout or cancellation. All eight required checks appear exactly once and pass. The persisted public result is 2,957 bytes; it agrees field-for-field with the complete 3,545-byte stdout. The latter additionally closes publication handles. All six SQLite connections and all 66 registered descriptors were retired, with no audit denial or cleanup error. Work completed in 2.711796 seconds under the unchanged 52/60-second limits; this is not a performance comparison.

The projection covers the already qualified restored generation: five agents, nine declared database families, six nonempty databases and three absent families. Every row in both agent tables is represented: five auth_profile_store rows and four auth_profile_state rows, nine business records. These dynamic counts independently agree with the original completed readback's public receipt. The projection retains source updated_at, original credential JSON strings and the source's SQLite NULL/BLOB encoding. It supplies a new baseline; it does not invent historical OpenBao versions or delete/destroy history.

The preceding r3 stage was independently checked against all six actual native file_info originals, raw local inputs and exact stage identities, modes, owners and link counts. Its twenty file descriptors and two directory descriptors closed. Stage preparation alone granted no projection or service qualification.

## Independent private-output reconciliation

The root agent separately read the complete small private projection (30,631 bytes), binding (8,367 bytes) and original capture manifest (12,523 bytes), with exact native whole-file pins and versions. A separately written checker imports neither the producer nor protocol implementation. It rejects duplicate/nonfinite JSON, verifies all original bindings and unique record scopes, sorts both complete tables by original primary key, and recomputes all five agents' row commitments against the original capture. It opens no database and repeats no whole-database readback. Its source and safe report are included; the private input/output bodies and their content fingerprints are excluded. The independent package reconciler checked the public report, source and native public evidence without reopening private rows. Per-file version matching does not claim an atomic multi-file snapshot.

## Scope

This completes a private allrows projection of the previously verified recovery generation. No long-lived HeptaBao service was initialized or exercised, no KV2 API import occurred, and no provider, J3160, AuthBus client, HA cohort or traffic migration was run. Formal KV2, HA, AuthBus, traffic cutover and old-asset cleanup remain unqualified. The failed r1 and r2 generations, their diagnostics and the original twenty-five-file r3 prepared package remain preserved unchanged.

This manifest indexes only the safe actual stage/projection evidence and reviews. Native wrappers and streams are exact original bytes; namespace and nanosecond integers were handled from original JSON with Python, without a JavaScript numeric roundtrip. The original private requests and original private verification wrappers stay outside this package.
