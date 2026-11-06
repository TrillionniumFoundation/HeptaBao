# R12 CI publication diagnostic — preflight HOLD

This was one actual Runtime attempt, job `1a1b1f14810-fc05-7b9e`, using source `9c68b95b152a468ab378b68730e9e3f04e6a7100`. It failed with `other_compiler_present` before any compiler or test subprocess. The controller recorded zero steps, zero groups and 11 unexecuted cases. The observation contains only the foreign compiler PID and comm; it does not attribute ownership or cause.

The reviewed preparation succeeded once; its complete 39-file evidence tree is `ee6a87d6f8be7898a72d6cc5b7c2138590f1aa74`. The 25 expected legacy artifacts remained byte-for-byte equal between this attempt's observations: 22 matched and the same 3 were absent. Legacy preservation remains false and machine acceptance remains HOLD. No original failed evidence was reclassified, no old asset was deleted or replaced, and the source/target/output are retained.

The frozen diagnostic used the original CI dev/test profile, a fresh empty target and default server features. Its intended scope was 10 existing timing guards plus one original failed case, once, with original request15s unchanged. None of those 11 ran. The 4200s Runtime ceiling, 3600s compile ceiling and two60s group ceilings were not renewed. This archive grants no formal KV2, physical HA, AuthBus, migration, rollback, DR, cutover or full replacement qualification. The original CI failure remains unresolved.

All files listed by the manifest are complete original safe input/output bytes or explicitly labelled local/derived review. The binary bundle is stored as an explicitly named lossless base64 representation. No business storage or credential material is included. No commit or branch was created by publishing this standalone tree.
