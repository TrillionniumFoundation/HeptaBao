# Original failed-test2 logs

Both actual logs are whole: stderr191 and stdout375. Six new original SDK calls, two returned operations and two immutable pages are complete; future statuses completed/stored/inactive. The preceding six INFO calls and original BUILD context are preserved. New arms all bind the separate BODY GO.

The real failure text is Error: "Identity projection", emitted through Fixture.snapshot's lossy mapping of whole EngineState serialization. It is not an observed501/400 assertion mismatch. The underlying Serialization/size category is not present in the log. Do not skip Identity or relax assertions based on this mapping.

Pure verifier API: evaluate pure.original.js+verifier.source.js, then verifyFailedTestLogBodies(files). No Native, Cargo or product cases executed by verification.
