# Fixed Mac public SDK source reads: completion

This packet closes the original read 11 and the already frozen reads 12 and 13. Every original operation is completed, has a stored result, and has no active owned future. Three files, totalling 682,650 bytes, have the exact original versions, lengths and SHA-256 hashes.

Read 11 was never resubmitted. Its two original immutable-page transport errors remain in `references/prior-partial`; only the same operation and offsets were recovered. Read 12 preserves its first status timeout and its one allowed same-ID status reconciliation. Read 13 was admitted only after read 12 was closed and fully reconstructed. The complete original SDK envelopes and native payloads are preserved before interpretation.

Git archive failures are separate from the Runtime observations. The first two archive failures surfaced only as an `External raw pin` exception and their Git response envelopes were not retained; this limitation is explicit. Later error envelopes are preserved. Same public content was archived using the supported base64 encoding and exact whole readback, without repeating a Runtime page. The auxiliary note with an observed 404 is not reported as an archived success.

The pre-existing checkpoints remain unchanged. Sequence 3 uses its previously archived root-tail adoption document rather than a newly invented standard observation object. The local table assembler initially assumed the latter existed; the correction changes only this reference and leaves all original data unchanged.

After read 13 completed, line B was released to the root and compatibility agent. No SDK module, selector, registry, fixture, provider, credential refresh, or service was executed. Full source availability does not prove the actual selected owner; that remains a separate admission question.
