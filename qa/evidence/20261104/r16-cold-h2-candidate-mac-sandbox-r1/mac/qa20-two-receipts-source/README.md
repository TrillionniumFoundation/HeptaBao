# Exact origin of the two existing QA receipts

The bounded metadata observation saw 18 expected source members and two additional regular files. Archived approved source proves that the latter are `inert-candidate.public.json` and `inert-synthetic-r2-candidate.public.json`, written by the initial five-source inert stage and the later one-source synthetic append.

Their basename hashes exactly match the two hashes disclosed by the new metadata observation. Their historical candidate bytes are recovered from archived final stdout using the original raw JSON value tokens and the original write-before-cleanup control flow; both complete SHA-256 values exactly match the old authoritative `candidateReceiptSha256` fields. The generated documents deliberately still have `ok:false`, because they were written before final cleanup and publication. Final success belongs to the old stdout plus authority, not to these intermediate candidates.

The new metadata did not read either file body. The next source-only inert proposal will preserve these two fixed public documents by exact historical bytes/SHA and current nine-field identity, while retaining the original source and root-document fences. It will still require an exact member set, not a subset or an ignore rule. No host request was made during this correlation.
