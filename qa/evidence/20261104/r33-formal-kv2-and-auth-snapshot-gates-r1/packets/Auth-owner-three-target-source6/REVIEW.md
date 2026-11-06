# Necessity of independent post-inert reads

Scope: pure local review of frozen SOURCE88 and the stdin correction. No Runtime, candidate execution or source mutation. The old GO952f applies only to the old root; this proposal requires a new explicit GO.

## Existing evidence that remains mandatory

Publisher f7a4a54c204fa2cc01590fb29f1317cc1a2ba531, publish_public (202–217 in the fixed file; exact function name is authoritative), writes create-only through HeldT5.write_new, then opens a separate held read descriptor. It compares every returned byte to the already hash-bound stdin and verifies the named full9 against the write record. HeldT5.write_new fsyncs the file and held parent; HeldT5.read compares before/after fstat and named full9 and closes once. All30 source/document rows are exposed in the final report. The receipt itself is also published through the same function, giving31 held-read publications in total.

Publisher main lines294–324 writes the receipt before final descriptor/command closure. The stored receipt has ok=false; only the post-finally stdout plus authoritative exit0 can qualify the stage. The final report exposes the exact receipt hash/identity and requires30 rows, all owned commands stopped, all descriptors closed, final anchor and the original45-second deadline. A receipt alone is not success.

Outer12a6fa7a0432281246b36915f1b4b5cd5cd5b400 lines915–929 checks every22 source whole SHA and full9 before importing helpers; read_public_source lines277–296 closes its descriptor once. Lines938–952 read and validate the entire candidate contract. Lines953/961–962 admit all7 public proof originals through capture entry6d81fc1a726b43f4b523a416a077c49953d96ac6: admitted_synthetic206–210 (2), admitted_native250–256 (3), admitted_wal356–360 (2), with exact byte length/SHA. These are before project_frozen979 opens the trusted private-source chain. Outer1079–1080 rechecks22 source identities at the end. No one of those predicates is removed.

## The concrete remaining distinction

The outer file is itself loaded by Python before its own920 self-check. That self-check cannot be described as an independent check before executing the bootstrap file. An independent whole read of the71506-byte outer after the publisher exits supplies a later external bootstrap observation; the remaining21 source reads and7 proof reads do not close an additional use-time predicate beyond the producer checks and the validated outer's own mandatory gates. Thus31 external whole reads are not needed to obtain this specific additional observation.

The proposed finite set is exactly outer + candidate + inert receipt. Candidate and receipt retain the external contract/publication reconciliation requested by root; the outer is the one additional bootstrap target. File-info full9 must equal the actual publication record, and body content must match the fixed or actual-final-receipt whole hash. No inference that the remaining28 files are currently unchanged is made from these3 samples.

These reads are sequential observations. They do not establish atomic custody between the final read and Python exec; the previous31 external reads would not establish that either. The reviewed publisher/owner-controlled create-only tree and the unchanged execution gates remain part of the acceptance model. No new hardening or policy relaxation is implemented here.

## Exact bounded read proposal

Three fixed file_info requests are included. Only after all3 have closed and matched final publication identities may the4 version-bound body requests be derived. Outer:65536+5970 bytes; candidate:7211; receipt:actual1..65536. New body total is at most144253 bytes (78717 + receipt). Every immutable result page is at most8192 bytes. File-info performs a whole-file hash and that work is not falsely counted under the binary body-return cap. No other path, dependency, private capsule or SDK entry is read.

The original45/30-clipped/60 publisher budget and every900/600/120/45/3/native15-8-3/1080 runtime budget are unchanged. This source proposal grants no dispatch.
