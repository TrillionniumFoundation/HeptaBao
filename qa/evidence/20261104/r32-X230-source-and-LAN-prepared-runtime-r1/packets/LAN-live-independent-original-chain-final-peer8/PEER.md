# Current 4e808 HA original observation-chain peer

The independent incremental verifier passed **1,800 byte/chain checks** with no failures. It adopts the previously completed 187 checks for two original observers without rerunning them, then checks the other 13 observers and 60 immutable pages. The complete original set is **15 observers and 62 pages**, not 17 observers.

## Exact evidence and scope

Original job: desktop / 1a1ad3a6dd4-fc05-5919. Original final packet: 06d392d5d549d060efa77faeb44a0d48933d8d45 (388 files / 3,007,450 bytes / 149 Merkle trees). Corrected archival packet: 625df69e7dbe4407686253564ccd607a3b60b939 (390 files / 3,012,088 bytes / 149 Merkle trees). Whole original contents were read and pinned before verification.

The new checks bind each exact read request and completed external intent to its original SDK admission, same operation ID, completed/stored/inactive status, and every immutable page. Every page is checked for exact offset, total, digest, strict base64, extent and EOF. The reconstructed 426,448 bytes of original payloads match their archived payloads and exact original native text. No new Runtime error or recovery is present in this original observation set.

The final native authority is succeeded / exit 0, full, durable and terminal-publication-confirmed. The 612-byte stdout and empty stderr match raw hex, text, EOF and authority counters. Earlier authority0–2 reports remain running observations; the original read-operation closure is not confused with business terminal state.

Seven version-bound body operations reconstruct three originals: launch 4,132 bytes, exit 652 bytes and summary 307,292 bytes, totalling 312,076 bytes. Their actual file-info sizes, SHA256 values, versions and full-nine-field projections bind the body chunks. Result records include exact paths, versions and Git blobs. This review verifies original-byte transport and binding only; root owns the 98+12 business checks and process-cleanup semantics.

## Four-leaf archival correction

The original 388-file packet is retained unchanged. Its READPLAN.public.json contained the 8,150-byte full body plan, so only 33 old non-STATE paths matched running35 at the same path. Corrected390 restores the original 2,419-byte READPLAN; preserves the 8,150-byte text under history/merged-core15-READPLAN.original.json (and unchanged readback-plan/body-plan.public.json); adds the correction statement; and updates MANIFEST.public.json. Exactly those four leaves differ. Corrected390 therefore preserves all 34 old non-STATE paths; old STATE remains under history/running35-STATE.original.json. All observation, actual-output, author-result and release originals are byte-identical across388→390.

## Reproduction and limitations

verifier.js is the actual pure V8 function executed. INPUT-INTERFACE.public.json names every immutable source tree and exact input shape; result.public.json.used_files lists all 326 consumed original paths and full pins. The result adopts prior preparation result c5040a809dfaec32f5bd739248ba1598c11e6065 from tree bdb2a3338c513bfa8846626157b00609de34a662. The old 187 checks were not run again; the HA author240 verifier was not executed.

A post-verification display attempt mistakenly treated observer_summary as an array and threw TypeError; its exact message is retained separately. That display error did not change the already passed result, source, original data or Runtime state.

These are evidence-chain checks, not product test cases. This peer performs no host read, SDK execution, loader/supports/factory execution, credential operation or product mutation. Actual selected owner and AuthBus production qualification remain unproved.
