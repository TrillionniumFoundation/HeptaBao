// SOURCE ONLY. Do not invoke without the separate exact root GO.
// Load pure_helpers.js, git_archive_once.js, then native_gitfirst.js.
// All calls below are separate explicit model/tool boundaries:
//
// gfInitializeOnlyAfterRootGO({
//   goRaw: EXACT_WHOLE_GO_TEXT, goPin: EXACT_GO_PIN, goWholeReadback: true,
//   digest: ROOT_RECOMPUTED_TYPED_DIGEST, fingerprint: ROOT_EXACT_UINT64_DECIMAL
// });
//
// 1) await gfPrepareOne({
//      callKey:"launchd-diag-start-r1", kind:"process_start",
//      requestRaw: WHOLE_d14f62155b86924edd5632673d2e73832f7b0af5_TEXT
//    });
//    Confirm the returned armed tree whole. No native call in this step.
// 2) await gfInvokePreparedOnce("launchd-diag-start-r1");
//    This invokes one original start; full original SDK is Git-whole, still uninterpreted.
// 3) gfAcceptArchivedSDK("launchd-diag-start-r1");
//    On exact ACK, use only the returned job; error/uncertainty stops.
//
// Later observer exact requests are generated only from that returned job and
// the current original operation ID/cursors. They use the same prepare -> invoke
// -> accept sequence and never change key/args to bypass a lost ACK.
// End each original read operation with await gfCloseOriginalObserver() after
// every original immutable page is whole and the original future is inactive.
//
// Outer catch example (does not retry):
// try { await ONE_EXPLICIT_STEP; }
// catch (e) {
//   store("owner_launchd_gitfirst_outer_failure", {
//     errorName: e.name, errorMessage: String(e.message),
//     state: load("owner_launchd_gitfirst_r1"),
//     automaticRetry: false, rootReviewRequired: true
//   });
//   throw e;
// }
//
// Only a root-directed pure Git reconciliation may inspect the original
// expected tree/blobs. It must not call gfInvokePreparedOnce again.
