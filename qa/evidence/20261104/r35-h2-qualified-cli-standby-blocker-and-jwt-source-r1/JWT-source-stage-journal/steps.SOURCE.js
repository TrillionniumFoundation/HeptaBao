// SOURCE ONLY. No call in this file executes automatically.
// Load exact pure b6890..., archive b093..., and native 4a2e... in one evaluation.
// Export only gfRun. Do not call obsolete processStartBinding from the pure helper.
// Root supplies actual whole GO/digest/fingerprint. No local journal is assumed.
//
// await api.gfRun("initialize", {goRaw:ROOT_WHOLE_GO,goPin:ROOT_GO_PIN,
//   goWholeReadback:true,digest:ROOT_TYPED_DIGEST,fingerprint:ROOT_DECIMAL_FP});
// After initialization returns normally:
// await api.gfRun("prepare", {callKey:"jwt-e3af-rog-source-start-r1",
//   kind:"process_start",requestRaw:WHOLE_c1429991e9c597d1639f02a68f791043e6c8b9e5});
// Wait for external armed whole; next model boundary:
// await api.gfRun("invoke", {callKey:"jwt-e3af-rog-source-start-r1"});
// Wait for original SDK external whole before:
// await api.gfRun("accept", {callKey:"jwt-e3af-rog-source-start-r1"});
//
// Later original job status/read: unique callKey prefix jwt-e3af-rog-source-;
// operation_start idempotency prefix heptabao-native-jwt-e3afc157-rog-source-observe-r1-.
// Prepare -> invoke -> accept for each original call, return normally on failure.
// Only actual returned IDs; no guessed job or repeat Native start.
// Same-ID status then8192 immutable pages, full payload close_observer.
// Any ok:false stops admission; only root-directed immutable Git reconciliation.
// No loop, no filesystem API, no new child, no formatter/build/test.
