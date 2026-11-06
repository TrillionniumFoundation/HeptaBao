// SOURCE ONLY. Every eventual step must be invoked through gfRun and return normally.
// Load the exact R2 archive helper and R2 native helper plus the unchanged pure helper.
// No bare internal helper invocation and no "throw" after a returned failure.
//
// const result = await api.gfRun("initialize", {
//   goRaw: EXACT_ROOT_GO_RAW, goPin: EXACT_ROOT_GO_PIN, goWholeReadback: true,
//   digest: "f670cf418c6ae40943b7f0224e09f0bd556ceb3b5975c377ad0e524a317f5cd7",
//   fingerprint: "17757921211157505033"
// });
// text({ok:result.ok, action:result.action, failure:result.failure});
//
// await api.gfRun("prepare", {
//   callKey:"cli-phaseb-live-r4-start",kind:"process_start",
//   requestRaw: WHOLE_2c0692832bfe24fe8b728589900896ae64152852
// });
// After its whole external armed tree and a model boundary:
// await api.gfRun("invoke",{callKey:"cli-phaseb-live-r4-start"});
// After full original SDK Git whole:
// await api.gfRun("accept",{callKey:"cli-phaseb-live-r4-start"});
//
// Only actual returned job/operation IDs and stream cursors may derive later
// process_status/process_read/status/page exact requests.
// Each goes through gfRun("prepare"), gfRun("invoke"), gfRun("accept").
// End a complete original payload with gfRun("close_observer",{}).
// Any ok:false stops new admission. Preserve it and return normally.
// A root-directed Git-only reconciliation uses:
// await api.gfRun("git_readonly_reconcile",{archiveKey: ORIGINAL_ARCHIVE_KEY});
// It never mutates, dispatches, clears paused, or grants replay.
//
// Complete original SDK serializations are immutable in
// original-sdk-by-blob:<Git SHA>, with ordered <prefix>:sdk_history.
// Aliases are convenience only. Include these exact raw SDKs in the final
// observer/archival companion. Never replace an earlier SDK with a newer response.
