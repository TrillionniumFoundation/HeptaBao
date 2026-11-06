// SOURCE ONLY. Every eventual step must be invoked through gfRun and return normally.
// Load the exact R2 archive helper and R2 native helper plus the unchanged pure helper.
// No bare internal helper invocation and no "throw" after a returned failure.
//
// const result = await api.gfRun("initialize", {
//   goRaw: EXACT_ROOT_GO_RAW, goPin: EXACT_ROOT_GO_PIN, goWholeReadback: true,
//   digest: "27412a077919b5f988477d9a0fcd4bdd7e5d049f21d2c1367ff35bd56f0d67ec",
//   fingerprint: "2828588252550247929"
// });
// text({ok:result.ok, action:result.action, failure:result.failure});
//
// await api.gfRun("prepare", {
//   callKey:"launchd-diag-start-r1",kind:"process_start",
//   requestRaw: WHOLE_d14f62155b86924edd5632673d2e73832f7b0af5
// });
// After its whole external armed tree and a model boundary:
// await api.gfRun("invoke",{callKey:"launchd-diag-start-r1"});
// After full original SDK Git whole:
// await api.gfRun("accept",{callKey:"launchd-diag-start-r1"});
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
