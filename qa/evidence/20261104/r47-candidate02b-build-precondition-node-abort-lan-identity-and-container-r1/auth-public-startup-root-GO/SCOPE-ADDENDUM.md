# Scope clarification from exact cycle source

Cycle source 9bbc3d403a4fb65176e9398cc71ef2464f94dc5a (24012 / f57fb90955342ecbbc6e8d5423d99f16bdd51dfe7a1d23076f8b78016a78837b) has static imports on lines 7–16, in-memory report initialization on line 23, try on line 79, and its only stdout report on line 382 after catch/finally. It has no process.abort or process.exit call; line 383 sets exitCode to 0 or 1.

Therefore old empty stdout and worker_report_unavailable do not prove that the old cycle stopped at startup/imports, and do not prove SDK or business code was never entered. A fatal interruption anywhere before the final report can produce this observation. No public standalone worker-report file is written by cycle; its save targets are private custody/baseline/candidate/rollback artifacts.

The new public probe is a bounded diagnostic of a prerequisite, not a claimed reconstruction of the old failing location. It never calls the original cycle, CAS functions, SDK, providers, or databases. Passing it would leave the old SIGABRT cause and any unobserved old cycle effects unknown.

The contract's ownDirectPopenEntries=2 is an upper bound: one volume helper and one sandbox/Node child if all preceding steps succeed. Internal ps subprocesses from the unchanged custody helper are separately acknowledged; this number is not an actual execution count.

The first local diff-check invocation used the helper's object return as a string. Its exact error note is retained; the note itself suggested .text, and the correction records the actual .raw property. Only the checker call changed. No source/request/Native action resulted.

This companion records the actual deterministic 110-check V8 comparison result and exact executable verifier interface. No Python syntax execution, Node imports, component runtime, or Native request occurred.
