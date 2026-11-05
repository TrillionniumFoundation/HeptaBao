# Three additional exact HTTP regressions

This is a small local execution adapter, with no product changes. It runs the
three HTTP R1 cases independently after the original host cohort has completed.
The original 55 Rust selections and 31 full34 checks are unchanged. Successful
execution of this adapter is evidence for three additional local Rust fixtures;
it is not evidence for the remaining full34 driver stages or LAN cutover.

## Reuse and artifact custody

The original 55 build already compiles the entire server libtest, including the
two newly added HTTPS tests and revised framing test. The adapter therefore
issues no Cargo command. It executes that exact existing libtest in its package
working directory. This avoids recompilation and preserves the original build
profile.

The adapter imports only explicitly verified bytes. It uses the candidate's
manifest-bound `native_candidate_host_run.py::verify_tree` and the already
verified R3 `native_service_only_compile.py` functions `acquire_target_lock`,
`run_logged`, `write_json`, and streaming SHA256. The R3 lifecycle keeps the
original child unreaped until it observes the owned group, handles the observed
Darwin zombie boundary, and refuses to start subsequent commands after an
unresolved cleanup. No process-management implementation is copied or altered.

The known R3 helper is 24,473 bytes, SHA256
`44468fb6de4eea5ea74852f1e7c7cf86d3326fcae3a67f0ca10409a72db765c4`,
Git blob `530ac880fa01c77f81c8d89f7013d48c5e2b8f75`. Its native-only `main` and
hardcoded source identity are not called. Its native-only compiler cfg parser
is not overridden: direct libtest execution emits no compiler invocations.
The actual compiler profile is instead checked against the original producer
command, explicit profile pin and retained version/build logs.

The source and libtest hashes are checked before and after all three cases,
while holding the original nonblocking exclusive
`heptabao-owned-candidate-run.lock`. A busy target starts no command and does not
truncate the prior owner's lock receipt. Input pins are checked again under the
lock and at completion. The runtime environment contains only the fixed PATH,
locale, one-thread setting and owned temporary/package directories. No real
credential or production endpoint is supplied.

## Exactly three cases

| Label | Exact Rust function |
| --- | --- |
| `snapshot-json-accept-history` | `http::snapshot_accept_tests::native_snapshot_https_json_accept_download_restore_and_cold_keep_exact_history` |
| `snapshot-json-accept-refusals` | `http::snapshot_accept_tests::native_snapshot_https_json_accept_keeps_actor_namespace_seal_and_archive_refusals` |
| `snapshot-json-accept-framing` | `http::snapshot::tests::binary_route_only_supports_chunking_and_snapshot_accept_remains_binary` |

Each case first executes `[libtest, exact_name, --exact, --list, --color=never]`.
Discovery must contain exactly that full name and the actual footer
`1 test, 0 benchmarks`. It then executes
`[libtest, exact_name, --exact, --nocapture, --test-threads=1, --color=never]`.
Every command retains the original independent 1,800-second budget. A passing
run requires the same observed full name, `running 1 test`, one terminal
libtest summary, exactly one pass and zero failures, ignored tests or measured
benchmarks, successful exit, and completed owned-group cleanup. Zero-test,
duplicate, wrong-name, ignored or missing-terminal outcomes cannot pass.

## Explicit invocation

Populate `native_snapshot_http_exact_run.config.example.json` from the exact
completed cohort. The example is intentionally invalid until its placeholders
are replaced. Supply the full `compiler_resource_profile` object from the
producer summary, including observed CPU/resource fields; do not leave `{}`.

The config explicitly supplies the candidate commit, tree, manifest SHA256,
source path, original host-runner SHA256, warm target path, completed producer
summary SHA256, actual compiled libtest path/SHA256, compiler paths and profile,
owned-process helper path/SHA256, and a new output directory. Its own SHA256 is
also supplied on the command line. No future commit is embedded in the adapter.

```sh
python3 /absolute/path/native_snapshot_http_exact_run.py \
  --config /absolute/path/additional-http3-config.json \
  --config-sha256 ACTUAL_CONFIG_SHA256
```

The libtest path must equal the unique `Executable unittests src/lib.rs (...)`
line in the SHA-bound `compile-server-tests.log`, and must be inside the exact
target's `debug/deps` directory. The compilation argv must retain the original
`cargo test --locked --offline -p heptabao-server --lib --features
experimental-native-v6-ha,private-ha-forward-diagnostic --no-run` profile.
Actual retained Cargo and rustc version logs must show 1.98.0. The completed
summary must bind the same source, manifest, before/after full tree, original
17 groups totaling 55, producer hostname and machine. Its original overall
status is preserved; this adapter never upgrades an earlier failed cohort.

This entry is for the same physical producer and existing target. It does not
claim transferred-artifact execution on X230; that has a separate explicit
producer/executor receipt. It can be invoked outside the candidate source tree
after the candidate is compiled, so adding this QA file need not delay or alter
that in-progress candidate's exact tree. Persisted evidence must retain the
actual tested source identity, even if stored by a later Git commit.

## Output

The new output directory retains six full command logs when all discovery and
run commands occur, per-command argv/PID/PGID/SID/exit/deadline/cleanup and log
SHA256, source before/after closure, libtest before/after SHA256, explicit build
profile, actual uname, per-case observed names/counts, and final status in
`summary.json`. An `inputs` directory retains the exact supplied config,
producer summary and original compiler/version logs. A failed discovery skips
that case's run, is recorded as blocked, and cannot pass the three-case gate.
Unresolved process cleanup stops further commands and retains the uncertain
owned PID evidence for reconciliation.

## Actual local verification and limits

The final adapter was checked by seven local Python tests on 2026-10-19. They
exercise count/name refusal, source/profile/producer binding, ambiguous artifact
logs, changed pins, changed binary rejection before any process starts, busy
target preservation, and a real owned short-lived Python child's cleanup.
All seven passed. The final local child receipt records a reaped leader, no
signals and an observed group with no live members.

The initial default-sandbox execution was 6/7: `/bin/ps` returned
`fatal library error, lookup self` during the owned-process check. That original
failure and the focused diagnostic are retained. Running the same assertions
in the approved local process environment passed; no helper or product check
was weakened to obtain the result.

Local checks use explicitly synthetic producer metadata and never execute the
synthetic artifact. They do not claim that any of the three Rust regressions,
the new candidate, full34 snapshot round-trip, or LAN path passed. Those actual
HTTP test results remain pending the parent's physical execution.
