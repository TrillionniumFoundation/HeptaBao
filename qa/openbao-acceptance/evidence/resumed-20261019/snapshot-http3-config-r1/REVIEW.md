# Preparing the additional HTTP3 configuration

`prepare_snapshot_http3_config.py` is separate from the frozen HTTP3 runner.
It supplies a concrete way to find and pin the original compiled libtest after
the original 55 has completed. It starts no process and changes neither the
target nor the original host receipt.

The input schema explicitly carries the candidate source/commit/tree/manifest,
manifest SHA256, host-runner SHA256, existing target, completed producer summary
SHA256, owned-helper SHA256 and future new HTTP3 output directory. The adapter
path and SHA256 are also explicit command arguments. No source commit is
inferred from this preparation script or embedded in it.

The preparation script checks the producer's `compile-server-tests.log` against
the SHA256 in the pinned summary. It requires exactly one
`Executable unittests src/lib.rs (...)` line whose absolute path is a regular
executable inside the original target's `debug/deps` directory. Under a
nonblocking shared lock on the existing target lock file it hashes that exact
libtest twice. It copies the actual compiler paths and complete resource
profile from the verified producer summary. The full config then passes the
frozen adapter's `load_context` checks and its candidate's full `verify_tree`.

The shared lock is opened read-only and is never created or truncated here.
An active original 55 owner causes refusal before any new config is written.
The original lock receipt must remain byte-identical. The new config and a
separate preparation receipt are created exclusively outside source and target.
This command does not run the HTTP3 tests. Source/artifact identities will be
checked again under the runner's exclusive lock when those tests execute.

```sh
python3 /absolute/prepare_snapshot_http3_config.py \
  --adapter /absolute/native_snapshot_http_exact_run.py \
  --adapter-sha256 53cc6423e54aee23b33e85fb9746042ba3a7a507633ab24525469276db63bd4e \
  --input /absolute/preparation-input.json \
  --input-sha256 ACTUAL_PREPARATION_INPUT_SHA256 \
  --config-out /absolute/new-http3-config.json
```

Read the generated config and its `.receipt.json`. The latter contains the
actual `config_sha256`, libtest path/SHA256, full source verification, and the
zero-process preparation scope. The execution command is then:

```sh
python3 /absolute/native_snapshot_http_exact_run.py \
  --config /absolute/new-http3-config.json \
  --config-sha256 GENERATED_CONFIG_SHA256
```

Local verification exercised two real filesystem cases with explicitly
synthetic build metadata: successful path/hash/profile derivation and refusal
while an exclusive target owner holds the lock. Both passed. The synthetic
artifact was never executed; these are configuration checks, not Rust tests or
remote acceptance evidence. The frozen R1 adapter and its 7-check receipts are
unchanged, as are the original 55/31 selectors and budgets.
