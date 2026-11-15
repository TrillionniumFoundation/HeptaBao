# Native-Service-only compile controller, R1

## Fixed execution source

- Commit: `9770bdd4ca77aa832ec8083a054760637e92cfa1`
- Tree: `f32f1acf9a794844719b6df225df3d23f2389e02`
- Complete source files: 2979
- Manifest SHA256: `9e167d20256e2d59c9ce57c73b90a0976403cf7a20db3e1d6b5de011c9d3cb0c`
- Controller SHA256: `f2ff71ec7f7088b0bbc7282bbad2aded47a518c0a0fa4298ad834857299597ea`

The controller is copied outside this source tree and takes its actual source,
manifest, output, Cargo, rustc, Cargo home and warm target paths as absolute
arguments. It has no source-identity override. Publishing this controller in a
later Git commit does not change which source it is allowed to compile.

## Execution contract

The target must already exist. The controller acquires the exact same
`heptabao-owned-candidate-run.lock` as the physical 55-test runner, exclusively
and without waiting. A busy lock is a recorded refusal before any child command;
the previous owner's lock receipt remains untouched. The target lock stays held
through the final source verification and summary publication.

The manifest's byte hash, commit, tree and file count are checked first. The
controller then authenticates the candidate's `native_candidate_host_run.py`
against its manifest Git blob, loads those exact bytes without creating source
`__pycache__`, and calls that runner's unchanged `verify_tree` before and after
the commands. Source, output and target directories must be disjoint.

The substantive commands are exactly, in order:

```text
cargo check --locked --offline -p heptabao-server --no-default-features --features fixture-native-v6-service --lib --bin heptabao-server --verbose
cargo test --locked --offline -p heptabao-server --no-default-features --features fixture-native-v6-service --lib --no-run --verbose
```

Each has its independent original 1800-second budget. There is no deadline
override argument. The controller first records the actual Cargo and rustc
verbose versions with bounded metadata commands and requires 1.98.0. It uses
the same environment sanitation and compiler resource settings as the existing
host runner. `--build-jobs` is explicit: use 2 for the approved Mac profile and
8 for the approved main Linux profile. The code does not select a peer package,
workspace, all features, tests to execute, or a server to start.

The approved warm targets reported by the physical-host coordinator are:

- Mac: `/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017/target`
- Main Linux: `/home/qian-qi/heptabao-next-gates-20261017/native55-target-20261019`

The caller supplies the already verified actual source/manifest/Cargo-home
paths from that host's receipt. No host path is inferred from an alias.

## Evidence and cleanup

Every command records exact argv, start/end time, budget, actual exit code,
raw combined stdout/stderr bytes and SHA256, owned PID/PGID/SID, and cleanup
observations. Raw command logs have no synthetic header prepended.

The controller leaves the session leader unreaped until it has observed and,
when needed, stopped its original process group. Linux uses WNOWAIT; Darwin
may use a bounded ps observation instead. No Popen poll/wait occurs before the
last group signals. TERM and KILL cleanup retain the original bounded 5-second
phases. It never signals a numeric group after reaping the leader. Failure to
prove cleanup prevents later commands from starting. The receipt separates
leader reaping from absence of live original-group members. It makes no claim
about arbitrary processes that escaped to another session.

An exited leader with a remaining live child causes a failure receipt even
when the leader returned zero. Expected test failure, timeout, interruption,
source mismatch and target contention remain failures or refusals; no command
is automatically replayed. A normal first compiler error may be followed by
the distinct second compile command, retaining both outcomes. Timeout or
unresolved child cleanup stops the sequence.

Cargo verbose root compiler argv is parsed by active `--cfg` arguments.
`--check-cfg` lists of declared feature names are deliberately not mistaken for
enabled features. An observed server feature set other than exactly
`fixture-native-v6-service` fails. If Cargo reports only cached Fresh targets,
the receipt explicitly leaves `root_rustc_cfg_observed=false`; it does not claim
that a compiler invocation absent from the log was observed.

## Scope of a successful controller receipt

The first command checks production library and binary-target cfg; it does not
link a new executable. The second compiles the unit-test target without running
it. R4's native Auth and Engine clock inheritance, Control Groups clock method,
single-node snapshot projection and test-only observer can therefore be checked
without enabling experimental HA or private forwarding diagnostics.

This is an additional compile receipt. Rust tests executed remain zero, and the
existing physical cohort remains 55. No HeptaBao process, network test, real
credential, cutover or replacement claim is produced by this controller.

## Local boundary checks performed

The same controller bytes were checked in six local cases: busy-lock receipt
preservation and later acquisition; changed-manifest refusal before runner
loading; real child stdout/nonzero exit/reaping; a zero-exit leader leaving a
live same-group child; a real child ignoring TERM until KILL after a short
fixture-only timeout; and active cfg versus declared check-cfg separation.

The first local attempt retained three successful checks and three process
observation errors. This tool's default PID namespace caused ps to return
`fatal library error, lookup self`; the controller refused to claim cleanup.
The unchanged controller was then run with a normal local process view after
automatic tool approval. All six cases passed. The second run's real process
receipts include both original-group observations and leader reaping.

Original first summary: 448 bytes, SHA256
`04eb78b10daaa6e2ae627e01391ae3a0e251a13cd69776f448bf65d619a6b630`.

Successful second summary: 472 bytes, SHA256
`e9dc951fe66b5cc00154f3bdc3fc49c28049f7c26f9be55fa8ac90ad5e945350`.

These are local synthetic controller checks. No Rust compilation or remote
execution was performed by the author, and they do not add six product tests.
