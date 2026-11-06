# Current Mac gateway registration source chain

These are complete public files read from the currently installed Mac OpenClaw package, together with the original independent file-read responses. Whole-file sizes and SHA256 values were checked. Multi-file reads are not an atomic snapshot. No live configuration, credential, profile ID, credential digest or private argument was exported.

## Established source path

The registered gateway's previously observed `dist/index.js` entry reaches `cli/run-main.js`. Its gateway fast path imports `run-command-DtjbCDeW.js`, which reexports `run-command-BndCI7AS.js`; that command calls `run-CSvF3r1e.js`. Pre-bootstrap invokes execution bootstrap with plugin loading disabled. The real command subsequently imports `server-BnSQQ3Aa.js`, whose lazy target is `server.impl-qYPVZMND.js`.

Normal server startup, including its deferred startup phase, reaches `server-startup-plugins-CaPrk84k.js`, `server-plugin-bootstrap-CtU_XTUf.js`, `server-plugins-XoQmHCe9.js`, and `loader-D8d2EvVh.js`. The latter executes the original plugin registration plan and activates the registry and global hook runner. `library-CqCP71YW.js` is retained as a checked alternative branch; it is not substituted for the gateway fast path.

The public AuthBus manifest has `activation.onStartup: true`, no channel declaration and no setup entry. The original loader returns a null registration plan when the effective enable state is false, records that plugin as disabled and continues before loading its module or calling its register function. The actual manifest parser, active registry implementation and global hook runner sources are included for the next isolated qualification.

## Explicit environment selectors

`paths-C6ahtu79.js` reexports the already qualified original path selectors. The global dotenv loader preserves pre-existing process environment values. Config environment application likewise preserves nonempty existing values, except values explicitly identified as lower precedence. The gateway command constructs that lower-precedence set from changes introduced by shell environment fallback. These source facts require a fresh production configuration and argument binding before a real restart; an old file timestamp does not prove the current gateway's in-memory configuration.

## Qualification boundary

This archive establishes source provenance and the reviewed control path. It does not claim that these newly archived modules were imported by an isolated qualification, that the running production gateway loaded a particular configuration, or that its writers have been quiesced. The completed 20-case Mac policy/path qualification is recorded separately. Actual normal-gateway registration and active-memory registry qualification is being prepared separately with a nonempty scope and a harmless positive control. A complete gateway restart, consumer cutover and whole relevant-state rollback remain separate work.

No provider request, production credential write, service mutation or J3160 interaction was performed by these fixed public-file reads. The `server-sleep-launchctl-info.original.json` response also retains public `/bin/sleep` and `/bin/launchctl` binary pins for the separate six-action QA-label primitive qualification; those metadata reads did not execute either binary.
