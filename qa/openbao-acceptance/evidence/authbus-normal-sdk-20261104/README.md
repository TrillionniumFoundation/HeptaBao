# Normal storage with the original installed AuthBus SDK

The fresh ROG run used normal source `33cafa4c6e29f0bde1553e041550d21b4c725d9c`, tree `cdc2376e7b39c1d8bbbeb10a813d58bfe923f336`, server SHA256 `7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`, configured `native_v6_file` and the public `sys/storage/native-v6/activate` route. Default features and the original optimized release profile were retained. No fixture option was passed.

The driver is published as `qa/openbao-acceptance/native_v6_authbus_coordinator_normal_live.py`. Its byte-exact contents (SHA256 `d67736322a29f5daad0eb657007f56b4922c727cdf7188e5a5f3a49fd17afa65`) were executed from the owned control directory under the original basename. The original fixture driver remains unchanged. The consumer is the existing exact `native_v6_authbus_coordinator_consumer.mjs`, SHA256 `069ac45973b28918dfe970e628ab3a56d8253ee697b09bb16e92452fbb7966e4`.

Only normal server startup/configuration and activation were adapted. The original worker is AST-identical; the complete original run steps/assertions are AST-identical after reversing those two entrypoint substitutions. The original HTTP 10-second, readiness 12-second and child-worker 75-second budgets are retained. The pre-execution adapter receipt remains historical with `runtime_executed=false`; the later result/outer/root-review are the execution evidence.

## Actual result

The run completed 314 dynamic checks in 19.109 seconds, terminal exit 0, with no remaining owned process. Ten actual installed SDK/plugin consumer processes exercised eight successful cases and two expected denials. The installed SDK was 2026.7.1-2; the production plugin and all seven dependency hashes were unchanged. Fifty positive observed HTTPS exchanges used a new full TLS handshake with exact CA/leaf checks. Credentials and SQLite databases were created only in the fresh fixture.

The actual producer emitted inbox events; the independent coordinator required an exact seven-field operator grant before immutable credential and CAS manifest publication; the actual follower consumed the resulting credentials. Real competing CAS, exit 73 after an acknowledged manifest commit, normal server SIGKILL/cold restart and read-only history recovery established no manifest replay. The complete SQLite backup/restore and wrong-CA binding rejection/reversal also passed. Twenty-one issued tokens were revoked and denied again after a second cold restart; three SecretIDs were destroyed, and the original follower login was denied. A real renew-self preserved its bearer; the harness made only the client local due clock advance and did not wait for the full lease to expire.

SDK source review confirmed the exact upsert interface disables external CLI synchronization. The fixture verifies its default agent and SQLite paths. Three finite production files (OpenClaw main configuration and native Codex auth/config) retained their exact before/after hashes. This is the observed finite scope, not an inventory of every production file.

## Scope that remains open

This is a **direct core API** execution. It does not execute the installed entry, a ROG service manager or production traffic. The X230 installed-entry system-manager result is separate evidence and must not be combined into an unexecuted end-to-end claim. All provider credentials here are synthetic; no provider request, OAuth refresh, J3160 contact or enforced scheduler qualification occurred. Actual installed-entry/SDK composition and per-host production configuration/restart/rollback remain separate gates. No old assets were removed.

The three reviewed installed SDK source pins are recorded in the outer result; third-party source bytes are not republished. Full byte-exact public reports and the independent root review accompany this file.
