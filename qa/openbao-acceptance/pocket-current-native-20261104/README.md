# Pocket4 current native consumer evidence (2026-11-04)

This is a frozen, host-bound QA publication packet. It contains source and public receipts only; it contains no credentials, SQLite payloads, private plans, server data, or binaries. The original private runtime inputs remain on their owner host.

## Proven scope

Normal HeptaBao commit 33cafa4c6e29f0bde1553e041550d21b4c725d9c, tree cdc2376e7b39c1d8bbbeb10a813d58bfe923f336, Linux binary 7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba. Native build receipts are included separately from the older 36076 helper provenance. QA helper bytes do not become part of the compiled server commit.

Current Pocket4 OpenClaw 2026.7.1-2, AuthBus 0.3.3, Codex plugin 2026.7.1-1 and actual managed native runtime 0.144.3. Both configured agents main and tg8687951891 select the exact current ordinal5 through actual registry -> actual default native selector -> actual native factory. No provider/profile/runtime alias or override is used. Native initialize and account/login/start return real original responses; login response type must be chatgptAuthTokens.

- Full-current baseline: core 49/49, initial 111/111, cold 111/111, initial rollback 80/80, cold rollback 80/80. Import is honestly idempotent.
- Owned missing-current-ordinal5 recovery: core 49/49, initial 110/110, cold 110/110, each rollback 80/80. Exact current credential is restored through HeptaBao into main; tg observes inherited effective state. Recovery rollback restores the missing fixture's own baseline.
- Each scope has four actual native factories and eight real RPC responses, zero unknown outcomes, and all owned processes stopped. Production files, hold markers and units remain unchanged.
- TG has one original primary metadata row with zero local profiles and no state row. Zero local profiles never means zero raw table rows.

## Runtime and rollback envelope

The launcher creates a fresh writable run root under bwrap. The root filesystem and production/source/input trees are read-only; the network and PID namespaces are private and --die-with-parent is set. Only the owned HeptaBao loopback is reachable. Native background network attempts are not counted as absent; provider availability and quota are not proven. Budgets remain 10 seconds HTTP, 70 seconds consumer, 35 seconds rollback and 440 seconds outer launcher.

Rollback consumes an attempt guard once, uses the installed SDK's local-store CAS, verifies effective inheritance, then restores complete original auth-table rows and timestamps with raw SQLite CAS. Cleanup always reaps owned groups even if native close fails. The PID namespace contains detached child escape after outer timeout.

## Separate production semantics

The test transport uses an isolated loopback, a private AppRole and fixture control documents. It disables publishNew and uses an isolated managed ordinal5 order for that scope. These are fixture-only values; they are not a production configuration proposal. The production Pocket configuration retains publishNew=true, orderExcludeAgentIds=[main,tg8687951891], shadow scheduling and independent local ordinal5 ownership. Production control-plane inbox/promotion semantics must be reviewed separately before a connection switch. Do not publish the fixture ordinal5 manifest/order to other hosts.

The two old systemd holds were not released; neither a production gateway restart nor traffic cutover occurred. These receipts do not establish HA acceptance, all-client migration, backup migration, legacy cleanup, or full OpenBao replacement.

## Retained failures and replay

The original current-native-full-r1 failed 12/13 before any runtime, because the observer incorrectly equated zero TG profiles with zero raw rows. The correction pins the exact original primary row and keeps both logical and raw CAS. Its failed receipt and correction receipt are included. An earlier prepare error assumed the platform npm package version lacked its linux-x64 suffix; the actual native handshake remains 0.144.3.

Original run directories are sealed evidence. The frozen launcher intentionally accepts only the executed r2 names and fails if they already exist. Do not reuse them or bypass their existing state. Any repeat needs a new explicitly reviewed launcher/input binding; preserve all original code, budgets, assertions and failures.

The older helper manifest is included byte-for-byte, together with its exact source/public-receipt dependencies. Installed SDK/native/plugin source files are represented by hashes, not copied into this packet. Do not distribute private runtime selection packets or auth-table captures with it.
