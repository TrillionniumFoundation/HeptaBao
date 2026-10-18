# AuthBus R5 SDK storage extension — 2026-10-18

This extension follows the frozen `authbus-r5-overlay.json` (SHA256
`33b81238daed4153cb8cf348a0b0741951c570402e84a03b334227621444aa11`).
The original overlay remains unchanged. The actual host tunnel is disconnected;
no installed SDK import, native HeptaBao test, or new host result is claimed here.

## Reviewed SDK write boundary

The first registry candidate called `upsertAuthProfileWithLock` directly. Its
OAuth-specific external CLI synchronization behavior was not yet inspected.
The SDK extension replaces that implicit writer with a bootstrap-bound
`commitCredential` function. Product requests cannot choose a writer.

`authbus_refresh_store_sdk_candidate.mjs` adds one export to the existing,
exact-hash-bound `dist/profiles-DyU-YCq2.js` module:
`heptaBaoCommitManagedOAuthCredential`.

The new export uses `updateAuthProfileStoreWithLock`, whose name and calling
contract are already present in the preserved R4 `setAuthProfileOrder` source
patch. It is a new candidate export, not an assumed installed SDK API.

The updater:

- Explicitly passes `filterExternalAuthProfiles: false` and
  `syncExternalCli: false` to the existing SDK transaction.
- Compares the expected previous credential digest inside the locked updater.
- Modifies only the selected profile in the current store; it does not write a
  whole stale store supplied by the caller.
- Captures the target directory, profile, expected digest and cloned new
  credential before waiting for the lock.
- Rejects cross-provider replacement and invalid OAuth input.

This closes a concrete stale-write gap and makes the external synchronization
choice explicit. It still requires actual SDK execution to establish that the
frozen SDK honors the transaction options in this OAuth path.

## Offline work actually completed

- Node syntax checking for the new overlay module, revised registry, and actual
  SDK storage runner.
- Node syntax checking of the generated export code itself, not only the string
  template that generates it.
- Python bytecode compilation of the static source-inspection helper.
- The existing synthetic TLS/process R5 regression was rerun with the revised
  bootstrap-bound commit interface. Its exact result and source hashes are in
  `refresh-r5-contract-receipt.json`.

The generated export was not imported into the actual SDK because its host is
unavailable. No actual SDK result is inferred from these checks.

## Connection-recovery continuation

The previously observed SDK root is:

`/home/qian-qi/heptabao-next-gates-20261017/authbus-admission-sdk-20261018-01/openclaw`

After transferring the original R5 overlay and this extension into an isolated
HeptaBao source tree, first inspect the required SDK code without executing it:

```bash
python3 /ABSOLUTE/ISOLATED/SOURCE/qa/openbao-acceptance/authbus/inspect_authbus_sdk_refresh_sources.py \
  --sdk-root /home/qian-qi/heptabao-next-gates-20261017/authbus-admission-sdk-20261018-01/openclaw \
  --output /ABSOLUTE/NEW/OUTPUT/authbus-r5-sdk-source-inspection.json
```

The output must be new and its parent directory must already exist. This reads
bounded `.js`/`.mjs` SDK code and package metadata only. Discovery starts at the
three frozen R4 boundary files and follows relevant static imports within the
24-file, 8 MiB total source, and 1 MiB per-file limits. It does not scan all of
`dist`; modules outside that import graph remain uninspected. It does not import SDK
code, read credential files, contact services, or modify installed files. The
receipt reports all three R4 baseline hashes and any unresolved external imports.
Review the returned OAuth manager/provider imports before adding refresh hooks;
no unobserved import name has been invented in this extension.

Then execute the actual SQLite owner test on a supported Node runtime, with a
new work directory under an existing parent:

```bash
node /ABSOLUTE/ISOLATED/SOURCE/qa/openbao-acceptance/authbus/authbus_refresh_sdk_store_live.mjs \
  --openclaw-root /home/qian-qi/heptabao-next-gates-20261017/authbus-admission-sdk-20261018-01/openclaw \
  --work-dir /ABSOLUTE/NEW/OUTPUT/authbus-r5-sdk-store-01
```

The runner:

1. Installs disposable exact-source module hooks and imports the actual SDK.
2. Seeds only synthetic OAuth credentials in a new scoped SQLite database, with
   external synchronization explicitly disabled.
3. Tests the new locked commit, fresh readback, preserved unrelated profile and
   selection metadata, and stale-digest/cross-provider rejection.
4. Creates real SQLite abort triggers, attempts a changed credential write,
   requires rejection and unchanged data, removes only its own triggers, and
   verifies a successful subsequent commit.
5. Blocks all network and child-process creation, blocks writes outside its
   fresh fixture, rejects fixture symlink writes, and blocks reads of other
   home-directory content outside the SDK root.
6. Verifies the installed SDK bytes remain unchanged and writes a public receipt
   containing no credential values.

If a source hash, private fixture boundary or SDK behavior differs, retain the
failure receipt and inspect it. Do not disable the boundary to obtain a pass.
These checks do not require a production service restart or credentials.

## Still open after the storage runner

A successful storage receipt will qualify only the scoped actual SDK/SQLite
commit path. The shared OAuth manager and final provider dispatch still need
exact-source hooks, realistic response-loss/crash tests and every caller entry
checked. R5 must then run against an isolated native HeptaBao TLS/AppRole/KV2
backend with restart and multi-host CAS evidence. Production bootstrap,
per-host real credential migration and OpenBao removal remain separate work.

## Actual SDK follow-up: first attempt and return-contract repair

On 2026-10-18 the main host connection recovered. The bounded inspector read
15 code files (210,424 bytes); all three R4 boundary hashes matched. The runner
then imported the actual SDK 2026.7.1-2 on Node v22.23.3, created a new SQLite
fixture and reread its synthetic OAuth seed. The next check failed: the bridge
returned the SDK store object while the coordinator requires a strict boolean.
The original failed receipt is retained as
`qa/openbao-acceptance/authbus/refresh-r5-sdk-actual-before-return-fix.json`.

The observed SDK transaction returns a store even when the updater makes no
change, and returns null after a caught transaction error. The repaired bridge
tracks whether its locked updater accepted the expected prior digest, then
requires the returned store to contain the exact successor credential digest
before reporting true. A no-op or failed transaction reports false. The exact
SDK source bindings and external synchronization restrictions remain in place.
This repair still requires a new actual-SDK fixture execution; the first failed
attempt must not be reclassified as passed. No real provider refresh or native
HeptaBao backend was used in this first attempt.
