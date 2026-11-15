# Read-only source inspection and local private export

`authbus_sdk_owned_source.mjs` uses the original installed OpenClaw
`2026.7.1-2` SDK. It checks the exact previously reviewed SDK store, SQLite,
source-normalization, scope and public API files before import. It supports two
operations in a disposable Node process. It does not alter installed code.

## Inspect

Write a mode-0600 configuration file on the same source host. All agent
directories must be explicit, existing directories owned by that user, and all
their SQLite files must already exist. Include the actual SDK default agent;
the reader rejects unlisted inherited owners.

```json
{
  "schema": "authbus-owned-sdk-source-v1",
  "mode": "inspect",
  "hostId": "main",
  "stateDir": "/home/qian-qi/.openclaw",
  "configPath": "/home/qian-qi/.openclaw/openclaw.json",
  "sdkRoot": "/home/qian-qi/.npm-global/lib/node_modules/openclaw",
  "agentDirs": ["/home/qian-qi/.openclaw/agents/main/agent"],
  "outputDir": "/home/qian-qi/heptabao-next-gates-20261017/sdk-owned-source-main-inspect-r1"
}
```

Run the host's actual Node executable with one argument:

```text
/usr/bin/node <path>/authbus_sdk_owned_source.mjs <path>/source-config.private.json
```

Mac uses `/opt/homebrew/bin/node`, its own home and
`/opt/homebrew/lib/node_modules/openclaw`. The output directory must be new,
outside every production state/store and SDK directory, with an existing owned
parent. The script creates it mode 0700 and writes its receipt mode 0600.

The public receipt contains provider/type, credential field names, hashes of
profile IDs, credential and identity digests, expiry metadata, source owner
database paths, and the actual SDK's inherited-owner result. Source credentials
are read in memory through `loadAuthProfileStoreWithoutExternalProfiles`,
`resolvePersistedAuthProfileOwnerAgentDir`, and
`findPersistedAuthProfileCredential`; their values do not appear in receipts.
The SDK's real SQLite adapter uses `DatabaseSync({readOnly:true})`.

The process sets `OPENCLAW_AUTH_STORE_READONLY=1` before import. It blocks normal
network paths, child processes and JavaScript filesystem mutation methods while
reading. It captures SDK stdout/stderr privately throughout the process and
emits only its own fixed public result. No `resolveApiKey`, OAuth refresh,
external CLI import, `ensure`, `save`, or provider API is invoked.

## Export selected, unchanged owner records

Create a second configuration with `mode: "export"` and a different new output
directory. Keep the same host/state/config/SDK binding and add:

```json
{
  "inspectReceiptPath": "/path/to/inspect-r1/public-receipt.json",
  "inspectReceiptSha256": "<exact SHA-256 returned by inspect>",
  "selection": [
    {
      "scopeAgentDir": "/exact/inspected/scope/agent",
      "ownerAgentDir": "/exact/inspected/owner/agent",
      "profileIdSha256": "<exact inspected hash>",
      "credentialDigest": "<exact inspected digest>",
      "identityDigest": "<exact inspected identity digest>"
    }
  ]
}
```

Each selected record must match both the earlier inspection and a fresh
effective-store/persisted-owner read. Multiple agent views of the same owner
record cannot create duplicate exports. A mismatch between an inherited OAuth
record and its persisted owner blocks that export. The script rechecks selected
owner digests before and after writing the private candidate. If the post-write
check detects a change, it removes only its own newly created candidate and
returns failure.

`candidate.private.json` contains the original profile IDs and credentials and
must remain on that host. Only its path, digest and count may be returned to the
controller. This is a source snapshot. It establishes no provider liveness,
refresh ownership, production cutover, or future protection against credential
rotation. Recheck the source before publishing it to a new AuthBus.

## Local validation

```text
node qa/openbao-acceptance/authbus_sdk_owned_source_contract_test.mjs
```

This synthetic test exercises the exact selection/ownership logic and network,
write and child-process guards. It explicitly does not claim actual installed
SDK qualification; that requires executing the inspector against the intended
host's hash-bound SDK and explicit stores.
