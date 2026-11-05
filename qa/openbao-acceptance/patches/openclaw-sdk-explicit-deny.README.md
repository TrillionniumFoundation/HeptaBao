# Isolated SDK explicit-deny candidate

This is a review candidate and a real-SDK regression. It does not install a
plugin or SDK, change the production gateway, enable enforcement, or replace
the AuthBus coordinator. Main's observed production settings remain shadow
with refresh-lease enforcement disabled.

## Which layer owns the defect

The installed OpenClaw resolver already returns no profile when the selected
provider has a present, empty order array. Two SDK persistence functions lose
that state: `pruneAuthProfileStoreReferences` discards the empty provider entry
on save, and `normalizeAuthProfileOrder` discards it on load. A missing order
permits fallback to other configured or stored profiles.

The existing `setAuthProfileOrder({ order: [] })` API intentionally clears the
override. That behavior must remain compatible. The candidate adds an opt-in
`explicitDeny: true` operation that requires the caller's original argument to
be an empty array. Missing values, malformed values, nonempty lists, and lists
whose entries would be trimmed or pruned away cannot become an explicit deny.

The operation changes only the selected provider's order and last-good
metadata under the SDK's existing SQLite write transaction. It clears aliases
of that provider, writes the canonical empty order, and removes its last-good
pointer. It leaves credential records and other providers intact. The plugin
candidate uses this operation instead of saving an entire caller snapshot,
which avoids losing an unmanaged profile added after that snapshot was read.

The persistence changes retain only originally empty arrays. A nonempty list
whose references are all pruned keeps the previous clear/fallback behavior.

## Review files and source binding

- `openclaw-sdk-explicit-deny.patch`: three SDK module changes.
- `openclaw-authbus-atomic-deny.patch`: the small plugin delta applied **after**
  `openclaw-authbus-lease-deadline.patch`.
- `../authbus_sdk_explicit_deny_candidate.mjs`: exact source SHA checks and
  deterministic transformations for those same changes.
- `../authbus_explicit_deny_sdk_live.mjs`: isolated actual-SDK execution.

The SDK source SHAs are:

| Installed module | SHA-256 |
| --- | --- |
| `dist/store-DH33UrUj.js` | `25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf` |
| `dist/source-check-ZSz5NzGW.js` | `9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9` |
| `dist/profiles-DyU-YCq2.js` | `075f9d6ecd43103c32a6908816bf42720076fd0aaedb2b5e7e96481d64a29ba5` |

The loader uses Node's synchronous module hooks to substitute exactly these
three source modules inside each disposable process. Every other SDK module,
SQLite adapter, transaction, and resolver is the actual installed code. It
verifies that all three candidates loaded and that the installed files remain
unchanged. The program fails if the runtime lacks the hook API.

The original production plugin remains bound to SHA-256
`b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b`.
The input deadline candidate remains bound to
`b59c461e710d12f1c2f85ed7f3a32f14c05818a491b55bdee8f597e7bf4588fc`.
The generated atomic-deny plugin candidate is
`6b3258940a325cdbb15edf705f951b8ad0ee8723e666935872cbb359c1e3ce41`.

## Run in a new isolated directory

Upload both `.mjs` files next to each other and the existing deadline candidate
to a private tools directory. No SDK copy or production patch is required.

```text
/usr/bin/node /path/to/tools/authbus_explicit_deny_sdk_live.mjs \
  --work-dir /home/qian-qi/heptabao-next-gates-20261017/authbus-sdk-explicit-deny-r1 \
  --openclaw-root /home/qian-qi/.npm-global/lib/node_modules/openclaw \
  --original-source /home/qian-qi/.openclaw/extensions/openclaw-authbus/index.js \
  --deadline-candidate /path/to/tools/authbus-index.lease-deadline-candidate.js \
  --lease-helper /home/qian-qi/.openclaw/extensions/openclaw-authbus/lease-assignments.js
```

The directory must be new. The runner creates six separate Node processes with
new or reopened private SQLite stores. HTTP, HTTPS, fetch, and socket connect
are disabled before importing the SDK. Credentials are synthetic. Each child
has a 45-second deadline and a bounded captured output buffer. Reports contain
only case names, counts, hashes, and qualification flags.

The phases reproduce the original failure, verify explicit SQLite denial and
legacy API compatibility, expire same-epoch grants, reject deadline extension
and lower epochs, test local expiry without a control document, preserve a
new unmanaged credential despite a stale caller snapshot, and reopen the
persisted deadline and expired tombstone in fresh processes. Assertions inspect
both SQLite's raw `state_json` and the actual resolver; a returned in-memory
store is insufficient.

## Revocation write failure remains a separate admission gate

The final two processes install a trigger only in the disposable database that
raises a real SQLite `ABORT` on the runtime-state upsert. This forces a
revocation transaction to fail. The regression checks that the operation
reports failure, does not acknowledge the new epoch, does not partially clear
last-good metadata, and does not delete unmanaged credentials. It also invokes
the actual resolver in that process and a new process while the failed state
and trigger remain. After observing the result, it drops the fixture trigger
and checks real revocation recovery.

Returning an error is insufficient to claim failure closed: an independent
gateway can still select the old persisted grant. The runner sets
`revocationFailureClosed` only if both real resolver observations deny use.
Otherwise `ok` stays false and exit status is 3, with the explicit blocker
`failed_revocation_does_not_close_gateway_admission`. The storage and lease
repair results remain separately available in
`explicitDenyAndLeaseRepairPassed`.

No credential deletion, fabricated empty resolver result, mocked SDK, or
permissive test expectation is used to hide this remaining failure. A stronger
production solution needs an actual request-admission check using durable lease
authority, including the accepted deadline and revocation state. The polling
plugin's error alone cannot provide that authority.

The cold tests fsync their fixture fence records between processes. They do not
certify atomic publication across the production plugin's separate fence file
and the SDK database, exact-deadline request admission, existing in-flight
operations, external environment credentials, or other independent writers.
`hardPerRequestDeadlineQualified` remains false throughout.
