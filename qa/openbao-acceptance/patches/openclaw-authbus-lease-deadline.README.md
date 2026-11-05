# AuthBus lease deadline review candidate

This is a patch for a private copy of the installed OpenClaw AuthBus plugin. It
is **not a production deployment or a completed scheduler qualification**.
The HeptaBao storage and authentication changes do not install this patch.

## Source binding and confirmed failure

The original `index.js` has SHA-256
`b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b`.
Its `lease-assignments.js` has SHA-256
`24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7`.

`leaseAssignmentForAgent` turns an expired ASSIGNED grant into an EXPIRED
projection with null profile, digest and lease ID. `applyLeaseAssignments`
compares that projection against the remembered ASSIGNED state, classifies the
same epoch as STALE, then skips the order cleanup. The remembered state does
not contain the deadline. A local witness executed the exact downloaded
functions with an explicitly identified in-memory SDK double: the initial
grant applied, the expired grant remained selected on repeated cycles, and a
fresh client without the remembered epoch did enter the cleanup branch.

## What the patch changes

- Keep the original normalized grant and its deadline in local epoch state.
  Compare same-epoch wire grants rather than time-dependent projections.
- Reject changes to grant identity, mode or deadline at the same epoch, and
  continue to reject lower epochs.
- Expire remembered grants before network access and before applying a control
  document. A missing document or stale response cannot extend the remembered
  deadline.
- Keep expiration as a tombstone, so a backwards wall clock cannot resurrect the
  same grant. Only a higher epoch can authorize again.
- Treat legacy ASSIGNED records without a deadline as unqualified. Clear them
  and require a higher epoch carrying a complete grant.
- Verify that a denied provider has a **present, empty order key**. A missing
  order key is not accepted as equivalent to a deny.

The wire agent-report shape stays unchanged; original grant metadata is stored
only in the local fencing record.

## Current SDK compatibility blocker

The installed SDK is OpenClaw `2026.7.1-2`. Downloaded source shows two places
that discard empty orders:

- `store-DH33UrUj.js`, `pruneAuthProfileStoreReferences`, keeps only nonempty
  provider order arrays.
- `source-check-ZSz5NzGW.js`, `normalizeAuthProfileOrder`, also keeps only
  nonempty arrays.

The existing plugin treats a missing order as an empty order in
`findProviderOrder`, so its current cleanup verifier can report success after
the SDK removes the explicit deny. The real SDK regression below checks the
actual `resolveAuthProfileOrder` result as well as the stored key. It must not
be weakened to treat a missing key as a deny.

On an SDK that cannot persist and enforce an explicit deny, this patch raises
an error rather than claiming that expiration succeeded. That error alone
cannot stop other gateway code from selecting credentials; therefore this
candidate must not be presented as a safe scheduler deployment until the SDK
contract is fixed and the full regression passes. No credentials are deleted
as a substitute for that missing contract.

## Actual SDK isolated regression

`../authbus_lease_deadline_sdk_live.mjs` executes the exact original and patched
lease functions against the actual installed SDK, using new private SQLite
databases and separate Node processes. SDK storage functions are not mocked.
The profile is synthetic. HTTP, HTTPS, fetch and socket connections are
disabled before the SDK import. The process verifies its default agent path
before loading any auth store.

Prepare a new private copy of the original plugin source, apply the patch only
to that copy, then run on the SDK's owner host:

```text
/usr/bin/node authbus_lease_deadline_sdk_live.mjs \
  --work-dir /home/qian-qi/heptabao-next-gates-20261017/lease-sdk-regression-new \
  --openclaw-root /home/qian-qi/.npm-global/lib/node_modules/openclaw \
  --original-source /home/qian-qi/.openclaw/extensions/openclaw-authbus/index.js \
  --candidate-source /path/to/private/patched/index.js \
  --lease-helper /home/qian-qi/.openclaw/extensions/openclaw-authbus/lease-assignments.js
```

The work directory must not already exist. The runner preserves its public
receipt, private configuration and process logs on failure. Exit 3 means the
SDK/lease qualification failed. It is not a successful skipped test.

Required cases include original-bug reproduction, explicit empty-order
persistence, actual resolver denial, grant deadline retention across a fresh
Node process, same-epoch expiry, changed-deadline rejection, lower-epoch
rejection, local expiration without a control document, backwards-clock
replay, legacy epoch migration, and a final cold reopen. The first SDK deny
failure prevents a false qualification result.

## Remaining runtime boundary

Network preflight fixes the observed bypass when the next cycle cannot fetch a
manifest. This polling plugin still does not provide an admission check on
every provider request at the exact deadline. An already running operation,
polling delay, runtime cache, environment credential source, another writer or
an independent provider client can require a separate gateway enforcement
contract. The receipt explicitly keeps `hardPerRequestDeadlineQualified=false`.

This patch neither creates a central inbox writer nor coordinates OAuth refresh
rotation. Those components require their own durable source, epoch and outcome
publication contract before production traffic and rollback authority can be
transferred from J3160.
