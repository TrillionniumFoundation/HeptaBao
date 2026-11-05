# Exact main-owned OAuth source acceptance

This separate QA driver qualifies one already preserved main-owned OAuth
credential through an isolated HeptaBao service and the actual OpenClaw SDK.
The previous synthetic central driver, consumer, coordinator and helper files
remain unchanged. Local contract tests use synthetic records and do not
constitute a live credential, HTTPS, or SDK pass.

## Frozen source selection

The driver accepts only the existing ordinary owner `/home/qian-qi` on Linux
host `main`, whose actual SDK host ID is `desktop`. Its selected persisted
owner is `/home/qian-qi/.openclaw/agents/main/agent`. No alternative profile,
newer expiry, inherited owner, SecretRef, provider call, or OAuth refresh can
replace this selection.

| Binding | SHA-256 |
| --- | --- |
| Actual export public receipt | `41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907` |
| Owner-local private snapshot | `f2c164581d5afb0c9f95b9a71aedaa3f2a889817dabe1201169f7b5ce6f5dbe6` |
| Selected profile ID | `7b0b24e17c166c04c73864d9d276562e30c15bd5bf9f719ea3abd1a9687b0c0d` |
| Selected credential | `71c3e21e28368490383dc3628f561e42fef261b0f4ef78263e4dcf3873dc381b` |
| Selected identity | `c84e09f9ec9749c94545ddf65091f448ff795b318fde24a3780b6f000ff4ee9d` |
| Unchanged owner inspector | `703cb463ce43488ff29f8a8394fab4bd591c69bc2a06c1c5ddc64d0abc1e14de` |
| Unchanged independent coordinator | `81bfbacfd14df399c1e8eef963447803cee8e01aebc2474c0f39c2595e7fce47` |

The source paths are fixed in the driver. It checks the private file's owner,
mode, regular-file status, byte bound, stable metadata and exact digest before
using it. The original inspector re-reads the actual persisted SDK owner
before authorization, immediately before each canonical manifest attempt,
and at final qualification. These reads consume the caller's original
deadline. The snapshot is never treated as a refresh lease.

The seven copied AuthBus plugin files must match the exact public source
fingerprints from the successful central R1 run. The five actual SDK module
fingerprints and SDK version `2026.7.1-2` are also fixed. All copied plugin
bytes are hashed before use and production files are checked again afterward.

## Required source package

Install a fresh private source directory; retain the relative paths below.
Do not add files to or replace files in the already executed central R1 source
directory. A source packet should contain the two new files and these seven
unchanged dependencies, with every file's exact size and SHA-256 verified
before and after execution:

```text
qa/openbao-acceptance/native_v6_authbus_owned_source_live.py
qa/openbao-acceptance/native_v6_authbus_owned_source_consumer.mjs
qa/openbao-acceptance/native_v6_authbus_client_live.py
qa/openbao-acceptance/native_v6_openclaw_authbus_live.py
qa/openbao-acceptance/cert_auth_live.py
qa/openbao-acceptance/owned_process.py
qa/openbao-acceptance/fixture_mounts.py
qa/single-node/smoke.py
tools/authbus/authbus_coordinator.py
```

The R2 local contract receipt binds these files, the previous R1 contract
receipt, the actual export's public observation and all seven original plugin
fingerprints. It contains no private candidate bytes.

## Root operator execution

Only the root operator dispatches this job through Runtime on `main`.
The example uses the already frozen R8j Linux executable:

| Binary binding | Value |
| --- | --- |
| Path | `/home/qian-qi/heptabao-next-gates-20261017/native-r8j-linux-freeze-01/heptabao-server` |
| SHA-256 | `c0821bae2a8435eddea8506311a09cd3e1f0533948b8489f1e606e210a073560` |
| Source commit | `4f0bacd59be21d204783d69b500d2a19ef6af55a` |
| Source tree | `9514b66b8cda559938e135d6c7c5b9606296fd4a` |
| Native build receipt SHA-256 | `fbe3ef1de04e732e3a36188a464d0814701300c49ded087abba4e45a2ed05509` |

The dispatch wrapper must first check the source package and immutable binary
against their exact manifests. Use a new work directory and create private
controller logs exclusively with mode `0600`. Persist the durable job ID and
reconcile that job before considering another run. The driver has one
360-second operation budget; a 420-second outer job timeout allows bounded
owned-process cleanup and evidence capture without extending qualification.

Assuming the source package was installed at the path shown here:

```bash
/usr/bin/python3 /home/qian-qi/heptabao-next-gates-20261017/authbus-owned-source-candidate-r2/qa/openbao-acceptance/native_v6_authbus_owned_source_live.py \
  --binary /home/qian-qi/heptabao-next-gates-20261017/native-r8j-linux-freeze-01/heptabao-server \
  --central-source /home/qian-qi/heptabao-next-gates-20261017/authbus-owned-source-candidate-r2/tools/authbus/authbus_coordinator.py \
  --plugin-root /home/qian-qi/.openclaw/extensions/openclaw-authbus \
  --openclaw-root /home/qian-qi/.npm-global/lib/node_modules/openclaw \
  --node /usr/bin/node \
  --source-receipt /home/qian-qi/heptabao-next-gates-20261017/authbus-sdk-owned-inspection-r1/owner-export-r1-7b0b24e17c16/snapshot/public-receipt.json \
  --source-receipt-sha256 41197f8d23229f9103b51505b319cc09eef0a48192631821caf7da2172d74907 \
  --source-inspector /home/qian-qi/heptabao-next-gates-20261017/authbus-sdk-owned-inspection-r1/authbus_sdk_owned_source.mjs \
  --work-dir /home/qian-qi/heptabao-next-gates-20261017/authbus-owned-source-actual-r2
```

Run as `/home/qian-qi`'s ordinary owner, with `PYTHONDONTWRITEBYTECODE=1`.
The executable must have the native V6 fixture feature. The driver itself
starts a new loopback listener, creates independent AppRoles and CA material,
and stops its owned server in `finally`. It never stops a production process.

## Expected live evidence

Read only the controller's public summary and the new work directory's
`public-receipt.json`. Never retrieve `source-owned.private.json`, token or
recovery files, SQLite files, private SDK diagnostics, or the original private
snapshot. The raw production profile ID, identity, access token and refresh
token stay on their original owner host. Public profile and identity values
are digests. JSON-escaped secrets are rejected as well as literal strings.

A successful public receipt uses schema
`native-v6-authbus-real-owned-source-live-v1`. Its `ok` must be true, every
check must pass, and check names must be unique. Record the actual observed
check count; a count from the older synthetic driver is not applicable.
The receipt must include these actual outcomes:

- The original producer creates one exact A inbox event after an empty
  baseline. The independent coordinator defers it until the explicit grant.
- A real competing manifest CAS produces HTTP 400 with the original exact
  CAS error contract. No canonical credential is published by that rejected
  attempt.
- The next same-A attempt exits the coordinator worker with code 73 after
  actual manifest commit but before its journal reply. The server is killed
  with SIGKILL and restarted/unsealed. Recovery proves the original manifest
  or its historical version, finishes the immutable receipt and avoids
  replaying the manifest write.
- The original follower imports the exact A digest through the actual SDK.
  A closed SQLite database/WAL copy restores the same digest. A bad CA fails
  authentication while retaining A; restoring the original binding bytes
  restores a successful fresh process cycle.
- The real renewal endpoint is called with the same live bearer. The local
  due point is shortened to trigger renewal; elapsed real lease expiry is
  not claimed. Producer/writer ACL negative checks retain their live read
  controls.
- Every captured fixture AppRole bearer is read live, revoked, denied and
  denied again after cold restart. Producer, follower and writer SecretIDs
  each fail actual login before and after cold restart. The bootstrap
  recovery root token is outside that captured AppRole-token scope.
- The owner inspector, original source snapshot, export receipt, production
  plugin and coordinator still match their original bindings afterward.

Expected successful qualification flags are
`actual_independent_service_credential_publication`,
`actual_original_producer_and_consumer`, `actual_sdk_qualified`,
`actual_service_https_qualified`,
`central_process_crash_and_server_restart_qualified`,
`allIssuedFixtureTokensRevokedAndColdDenied`,
`allFixtureAppRoleSecretIdsDestroyed`,
`allFixtureAppRoleSecretIdsColdLoginDenied`, and
`sourceStillExactAtFinalRecheck`, all true. `realCredentialVersionsUsed` is 1.

The original absolute monotonic deadline is passed to every coordinator and
SDK child. Node validates its Linux monotonic clock domain, checks each SDK
stage, and bounds real HTTPS requests by the original operation deadline and
the original request budget. It cannot obtain a new budget by importing the
SDK, starting a second cycle or receiving another response chunk. Parent
fixture control/startup operations retain their existing bounded helpers and
are checked before and after against the same operation budget; completion
after expiry never qualifies as a pass.

If a worker fails after a potentially dispatched manifest, the retained
journal makes `unknownOutcome` true and exits with code 3. The top-level
receipt retains `mutationOutcomeUnknown`, the worker receipt fingerprint and
`automaticRetryAllowed: false`. Resolve the original pending operation from
its immutable receipt or exact manifest history before any future attempt.
An owner, credential, config or SDK fingerprint change fails immediately;
the driver does not select a replacement source.

The successful fixture still leaves `production_cutover`,
`production_coordinator_replacement`, `production_mutation`,
`j3160_contacted`, `provider_called`, `oauth_refreshed`,
`provider_liveness_verified`, `oauth_refresh_ownership_qualified`,
`enforced_scheduler_qualified`, and `ha_cluster_qualified` false. This
one-owner fixture supplies no OAuth B rotation, provider liveness,
cross-host refresh ownership, scheduler enforcement, production cutover or
legacy-deletion evidence.

## Local contract checks

```bash
PYTHONDONTWRITEBYTECODE=1 python3 qa/openbao-acceptance/native_v6_authbus_owned_source_live.py --self-test
node --check qa/openbao-acceptance/native_v6_authbus_owned_source_consumer.mjs
node qa/openbao-acceptance/native_v6_authbus_owned_source_consumer.mjs --self-test
```

R2 requires Python 11/11 and Node 14/14. These test exact source/owner
selection, changed source and identity rejection, private-file custody,
escaped-secret redaction, monotonic deadline retention and conservative
post-dispatch failure classification. They do not run the provider, actual
SDK, real candidate or remote HTTPS service.
