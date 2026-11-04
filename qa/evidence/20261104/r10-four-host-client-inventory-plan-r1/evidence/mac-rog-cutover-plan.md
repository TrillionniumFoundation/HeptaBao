# Mac and ROG AuthBus connection transition — prepared plan

This plan replaces the current OpenBao/J3160 connection used by the installed
AuthBus plugin. It preserves the existing local account ownership, configured
models, native runtime scope, publishing behavior, and per-agent order. It does
not install a publisher, restart a production gateway, edit a production file,
or declare the fleet cut over.

The final HeptaBao build, HA readiness receipt, listening port, certificates,
new AppRoles and supervisor registrations remain unbound. These are required
inputs to a concrete execution intent; they must not be filled with fixture
endpoints or test credentials.

## 1. Exact observed starting point

The source projection is
`cutover-preparation-r1/source-observations.public.json`, SHA-256
`7685a8dd41a555804f106fb880c1c75652d75af447aa2b5494c66ba2a7670bd2`.
It records the exact configuration, selected startup files, all configured
agents' primary auth rows, and the six state files named by the installed
plugin. Each database was read in a separate read-only SQL transaction while
production continued. Several database sidecar metadata tuples changed.
These observations are useful planning inputs, **not** a stopped-service,
globally atomic rollback backup. The execution phase must capture again after
the relevant gateway and its credential writers have stopped.

| Binding | Mac | ROG |
| --- | --- | --- |
| Home | /Users/qianqi | /home/qian-qi |
| Current configuration | ~/.openclaw/openclaw.json | ~/.openclaw/openclaw.json |
| Configuration SHA-256 | ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d | a042bc7fba4ac1295e323e0112598972a2872a040c5464af9614e4c2e600bd15 |
| Gateway | launchd ai.openclaw.gateway, observed PID 18437 | systemd user openclaw-gateway.service, observed PID 2436 |
| Current endpoint | https://100.66.117.33:8200 | https://100.66.117.33:8200 |
| AuthBus flags | leader=false; publishNew=true; manageOrder=true | leader=false; publishNew=true; manageOrder=true |
| Central order exclusion | none | main |
| Current releaseGeneration field | 200 | 203 |
| Scheduler setting | omitted; actual default shadow | omitted; actual default shadow |
| Default model | openai/gpt-5.6-sol | codex/gpt-6.1-sol |
| Native route | registered Codex runtime, agent home scope, managed 0.144.3 | registered Codex runtime, explicit user home scope, managed 0.159.2 |

The Mac native home scope above comes from the actual installed runtime
configuration/default resolution evidence; it is not inferred from the absent
raw `appServer.homeScope` key. ROG's explicit command is
`/home/qian-qi/.openclaw/runtime/openai-codex-0.159.2/node_modules/.bin/codex`.
No model, home scope, command, session override, provider base URL, proxy,
profile identifier or quota field is changed by this connection transition.

The Mac gateway plist is
`/Users/qianqi/Library/LaunchAgents/ai.openclaw.gateway.plist`, SHA-256
`e176c41f40b462b288177c20ced94c0e645b3a58f6bda024e53366f1592e8d08`.
It has RunAtLoad and KeepAlive enabled and launches its existing /bin/sh
wrapper. Its existing program arguments and logging arrangement are preserved.

ROG's unit is
`/home/qian-qi/.config/systemd/user/openclaw-gateway.service`, SHA-256
`987e55191a1a607ce3b56a79d115d58c8071e7e708ed5ee18208e60a45450f88`.
Its three observed drop-ins have SHA-256 values
`c28f7d2c30ad9ee1ccafe10be981f7b1de391eafab3592188809251ce45f7f3b`,
`8e8a6132204886a1ac652627f590fc47c319dea3b6813a990744edac6dadf1cc`,
and `4f90104dc1b9d6f5ec391e3d8b1b5c3b8b4fca16960913da1764840a0ab2a49a`.
The effective unit uses KillMode=control-group, SIGTERM and a six-minute stop
timeout. The planned stop is asynchronous and observed to completion; the
migration does not silently shorten this existing drain budget.

### Current identities and orders

Numbers 1, 2 and 3 below are the stable managed identities used by the existing
evidence, not arbitrary current array positions. ROG's separate native identity
4 is now also present as local ordinal 3 in its main SDK store. This corrects the
earlier inference that it existed only in the user-native file.

| Host / agent | Captured local profiles | Captured stored openai order | Required treatment |
| --- | --- | --- | --- |
| Mac main | 1, 2, 3 | 1, 2, 3 | Preserve identity 3 and its failed generation as a fallback and recovery material |
| Mac hepta-ui, hepta, hepta-backend | 1, 2, 3 | 1, 2, 3 | Preserve each complete local row and usage state |
| Mac trnm | profile-free primary row | no local state row | Actual SDK preview inherits main's three profiles and order 1,2,3 |
| ROG main | 1, 2, independent 4 | 4, 2, 1 | Retain original order exclusion and user-native ownership |
| ROG azi2–azi5 | 1, 2 | 2, 1 | Preserve each actual effective order |
| ROG zbj-llm-runtime | profile-free primary row | empty local order | Actual SDK preview inherits main's three profiles and order 4,2,1 |

The exact profile-ID SHA-256 values for 1 and 2 match on both machines:
`7b0b24e17c166c04c73864d9d276562e30c15bd5bf9f719ea3abd1a9687b0c0d`
and `eef0b72e4a8ba90bee622442f4d489172568664397a6da152e3faf0bf9eac6a1`.
No account identifier, token or credential value is included here.

## 2. Connection topology and target binding

The preferred deployment topology is a qualified HeptaBao HA node on each
Mac/ROG/Pocket host, with each AuthBus client connecting to its **own local TLS
API**. The local node must serve or forward the request to the current leader
using the qualified implementation. This avoids introducing an untested VIP,
DNS failover service or load balancer as part of the client transition.

The actual local address and port are deliberately not selected in this
document. A final binding must contain all of the following, taken from the
actual deployment and its read-back evidence:

- Product source commit and tree, normal build receipt, installed server binary
  hash, node ID, cluster identity and the successful final HA qualification.
- The exact local API address and selected free listening port. The certificate
  must validate that exact hostname or IP, including a loopback SAN if a loopback
  literal is used. A successful remote fixture TLS test is not this binding.
- The CA certificate bytes and SHA-256, host leaf certificate SHA-256, configured
  trust mode, and the local API's observed TLS identity before and after a local
  cold restart and a change of cluster leader.
- The new host-specific AppRole identity, policy digest and secret-ID issuance
  receipt. Role and secret values stay in owner-private files. Client roles read
  the required shared AuthBus documents and credential blobs and write only
  their own inbox; they cannot authorize transitions, publish the manifest or
  write another host's inbox.
- The actual HeptaBao supervisor registration, its executable/configuration/
  storage paths, and its restart/unseal/recovery contract. A Mac external-volume
  deployment must bind the real mounted volume and refuse a missing/replaced
  volume instead of creating a fresh empty store at the same pathname.
- The original gateway registration and its private wrapper/configuration
  binding. Gateway startup must be observed against the qualified local API;
  the existing native home scope and independent user-native account are
  retained.

A single publisher may initially use one explicitly bound host, one owner
identity, one AppRole and one durable owner directory. This is a single
publisher with recoverable state; it is **not** distributed publisher HA merely
because its KV storage is an HA cluster. A local-node outage can leave inbox
entries durably queued until that publisher recovers.

## 3. The only client configuration edits

For each host, the candidate configuration changes exactly these four paths:

```text
plugins.entries.openclaw-authbus.config.address
plugins.entries.openclaw-authbus.config.caFile
plugins.entries.openclaw-authbus.config.roleIdFile
plugins.entries.openclaw-authbus.config.secretIdFile
```

The three new files live together in a fresh, owner-private, deployment-specific
directory under that host's `.openclaw/credentials`. Its exact name and all three
file hashes are frozen in the final execution intent. The existing
`credentials/authbus/ca.crt`, `role_id` and `secret_id` remain intact as
rollback inputs. No secret file is replaced in place and no production pointer
is changed during preparation.

The comparison checks the complete parsed configuration, with these four paths
removed from each side, for equality. It also retains and hashes the exact old
bytes, permissions, owner and file identity for reversal. The releaseGeneration,
leader, publishNew, manageOrder, exclusion list, scheduler settings, models,
channels and native runtime settings are invariant.

In particular, `publishNew=true` is preserved. An existing client can submit a
new local identity to its authorized inbox. That submission is not authorization
to distribute the identity to other machines.

## 4. Trusted publication and ordering contract

The existing source at `tools/authbus/authbus_coordinator.py`, SHA-256
`cc46822439dfd33c86d1068c886941a92c5581871474cef846d2aee14ce80fe0`,
speaks the current installed plugin's inbox/manifest protocol. A grant binds
authorization ID, profile ID, source host, provider, full identity digest,
expected current credential digest and exact next credential digest.
Unapproved new-profile or changed-generation events remain deferred in the
inbox. The installed clients cannot write the manifest themselves.

The coordinator writes a content-addressed profile with CAS 0, publishes the
manifest with its exact observed version, and records a durable receipt.
Its private journal is fsynced before dispatch. Recovery uses exact versioned
read-back and does not retry an unknown manifest mutation. Its local lock does
not provide cross-machine fencing.

The current coordinator CLI explicitly requires an uninstalled scope and reports
`production_cutover=false`. That restriction must be replaced only through the
separate reviewed production entry, owner binding and recovery work. It must not
be installed while falsely retaining the fixture flag. Its service registration,
owner custody, explicit authorization workflow and interrupted-cycle recovery
must be qualified before traffic relies on it.

The initial shared managed profile set contains the two verified same-identity
sources 1 and 2. Independent Pocket local identity 5 and ROG identity 4 are not
silently enrolled in the common manifest. Their original authorized inbox
behavior remains; absence of an exact transition grant prevents promotion.

Mac identity 3 is preserved in its complete current stores, fallback semantics
and encrypted/private recovery material. The already rejected refresh generation
is not presented as a new valid provider credential. Omitting it from the active
replacement manifest avoids re-injecting it into ROG, where it is currently
absent. Its retained recovery material and account identity are not deleted.

The central order policy is non-enforced, has no activeProfile override and does
not enable a scheduler. Its selected managed candidate sequence is **2,1**.
The actual installed SDK and merge function have now verified that this
preserves every currently configured Mac and ROG agent's stored/effective
order. This does not make 2 the first candidate on Mac: its existing first
candidate 1 and tail 2,3 remain intact. ROG main and inherited zbj retain 4,2,1;
azi2–azi5 retain 2,1. ROG main's existing exclusion remains unchanged.

The alternative 1,2 was evaluated separately and was rejected for this fleet:
it changes ROG zbj's actual inherited order from 4,2,1 to 4,1,2. That result
remains in its original receipt; it was not relabeled as a preserving policy.

The completed preview compared the two permutations as separate alternatives
using the actual installed functions and each host's full captured logical
state. It did not clear quota/usage state, install a new order, replace a
credential, invoke a provider or substitute for the final full plugin cycle.
Final credential digests and enrollment times are bound separately to the
verified source generations.

Mac's controller passed 9/9 and its actual SDK checks passed 44/44 in 1.878
seconds. The source is
`cutover-preparation-r1/effective-order-mac-r1/controller.public.json`, SHA-256
`84a6796d70dddd290da61e8817f811755d10fec4aac3a84cee5469cbdb337b61`;
the adjacent `result.public.json` has SHA-256
`f6522d170c06276f82088264d7a5c77a8a87225911d9d3235d96051c76afee0e`.

ROG's controller passed 9/9 and its actual SDK checks passed 47/47 in 1.529
seconds. Under
`/home/qian-qi/heptabao-installed-authbus-consumer-36076-20261104-r1/current-order-preview-r1`,
`controller.public.json` has SHA-256
`7e1bed344052b72bdfe08efd0b06551ad20b2ac6550d767e5d3e99e88b6e4a83` and
`result.public.json` has SHA-256
`244be61bad65a3c1f059188fe96960ed57d9ff8c27f5246b2e99813fd4ea3677`.

These are two separate host observations, not one combined runtime test.
Both reaped their owned process, made zero provider/native calls, invoked no
auth-store write API, and retained the same production configuration, primary
auth rows and exact registry row. Running-production sidecar metadata changes
are explicitly reported and are not hidden behind a global unchanged-filesystem
claim. The reviewed controller SHA-256 is
`4df0c468e1a15e333c6bd57a0ec5961e8f909053dae66be5ab6c18f8df9aa968`;
the consumer is
`1b23fe9d5a0e0f43657b1e9218bf71fff1dfc8983813202e5439716822779833`.

## 5. Forward operation, one host at a time

1. Freeze a deployment-specific intent with the exact old configuration SHA,
   source pins, new local endpoint/CA/AppRole files, required central documents,
   publisher ownership and the accepted pure-preview result. Reject stale inputs
   and generate a new intent; do not edit a previously sealed intent.
2. Confirm the local HA API and its peer/cluster identity with the new private
   trust material. Exercise a private authorized KV path, a denied path, token
   renewal and revocation using the real host role. Preserve each request
   outcome, including unknowns, without blind replay.
3. Stop the existing gateway through its actual supervisor, retaining all
   registrations. On ROG, use the existing control-group and drain semantics.
   On Mac, unload the exact current launchd job and wait for its owned gateway
   and credential-writing descendants to finish. Keep the prior running/enabled
   state as part of the reversible intent.
4. While stopped, capture the exact configuration and wrapper/unit files;
   every configured agent's primary `auth_profile_store` and
   `auth_profile_state` row including updated_at; each original absence or
   profile-free primary row; applied-profiles, publish-baseline,
   bad-refresh-quarantine, refresh-backoff, lease-epochs and status; and the
   exact relevant native-auth/config inputs. Preserve full order, usage,
   lastGood and all non-target identities. Create private backups and fsync
   them before any write.
5. Produce candidate bytes from that fresh configuration. Recheck file identity,
   full SHA and the four-path diff immediately before atomic replacement in an
   exclusive maintenance window. The gateway is stopped and the migration owns
   the configuration write. This is a compare-and-replace precondition plus
   atomic replacement, not a claim that a private advisory lock fences an
   unrelated writer. If another writer is observed or cannot be excluded, stop
   and take a new baseline instead of overwriting it.
6. Start the same gateway registration against the new local endpoint. Observe
   one complete installed AuthBus cycle: successful AppRole/TLS, exact
   manifest/profile digests, source-host inbox boundaries, deferred unrelated
   identities, actual order/exclusion behavior and full effective stores for
   all configured agents. Recheck that original source usage and independent
   native identity 4 remain intact. Record actual runtime credential
   consumption under the installed native contract; do not force a profile,
   model or home scope.
7. Perform the required cold stop/start and repeat the bounded state/credential
   observation. Provider background calls are governed by the actual installed
   native version; they are not assumed absent. The sealed earlier 429 and
   invalid-refresh request are not replayed to obtain a greener result.
8. Stop again and capture one exact post-transition checkpoint. Perform the
   inverse operation below once. Only after that real reversal and restored
   startup have a terminal receipt can this host be marked eligible for the
   final forward cutover. A further forward application gets a fresh intent and
   baseline; it is not a replay of an unknown request.

This ordering permits review before the production action. No host advances
merely because another machine passed an isolated SDK fixture.

## 6. Exact inverse operation and failure handling

The inverse stops the currently running new-config gateway first. It checks
the exact new configuration hash and each expected committed local store/cache
checkpoint. It restores the old configuration bytes and original metadata;
restores each complete auth row and updated_at under the installed SDK/SQLite
transaction contract; restores each exact cache file or original absence; and
preserves the original native-auth ownership.

Local and effective stores are different comparison points. Transaction
callbacks see the local store. Restoration verifies both the local committed
store and the actual SDK's effective result, and separately restores the raw
profile-free primary rows. An inherited empty-local agent must not be converted
into a copy of the main store by the rollback.

Each stage consumes a durable rollback-attempt marker **before** making its
one restore attempt. A failed or unknown CAS is retained and is not retried
automatically. If an independent credential refresh or user write creates a
new generation outside the recorded checkpoint, do not overwrite it with an
older token. Seal the observed generation and stop for source-bound
reconciliation. A client rollback does not rewind the shared HA cluster or
delete durable inbox/profile/manifest history used by other clients.

After successful restoration, start the original gateway registration and
verify the restored configuration, raw/effective auth state, original order,
native inputs and prior service condition. The original endpoint is currently
unhealthy in the captured AuthBus status. Returning to its exact old
configuration is not proof that J3160 became available again; this limitation
must remain explicit in a rollback result.

The four legacy Mac relay services and ROG's two held dormant helpers are
separate registered paths. This transition does not stop, delete or release
them by inference. Their finite consumer/retirement or explicit-release
decisions remain part of the whole-fleet completion record.

## 7. Evidence that remains necessary

The normal360 Mac native fixture proved actual registered local credential
consumption, cold HeptaBao restart and two full-store rollbacks. The ROG normal360
fixture proved SDK import and independent user-native preservation. Those are
scoped evidence, not production cutover receipts.

This prepared plan still requires the final qualified normal HA candidate,
bound local TLS endpoints and durable production services, the reviewed
publisher production entry, final trusted credential-generation documents,
fresh stopped-state backup creation, and each host's actual
forward/restart/inverse receipts. It does not make provider quota recovery or
login to an unselected historical account an invented HeptaBao feature gate.
Old OpenBao/HeptaBao services or backups are not removed under this plan before
the finite migration and recovery-path inventory is closed.
