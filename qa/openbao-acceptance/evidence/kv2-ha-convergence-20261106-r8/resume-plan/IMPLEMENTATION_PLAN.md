# Existing candidate resume and first initialization: implementation plan

## Status and scope

The continuation direction has been reviewed by root: use a new bounded entry for the stopped, repaired candidate; preserve the original failure; do not replay the create-only installer. This frozen document is an implementation plan for exact review. The new entry and its checker are **not implemented**, no ready status is granted, and no remote operation has been dispatched by this preparation.

Execution remains held for lawful macOS authorization of the actual launchd/xpcproxy access to the removable volume. The original kernel denial is actual evidence. A repaired Python binding, successful TLS preparation, a plan flag, or a caller assertion cannot establish that the OS permission was granted. The OS authorization is the user's remaining intervention; it is separate from permission to do ordinary code preparation. No TCC database, privacy rule, launch identity, mount policy, log placement or executable path will be changed to bypass that denial.

The proposed future step has one 110-second work deadline and one 120-second native runtime cap from the original entry timestamp. Existing 15-second HTTP limits and 5-second utility waits remain bounded by that same work deadline. Cleanup receives only the original final 10 seconds. This is a new attempt after a new admission, not extra time for the failed attempt.

## Exact starting generation

- Candidate manager: `gui/501/org.heptabao.kv2`; unchanged API origin `https://127.0.0.1:18240`.
- The installed plist, copied launch guard, normal server/seed binaries, public certificates, server configuration and existing data directory are retained. TLS private key bytes are not read by the admission controller; their original metadata/held descriptors remain checked, and the actual server consumes the key.
- Actual repair job `1a1b295b02c-fc05-7ec7` finished successfully. It changed only `launch_binding.files.python` to the original plist's real base launcher. Binding state is `initial_empty`, `seal_file` is null, the original data directory was empty, and five nonce/root/share leaves were absent. These are recorded observations, not a claim about future currentness.
- The base launcher is 34,640 bytes, public SHA256 `cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13`. The controller still runs under the independently qualified isolated venv. These two roles must remain distinct.
- The existing service binary remains normal candidate `4bde9aee03fcd27c59e13607e529b1cee594b249`, tree `f08493a23f8ea0637073651231865ea9607b790e`. Publishing source commit f0e4694e does not change or qualify these deployed copies. The known full-CI failures and any pending newer CI remain explicit holds; this step does not declare them resolved.
- The observed leaf certificate DER SHA256 is `0bd8bab80fe2b8b5b44b6ccc5da2fccbbbf163dd084d6adcf62a45d66575da9b`. The actual TLS handshake must still verify the original CA, hostname and this leaf.

Historical native receipts, public results and full final stdout are exact immutable inputs. Current artifact identities and private content hashes are consumed only from the private envelope and rechecked on the host. They are never copied into the public plan or request envelope.

## Why the original entry cannot be reused

| Original `manager_start_init.py` behavior | Necessary resume behavior |
| --- | --- |
| Requires plist, copied guard and current binding to be absent, then installs them | Require those exact existing artifacts and reopen them against actual stopped/repair evidence; install none of them |
| Calls `build_initial_binding(prep, ...)`, whose historical prep Python role is the venv copy | Consume and validate the actual repaired current binding; do not reconstruct it with the obsolete role |
| Writes the private closeout to the existing preparation `manager-init.private.json` | Preserve the old private closeout; create a new private attempt subdirectory and keep the same allowed closeout basename there |
| Treats successful preparation as the only generation predecessor | Also bind the original manager failure, retirement, actual repair, their final closeout, and native post-repair identities |

Only these admission and evidence-location differences are proposed. The reviewed `launch_guard`, `manager_runtime`, `init_delivery`, custody module and existing initialized-binding publication method remain unchanged. There is no planned generic recovery engine or broader storage refactor.

## Proposed smallest checker interface

`derive_existing_candidate_expectations(preparation, failed_attempt, retirement, repair, private_native_envelope) -> ExpectedExistingCandidate`

This proposed helper is pure: no file reads/writes, HTTP, subprocesses, manager calls, key material or authority creation. Its returned object contains expected artifact metadata and relations for the actual entry to verify. It is not a liveness or authorization receipt.

The helper would check the exact predecessor schemas and jobs, complete/durable native terminal forms, complete final streams with `seen == stored == actual bytes`, the original failed attempt's `initialization_attempted=false`, the original 0/0/113 retirement sequence, successful single-field repair and complete FD/child closeout. It would require that the repaired binding differs from the retained initial archive only at `files.python`, and that the new role matches the independently observed base launcher. No arbitrary patch or new field would be accepted.

The actual entry must independently reopen all referenced artifacts with the unchanged original-FD registry. A pure helper result cannot replace that revalidation or the live manager/TLS observations.

## Proposed execution sequence after exact code review and lawful OS authorization

1. **Admit immutable predecessors and current artifacts.** Recheck the qualified isolated interpreter, fixed code bytes, exact prerequisite original bytes and private envelope identity. Hold the original service, authority, LaunchAgents and volume roots. Reopen the actual repaired current binding, original initial archive, retained old current, installed plist, copied guard, config, public certs and normal binaries against their private pins. Keep all original file/directory descriptors until closeout. Verify the unchanged plist still uses the base launcher and exact guard arguments. Verify current binding state `initial_empty`, null seal and the original empty data-directory identity. Recheck the actual server private-key metadata without loading its contents.

2. **Deny any previous init footprint.** Check all five nonce/root/share leaves absent, not merely the three shares. Also require the init-request intent and initialized-binding pending leaf absent. Preserve the old failed manager receipt and repair evidence. Any nonempty data, replaced directory, missing predecessor, changed artifact, already initialized endpoint or partial material requires a different reconciliation path; this entry must fail before initialization.

3. **Create only new attempt evidence roots.** Proposed logical suffixes are `formal-kv2-manager-resume-first-init-inputs-r1`, `formal-kv2-manager-resume-first-init-execution-r1`, and private preparation child `resume-first-init-r1`. Final absolute paths, identities, file bytes and idempotency key will be frozen when the entry exists. The private child may still contain the whitelisted basename `manager-init.private.json`, so `PrivateIO.put` needs no cleanup exception expansion. No existing receipt, plist, guard, binding, logs or data is deleted or overwritten by this setup.

4. **Reobserve exact label absence and bootstrap once.** Use the same bounded exact queries for `gui/501`, `user/501` and `system`, require original return code 113 plus the precise label/domain absence grammar. A missing domain, query failure, existing label or ambiguous output rejects admission. Then invoke one `launchctl bootstrap gui/501 <unchanged-installed-plist>` and mark its outcome unknown until actual owned readiness is observed. No automatic bootstrap retry, kickstart or emergency alternate launch mode is introduced.

5. **Require actual strict TLS and owned uninitialized server.** Retain the original bounded readiness loop, positive CA/hostname/exact-leaf verification, GET `sys/init` returning exactly uninitialized, and actual launchd/PID/executable/plist/data observations. Run the same two single-shot wrong-CA/wrong-hostname handshakes before creating a nonce. Success is based on the real manager and handshake; it cannot be set by the OS-authorization input alone. A phase name is not evidence that the endpoint exists.

6. **Persist nonce and send one first-init request.** Create and fsync one 32-byte-random nonce encoded as canonical base64 in its separate private leaf. Persist the original single-init intent. Issue at most one POST `sys/init` with exactly 3 shares, threshold 2 and that nonce. Do not retry after a lost response, timeout, non-200 or malformed response. The server's pending encrypted init capsule remains unacked for a separate, explicitly reviewed recovery path if necessary.

7. **Deliver separated material and bind the actual initialized generation.** On a complete 200 response, use the unchanged exact three-share decoder. Hold and prove the actual init directory replacement before creating material. Read the actual seal metadata, require generation1/Shamir3/2, fsync/read back the root token and each of the three shares in their existing distinct private role directories. Never persist the combined init response. Only after all deliveries close may the existing `build_initialized_binding` and `publish_initialized_binding` transition the repaired current binding to the actual new data inode/seal. The repaired base Python role must remain intact.

8. **Observe and close out.** Require the same actual manager before/after, GET seal status showing initialized, sealed, threshold2/shares3/progress0, and unchanged TLS ownership. The service remains under launchd and sealed. Final public receipt, complete final stdout and authoritative terminal must jointly establish every original FD, HTTP connection and short utility child retired. The controller never claims waitpid ownership of the long launchd child. Signals, failed fsync/close, unknown mutation outcome or original deadline breach remain failures even during receipt publication.

## Failure and scope rules

| Event | Required result |
| --- | --- |
| Changed predecessor/current metadata, nonempty data, any material present, label not exactly absent | Reject before bootstrap/init; preserve all files |
| Bootstrap command fails or ownership/readiness remains unknown | Keep unknown result; do not replay bootstrap or init; reconcile this exact candidate separately |
| macOS again denies removable-volume access | Retain actual failure and TCC evidence; no permission bypass or alternate permanent service wrapper |
| Readiness observes initialized=true | Stop this first-init path; do not issue init or interpret it as prior success |
| Init response is lost/non-200/malformed or delivery is incomplete | Preserve nonce/intent/partial material, keep unknown initialization result, no blind request replay or ack |
| Binding publication or final seal/owner observation is incomplete | Preserve the actual generation and partial evidence; do not restart or recast it as successful |
| All initialization checks close | Status may only be initialized-and-sealed-awaiting-offhost-custody; formal KV2/HA/AuthBus/cutover remain false |

Launchd KeepAlive may itself schedule attempts after a bootstrap; those are not additional controller bootstrap calls. An uncertain long-service outcome must be reconciled and, if root directs, retired with the exact separate manager procedure. The short-child custody layer must not kill a guessed long-service PID/group.

This step performs no unseal, init ack, mount creation, preactivation seed, activation, business import, source capture, provider/J3160 call, AppRole creation or traffic switch. Offhost share2/share3 custody, real independent 1+2 and 1+3 unseal tests, ack, seed and KV2 protocol acceptance remain subsequent steps. The existing remote empty receiver roots are not evidence that shares have been delivered.

## Implementation and validation boundary

Implement a new entry only after root reviews this exact plan. Do not change the frozen original controller or execute it by replacing its globals. Avoid a large shared-logic refactor: first prepare the small expectation checker, then reuse the already reviewed bootstrap/first-init flow with an explicit source comparison showing what stayed identical. Exact implementation filenames and hashes will be separate reviewed inputs.

Any future local guards should target only the new admission risks: arbitrary repaired-field delta rejected; stale private metadata rejected; present nonce/intent/nonempty data rejected; failed historical result cannot become success. They cannot establish actual TCC, manager, TLS or Shamir behavior. No new tests or remote probes were run to prepare this plan.
