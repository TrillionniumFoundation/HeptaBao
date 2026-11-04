# Actual native writer retirement — isolated baseline candidate

Status: source frozen for review; this candidate has not started a native process or HeptaBao service. It does not install a production SDK or plugin. The only completed new jobs were read-only source/command/binary resolution and syntax checks.

## Scope and expected negative result

The baseline uses the exact installed ROG factory bff60f1b… and original AuthBus recycler d3fffe4c…. Current managed profile 2 is copied from the real SQLite source, published through a fresh loopback normal33 HeptaBao KV2 service, and recovered through the original plugin and installed SDK. The native user-home source remains original unmanaged profile 4; auth.json and config.toml are copied exactly into each private HOME. The original default model, Codex configuration, order 4/2/1 and main exclusion are preserved.

Three original-code cases run in separate Node processes/private homes: (1) actual ready old lease, then actual managed import and a concurrent new acquire; (2) original initialize dispatch deliberately held, then actual import/new acquire, then release the gate; (3) the real spawn callback invokes the real recycler before factory onStarted/client publication, then actual import and a concurrent acquire. Case 3 is a deterministic component timing boundary, not a claim that a complete asynchronous plugin cycle ran inside spawn. No fake transport or native response is used.

A complete baseline receipt must separately record shared-entry removal, second process spawn, second factory readiness, and both actual initialized leases with the old native process still alive. It records singleWriterGatePassed=false and explicit failed one-writer assertions. A successful baseline process exit means the negative observation, cleanup and private CAS rollback were collected; it never means the product single-writer gate passed.

The lifecycle helper also contains fixed-candidate branches for later review. The current stage input permits only candidateMode=baseline and the exact original installed factory; these branches are not executed by this baseline. A later paired factory/recycler overlay will require a new source freeze, staging root and run key.

## Native process and credential custody

The actual CLI is 0.159.2. Its wrapper SHA256 is 61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70. The exact launcher resolver selected @openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex, 286754152 bytes, SHA256 1748767b230ebfc3d4ab7e4e254920d0c0ad9691fd8c11f190e7d44511a4a92e. The older failed vendor glob is retained separately as a helper failure.

The fixture uses the existing OPENCLAW_QA_PARENT_PID lifetime option so original wrapper and native children stay in the owned Node process group, inside a private PID and network namespace. It records both /proc start identities using executable, parent/group/session and start ticks; it does not inspect process arguments or environments. New spawn observations do not block an unsafe spawn. Normal old-process retirement must be observed before harness cleanup and before the second spawn.

Only original initialize/initialized and account/read(refreshToken:false) are permitted. Server-side refresh/tool/approval requests are refused before the installed handler. No external-token login, OAuth refresh or model request is dispatched. Native background network attempts are not measured; the kernel namespace denies external egress. Credential and configuration bytes/generation are independently checked at each important transition and on filesystem notifications, with original account responses retained privately.

Both wrapper and native process shutdown are recorded. The future fixed barrier must accept only closeAndWait=true plus a normal wrapper exitCode=0 with no signal, under the pinned wrapper contract in which that zero exit follows the actual native exit. Forced/abnormal or any signal exit remains unknown and retains the barrier. The future abnormal case intentionally stops only the exact owned native PID, kills only its exact wrapper PID, observes the surviving native process, requires a rejected new acquire, and performs separately labelled owned cleanup.

## SDK state and boundaries

All logical CAS delete/restore operations use the installed SDK's official filterExternalAuthProfiles:false and syncExternalCli:false options. This preserves the full private logical store while a native auth file is present; these are already the original upsert implementation's fixed options. The deletion also retains preserveStateProfileIds for managed2. Full order, usage, other profiles, configuration, source rows and whole-store rollback assertions remain strict.

Production roots and code are kernel read-only. Only the newly created run directory is writable. Actual AppRole/TLS reads, scoped denial, renewal/revocation, a normal33 process SIGKILL/cold unseal, and per-case CAS rollback are retained from the reviewed existing driver. No production service manager action or traffic switch occurs.

Budgets remain HTTP 10 seconds, consumer 70 seconds, rollback 35 seconds, outer 440 seconds. Actual native acquire uses the original 15-second limit; account/read uses 8 seconds. Known independent normal-release build job 1a1a7a26c1b-fc05-2c06 may coexist; no host-wide exclusivity is claimed.

Fresh remote root: /home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-native-writer-61ff8bef-baseline-r1. The stage source refuses an existing root and validates the exact stage stdin SHA and all source pins before creating files. It stages only public code/proof inputs; private source credentials are copied later inside the isolated run.
