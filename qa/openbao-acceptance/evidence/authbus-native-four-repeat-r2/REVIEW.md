# Native R1 four-case rerun on OpenAI R3 shared adapters

This is a new candidate, not inherited native qualification. The prior exact 0f1c/native-R1 run passed 120 controller assertions plus warm 59 / cold-before 57 / cold-after 57. These counts and ordered check inventories are retained in the new rerun configuration solely as expectations. The exact original public receipt is rejected by the new bootstrap because its binary and runtime manifest differ.

## Exact runtime scope

The runtime is the original 21-file native/cold closure, replacing exactly two files with the frozen OpenAI R3 adapter bytes:

- authbus_refresh_sdk_candidate.mjs: SHA256 42d91742365526b548c49d0a900d88ccfaf7d93ab57fa61bff3d97a86df663d3.
- authbus_refresh_sdk_registry_candidate.mjs: SHA256 c7985bd4c07c2143009802f74392adc92ec9b5388b909b51d2f7709ac7ddd01d.

The other 19 files are byte-identical to native R1, including the full native controller, gateway, fixture safety, SQLite/cold worker, process owner, recovery and TLS helpers. The controller accepts the new manifest and binary pins using its existing CLI. Its four cases, original 180-second deadline, 120 checks, three distinct SDK worker processes, native SIGKILL/reopen, reader/issuer AppRole lifecycles and UNKNOWN persistence are unchanged. There is no new general controller framework.

The supplied one-shot bootstrap reuses the previous packet staging/driver invocation and adds new pin bindings and an outer denominator qualification. It requires all exact original check names (120/59/57/57), actual new runtime/binary identities, one committed UNKNOWN lost-ack injection, final provider counts 1/0/1/1, distinct cold processes, actual native SIGKILL, no extra provider attempts and no outside reads/writes/network/process attempts. These outer checks do not inflate the original native controller denominator. The 180 seconds belong to the unchanged original native controller, beginning at its run entry as in R1; staging and source/build-file preflight are separately recorded bootstrap work.

## Binary provenance

The current main binary is /home/qian-qi/heptabao-next-gates-20261017/native-full55-9770-main-r1/heptabao-server, 779,960,952 bytes, SHA256 7e68ebb51d3440c30696a7f7456322e48d2a39e702709a27736b78f451ae591c. Its exact source is commit 9770bdd4ca77aa832ec8083a054760637e92cfa1, tree f32f1acf9a794844719b6df225df3d23f2389e02, 2,979 files. Build receipt SHA256 8b8b4501bd94085bb65efa23482d4a81bbf768b5f29c74f9104fc86465f3cbb2 and complete source-manifest SHA256 9e167d20256e2d59c9ce57c73b90a0976403cf7a20db3e1d6b5de011c9d3cb0c are preflight inputs. The actual build receipt records 55/55 scoped tests and an unchanged full source tree. This is build provenance, not an AuthBus runtime pass. The 779 MB artifact fits the existing native artifact reader; no product or fixture request limit changes.

## Delivery and verification

The tar has exactly 22 regular mode-0644 members: 21 runtime files and source-manifest.json. Tar SHA256 is 36f4548dfed1c999451b252b2ddcee707c2cf368870c06e1b5956fb911c7f97c (91,870 bytes); manifest SHA256 c13159524080c0c0a9588fffae8fdc01fdd1a2dc1068972fd2ce4232c2a6f58d (7,640 bytes).

The local verifier checks the exact two-file delta, tar closure, all 21 hashes, unchanged original controller/worker/fixture, all six Python and fifteen JS syntax checks, valid manifest acceptance, changed pin rejection and refusal to borrow the original real 120/120 receipt. No installed SDK, native binary, provider or remote call was executed locally.

Transfer packet/source-packet-0.b64 through -4.b64 to the fixed main names auth-native-cold-r2-20261019-0.b64 through -4.b64, and stage the exact bootstrap at a fresh owner path. It creates only the new source directory authbus-r5-native-cold-r2-source-20261019 and fixture authbus-r5-native-cold-r2-actual-20261019-01. Run once:

```sh
python3 -B /home/qian-qi/heptabao-next-gates-20261017/authbus-native-cold-r2-once-20261019.py
```

The bootstrap journal is authbus-r5-native-cold-r2-20261019-controller.json. An unknown response is reconciled by that journal/source/work claim; it never authorizes a duplicate submission. Original R1 and OpenAI R3 source/evidence remain frozen. The new native four-case result is pending. Actual OpenAI/Undici transport backed by native KV remains a separate next profile and is not claimed by this Anthropic four-case repeat.
