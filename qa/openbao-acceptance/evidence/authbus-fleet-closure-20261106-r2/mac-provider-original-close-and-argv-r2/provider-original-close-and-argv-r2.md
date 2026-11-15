# Current SDK close helper and gateway argv R2

This checkpoint records read-only observations. It does not qualify a provider refresh, a running writer exclusion, production CAS, or cutover.

## Actual public SDK closure sources

The single `read_multiple_files` call returned complete public SDK files with independent stable versions. It did not create a child process or open credential stores. The original tool result is retained verbatim.

| Source | Bytes | SHA256 |
| --- | ---: | --- |
| `dist/ssrf-BayeDjCv.js` | 16675 | `dd29e02505654eb7aac62519013fe9cdd883b56f78855806f6d643aadadc4295` |
| `dist/undici-runtime-BL8ZN-Ey.js` | 9835 | `3528db33bb716a2e30fe895cd93c4027750c2da57379c8107d0b748cb0857978` |

The actual `ssrf` helper races `close.call(candidate)` against a 100 ms timer. Its timeout path invokes `candidate.destroy()` without awaiting the result. The public `closeDispatcher` wrapper swallows errors. Therefore a return from this helper is not evidence that the original close/destroy Promises or native transport have finished. The prepared core R2 keeps the cooperative lock and the consumed once slot when transport closure remains unknown.

`undici-runtime` imports the Undici package lazily through `createRequire(import.meta.url)("undici")`. Pinning this public SDK source is distinct from observing that a particular runtime branch actually loaded the package. No unused lazy path was imported by this read-only observation.

The sibling review identified a concrete compatibility question for the prepared dispatcher observer: an actual Undici no-argument Promise overload may call its own callback overload through `this.close(...)` or `this.destroy(...)`. The current one-call wrapper must not reject such an original internal call. The installed package implementation and zero-network actual Agent tests are still required. This checkpoint does not claim that the question was resolved or that a provider hook ran successfully on the Mac.

## Gateway argv R2 actual result

Job `1a1b256bfb1-fc05-7d98`, stable key `heptabao-authbus-current-gateway-argv-readonly-20261106-r2`, was authoritatively `succeeded`, exit 0, with complete durable stdout of 1649 bytes and empty stderr. The original launch, terminal record, process-read result, and exact stdout are retained. Elapsed time inside the original 30-second operation was 0.001366 seconds; its supervisor limit was 45 seconds.

The operation read the already captured private restore record from the exact gateway-lineage job, rechecked its full identity and bytes, and rechecked the current registered configuration against that original private full9 and byte binding. It did not reread a credential database, query the business gateway, call a provider, create a child, or modify a service. All opened file descriptors were closed once.

The safe projection identified `/bin/sh`, the public Homebrew Node path, `/opt/homebrew/lib/node_modules/openclaw/dist/index.js`, and `gateway --port 18789`. The two unclassified shell arguments remain private. The public entry source was copied into the owned observation directory: 3293 bytes, SHA256 `9832720dcaf85519d315dda624497e352588f0d65c5607390df0501cc2358985`.

The R2 classifier did not recognize the shell switch/script shape. Its classifier booleans do not establish the absence of login-shell behavior or other flags. The current process was not reobserved in this operation; its original identity remains a prior observation. Default configuration selection, loaded plugin memory, and exclusion of concurrent writers remain unproven. The previous R1 failed result is retained separately and is not relabeled.

No credential value, profile ID, credential digest, production configuration digest, or raw private argv was published.
