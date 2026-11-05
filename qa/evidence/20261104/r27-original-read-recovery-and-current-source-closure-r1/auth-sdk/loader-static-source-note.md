# Actual loader-only source observation

## Exact source and limits

The actual public file `/opt/homebrew/lib/node_modules/openclaw/dist/runtime-registry-loader-Duw3fvRO.js` was completely reconstructed from its approved version-pinned binary read. It is 6,047 bytes, SHA256 `bd6a9f363bc7aac2fb0503640e339ffce52e0eab15336e6489b6f8129df748fb`, Git blob `909ec9eab6932b1f9241fbb0969c772639f18cb3`. The exact operation is `4067ea1adf703ac98617ad01d82659d0b54e4d041eddfe64d14bd0c5bf0989b0`; its raw original SDK payload and native binary result are preserved in partial packet `df282bad33bae04e947cea7a6d823dc7e1bf18e5`.

This note covers only that complete loader file. The 673,468-byte selector and 3,135-byte registry are not yet complete. No SDK or imported dependency was executed. No selected harness, owning plugin, unused enabled plugin, private credential, or code-root admission conclusion is made here.

## Directly visible control flow

1. Line 119 exports `ensurePluginRegistryLoaded` as `t`. This matches the actual worker's `await loader.t(...)`. The earlier diagnostic description string saying `loader.r` remains an archived description error, not an actual call.
2. Lines 69–85 normalize `options.onlyPluginIds`, derive `requestedPluginIds`, and set `scopedLoad` from the imported explicit-scope predicate. On the explicit-scope branch, `expectedPluginIds` comes from that requested set. This branch also exists when the requested scope string is `all`.
3. Lines 89–96 may reuse an active registry after workspace and requested-plugin containment checks. The implementation of imported containment/normalization helpers is not contained in this file, so this note does not strengthen those predicates beyond the visible call sites.
4. Lines 102–113 forward the resulting context/configuration and `onlyPluginIds: expectedPluginIds` to the runtime load-options builder with `throwOnLoadError: true`. Lines 61–67 call `loadOpenClawPlugins` only if the imported loaded-registry query has not satisfied those load options.
5. This file does not itself identify which registered harness the selector chooses for any of the five agents, and it does not establish an owner-plugin-to-code-root mapping.

## Consequence for a later admission repair

Changing the explicit plugin-ID set changes the input to the loader's scoped-load path; retaining the string `scope: 'all'` does not make that change equivalent to loading the former set. Therefore simply deleting the currently failing enabled non-npm registry entry is not evidence that it is unselected or irrelevant. A later narrowly bound repair still needs the complete selector/registry code, the actual original selector and registered-instance relationship, and exact manifests/code-root pins for its required load closure. No directory whitelist or existing private-input guard is relaxed by this note.

The observed third read's immutable-payload tail error remains unchanged. This source-only review adds no Runtime call, new admission, retry, or alternative request key.
