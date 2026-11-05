# Whole-source reading: policy, support and Codex harness

Status: SOURCE-ONLY findings from exact retrieved bytes. The three original body operations have completed; their 13,569 bytes, versions, SHA-256 values and EOFs are verified. No SDK was imported or executed. The original worker and every old guard, configuration, model, flag and budget are unchanged.

## What the new source establishes

1. Policy (`4c2a270a3a9e21ccf86032131700daf685157388`, lines 8–35) delegates configuration precedence to `resolveModelRuntimePolicy`, normalizes the returned policy ID, and calls the imported `openAIProviderUsesCodexRuntimeByDefault`. Only when that predicate is true and the computed runtime equals `auto` does this body return runtime `codex`. Neither imported implementation is present in this completed read set. This is conditional control flow, not proof that the five actual agents reach that branch.

2. Support context (`f216481adbe96bcba9f138a95c2ced5d25b11d4b`, lines 8–25) derives provider/model API, base URL, Azure version, provider request configuration, requested runtime, and optional owner metadata. A credential-free diagnostic cannot simply replace the entire original configuration with an empty object and claim equivalent selection. Each preserved or removed field needs a source-backed selection-equivalence argument. Provider request configuration may be sensitive; it is not admitted for public disclosure by this source review.

3. The comparator (same support source, lines 38–40) sorts larger priority first and uses harness ID locale order for ties. The automatic path probes every registered harness (lines 28–36; exact selector `41d3492a4965c62292eaa74a4d0b746b6bc4e4b2`, lines 15330–15358). Therefore a Codex positive support result alone does not prove it wins automatic selection, and filtering Google before observing the original selector would change the candidate set.

4. Actual Codex source (`39b49d3be2df87cde0af1f592a049cb49013c57d`, lines 2 and 16–33) declares default provider IDs `codex` and `openai`, but `options.providerIds` may override them. The exported creator also allows `options.id` to override the harness ID. Its default support branch returns priority 100. This file does not show which options were used to register the current object, and it does not supply a registration owner. The creator was not invoked.

5. The exact selector has distinct forced-plugin, automatic and built-in paths (lines 15255–15358), including an implicit-Codex-unavailable fallback. The original worker still calls `loader.t` with its preserved scope/config/owner-ID inputs, then `selector.o`, then compares the actual returned object to `registry.r('codex').harness` (worker `3614c27cb06f311870ceeeda3f01e806306ae0d1`, lines 338–343). These assertions are retained. `record.ownerPluginId`, `harness.pluginId`, selected harness ID and same-instance identity remain distinct observations.

6. The whole registry loader (`909ec9eab6932b1f9241fbb0969c772639f18cb3`, line 5 and lines 61–67) imports and delegates to `loader-D8d2EvVh.js`. It does not name a Google manifest or implement root resolution. The actual catalog's Google root is metadata evidence, not permission to invent a manifest path, widen the old npm guard, or claim that record 22 is irrelevant.

## Next bounded evidence

The accompanying SOURCE-only proposal names exactly three public files using literal imports from the two completed parent files: model-runtime-policy, openai-routing, and plugin loader. It requests only metadata if separately authorized; actual size/hash/version slots and subsequent body requests remain unset. There is no automatic import traversal, root scan, alias fallback or Google-file read. The remaining normalization and provider-owner helper implementations are still separately unresolved; these three files are a next evidence step, not a claim that the complete transitive import set is already qualified.

## Diagnostic admission boundary

A future owner diagnostic must preserve the five actual agent/model inputs and original flags and natural selector behavior. It must observe the actual registered object, owner metadata and canonical code/manifest pins in fresh isolated state. Any loader or supports invocation is SDK execution and requires its own exact reviewed request, an actual OS sandbox proving network and non-owned writes denied, and an explicit read allowlist that excludes current credentials, caches and auth stores. No factory/native/provider/refresh action is part of this source review. The current unbound diagnostic remains unbound; no source or guard has been changed to make the old failure pass.
