# Independent peer: actual public runtime loader and harness registry

Scope: whole-source review only, performed during the LAN readback sequence. No SDK import, module execution, synthetic test, host request or runtime authorization was performed for this peer.

## Exact reviewed inputs

- loader: Git blob 909ec9eab6932b1f9241fbb0969c772639f18cb3, 6,047 bytes, SHA256 bd6a9f363bc7aac2fb0503640e339ffce52e0eab15336e6489b6f8129df748fb.
- registry: Git blob 9f5042ec5442239f12975e3680c0568b3c85bdf8, 3,135 bytes, SHA256 a845875a1998c2a6bdd9fe4c824a0a7c3e7da0f3ee75ec56dc6163d4327f7ff0.

Both complete UTF-8 byte strings and Git blob identities were independently recomputed. These are the actual public files supplied by the SDK evidence owner; this peer does not replace that owner's host metadata/source provenance.

## Loader guarantees and limits

The exported t is ensurePluginRegistryLoaded. It normalizes options.onlyPluginIds and options.onlyChannelIds through imported helpers, resolves a load context, and derives expectedPluginIds. When channel IDs are provided and resolveDiscoverableScopedChannelPluginIds returns owner IDs, those IDs are combined with the normalized requested plugin IDs. Thus the original onlyPluginIds array is not necessarily the final closed set when both options are used.

For a scope treated as explicit by hasExplicitPluginIdScope, expectedPluginIds is the normalized requested list (or an empty list). The load-options call forwards onlyPluginIds: expectedPluginIds and throwOnLoadError: true under the written condition. This proves local argument flow. The exact normalization, empty-scope semantics, loading side effects and error behavior remain contracts of the imported helpers; those helper bodies were not reviewed here.

There are early returns when activeRegistrySatisfiesScope succeeds. Its requested-ID branch checks the requested workspace if defined, then delegates to registryContainsRuntimePluginIds. No local equality check requires that the active registry contain only the requested set, and this module does not clear extra harness registrations. resolveOrLoadRuntimePluginRegistry can likewise reuse an imported getLoadedRuntimePluginRegistry result rather than call loadOpenClawPlugins. The module performs no independent post-load exact-set assertion and returns no selected harness record.

Consequently, passing onlyPluginIds does not by itself prove an exclusive fresh instance, absence of other registered plugins, a particular executed handler, or the gateway's actual selected owner. The source also does not justify treating an isolated reviewing process as the pre-existing gateway process.

## Registry guarantees and limits

The exported r is getRegisteredAgentHarness. It looks up id.trim() in a process-local globalThis map stored under Symbol.for("openclaw.agentHarnessRegistryState"). Repeated imports in that same global context share the map. This is not a cross-process registry guarantee.

registerAgentHarness trims harness.id and uses Map.set, so a later registration with the same trimmed ID replaces the record. The returned object contains a copied harness whose pluginId is harness.pluginId ?? options?.ownerPluginId, and a separate ownerPluginId taken directly from options?.ownerPluginId. No local check requires those two fields to agree. An explicit differing harness.pluginId remains intact. The lookup returns the stored record directly, not a validated immutable copy; a missing ID returns undefined. Clear and restore functions can replace the map contents.

ownerPluginId therefore represents the ownership metadata supplied to registration. This file does not authenticate that metadata, establish configured/enabled status, or prove actual selection or invocation. A consumer wanting a specific owner must compare the actual returned record with its independently admitted intended owner and retain the selector's actual decision evidence. Any policy requiring consistency with an explicit harness.pluginId needs an explicit check elsewhere; it cannot be attributed to registry.r.

## Peer conclusion

The two exact files support the bounded claims above. They do not resolve the current selected-owner qualification by themselves. The larger selector implementation and its actual call context remain with authbus_migration for separate review. No new candidate, guard relaxation or runtime GO is proposed or granted here.
