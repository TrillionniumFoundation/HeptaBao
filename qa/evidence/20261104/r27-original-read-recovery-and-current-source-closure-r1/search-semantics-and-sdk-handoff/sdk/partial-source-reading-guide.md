# Loader and selector-prefix reading guide — no selected-owner conclusion

## Verified inputs

The loader is complete: 6,047 B / bd6a9f363bc7aac2fb0503640e339ffce52e0eab15336e6489b6f8129df748fb / blob 909ec9eab6932b1f9241fbb0969c772639f18cb3. The selector input here is exactly offsets 0..131071 from two separately version-pinned 65,536-byte chunks, SHA256 db157816812dfcae9aa9fc900df23002c6db335d711dd2b7677499dc86d8b1a0 / blob 11b174952c5e5a073c3378351a425c820e6704fc. It is a partial text artifact, not an importable module or the complete 673,468-byte selector. The UTF-8 prefix decodes without removing bytes; its final source line is incomplete. Registry contents have not been read. Original first-three read evidence: partial df282bad33bae04e947cea7a6d823dc7e1bf18e5 plus root-tail adoption 9e7e3bb7c7e3e891506ca7109625a28d3f8a8fa0.

## Visible interface relationships

- Complete loader line119 exports ensurePluginRegistryLoaded as t. Lines69–113 treat explicit onlyPluginIds as a scoped set even when scope is all; changing that set changes the loader input. The complete loader-only note is included unchanged.
- Selector prefix line43 imports registry-DtLZ3rba.js alias r as getRegisteredAgentHarness and alias i as listRegisteredAgentHarnesses. This establishes the imported names; the registry function bodies and returned-owner fields remain unseen.
- Prefix line35 imports resolveAgentHarnessPolicy from harness-runtimes-CA3PNIDt.js; line106 imports compareHarnessSupport and buildAgentHarnessSupportContext from thinking-runtime-rftFo2fO.js. Lines28–30 import agent configuration and plugin metadata helpers. These are reading targets, not proof of their semantics or installed execution.
- The observed 131,072-byte prefix has zero export statements and zero call expressions to either getRegisteredAgentHarness or listRegisteredAgentHarnesses. It therefore does not identify what export o names or show the actual harness-selection algorithm. Its early agentHarnessIds mentions are metadata/diagnostic structure, not an observed selection result.

## Smallest useful next static reading order

1. Complete only the already frozen reads04–13. Reconstruct selector673468/ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66 and registry3135/a845875a1998c2a6bdd9fe4c824a0a7c3e7da0f3ee75ec56dc6163d4327f7ff0 before using them as complete source.
2. In the completed selector, locate the terminal export mapping for o, then read that exact function and its local callees. Determine which actual provider/model/config/agentId fields it uses, which registered candidates it considers, and its refusal/fallback branches. Do not infer these from imported helper names.
3. In the completed registry, locate export r and the registration/lookup data shape. Check whether it exposes an owning plugin identity and how the worker's registered.harness === selectedHarness assertion relates to registration. Static code can explain the assertion; it does not supply the live registered instance.
4. Compare those source contracts with the already captured five-agent declared models and actual worker loader.t/selector.o/registry.r calls. Any required imported implementation not already in the fixed evidence remains an explicit source gap; this guide does not authorize another path or SDK execution.

The enabled registry ordinal22 that failed the npm-root predicate is not labeled unused. No plugin is dropped and no namespace guard is broadened. Actual selected owner and complete code/manifest/root pins remain required for an admission repair.

## Fixed next request and scheduling

Read04 is the original blob a2a547a6bbc82a257554894738921a5aa6c3af40, 414 B / 73f1d1574b6c024a3393a622a228680a87b400022a4e425c8988682a8ef60403; its original key ends selector-ccff1311-o131072-20261105-r1. The ordered original requests are included unchanged. Reads04–11 each request65536 bytes, read12 requests18108, and read13 requests3135. Expected immutable original-SDK pages at16384 are6 each for04–11, then2 and1:51 pages total. These are planning estimates only; each actual page0 total_bytes, whole payload hash, cursor and EOF remain authoritative. All ten reads remain unsubmitted, and Runtime admission remains paused.
