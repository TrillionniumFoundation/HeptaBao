# AuthBus evidence recovered after executor loss

These files preserve existing observations from 2026-11-04. Recovery used cached exact requests, durable original job logs, immutable operation payloads, read-only original public receipts, and already published Git blobs. No provider request, token refresh, native Codex process, service restart, or production cutover was performed to recover evidence.

## ROG managed profile 2

The original installed SDK selected current managed profile 2 from a private copy of current SQLite state with forceRefresh:false and 69 successful dynamic checks. The separately authorized one-request case then made exactly one TLS-verified GET to the fixed wham/usage endpoint and received HTTP 200. Its response was fsynced privately before the SDK parser. The current credential, configuration, original unmanaged native profile 4 generation, production gateway PID, and source pins were unchanged; the owned namespace exited.

Exact source credential digest: 131b8515d48433365dd84555e7659297d4d62de631f9a526a8a4293f03396175. The successful provider job is 1a1a776065f-fc05-2b85; the actual SDK resolver job is 1a1a771eaeb-fc05-2b75. The two original public capsules retain SHA256 180eddd9b833b983c16b562cf2d92bf956412b1aa2d4c1fabc38b1283ac796f5 and b623c8d609523f9cddfed6ab34c8f0cfb33d71fc6a35b7ea29261363329b5e78. All 11 embedded files were independently read back from their original ROG paths and matched byte for byte.

The recovery directory contains exact executed source, stage stdin, public receipts, exact once-only requests, all five authoritative terminal records, original stdout, and immutable original controller payloads. A new recovery verifier passes 49 integrity and scope checks; this is distinct from the 69 actual SDK dynamic checks. The original local 29-file manifest (known SHA256 49eadaa0a8fb1e39b5550841f8e41e056bbc0d6f08c03dc9cfaa134eabc6d0a9) and original local reviewer report (f93405fc91aee2f924e8ff44f7671888a3df399a235ab21e3f729cce0f2759db) were not recovered, and this archive does not claim to reproduce that original file collection.

Run: node qa/evidence/20261104/authbus-fresh-managed2-61ff-r1/recovery/review_recovered.mjs

This result does not override managed profile 1's separately recorded current token_expired 401. It does not adopt unmanaged native profile 4 as an AuthBus identity, qualify a default gateway path, prove a model request, or establish HeptaBao migration in this managed2-only run.

## Desktop dependency inventory

Twenty of the original 23 files including the original manifest are recovered with exact original byte lengths and SHA256 values. The original read-only audit report was recomputed from its original 33 predicates and exact inputs: 5841 bytes, SHA256 93ef0242e3fadda725a4e8e30287d013fb7f1f898859f042f30f2945bdbf31cd. The original Python reviewer and full raw reports are retained. Its two auxiliary diffs and one prior syntax-failure wrapper remain unavailable and are explicitly listed in evidence/recovery-status.public.json; the manifest was not edited to hide them. The original failing reader, actual failed terminal, and SyntaxError stderr are nevertheless retained.

Run: python3 qa/evidence/20261104/authbus-desktop-source-61ff-r2/review_dependencies.py

Desktop has eight configured agents, six existing auth databases, ten OAuth rows and four distinct stored credential generations. The existing client still points to https://127.0.0.1:18200. The system provider and leaf renewal timer were active; its unit referenced /opt/hepta-openbao/2.7.0/bao (a path observation, not a measured binary version). Two pending runtime refreshes and three existing hold conditions were preserved. User-manager probes were refused inside the read-only namespace and do not qualify user gateway state. Root-only provider and renewal configuration reads were refused; no permission policy was changed.

## Native writer retirement gate

The fixed public SDK upsert/save sources prove the audited path does not write native Codex auth.json. The original AuthBus recycler bypasses Desktop's factory retirement barrier and ROG has no barrier in the original factory; static reachability is established, but live concurrent ready writers have not yet been observed. A native command pin helper failed on an incorrect vendor-layout glob before starting any native process. Its failure is retained as a helper issue. The next isolated test must separately prove shared-entry removal, second process spawn, and actual initialized leases, then validate the patched barrier for active leases and pending startup.

Production SDKs, AuthBus plugin installation, provider configuration, native credentials, held markers, and traffic were not changed by this recovery.
