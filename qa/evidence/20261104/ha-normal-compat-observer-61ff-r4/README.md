# Normal-binary standby compatibility observer r4

This revision changes only reference-completeness metadata, the public wire schema revision, and the new exact TTL-restore reference. The original 34 expected statuses, actual credentials, requests, HTTP and setup budgets, artifact pins, fresh fixture, response parsing, exact-once coverage and owned-process cleanup are unchanged from corrected r3. No version of this observer has yet run.

## Complete reference and preserved correction

Thirty cases remain tied to the executed policy wire d1f40a22. Three cases remain tied to the older token wire 070f7234: TTL snapshot GET 200 and finite-use 1/2 GET redirects 307 with uses unchanged. That older oracle has 87 known operations and 83 dynamic checks, and does not contain the TTL invalid-restore request. The earlier incorrect attribution and the r3 refusal to grant scoped compatibility are retained in commits de16385 and 3fdb3ae.

The missing case is now supplied by a separate fresh fixed OpenBao 2.7.1 observation, job 1a1a7ce3181-fc05-2c94, archived at commit df47f00f3289fe690f38a8fd433f11b6f530ecc9. Exact wire cd035b00 has sequence 66 proving the actual TTL credential's root policy, zero use limit and remaining TTL 580; sequence 68 is the same credential's POST to the default standby snapshot route with no extra header and the exact 22-byte invalid body. It returned a complete HTTP 500 within the original 15-second request budget. Subsequent lookup retained zero use limit and positive TTL. The run recorded 75 known intents/outcomes, zero unknowns, and all 75 clients and three servers stopped. The HA agent independently read and hashed the full wire/result and the exact request/outcome, and checked the complete unchanged 34-label catalog.

## Execution and result limits

Use only the actual normal Mac source 70714605 / tree ef0ae637 and the three artifact SHA256 pins recorded in the manifest. Runtime checks enforce all pins. The fixture remains one physical host with three real processes and public TLS listeners. It uses actual fresh V5 initialization, cold copies, native V6 activation, policies and credentials. No redirect following or unknown mutation replay is enabled.

Exit 0 means a completed observation with owned cleanup. Scoped status compatibility requires all 34 labels exactly once, complete responses and no status differences; the reference gate is now grounded and enabled. Full replacement remains false. Bounded archive-shape checks are not restore or format compatibility proof. Product shortcomings are recorded as actual differences, never removed from the oracle.
