# Fixed OpenBao 2.7.1 policy and consistency observation

This directory preserves the exact successful reference-oracle helper, result and wire observations recovered from the original Desktop host after the local executor became unavailable. It also preserves the previous setup-only failure without relabeling it as a business result.

The original live job `1a1a75f341d-fc05-2b2d` remains authoritatively succeeded with exit 0, complete durable output and all owned processes stopped. There were 70 request intents and 70 outcomes, with zero unknown outcomes. The independently reviewed denominator is 67 complete HTTP responses and 3 definite failures before connection; the raw journal is being collected separately and is not silently invented here.

## Observed contracts

- On the default standby, unlimited root and TTL-root KV GET with a nonempty X-Vault-No-Request-Forwarding header, including the text false, returned 200 and the exact value.
- With consistency_missing_header_forward enabled, the same absent-consistency-index requests returned 307. Supplying the explicit X-Vault-Inconsistent policy allowed the declared local read. Writes remained 307 with a later leader GET returning 404.
- Real non-root read-policy tokens could download snapshots on the leader and default standby. The read-only policy was denied restore with 403. Read/update policy tokens reached malformed-archive validation and received 500 on the leader and default standby.
- The prior readiness failure had 73 known GET outcomes, zero mutations and no admitted business cases. The successful setup retained the original no-header sealed 503 observation, then used X-Vault-Inconsistent: fail only for node3 setup/control. Business headers and the original 15-second HTTP / 45-second readiness budgets were preserved.

These are reference observations on one physical host and three TLS processes. They do not qualify HeptaBao, demonstrate physical multi-host failover, or establish snapshot format interoperability or restoration. The 64 passed checks are observation and cleanup invariants.

## Recovery boundary

The recovered SDK envelopes are newly captured readbacks of the original durable job and original files. Original file content is byte-for-byte preserved and independently hashed. The new public-journal collector reads only 140 existing public intent/outcome files; its admission is known, but its terminal result was not yet delivered when this commit was made. No service or HTTP operation was replayed.

The unexecuted normal-binary observer r2 and Mac launcher r2 were still only in the unavailable local executor. Their known hashes are recorded, but replacement bytes are not claimed to be those originals. New Denied/ACL/KV product changes are still design work at this checkpoint.

## Later journal reconciliation

Commit `7700d695fa15018e855fb70eda3175a3a4a7a534` preserves the original collector's authoritative succeeded/exit-0 status and the exact 181,993-byte public journal packet. All 140 original intent/outcome files were individually decoded and hashed. The denominator is 70 intents and 70 outcomes: 67 complete HTTP responses and 3 definite preconnect failures, with 0 unknown outcomes. The earlier SDK timeouts remain in this archive as historical evidence; no mutation or oracle run was replayed. The prior review is preserved separately.
