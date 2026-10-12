# R700 — Bounded KV2 JSON ingress compatibility

**Scope:** isolated candidate; **not** a KV2 V6 production storage release.

## Reason for the change

The pinned OpenBao 2.7.1 same-host HTTPS oracle accepts a synthetic 2560KiB
KV2 JSON payload (HTTP 200), while the prior HeptaBao 2MiB ordinary HTTP
ingress returned 413 before state/engine admission. This is recorded in
`r680-official271-large-public.json` and the official denominator.

## Exact changes

- Ordinary HTTP JSON remains strictly bounded to **2MiB**.
- Only POST/PUT `application/json` with an unambiguous
  `/v1/<syntactic-mount>/data/<nonempty-path>` route receives a **3MiB**
  cap. Reserved non-KV mount names, encoded/ambiguous paths, traversal,
  alternative methods and media do not receive this allowance.
- HTTP/1.1 and HTTP/2 use the **same** route/budget predicate.
- The 413 rejection path still caps its optional body drain at 4MiB and
  never parses rejected bytes. Existing request deadlines, TLS, content
  framing, parsing strictness, rate limits and Service ACL/owner checks
  remain mandatory.
- Canonical request metadata digesting accepts the maximum legal bounded
  KV2 payload without allocating another plaintext copy.

The route predicate is a **syntactic ingress bound, not an authorization**
that the target is KV2. Service still has to resolve mount ownership and
reject unauthorized writes. The same bound must not be casually extended to
authentication, control, external plugin or snapshot interfaces.

## Actual evidence

Source branch: `fix/heptabao-r700-kv2-ingress-scoped`.
Pinned single-node binary SHA256:
`70987127633d2f16b15129d0bc130d6da6f7a96c70e8fb9deaa9429f424127a9`.

- Mac parsed HTTP/1.1 2560KiB unit test **1/1 passed**.
- Mac HTTP parser suite **27/27 passed**.
- Real Mac loopback HTTPS HTTP/1.1: 2560KiB KV2 POST 200, exact
  readback SHA256, version 1, restart/reunseal readback, non-KV2 >2MiB
  413 and KV2 >3MiB 413. Private fixture and process removed.
- Real Mac ALPN HTTP/2, explicitly negotiated version 2: same exact
  2560KiB successful write/read/restart and bounded rejections.
  Private fixture and process removed.

Receipts:
`r700-kv2-scoped-transport-validation/live-https-receipt.json`
and
`r700-kv2-scoped-transport-validation/http2-evidence/receipt.json`.

## Still OPEN

This does **not** lift V5 aggregate owner/state capacity (16MiB).
KV2 V6 remains test-only; no admitted durable production writer/reader,
migration, HA epoch/replay fencing or full OpenBao 2.7.1 parity has been
proven. Previous J3160 credentials cannot be copied from the failed device.
OpenClaw production AuthBus configs and the active old OpenBao provider
must remain unchanged until the complete migration and restart/rollback
proofs are satisfied.

## Rollback

The change is confined to this isolated worktree. Revert the source commit
or retain the old production binary/config; no production switch occurred.
