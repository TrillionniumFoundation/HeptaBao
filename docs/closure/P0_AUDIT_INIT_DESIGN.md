# P0 wire-audit and initialization-delivery protocol

## Wire rejection

After TLS is established, every bounded HTTP parse rejection must pass through the authenticated audit writer before an error response is released. The event records only a fixed rejection class, status, peer-independent opaque fingerprint, sequence, previous MAC and time. It must never record headers, bearer values, request bodies, paths or query contents.

If the audit append cannot be persisted, the server releases no application response and fences new service admission until operator recovery.

## Initialization

Initialization has explicit `absent -> prepared -> published -> delivered` states. The server must not publish the durable initialized state before it has reserved and authenticated the one-time credential-delivery event. If a terminal audit write fails before publication, the prepared state is removed and the same request can safely retry. Once publication succeeds, the response contains the only unseal key and root token; a later transport loss is an operator-visible unknown delivery outcome and must not silently regenerate credentials.

Tests must inject exact audit-capacity exhaustion and real I/O failure before publication, restart the service, and prove either safe retry or deterministic recovery without credential destruction.
