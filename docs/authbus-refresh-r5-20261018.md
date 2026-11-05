# AuthBus R5 refresh outcome fencing — 2026-10-18

R5 is an isolated candidate on the AuthBus sources preserved at HeptaBao commit
`40b183000db486a677fadf9bd2fd34873a28c78e`. It does not switch production clients.

## Concrete R4 gap

R4 binds a refresh lease to an actual TLS/AppRole/KV2 CAS document and blocks a
competing owner while that lease is active. After the lease expires, R4 can issue
the same credential digest to a new owner. A provider can already have consumed
or rotated a refresh token before the old process dies or loses the response.
Lease expiry does not distinguish that state from an unsent refresh.

## R5 behavior

`TrustedBaoCoordinator.refreshOnce()` performs the following ordered actions:

1. Read the configured SDK owner's credential and check its authorized digest.
2. Durably close that owner's local admission before modifying control state.
3. Check the actual current assignment and refresh owner through TLS/AppRole.
4. CAS a persistent `UNKNOWN` refresh attempt and `REFRESH_PENDING` assignments.
5. Only after the CAS acknowledgement, permit one provider dispatch before the
   original trusted deadline. A second dispatch is rejected synchronously.
6. Accept a changed, nonexpired OAuth result, write it to the configured SDK
   owner, and reread the actual store to verify the new digest.
7. CAS `PUBLISHED` at a higher generation. A further fresh trusted epoch is
   required to reopen normal admission.

An intent CAS error, response loss, provider error, process death, SDK write
failure, failed readback, and completion CAS ambiguity have no retry or automatic
clear path. `UNKNOWN` remains in control storage even after every lease expires.
A published attempt permanently rejects reissuing its old credential digest.
If the completion response was lost but `PUBLISHED` committed, a cold issuer with
the already verified newer credential can obtain a new epoch without repeating
provider I/O.

The candidate uses protocol `heptabao-authbus-trusted-bootstrap-r5`. This is an
intentional closed bootstrap boundary: an R4 reader must not silently ignore
refresh attempts. Existing R4 documents require an explicit migration/new
bootstrap; this change does not convert them in place.

## Evidence

`qa/openbao-acceptance/authbus/refresh-r5-contract-receipt.json` records **13
scenarios and 52 passing assertions**. Its source manifest binds the receipt to
the exact tested modules. The test uses a real loopback HTTPS control endpoint,
fsync/rename control persistence, real HTTP provider requests, independent Node
processes, and a real `SIGKILL` after provider response. The control backend is a
TLS KV2 protocol emulator and the credential owner is an isolated JSON fixture.
It is not native HeptaBao or actual SDK OAuth qualification.

| Scenario | Provider requests | Durable outcome |
| --- | ---: | --- |
| Local admission close fails | 0 | No refresh attempt |
| Intent write denied | 0 | No refresh attempt |
| Intent commits, response lost | 0 | UNKNOWN; cold retry after expiry denied |
| Provider consumes request, response lost | 1 | UNKNOWN; cold retry after expiry denied |
| Owner SIGKILL after provider response | 1 | UNKNOWN; cold retry after expiry denied |
| SDK write returns false | 1 | UNKNOWN; cold retry after expiry denied |
| SDK reports success but reread is old | 1 | UNKNOWN; cold retry after expiry denied |
| Duplicate final dispatch | 1 | UNKNOWN; second send rejected |
| Deadline passes before final dispatch | 0 | UNKNOWN; send rejected |
| Completion commits, response lost | 1 | PUBLISHED; cold newer credential recovery |
| Successful publication | 1 | PUBLISHED; next trusted grant epoch advances |
| Two concurrent calls from same owner | 1 | One publication; competing CAS rejected |
| Registry successor resolution | 1 | New wire credential admitted; old credential rejected |

The original 11 R4 trusted-bootstrap contract scenarios also passed with the R5
control candidate. This preserves the cold-epoch, pending-write, proof-binding,
reader policy, renewal and revocation behavior at protocol-contract scope.

## SDK integration status

`authbus_refresh_registry_candidate.mjs` contains the scoped SDK adapter. It
closes local admission, invokes the durable coordinator, verifies the SDK store,
and reopens only with a fresh trusted grant. A private successor record permits
an in-flight resolver to return only the exact new wire credential produced by
that refresh; a stale credential cannot borrow the new epoch.

The registry has passed the synthetic credential-owner contract through an
actual HTTPS grant, refresh, new-epoch admission and successor-wire check. Its exact shared OAuth manager
and provider dispatch overlays must be bound to the actual installed SDK bytes
before it is connected or claimed as tested. The existing API-key SDK tests do
not qualify OAuth owner writeback or external CLI synchronization behavior.

## Required remaining evidence

- Bind and run the real SDK shared OAuth manager and final refresh transport.
- Verify OAuth writes cannot synchronize synthetic credentials to external CLI
  credential stores; use explicitly disabled external synchronization.
- Run the R5 protocol against an isolated native HeptaBao TLS/AppRole/KV2 backend,
  including server restart and cross-host CAS contention.
- Establish actual product bootstrap and complete caller coverage, including
  non-LLM callers, before production migration.
- Recover truly unknown provider outcomes only through a separately verified
  newer credential publication. No automatic provider retry is qualified.

No real provider refresh, real credential rotation, production service restart,
client traffic cutover, or OpenBao removal is part of this evidence.
