# Committed SDK secret Storage invalidation

This candidate adds one bounded owner path: an unchanged, admitted secret SDK
mount may keep its persistent backend cache across a received committed Storage
change only after its actual `InvalidateKey` hook acknowledges the exact key
set. It does not qualify SDK Auth invalidation, the global plugin manager,
GoRPC, provider autojoin, V6 production writes, or full OpenBao replacement.

The genuine bridge uses the official OpenBao SDK v2.7.0 module and its typed
AutoMTLS plugin connection. Core OpenBao 2.7.1 uses a separately pinned oracle;
the SDK module version is recorded independently and is not renamed 2.7.1.

The received publication supplies both previous and installed StateIdentity
and its original deadline. The private notification binds namespace
incarnation, mount incarnation, catalog generation, the full descriptor,
unseal nonce, the persistent Control pointer, and canonical scoped old/new
record hashes. The engine decodes actual `sdk92/` records to recover Storage
key names. No SDK value becomes a callback capability or leaves the graph.
Unrelated mounts and byte-identical entries produce no notification. The
scan is bounded to 10,000 records, 256 changed keys and a 60 KiB key frame;
unprovable changes retire the entire old cache.

Before the received state is installed, an idle owner is reserved and its
storage epoch advances. Old Plans are rejected at execution, ordered worker
entry, Storage callbacks and terminal delivery. An already busy, fenced,
retiring or replaced owner is retired. A running old owner retains busy until
its original worker actually finishes, so a new owner cannot overlap it.
Dropping an incomplete or superseded notification also retires the cache.

After state and recovery index installation, the same writer checks the exact
installed graph and private capsule again, then queues `Invalidate` on the
existing worker. The hook has no Storage or auth callback authority. The
effective deadline is the minimum of the original publication deadline and
each current scope; transport sends a same-host absolute monotonic deadline.
An RPC error, missing or late acknowledgement fences the old process. A safe
cache discard may let installation complete while time remains; it is never
counted as a successful hook.

`HBSDK-INVALIDATION` records bounded owner hashes, incarnations, key count,
epoch and remaining time. Its disposition distinguishes `hook_acknowledged`,
`no_cache`, `discarded`, and `discarded_queue`. It prints no Storage key names,
opaque values, actor tokens or callback authority.

Validation is separated into three scopes:

- Engine and Service tests use actual record graphs and encrypted record
  publication. Explicitly named model queue tests cover finisher ACK, error,
  missing and late ACK, shortened clock, capsule mismatch and a real staged
  Plan's execution and terminal delivery veto. They are not SDK process proof.
- The bridge receipt pins genuine SDK processes, the typed RPC, monotonic
  clock, forbidden StoragePut during a hook, old companion rejection, blocked
  hook timeout and owned process cleanup.
- `sdk_storage_invalidation_multihost_live.py` has a fixed 65-case physical
  Linux LAN denominator. It must prove a primed cache returns a new committed
  value in the same plugin PID, actual hook StoragePut denial, a busy original
  invocation's fencing, an actual blocked invalidation hook's cache disposal,
  seal/unseal, encrypted restart, exact artifact custody and owned cleanup.
  A failed or unrun profile remains failed or unproven. Final mixed native
  Mac/X230/ROG qualification is a separate exact-HEAD artifact profile.

The original exploratory build failures and partial-parent receipts are kept.
Only a fresh source-frozen build and complete fixed-denominator live receipt
may qualify this candidate.
