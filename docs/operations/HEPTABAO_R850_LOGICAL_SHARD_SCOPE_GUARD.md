# R850 - Fail closed before deriving V6 physical shard identity

This isolated security hardening change builds on the exact R820
integrated candidate. It is not a V6 production writer or migration grant.

## Counterexample

The generic immutable Kv1Key constructor rejects NUL but can accept
other control characters in namespace, mount, and path. The previous
sharded_version_scope only rejected U+001F inside a logical mount.
It could therefore derive an apparently valid physical shard identifier
from an invalid logical owner. A future caller might stage physical
objects before a signed-graph check rejects the owner.

The red regression proves Kv1Key accepts three such malformed owners,
then asserts shard derivation must reject them. Before the fix this
single actual test failed naturally, exit 101.

## Fix

After checking the original typed scope, shard derivation rejects all
Unicode control characters in its namespace, mount, or path before
hashing the physical shard address. Original keying, schema, graph
authentication, object integrity, version cap, request deadlines,
and the production V5 writer are unchanged.

Successful targeted and full native tests are required on an exact
frozen commit. This remains pre-admission: the V5 aggregate 16 MiB
owner limit, V5-to-V6 migration, V6 HA publication, physical faults,
full official OpenBao 2.7.1 parity, custody, and release gates remain
OPEN. Replacement authority stays NOT_ADMITTED.
